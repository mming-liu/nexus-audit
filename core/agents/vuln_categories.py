"""漏洞类目注册表：把 OWASP Benchmark 的 11 个真实类别映射成
「Scenario 场景问题」+「Property 属性核对」两步法客观判断题。

设计要点（对齐 GPTScan 的 query_template）：
  - Scenario：Yes/No —— 代码里是否存在该类别对应的危险汇聚点（sink），且入参可达
  - Property：Yes/No —— 汇聚点之前是否存在对应的净化/校验/参数化处理

之所以拆成两问：单个"这里有没有漏洞"的提问对 LLM 来说太主观，
拆成"有没有 sink"+"有没有净化"两个可核对事实后，误报率显著下降。

合规：所有措辞都是防御视角（"是否已做参数化处理""是否使用安全随机源"），
不包含攻击载荷、利用步骤等敏感内容。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnCategory:
    key: str            # 与 OWASP expectedresults.csv 的 category 列一致
    display: str        # 中文展示名
    sink_question: str  # Scenario：危险汇聚点是否可达
    property: str       # Property：应有的防护是否缺失
    cwe: str = ""
    needs_taint: bool = True   # Scenario 是否要求"外部输入可达汇聚点"
    # 注意：weakrand / hash / crypto / securecookie 这类"配置型缺陷"，
    # 缺陷出在 API 选择本身，与外部输入是否可达无关。若强行要求污点可达，
    # 模型会因为"没看到用户输入流入"而一律答 No，导致整类漏报。
    owasp: bool = True         # 是否属 OWASP Benchmark 的 11 类（决定默认跑分范围）
    # 注意：Java 生态特有的类目（ssrf / xxe / spel / deserial / redir）
    # 在 OWASP Benchmark 里没有对应样本，只在真实项目评测中启用。


CATEGORIES: dict[str, VulnCategory] = {
    "sqli": VulnCategory(
        key="sqli", display="SQL 注入", cwe="CWE-89",
        # 判据必须覆盖**两种**拼接形态：JDBC 的字符串相加，和 MyBatis 的 ${} 占位符。
        # 只写 JDBC 形态时，MyBatis 样本里既看不到 `+` 也看不到 executeQuery，
        # 模型严格按字面判据只能答 No，于是整类漏报（mybatisVuln02 就是这么错的）。
        sink_question=("函数是否把外部可控的字符串直接拼进 SQL 语句？两种形态都算："
                       "① JDBC 字符串相加（如 \"... WHERE x='\" + param + \"'\"），"
                       "并交给 execute/executeQuery/executeUpdate；"
                       "② MyBatis 的注解或 XML 语句里用 ${...} 直接插入参数"
                       "（如 '%${_parameter}%'、ORDER BY ${order}）。"
                       "注意 #{} 是预编译占位符，不属于拼接。"),
        property=("该 SQL 是否使用参数化查询（PreparedStatement 的 ? 占位符 + setString/绑定参数，"
                  "或 MyBatis 的 #{} 占位符），或对入参做了白名单校验？"
                  "注意：仅对入参做 remove/setCharAt/URL 编码等处理，能改变内容但 "
                  "不阻止 SQL 语法注入的，可视作未充分防护。"),
    ),
    "cmdi": VulnCategory(
        key="cmdi", display="命令注入", cwe="CWE-78",
        # sink 不能只列 exec。Hello-Java-Sec 有两条真漏洞走的是别的入口：
        #   RuntimeVul.vul2        → rt.load(file)          （加载本地动态库）
        #   ProcessImplVul.vul     → 反射 Method.invoke 到 ProcessImpl.start
        # 判据里没写这两种，模型严格照字面只能答 No —— 表现为"模型漏报"，
        # 实际是判据漏项。凡"这一类 API 有哪些写法"，枚举必须来自真实样本
        # 反查，不能凭想当然。
        sink_question=("函数是否把外部可控字符串传入会导致命令/代码执行的 API？包括："
                       "① Runtime.getRuntime().exec(...)；"
                       "② new ProcessBuilder(...) 的命令参数、或 .command(...)；"
                       "③ Runtime.getRuntime().load(...) / loadLibrary(...)"
                       "（加载本地动态库，同样能执行本地代码）；"
                       "④ 通过反射触达的进程启动入口"
                       "（如 Class.forName(\"java.lang.ProcessImpl\") 后 Method.invoke）；"
                       "⑤ ScriptEngine/GroovyShell 之外的系统命令封装（如 commons-exec）。"),
        property=("传给命令执行 API 的内容是否为固定常量命令（不含外部输入），"
                  "或入参已通过白名单/转义处理？"
                  "注意：黑名单过滤（如过滤 | & ; 等特殊字符）**不算防护** —— "
                  "换行、$()、反引号等写法可绕过，看到黑名单仍应判定防护缺失。"),
    ),
    "xss": VulnCategory(
        key="xss", display="跨站脚本", cwe="CWE-79",
        sink_question=("函数是否把外部可控字符串未经编码地输出到客户端可见的位置？"
                       "两种形态都算："
                       "① 直接写进 HTTP 响应体（response.getWriter().println/print、"
                       "return 视图字符串且模板未转义）；"
                       "② 写入数据库/共享存储（Mapper/DAO/Repository 的 add/save/insert），"
                       "且另有路由把该数据未编码地回显（存储型 XSS）。"),
        property=("写入响应前是否调用了输出编码（如 ESAPI.encoder().encodeForHTML / encodeForJavaScript）？"
                  "单纯把输入转换为数值（parseInt/valueOf）或做 URL 解码，不算输出编码。"),
    ),
    "pathtraver": VulnCategory(
        key="pathtraver", display="路径遍历", cwe="CWE-22",
        sink_question=("函数是否把外部可控字符串拼进文件路径，并传给 "
                       "FileInputStream/FileOutputStream/Files.read/File/Paths.get 等文件 API？"),
        property=("构造文件路径前是否对入参做了路径规范化校验"
                  "（如 new File(esapi.encoder().encodeForPathTraversal(...)) 或白名单）？"),
    ),
    "weakrand": VulnCategory(
        key="weakrand", display="不安全随机数", cwe="CWE-330", needs_taint=False,
        # 配置型缺陷：与外部输入是否可达无关，只要随机源强度不足即成立。
        # 若把 SecureRandom 与 Random 一起问到，模型会被安全那一支带偏，故按强度提问。
        sink_question=("函数是否用非密码学安全的伪随机源生成安全敏感值"
                       "（如 rememberMe 令牌、会话密钥、盐值）？"
                       "判定依据是随机源类型：java.util.Random / Math.random() 属于不安全；"
                       "java.security.SecureRandom 属于安全。"),
        property=("该安全敏感值是否由 java.security.SecureRandom（或同等级密码学安全随机源）生成？"
                  "若代码中只出现 java.util.Random / Math.random()，则本属性为 No。"),
    ),
    "securecookie": VulnCategory(
        key="securecookie", display="不安全 Cookie", cwe="CWE-614", needs_taint=False,
        sink_question="函数是否构造并写入了 Cookie（new Cookie(...) + response.addCookie）？",
        property="该 Cookie 是否同时设置了 setSecure(true) 与 setHttpOnly(true)？",
    ),
    "trustbound": VulnCategory(
        key="trustbound", display="信任边界违例", cwe="CWE-501",
        # 枚举必须含 putValue：OWASP 的 trustbound 有 45/83 真漏洞用的是
        # session.putValue() 而非 setAttribute()，漏写会整批漏报。
        sink_question=("函数是否把外部可控值直接写入会话或请求的信任边界属性"
                       "（如 session.setAttribute / session.putValue / "
                       "request.setAttribute，键或值为外部输入）？"),
        property=("写入会话/请求属性的键与值是否都来自服务端可信常量，"
                  "或入参已通过白名单校验？只要键或值有一方来自外部输入，本属性即为 No。"),
    ),
    "hash": VulnCategory(
        key="hash", display="弱哈希", cwe="CWE-328", needs_taint=False,
        sink_question="函数是否使用 MessageDigest 对数据计算摘要？",
        property=("摘要算法是否为安全算法（SHA-256/SHA-512/SHA-3）？"
                  "MD5、SHA-1、SHA-0 属于已被证明不适合安全用途的弱算法。"),
    ),
    "crypto": VulnCategory(
        key="crypto", display="弱加密", cwe="CWE-327", needs_taint=False,
        sink_question="函数是否使用 Cipher 做加解密？",
        property=("算法是否为安全算法（AES-GCM / AES-CBC + 随机 IV）？"
                  "DES、3DES（DESede）、RC2、RC4、Blowfish、以及 ECB 模式属于弱加密。"
                  "注意：算法名以 Cipher.getInstance 的实际字符串实参为准，"
                  "注释里出现的算法名不构成证据。"),
    ),
    "ldapi": VulnCategory(
        key="ldapi", display="LDAP 注入", cwe="CWE-90",
        sink_question="函数是否把外部可控字符串拼进 LDAP 检索过滤器，并传给 DirContext.search？",
        property="LDAP 过滤器是否对入参做了转义（ESAPI.encoder().encodeForLDAP）或使用固定过滤器？",
    ),
    "xpathi": VulnCategory(
        key="xpathi", display="XPath 注入", cwe="CWE-643",
        sink_question="函数是否把外部可控字符串拼进 XPath 表达式，并交给 XPathExpression.evaluate 执行？",
        property="XPath 表达式是否对入参做了转义（ESAPI.encoder().encodeForXPath）或使用变量绑定？",
    ),

    # ---------------- 以下为 Java 生态特有类目（非 OWASP Benchmark 类别） ----------------
    # 引入动机：java-sec-code 这类真实项目里，SSRF / XXE / SpEL / 反序列化 / 开放重定向
    # 才是主力漏洞面，只跑 OWASP 那 11 类等于把真实项目大半入口丢掉。
    "ssrf": VulnCategory(
        key="ssrf", display="服务端请求伪造", cwe="CWE-918", owasp=False,
        sink_question=("函数是否把外部可控的 URL 字符串直接交给出站请求 API"
                       "（如 new URL(url).openStream()/getContent()、URLConnection.connect、"
                       "HttpClient.execute、OkHttp newCall、Jsoup.connect、IOUtils.toByteArray(url)）？"),
        property=("发起出站请求前是否校验目标 URL 的协议与主机"
                  "（协议限定 http/https + 解析域名后校验 IP/白名单）？"
                  "有效防护包括：① 请求前先判断协议；② 在 socket 层拦截域名解析并校验 IP"
                  "（如 startSSRFHook / 自定义 socket 工厂 / SocketHook 之类的钩子机制）；"
                  "③ 对域名做白名单校验。"
                  "仅仅「不判断 URL 前缀、不解析域名」的字符串校验不构成防护。"),
    ),
    "xxe": VulnCategory(
        key="xxe", display="XML 外部实体注入", cwe="CWE-611", owasp=False,
        sink_question=("函数是否把外部可控的 XML 内容交给 XML 解析器"
                       "（如 DocumentBuilder.parse、SAXReader.read、SAXBuilder.build、"
                       "SAXParser.parse、XMLReader.parse、Digester.parse、"
                       "TransformerFactory/XMLInputFactory/Unmarshaller 等）？"),
        property=("解析前是否禁用了外部实体与 DTD"
                  "（如 setFeature(disallow-doctype-decl, true)、"
                  "setFeature(load-external-dtd, false)、setExpandEntityReferences(false)、"
                  "setEntityResolver 返回空实现、setXIncludeAware(false)）？"),
    ),
    "spel": VulnCategory(
        key="spel", display="表达式注入", cwe="CWE-94", owasp=False,
        sink_question=("函数是否把外部可控字符串交给脚本/表达式引擎求值"
                       "（如 SpelExpressionParser.parseExpression、"
                       "ScriptEngine.eval、GroovyShell.evaluate、"
                       "Jakarta EL 的 ExpressionFactory.createExpression）？"),
        # 防护有两类互不替代的形态，判据必须都写出来：
        #   ① 限"表达式能访问什么" —— 受限 Context / 沙箱 / 类白名单
        #   ② 限"能传进来哪几条表达式" —— 对输入本身做枚举或精确比对
        # 只写 ① 的时候，GroovyVul.safe（safeCodeList.contains(cmd) + throw）
        # 会被一致判成"未防护"：模型严格照判据办，判据里确实没有 ②。
        # 这类漏必须在判据里补，改 prompt 措辞是没用的。
        property=("求值是否使用受限上下文"
                  "（如 SimpleEvaluationContext 且非 forReadWriteDataBinding，"
                  "或脚本引擎的沙箱/类白名单），"
                  "**或**对传入的表达式/脚本内容本身做了精确白名单比对"
                  "（如 `if (!whiteList.contains(expr)) throw ...`、"
                  "枚举映射、只接受固定几个字面量）？"
                  "注意两点：① 白名单必须**阻断执行**（throw/return），只记日志不算；"
                  "② 黑名单（如 Pattern 正则过滤 Runtime/exec）不算防护，天然可绕。"
                  "使用 StandardEvaluationContext 或未指定上下文且无上述白名单，属未防护。"),
    ),
    "deserial": VulnCategory(
        key="deserial", display="不安全反序列化", cwe="CWE-502", owasp=False,
        sink_question=("函数是否把外部可控数据交给反序列化 API"
                       "（如 ObjectInputStream.readObject、"
                       "XStream.fromXML、readValue(...enableDefaultTyping)、"
                       "fastjson parseObject、snakeyaml 默认 Yaml().load 等）？"),
        # 判据要写死"黑名单不算防护"，否则模型会把任何"看起来在做校验"的代码
        # 当成已防护。这不是理论问题：Deserialize.rememberMeVul 用了
        # AntObjectInputStream 的 denyClasses 黑名单（只 deny 三个包名前缀），
        # 模型 5 轮里有 2 轮判成"protected"，而黑名单本身就是可绕过的。
        # 反序列化防护的可信判据只有两类：白名单（只允许确定的类），
        # 或彻底关闭多态（SafeConstructor / safeMode / 关闭 DefaultTyping）。
        property=("反序列化前是否用**白名单**限定可还原的类（ObjectInputFilter 白名单、"
                  "SafeConstructor、fastjson safeMode、关闭 enableDefaultTyping），"
                  "**或**对反序列化的**输入内容本身**做了白名单/精确比对后才会进入"
                  "反序列化（如 `if (!allowList.contains(payload)) throw ...`），"
                  "或根本不做多态反序列化？"
                  "注意：黑名单/deny-list（如 resolveClass 里 startsWith 判断若干包名、"
                  "setBlacklist、Pattern 过滤 gadget 关键字）**不算防护** —— "
                  "黑名单天然可被未列举的 gadget 绕过，看到黑名单仍应判定防护缺失。"
                  "另外，把 XMLDecoder 换成 ObjectInputStream.readUnshared() 并不构成防护："
                  "readUnshared 只影响引用共享，不做任何类型过滤，同样是任意字节流的"
                  "多态反序列化。"),
    ),
    "redir": VulnCategory(
        key="redir", display="开放重定向", cwe="CWE-601", owasp=False,
        sink_question=("函数是否把外部可控字符串作为跳转目标传给 "
                       "sendRedirect、RequestDispatcher.getRequestDispatcher(...).forward(...)、"
                       "ModelAndView(redirect:...)、RedirectView、"
                       "response.setHeader(\"Location\", ...)？"),
        property=("跳转前是否把目标限制为站内相对路径或白名单域名"
                  "（如校验以 / 开头且不含 ://，或域名白名单校验）？"),
    ),
    "cors": VulnCategory(
        key="cors", display="跨域配置缺陷", cwe="CWE-942", owasp=False, needs_taint=False,        # 配置型缺陷：问题出在 CORS 响应头的取值上。
        # 注意 vuls2 写的是 `Access-Control-Allow-Origin: *`（常量），
        # 若按污点可达提问会被判成"没有外部输入流入，无 sink"。
        sink_question=("函数是否设置了 CORS 响应头 Access-Control-Allow-Origin"
                       "（response.setHeader、CorsConfiguration、@CrossOrigin 等）？"),
        property=("Access-Control-Allow-Origin 的取值是否受限（站内白名单）？"
                  "若取值直接原样回写请求头（如 response.setHeader(..., "
                  "request.getHeader(\"Origin\")) 未经校验），本属性为 No。"
                  "注意：固定为 \"*\" 是公开可读的常规用法，"
                  "只有同时设置了 Access-Control-Allow-Credentials: true 才构成缺陷。"),
    ),
    "hardcoded_secret": VulnCategory(
        key="hardcoded_secret", display="硬编码密钥/凭证", cwe="CWE-798",
        owasp=False, needs_taint=False,
        # 配置型缺陷：问题出在密钥的存放方式（代码 vs 环境/配置中心），
        # 与污点可达无关。
        sink_question=("函数或配置里是否把密钥/凭证直接写死为字符串字面量"
                       "（JWT 签名密钥、API Secret、私钥、accessKeySecret、"
                       "SECRET_KEY 等）？"),
        property=("密钥是否来自环境/配置读取（os.environ / System.getenv / "
                  "@Value(\"${...}\") / 配置中心）而非代码字面量？"
                  "注意：① 'random'、'test' 这类弱 JWT 签名密钥本身就是缺陷"
                  "（可猜测性是危害）；② 占位符（your-secret/xxx/123456）"
                  "不算；③ 单元只从 config/env 读取、不定义字面量的不算。"),
    ),
    "jwt_weakness": VulnCategory(
        key="jwt_weakness", display="JWT 验签绕过", cwe="CWE-347",
        owasp=False, needs_taint=False,
        # 配置型缺陷：问题出在验签调用本身，与外部输入是否可达无关。
        sink_question=("代码是否在解析 JWT 时关闭了签名校验或允许无签名算法？"
                       "包括 Python `jwt.decode(..., options={\"verify_signature\": False})`、"
                       "`verify=False`、`algorithms=[\"none\"]`；Java "
                       "`.parseClaimsJwt(`（未验签解析器）等。"),
        property=("解析 JWT 时是否强制验签并限定安全算法？"
                  "有效防护包括：`jwt.decode(..., algorithms=[\"HS256\"])` 且未关"
                  "`verify_signature`；Java `.setSigningKey(...).parseClaimsJws(`。"
                  "注意：① `algorithms=[\"none\"]` 本身即无验签；② 只把 token "
                  "当不透明字符串解码（base64）不算 JWT 验签；"
                  "③ `jwt.get_unverified_header` 只读头不算验签入口。"),
    ),
    "authz": VulnCategory(
        key="authz", display="越权与未授权访问", cwe="CWE-285",
        owasp=False,
        # 判据来源不是想象，是 JavaSecLab 的 idor 页面自述原文：
        #   "服务端把用户可控的对象标识符直接用于查询或操作资源，
        #    但没有校验该资源是否属于当前登录用户"
        #   "当前用户身份从 Session、JWT、OAuth Token 等可信上下文获取，
        #    不从请求参数决定"
        #   "管理员接口必须在服务端校验当前用户角色、权限点和资源归属"
        #
        # needs_taint=False 是刻意的：未授权访问样本（`/vulnapi/unauth/api/info`
        # 直接吐身份证号）**根本没有入参**。若按"外部输入可达汇聚点"提问，
        # 模型会严格照字面答 No，整类漏报 —— 与记忆里"定义上成立的短路仍会
        # 漏报"是同一个坑。本类目的判据是"资源访问是否缺少主体归属/角色校验"，
        # 与入参可不可控是两件事。
        needs_taint=False,
        sink_question=("函数是否在服务端访问了**归属于某个主体的资源**"
                       "（按用户名/用户ID/订单ID/文件名查库或读文件并返回其内容），"
                       "或者是否暴露了只应给特定角色/已登录用户使用的功能？"),
        property=("访问该资源前是否在**服务端**核对了主体归属或角色？有效防护包括："
                  "① 从可信上下文取当前主体（SecurityContextHolder 的 Authentication、"
                  "Session、JWT/OAuth Token）并与请求里的资源标识比对，不匹配则拒绝；"
                  "② 角色/权限点校验（@PreAuthorize、@RequiresRoles、hasRole、"
                  "或对当前主体做显式的角色常量比对）；"
                  "③ 查询条件本身把归属写死（如 where 里带 owner_id = 当前用户），"
                  "使越权在 SQL 层物理不可能。"
                  "注意：① 只在前端隐藏入口、只靠 URL 不公开、或只在方法注释里写"
                  "\"需要管理员\"，都不算服务端校验；② 把资源标识入参原样透传给"
                  "Mapper/DAO 而没有任何主体比对，本属性即为 No。"),
    ),
    # ---------------- M89：第 24 类 —— 服务端模板注入（SSTI） ----------------
    # OWASP Benchmark 没有此类样本，故 owasp=False —— 真值来自 Hello-Java-Sec
    # （Velocity evaluate / merge、FreeMarker putTemplate）与 Python 的
    # render_template_string / jinja2 动态模板样本。
    #
    # 判据的**关键区分**：问的是"模板**源**（模板文本本身）是否由外部输入决定"，
    # 而不是"模板里有没有渲染外部数据"—— 后者是所有模板的正常用法，
    # 把它算进来会让整类判成一堆误报（FreeMarker 的 Model 传参、Flask 的
    # `render_template("a.html", k=v)` 都属正常）。
    "ssti": VulnCategory(
        key="ssti", display="服务端模板注入", cwe="CWE-1336",
        owasp=False,
        sink_question=(
            "函数是否把外部可控字符串当作**模板源本身**交给模板引擎求值/编译？"
            "包括：① Velocity 的 `Velocity.evaluate(ctx, out, tag, templateString)`"
            "且 templateString 含用户输入；② FreeMarker 的 "
            "`new Template(name, new StringReader(content))` 或 "
            "`StringTemplateLoader.putTemplate(name, content)` 且 content 可控；"
            "③ Python 的 `jinja2.Template(user_str).render()` / "
            "`Environment.from_string(user_str)` / "
            "`flask.render_template_string(user_str)`。"),
        property=(
            "模板源是否来自**固定文件或服务端常量**，用户输入只作为模板**数据**"
            "（`VelocityContext.put(...)`、`model.addAttribute(...)`、"
            "`render_template(\"a.html\", k=v)`）传入？"
            "注意：① 把用户输入拼进模板文本（哪怕只是 `.replace(...)` 填占位符）"
            "本属性即为 No —— 用户输入进入了模板**语法**层；"
            "② 固定模板文件 + 用户数据入 model 属正常用法，本属性为 Yes；"
            "③ 只靠黑名单过滤模板语法关键字（`$`、`#`、`{`）不构成防护。"),
    ),

    # ---------------- M123：第 26 类 —— 批量赋值（CWE-915） ----------------
    "mass_assignment": VulnCategory(
        key="mass_assignment", display="批量赋值 / 权限字段越权绑定",
        cwe="CWE-915", owasp=False,
        sink_question=(
            "函数是否把**整个**请求体（dict / JSON / Map）一次性灌进模型或实体？"
            "包括：① Python `User(**request.json)` / `Model(**request.form)` /"
            " `obj.__dict__.update(request.json)` / `setattr` 循环；"
            "② Java `BeanUtils.copyProperties(reqMap, entity)` /"
            " `BeanUtils.copyProperties(dto, entity)`。"
            "只算「整包灌入」的形态；逐字段 `name=form['name']` 不算。"),
        property=(
            "灌入的目标模型是否含**权限字段**（`is_admin` / `is_superuser` /"
            " `role` / `permissions` / `is_staff` / `balance` / `owner_id`），"
            "且这次调用是否**没有**字段白名单或 `ignoreProperties` 排除？"
            "注意：① 没有权限字段的模型（如纯 Article）本属性为 Yes；"
            "② `Model(**{k: v for k, v in data.items() if k in ALLOWED})`"
            " 这类显式白名单为 Yes；③ 只更新普通业务字段的 DTO 也为 Yes。"),
    ),

    # ---------------- M124：第 27 类 —— 链上伪随机（SWC-120） ----------------
    "bad_randomness": VulnCategory(
        key="bad_randomness", display="链上伪随机数（可预测/可操纵）",
        cwe="CWE-330", owasp=False,
        sink_question=(
            "函数是否用**链上可观测/可操纵**的值决定资金归属或稀缺资源分配？"
            "包括：① `keccak256(abi.encodePacked(block.timestamp, …))`；"
            "② `block.blockhash(…)` / `blockhash(…)`；③ `block.difficulty` /"
            " `block.prevrandao` / `block.number` / `now` 参与取模 `%` 或比较后"
            "决定赢家；④ 上述结果直接驱动 `transfer` / `send` /"
            " `call{value:}` 或 NFT 铸造。"),
        property=(
            "随机源是否换成了**链下不可预测**的方案（Chainlink VRF 的"
            " `fulfillRandomWords` / `requestRandomWords`，或提交-揭示"
            " commit-reveal），或该 `block.timestamp` 只用于**冷却期/截止时间**"
            "比较（`require(block.timestamp >= unlockTime)`）而没有参与结果判定？"
            "注意：只做时间窗口校验、抽奖结果另用 VRF 的，本属性为 Yes。"),
    ),

    # OWASP Benchmark 无此类样本 → owasp=False。真值来自 Hello-Java-Sec 的
    # CSVInjection.exportVul / Traversal.download / SSRF 的图片下载（都把
    # 形参直接拼进 Content-Disposition）。
    "header_injection": VulnCategory(
        key="header_injection", display="HTTP 响应头注入（CRLF）", cwe="CWE-113",
        owasp=False,
        sink_question=(
            "函数是否把外部可控字符串直接拼进**响应头**下发？包括："
            "① `response.setHeader(name, value)`；② `response.addHeader(name, value)`；"
            "③ `response.setHeader(\"Location\", …)` 之外的其它自定义头。"
            "只算 value 里**直接出现**请求读取（`request.getParameter(...)`）或"
            "本函数裸形参的形态。"),
        property=(
            "写入响应头之前是否清除了 CR/LF（`replaceAll(\"[\\\\r\\\\n]\", \"\")`、"
            "`replace(\"\\r\", \"\")`），或做了 URL 编码/安全包装"
            "（`URLEncoder.encode`、`safeHttpHeader`、`StringEscapeUtils`、"
            "`ESAPI.encoder()`）？"
            "注意：① 值若是纯常量、数字长度、或服务端对象取值"
            "（`file.getName()`、`realFilePath.getFileName()`）本属性为 Yes；"
            "② 只做业务字符过滤（去掉中文/符号）不算清 CR/LF。"),
    ),

    # ---------------- Solidity / Web3（Module 17）----------------    # 这两类的判据形状与 Web 类目不同：都不需要"外部输入可达"——
    # 重入是**执行顺序**问题（外部调用与状态写入的先后），
    # 访问控制是**身份校验**问题（特权操作前有没有主体比对）。
    # 若沿用 needs_taint=True 的提问，模型会因为"链上函数本来就被任何人调用"
    # 而一律答 Yes/No 走偏，重演 authz 那个"定义上成立的短路仍会漏报"的坑。
    "reentrancy": VulnCategory(
        key="reentrancy", display="重入漏洞", cwe="CWE-841",
        owasp=False, needs_taint=False,
        # 判据挂"机制"不挂类目（记忆条 10）：真正要问的是调用顺序，
        # 不是"这个类别存在不存在"。
        sink_question=("函数是否向外部地址转出以太币或调用外部合约"
                       "（call / transfer / send / delegatecall，含老语法 "
                       "msg.sender.call.value(x)()），**并且**在这类外部调用之后"
                       "仍然写本合约的状态变量（余额映射、计数器、标志位）？"),
        property=("外部调用之前是否已经把本合约的状态更新完毕，或有等效的重入防护？"
                  "有效防护包括：① 严格按「检查-生效-交互」(CEI) 的顺序，"
                  "先更新余额/状态再做外部调用；② 使用 nonReentrant 一类的互斥锁 "
                  "modifier，且其**实现体**真的设置了锁标志并在退出时清除；"
                  "③ 外部调用之后不再有任何状态写入。"
                  "注意：① 状态更新写在外部调用之后（哪怕中间隔着一层 if 或返回值判断）"
                  "即为 No；② 只在注释里写「本函数安全」不算防护；"
                  "③ 只把金额改成常量或只读状态不算 CEI。"),
    ),
    "access_control": VulnCategory(
        key="access_control", display="访问控制缺失", cwe="CWE-284",
        owasp=False, needs_taint=False,
        sink_question=("函数是否执行了只应给特定主体做的特权操作"
                       "（转出合约以太币、销毁合约 selfdestruct/suicide、"
                       "修改 owner/管理员地址、铸造代币、清空或改写他人余额、"
                       "修改手续费/利率等关键参数）？"),
        property=("执行该操作前是否在链上核对了调用者身份或权限，"
                  "且核对不通过时拒绝继续执行？有效防护包括："
                  "① 用 require/revert 把 msg.sender 与 owner/admin 状态变量"
                  "或常量比对，不相等则中止；② 使用 onlyOwner / onlyAdmin 一类的 "
                  "modifier，且其**实现体**真的做了 msg.sender 比对；"
                  "③ 多签或角色表校验，且实现体真的查表。"
                  "注意：① 用 tx.origin 做比对不算防护（可被钓鱼绕过）；"
                  "② 只检查初始化状态（m_numOwners > 0、initialized 标志、"
                  "supply > 0）不是身份校验；③ 只在前端隐藏入口或只在注释里声明"
                  "「仅管理员」不算链上校验；④ 名字叫 onlyOwner 但实现体没比对 "
                  "msg.sender，也不算防护。"),
    ),
    # M53：Solidity 算术溢出/下溢（SWC-101）。OWASP Benchmark 无此类样本，
    # 故 owasp=False —— 它的真值来自 smartbugs dataset/arithmetic。
    "arithmetic": VulnCategory(
        key="arithmetic", display="算术溢出/下溢", cwe="CWE-190",
        owasp=False, needs_taint=False,
        sink_question=("函数中是否存在可能发生整数溢出或下溢的算术运算"
                       "（对状态变量/映射的 += -= *= /=，或含外部输入的二元"
                       "算术表达式）？"),
        property=("该算术运算是否受到有效的溢出保护？有效防护包括："
                  "① 编译器版本为 0.8 或更高（内置溢出检查，unchecked 块除外）；"
                  "② 全部算术走 SafeMath 库的 add/sub/mul/div；"
                  "③ 减法/加法前有显式的上下界校验（require(a >= b) / "
                  "require(b <= a) / if (a < b) revert）。"
                  "注意：① 0.4.x ~ 0.7.x 编译器不检查溢出；"
                  "② 只在注释里写「注意溢出」不算防护；"
                  "③ 对加法用 require(a >= b) 不构成溢出防护。"),
    ),
}

ALL_KEYS = list(CATEGORIES.keys())
OWASP_KEYS = [k for k, v in CATEGORIES.items() if v.owasp]


def get(key: str) -> VulnCategory | None:
    return CATEGORIES.get(key)
