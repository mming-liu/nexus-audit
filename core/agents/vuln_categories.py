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
        key="cors", display="跨域配置缺陷", cwe="CWE-942", owasp=False, needs_taint=False,
        # 配置型缺陷：问题出在 CORS 响应头的取值上。
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
}

ALL_KEYS = list(CATEGORIES.keys())
OWASP_KEYS = [k for k, v in CATEGORIES.items() if v.owasp]


def get(key: str) -> VulnCategory | None:
    return CATEGORIES.get(key)
