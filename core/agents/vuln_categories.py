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
        sink_question=("函数是否把外部可控的字符串直接拼接进 SQL 语句"
                       "（如 \"... WHERE x='\" + param + \"'\"），并交给 "
                       "execute/executeQuery/executeUpdate 执行？"),
        property=("该 SQL 是否使用参数化查询（PreparedStatement 的 ? 占位符 + setString/绑定参数），"
                  "或对入参做了白名单校验？注意：仅对入参做 remove/setCharAt/URL 编码等处理，能改变内容但 "
                  "不阻止 SQL 语法注入的，可视作未充分防护。"),
    ),
    "cmdi": VulnCategory(
        key="cmdi", display="命令注入", cwe="CWE-78",
        sink_question=("函数是否把外部可控字符串传入 "
                       "Runtime.getRuntime().exec(...) 或 ProcessBuilder 的命令参数？"),
        property=("传给命令执行 API 的内容是否为固定常量命令（不含外部输入），"
                  "或入参已通过白名单/转义处理？"),
    ),
    "xss": VulnCategory(
        key="xss", display="跨站脚本", cwe="CWE-79",
        sink_question="函数是否把外部可控字符串直接写进 HTTP 响应体（如 response.getWriter().println/print）？",
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
        property=("求值是否使用受限上下文"
                  "（如 SimpleEvaluationContext 且非 forReadWriteDataBinding，"
                  "或脚本引擎的沙箱/类白名单）？"
                  "使用 StandardEvaluationContext 或未指定上下文，属未防护。"),
    ),
    "deserial": VulnCategory(
        key="deserial", display="不安全反序列化", cwe="CWE-502", owasp=False,
        sink_question=("函数是否把外部可控数据交给反序列化 API"
                       "（如 ObjectInputStream.readObject、"
                       "XStream.fromXML、readValue(...enableDefaultTyping)、"
                       "fastjson parseObject 等）？"),
        property=("反序列化前是否限制了可还原的类"
                  "（如 ObjectInputFilter 类白名单、"
                  "setBlacklist/setWhiteList、"
                  "关闭 enableDefaultTyping、fastjson 开启 safeMode）？"),
    ),
    "redir": VulnCategory(
        key="redir", display="开放重定向", cwe="CWE-601", owasp=False,
        sink_question=("函数是否把外部可控字符串作为跳转目标传给 "
                       "sendRedirect、ModelAndView(redirect:...)、"
                       "RedirectView、response.setHeader(\"Location\", ...)？"),
        property=("跳转前是否把目标限制为站内相对路径或白名单域名"
                  "（如校验以 / 开头且不含 ://，或域名白名单校验）？"),
    ),
}

ALL_KEYS = list(CATEGORIES.keys())
OWASP_KEYS = [k for k, v in CATEGORIES.items() if v.owasp]


def get(key: str) -> VulnCategory | None:
    return CATEGORIES.get(key)
