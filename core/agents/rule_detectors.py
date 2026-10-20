"""确定性算法强度判定（第5周补充：为配置型类目兜底）。

为什么需要：OWASP Benchmark 的 crypto/hash/weakrand/securecookie 四类，
判定依据是「用了哪个 API / 哪个算法」，这是**客观事实**而非语义推理。
实测发现免费模型对 RSA/ECB/OAEP（把 RSA 的 ECB 当成 AES-ECB 不安全）会误判，
且上下文再全也改不了 —— 属于模型知识盲区。

工程结论：凡能用确定性规则判定的，就不该交给概率模型。
本模块对可提取到明确证据的样本直接给出结论，模型只处理无法判定的剩余部分。

每个规则返回 True(不安全) / False(安全) / None(证据不足，交回 LLM)
"""
from __future__ import annotations

import re

from core.text_utils import strip_comments

# ---------------- 算法强度表 ----------------

WEAK_CIPHERS = ("DES", "DESEDE", "TRIPLEDES", "RC2", "RC4", "ARCFOUR", "BLOWFISH", "IDEA")
# RSA 的 ECB 是填充/工作模式标识，不构成 ECB 可预测性缺陷，必须排除
RSA_FAMILY = ("RSA", "OAEP", "MGF1")

WEAK_HASHES = ("MD2", "MD4", "MD5", "SHA", "SHA-0", "SHA-1", "SHA1")


# ---------------- 入口体切分 ----------------
#
# 切片里除了入口方法体，还拼了同文件辅助方法、跨文件实现体、配置取值。
# 逐行扫关键词做规则判定时，必须只扫**入口方法自己的体**，否则：
#   - Cors.vuls1 的切片里躺着同类的 seccode()（安全写法，含 checkURL 白名单），
#     扫"有没有白名单校验"会把 vuln 判成 safe；
#   - Rce.yarm 的切片里躺着同文件的 CommandExec()（含 exec），
#     扫"有没有 exec"会把 yaml 反序列化判成命令注入。
# 两类污染都是真实踩出来的，所以统一先截到第一个分隔注释之前。

_SEP = re.compile(r"^//\s*----", re.M)


def entry_body(source: str) -> str:
    """只保留入口方法体：截到第一个 `// ---- ...` 分隔注释之前，并**剥掉注释**。

    剥注释这一步不能省。Hello-Java-Sec 的 XXE 样本里，作者把修复写法注释掉
    留在原地：

        // 修复：禁用外部实体
        // xmlReader.setFeature("...disallow-doctype-decl", true);
        xmlReader.parse(...);

    不剥注释，`XXE_NO_DOCTYPE_RE` 就会命中那行注释，把真漏洞判成"已禁用
    DOCTYPE = 安全" —— 一条规则把整个类的真值判反，而且不报错、不留痕迹。
    真实项目里"留一行注释掉的修复"很常见（java-sec-code 整个 CorsConfig2.java
    就是被注释掉的死配置）。

    注意只剥**入口体**的注释：分隔符之后的证据块本身是用 `//` 渲染的代码，
    剥掉就把证据删了。
    """
    m = _SEP.search(source)
    body = source[: m.start()] if m else source
    return strip_comments(body, keep_lines=False)


def _sibling_methods(source: str) -> str:
    """分隔注释之后的部分（同文件辅助方法 + 跨文件实现体 + 装配证据），不含配置块。

    这里踩过一个坑：切片有两种"实现体"通道，位置不同 ——

        // ---- 跨文件辅助方法实现（入口方法调用的外部方法…）----   ← obj.method() 形式
        // ---- 跨文件证据：checkOs() 的接口实现类方法体 @ … ----     ← 接口实现/MyBatis 通道

    `Security.checkOs(...)` 走的是**第二条**（静态工具类被当"接口实现类"解析）。
    只截到第一个「相关配置实际取值」之前、或者只认段名里带"辅助方法"的那一段，
    这段就会被整体漏掉 —— 于是明明证据就在下面 10 行，规则却说"读不到实现"。
    这里改为：配置块之后的所有内容都算证据（配置在段首，实现在段尾）。
    """
    m = _SEP.search(source)
    if not m:
        return ""
    body = source[m.start():]
    cfg_mark = "相关配置实际取值"
    i = body.find(cfg_mark)
    if i < 0:
        return body
    # 配置段从它自己的 `// ----` 行开始，结束于下一个 `// ----` 行。
    # 跳过整段配置，保留其后所有实现体/装配证据。
    nxt = _SEP.search(body, body.find("\n", i) + 1)
    if nxt and nxt.start() > i:
        # 保留配置段之前的头部说明 + 配置段之后的全部内容
        return body[: body.rfind("\n", 0, i) + 1] + body[nxt.start():]
    return body[: body.rfind("\n", 0, i) + 1]


_WIRING_MARK = "框架装配证据"


def wiring_block(source: str) -> str:
    """抽取切片里的框架装配证据段（Filter / Interceptor / CORS Bean 的配置体）。

    为什么需要：CORS 有一半样本入口方法体是空的 ——

        @GetMapping("/sec/webMvcConfigurer")
        public CsrfToken getCsrfToken_01(CsrfToken token) { return token; }

    防护完全在方法外的 Filter / WebMvcConfigurer / CorsConfigurationSource 里。
    切片器已经把那段配置体当证据拼进来了（`// ---- 框架装配证据 ----`），
    但规则此前只扫入口体，看不见 —— 于是这几条仍然靠模型猜。
    有了这个函数，规则就能吃到同一份证据。

    返回的是**去掉了每行 `// ` 前缀的纯代码**，方便直接复用正则。
    """
    i = source.find(_WIRING_MARK)
    if i < 0:
        return ""
    # 回退到该行行首，避免把 "// ---- " 截一半
    lo = source.rfind("\n", 0, i)
    lines: list[str] = []
    for ln in source[lo + 1:].splitlines():
        s = ln.lstrip()
        if not s.startswith("//"):
            break                       # 装配块结束
        body = s[2:]
        if body.startswith("   ") or body.startswith("  "):
            lines.append(body[3:] if body.startswith("   ") else body.strip())
        else:
            lines.append(body)          # 头部说明行（[filter] ...）保留也无害
    return "\n".join(lines)


def _wiring_sections(wblock: str) -> list[tuple[str, str]]:
    """把装配块切成 [(组件名, 组件体)]。

    头部形如 `[filter] ReferFilter  urlPatterns=['/*'] ...` / `[cors-config] ...`。
    块首那一行 `---- 框架装配证据：... ----` 不是组件，必须丢掉 ——
    否则会产出一个名字为空、体为说明文字的伪组件。
    """
    out: list[tuple[str, str]] = []
    name = ""
    buf: list[str] = []

    def flush() -> None:
        if name:
            out.append((name, "\n".join(buf)))

    for ln in wblock.splitlines():
        m = re.match(r"\s*\[([\w-]+)\]\s+(\w+)", ln)
        if m:
            flush()
            name, buf = m.group(2), []
        elif name:
            buf.append(ln)
        # 组件出现之前的任何行（标题、空行）直接忽略
    flush()
    return out


_DECORATOR = re.compile(r"^\s*@\w+", re.M)


def _entry_head(source: str) -> str:
    """入口方法的注解 + 签名 + 方法体（不含兄弟方法）。

    `entry_body()` 截到第一个分隔注释，已经排除了兄弟**方法体**，
    但注解行也在入口体前面，这里不需要额外处理 —— 保留此别名是为了
    语义清晰：凡涉及"这个入口上的注解"都应走它，而不是裸 `source`。
    """
    return entry_body(source)


def _norm(alg: str) -> str:
    return alg.strip().upper()


def cipher_is_weak(alg: str) -> bool | None:
    """判定 Cipher 算法字符串是否弱加密。返回 None 表示无法判定。"""
    if not alg:
        return None
    a = _norm(alg)
    if any(k in a for k in RSA_FAMILY):
        return False                       # RSA-OAEP 系列：安全
    if any(k in a for k in WEAK_CIPHERS):
        return True                        # DES / 3DES / RC4 ...
    if a.startswith("AES"):
        # AES-ECB 无 IV，相同明文产生相同密文，属可预测模式
        if re.search(r"(^|/)ECB(/|$)", a):
            return True
        return False                       # AES-GCM / CBC / CCM 等
    if a.startswith("CHACHA") or a.startswith("POLY1305"):
        return False
    return None


def hash_is_weak(alg: str) -> bool | None:
    """判定 MessageDigest 算法是否弱哈希。"""
    if not alg:
        return None
    a = _norm(alg).replace("_", "-")
    if a in ("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512",
             "SHA-512/256", "SHA-256/224"):
        return False
    if a in ("MD5", "SHA-1", "SHA1", "SHA-0", "MD2", "MD4", "SHA"):
        return True
    if a.startswith("SHA-") and a.split("-")[1].isdigit():
        return int(a.split("-")[1]) < 224  # SHA-1 系列归弱
    if a.startswith("SHA3-"):
        return False
    return None


# ---------------- 证据提取 ----------------

# Cipher.getInstance("ALG") 直接字面量（可能跨行、可能带 provider 第二参数）
CIPHER_LITERAL = re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"([A-Za-z0-9/_\-]+)"', re.I)
HASH_LITERAL = re.compile(r'MessageDigest\s*\.\s*getInstance\s*\(\s*"([A-Za-z0-9/_\-]+)"', re.I)
PROP_REF = re.compile(r'getProperty\s*\(\s*"([^"]+)"')


def extract_cipher_alg(source: str, config: dict[str, str] | None = None) -> str | None:
    """从源码里提取实际生效的 Cipher 算法：优先字面量，其次配置回填值。"""
    m = CIPHER_LITERAL.search(source)
    if m:
        return m.group(1)
    return _from_config(source, config, hints=("cryptoalg", "cipher", "encrypt"))


def extract_hash_alg(source: str, config: dict[str, str] | None = None) -> str | None:
    m = HASH_LITERAL.search(source)
    if m:
        return m.group(1)
    return _from_config(source, config, hints=("hashalg", "hash", "digest"))


def _from_config(source: str, config: dict[str, str] | None, hints: tuple[str, ...]) -> str | None:
    """源码里 getProperty 引用的键，或配置块（切片尾部回填）里的算法键。"""
    if not config:
        return None
    for m in PROP_REF.finditer(source):
        key = m.group(1)
        if key in config:
            return config[key]
    for k, v in config.items():
        if any(h in k.lower() for h in hints) and "/" in str(v):
            return str(v)
    return None


def parse_config_block(source: str) -> dict[str, str]:
    """解析切片尾部注入的 `// key = value` 配置块。"""
    out: dict[str, str] = {}
    in_block = False
    for line in source.splitlines():
        if "相关配置实际取值" in line:
            in_block = True
            continue
        if in_block:
            s = line.strip()
            if not s.startswith("//"):
                break
            body = s[2:].strip()
            if "=" in body:
                k, _, v = body.partition("=")
                out[k.strip()] = v.strip()
    return out


# ---------------- CORS ----------------
#
# 为什么 CORS 必须用规则而不是问模型：Java 里 CORS 防护的写法极度分散，
# 同一个仓库里四种写法（@CrossOrigin 注解 / WebMvcConfigurer / Spring Security
# CorsConfiguration / Filter），模型每次都在"这段代码有没有设置 ACAO"和
# "有没有校验 Origin"之间摇摆。实测 8 条 CORS 样本 5 轮里 7 条结果不一致。
# 而判据本身是完全客观的：回显 Origin 且带 Allow-Credentials 就是漏洞。
#
# 三种结论：
#   True  — 入口体内回显了外部 Origin（或写 *），且没有本地 Origin 校验
#   False — 有 Origin 白名单校验，或 ACAO 是写死的固定域名（不看请求）
#   None  — 入口体内根本没有 CORS 响应头 → 防护在方法外（Filter/Bean 装配），
#           这类必须交给装配解析器，规则不做猜测（见 core/context/framework_wiring.py）

ACAO_RE = re.compile(
    r"""setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*([^)]*)\)""", re.I)
ACAC_RE = re.compile(
    r"""setHeader\s*\(\s*["']Access-Control-Allow-Credentials["']\s*,\s*["']true["']""", re.I)
# 请求头读法：getHeader("Origin") 及其变体
ORIGIN_READ_RE = re.compile(
    r"""getHeader\s*\(\s*["']origin["']\s*\)""", re.I)
# 本地 Origin 校验的迹象（白名单比对 / 正则 / equals 判断）
ORIGIN_CHECK_RE = re.compile(
    r"checkURL|checkOrigin|allowedOrigins?|whiteList|whitelist|"
    r"isAllowedOrigin|matches\s*\(|\.equals\s*\(\s*origin", re.I)
# 单个标识符即"原样回显请求头"
_IDENT = re.compile(r"^[A-Za-z_]\w*(\s*\.\s*\w+\s*\(\s*\))?$")


# ---------------- CORS：装配型证据 ----------------
#
# 入口方法体里没有 CORS 头时，防护只可能在方法外，共有四种装配形态：
#
#   1. @WebFilter + doFilter 里 setHeader           → OriginFilter
#   2. WebMvcConfigurer.addMapping(...).allowedOrigins(...)  → CustomCorsConfig
#   3. CorsConfigurationSource.registerCorsConfiguration("/path", cfg)
#                                                    → BaseCorsFilter / WebSecurityConfig
#   4. @CrossOrigin 注解直接写在入口方法上（入口体里，不走这里）
#
# 判据与入口体型完全一致：**回显外部 Origin 且允许携带凭据 = 漏洞**。
# 关键客观事实是 `allowedOrigins` / `addAllowedOrigin` 的取值：
#   - 全部是固定字面量域名（且不是 "*"）→ 有白名单，安全
#   - 出现 "*" 或 allowedOriginPatterns("*")     → 过宽，不安全
#   - allowedOrigins 被注释掉 / 完全缺失          → 等于不限 Origin，不安全
# 最后一条是 CustomCorsConfig 的真实情况：`.allowedOrigins(allowOrigins)` 整行
# 被注释掉，只剩 allowCredentials(true)，即"任意 Origin 可携带 Cookie"。

CORS_CFG_ALLOW_RE = re.compile(
    r"""\.\s*(?:allowedOrigins?|addAllowedOrigin|setAllowedOrigins?|"""
    r"""addAllowedOriginPattern|setAllowedOriginPatterns?)\s*\(([^;]*?)\)\s*(?:\.|;|$)""",
    re.I | re.S)
CORS_CFG_CRED_RE = re.compile(
    r"(?:allowCredentials|setAllowCredentials)\s*\(\s*true\s*\)", re.I)
CORS_CFG_ANY_RE = re.compile(
    r"""setAllowedOrigins?\s*\(\s*(?:Arrays\s*\.\s*asList\s*\(\s*)?"\*"|"""
    r"""addAllowedOrigin\s*\(\s*"\*"|"""
    r"""allowedOriginPatterns?\s*\(\s*"\*"|addAllowedOriginPattern\s*\(\s*"\*"|"""
    r"""setAllowedOriginPatterns?\s*\(\s*"\*"|"""
    r"""\.\s*allowedOrigins?\s*\(\s*"\*"|\.\s*allowedOriginPatterns?\s*\(\s*"\*" """,
    re.I)


def cors_wiring_verdict(wblock: str) -> bool | None:
    """从装配证据判定 CORS。True=有漏洞，False=有防护，None=证据不足以判定。

    **组件有优先级，不能简单"任一不安全即不安全"**：

      cors-processor  自定义 CorsProcessor 重写了 checkOrigin。
                      它**优先于** allowedOrigins 生效 —— Spring 的
                      DefaultCorsProcessor 先按 config 校验，取不到再走
                      子类覆写。所以只要 processor 做了白名单校验，
                      allowedOrigins 缺失就不再等于"不限 Origin"。
                      实测反例：CustomCorsConfig 里 allowedOrigins(...)
                      整行被注释，只有 allowCredentials(true)，
                      单看它是"任意源可带凭据"；但同一个 Mapping 类
                      setCorsProcessor(new CustomCorsProcessor())，
                      而 CustomCorsProcessor.checkOrigin 里走了
                      SecurityUtil.checkURL 白名单。作者把该路由标为
                      /sec/webMvcConfigurer（安全），是对的。

    因此：先看 processor 的结论，有结论就以它为准；没有再看配置型组件。
    """
    if not wblock.strip():
        return None

    sections = _wiring_sections(wblock)
    proc = [v for name, body in sections
            if re.search(r"checkOrigin\s*\(", _strip_java_comments(body))
            for v in [_cors_from_one(body)] if v is not None]
    if proc:
        return True if any(proc) else False

    verdicts: list[bool] = []
    for name, body in sections:
        v = _cors_from_one(body)
        if v is None:
            continue
        # 配置型组件：任一装配放宽了 Origin，整体就是可跨域读取。
        # 因此"任一处不安全"即不安全，全部安全才算安全。
        verdicts.append(v)

    if not verdicts:
        return None
    return True if any(verdicts) else False


def _cors_from_one(body: str) -> bool | None:
    """对单个装配组件给出的配置体做 CORS 判定。"""
    txt = _strip_java_comments(body)

    # --- 形态 D：自定义 CorsProcessor，重写 checkOrigin 做域名校验 ---
    # checkOrigin() 的返回契约：返回请求源 = 允许，返回 null = 拒绝。
    # 只要它调用了白名单校验（checkURL / 白名单集合 contains / endsWith）
    # 并在失败时 return null，就等价于 allowedOrigins 白名单，判安全。
    if re.search(r"\bcheckOrigin\s*\(", txt):
        if re.search(r"checkURL|allowedOrigins?|whiteList|whitelist|safeDomains?|"
                     r"isAllowedOrigin", txt, re.I) and re.search(r"return\s+null", txt):
            return False
        if re.search(r"return\s+requestOrigin\s*;|return\s+origin\s*;", txt) and \
                not re.search(r"checkURL|whiteList|whitelist", txt, re.I):
            return True                 # 原样返回任意 Origin
        return None

    # --- 形态 A：Filter.doFilter 里直接写响应头（与入口体同一判据） ---
    if ACAO_RE.search(txt):
        echoes = False
        for m in ACAO_RE.finditer(txt):
            val = m.group(1).strip()
            if val in ('"*"', "'*'"):
                echoes = True
            elif val.startswith('"') or val.startswith("'"):
                continue                # 固定域名
            elif _IDENT.match(val):
                echoes = True           # 变量，通常是 getHeader("Origin")
        if not echoes:
            return False
        if ORIGIN_READ_RE.search(txt) and ORIGIN_CHECK_RE.search(txt):
            return False                # 先校验再回显
        return True

    # --- 形态 B/C：CorsConfiguration 的 allowedOrigins 取值 ---
    if not re.search(r"allowedOrigin|AllowCredentials", txt, re.I):
        return None

    cred = bool(CORS_CFG_CRED_RE.search(txt))
    if CORS_CFG_ANY_RE.search(txt):
        return True                     # "*"：任意 Origin（带凭据时更危险）

    allowed = CORS_CFG_ALLOW_RE.findall(txt)
    if allowed:
        # 有非空取值：必须全部是固定字面量域名
        for raw in allowed:
            vals = re.findall(r'"([^"]*)"', raw)
            if not vals:
                # 传的是变量（如 allowOrigins 列表），看它是否被定义过
                if re.search(r"\.\s*(?:add|set)Origin", txt, re.I):
                    return None         # 列表内容不在切片里，交回 LLM
                continue
            if any(v.strip() == "*" for v in vals):
                return True
        return False

    # 完全没有 allowedOrigins 取值：等于不限 Origin。
    # 只有**同时**开了 allowCredentials 才构成"任意源可带凭据读取"，
    # 否则只是没限制，不构成该类的判定依据。
    return True if cred else None


def _strip_java_comments(text: str) -> str:
    """剥掉 // 与 /* */ 注释，避免把被注释掉的配置当成生效。

    CustomCorsConfig 里 `.allowedOrigins(allowOrigins)` 是注释状态，
    不剥注释会误判成"有白名单"。
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def cors_verdict(source: str) -> bool | None:
    body = entry_body(source)

    # 入口体里自己写了 CORS 头 → 就地判（含 @CrossOrigin 走 Spring 默认策略的情况）
    if ACAO_RE.search(body):
        echoes_origin = False
        for m in ACAO_RE.finditer(body):
            val = m.group(1).strip()
            if val in ('"*"', "'*'"):
                # ACAO=* 且带 Credentials：浏览器实际会拒绝这种组合，
                # 单独 * 不构成"读取任意响应"的漏洞，但仍是过宽的跨域策略。
                # 这里保守判定为不安全（作者也把它标成 /vuln/setHeader）。
                echoes_origin = True
                continue
            if val.startswith('"') or val.startswith("'"):
                continue               # 固定字面量域名，不看请求，安全
            if _IDENT.match(val) and ORIGIN_READ_RE.search(body):
                echoes_origin = True   # 变量 = getHeader("Origin")，原样回显
            elif _IDENT.match(val):
                # 变量来源不明，但 body 里出现过读 Origin 头的动作
                echoes_origin = echoes_origin or bool(ORIGIN_READ_RE.search(body))

        if ORIGIN_READ_RE.search(body) and ORIGIN_CHECK_RE.search(body):
            return False               # 读了 Origin，但先做了白名单校验
        return echoes_origin or None

    # @CrossOrigin 注解：Spring 按 origins 列表做白名单，列的是固定域名即安全。
    # 必须只看**入口方法自己的注解**（entry_body），不能用整份 source ——
    # 切片里拼了同文件兄弟方法，Cors.secCrossOrigin 就带 @CrossOrigin，
    # 在全文里搜会把 getCsrfToken_01 也判成"有白名单"，直接漏报。
    own = _entry_head(source)
    if re.search(r"@CrossOrigin", own):
        m = re.search(r"@CrossOrigin\s*\(([^)]*)\)", own)
        if m and re.search(r"origins?\s*=\s*\{", m.group(1)):
            vals = re.findall(r'"([^"]+)"', m.group(1))
            if vals and all(v.strip() != "*" for v in vals):
                return False
        return None

    # 入口体没有 CORS 头 → 防护在方法外，交给装配证据
    return cors_wiring_verdict(wiring_block(source))


# ---------------- 反序列化 ----------------
#
# 只有"白名单 / 关闭多态"才算防护。黑名单（resolveClass 里 startsWith 几个包名）
# 天然可绕，必须判为不安全 —— 模型在这一条上会摇摆（Deserialize.rememberMeVul
# 5 轮里 2 轮判成 protected），所以也交给规则。

DESERIAL_SINK_RE = re.compile(
    r"\.readObject\s*\(|\.readUnshared\s*\(|"
    r"new\s+(?:[A-Za-z_][\w.]*\.)?(?:ObjectInputStream|XStream)\b|"
    r"\.fromXML\s*\(|enableDefaultTyping|readValue\s*\(|"
    r"new\s+(?:[A-Za-z_][\w.]*\.)?Yaml\s*\(|\.load\s*\(", re.I)
# 白名单式防护
DESERIAL_SAFE_RE = re.compile(
    r"SafeConstructor|safeMode|setAllowedClasses|ObjectInputFilter|"
    r"createFilter\s*\(|allowList|whitelist|setWhiteList|"
    r"ValidatingObjectInputStream|\.\s*accept\s*\(\s*[\w.]+\.class", re.I)
# 黑名单式"防护"：看起来在防，实际可绕
DESERIAL_BLACKLIST_RE = re.compile(
    r"denyClasses|denyList|blacklist|setBlacklist|startsWith\s*\(\s*deny", re.I)

# ---- fastjson：**版本决定结论**，代码本身给不出答案 ----
#
# `JSON.parseObject(body, X.class)` 这一行：
#   fastjson 1.2.31 —— autoType 可被 `@type` 劫持（<=1.2.47 的 Class 缓存
#                     绕过全线通杀，1.2.31 正是靶场里那个）
#   fastjson 1.2.83 —— safeMode 默认开启，同一行不可利用
# 判据必须问版本，而版本在 pom.xml 里。切片尾部的
# `// ---- 依赖组件版本 ----` 由 core/context/dependency_versions.py 注入。
#
# 三态写死：低于 1.2.83 → True；>= 1.2.83 → False；**没有版本证据 → None**。
# 少了第三条，"我不知道"就会被伪装成"我有把握"。
FASTJSON_SAFE_VERSION = "1.2.83"
_FASTJSON_SINK_RE = re.compile(
    r"\bJSON\s*\.\s*parse(?:Object|Array)?\s*\(|"
    r"\bJSONObject\s*\.\s*parse\w*\s*\(|"
    r"\bJSON\s*\.\s*parseWithException\s*\(", re.I)
# 全局关掉 autoType / 打开 safeMode：与版本无关地消除该风险
_FASTJSON_SAFE_RE = re.compile(
    r"setSafeMode\s*\(\s*true|ParserConfig\s*\.\s*getGlobalInstance\s*\(\s*\)\s*\."
    r"\s*setSafeMode|setAutoTypeSupport\s*\(\s*false", re.I)


def _fastjson_verdict(source: str, body: str) -> bool | None:
    from core.context.dependency_versions import compare_versions, parse_block

    if _FASTJSON_SAFE_RE.search(source):
        return False                    # 代码里显式关了 autoType
    if not has_external_input(source):
        return None                     # 解析的是常量，谈不上注入面
    ver = parse_block(source).get("fastjson")
    rel = compare_versions(ver, FASTJSON_SAFE_VERSION)
    if rel is None:
        return None                     # 没有版本证据：不表态
    return rel < 0


def deserial_verdict(source: str) -> bool | None:
    body = entry_body(source)
    # fastjson 单独一条：同一行代码在两个版本上是两个结论。
    if _FASTJSON_SINK_RE.search(body):
        return _fastjson_verdict(source, body)
    # 只有当**入口体自己**把外部数据交给反序列化 API 时才判；
    # 体里没有 sink 就说明反序列化发生在别处（helper），交给 LLM。
    #
    # 这里复用 DESERIAL_SINK_RE，不再单独写一份枚举 —— 两份枚举必然漂移，
    # 事实上就漂过一次：`readUnshared` 只补进了常量那份，判定用的这份漏了，
    # 于是 `in.readUnshared()` 的样本被判"没有 sink"退回模型。
    if not DESERIAL_SINK_RE.search(body):
        return None
    if DESERIAL_SAFE_RE.search(body):
        return False
    return True                        # 含黑名单也算"未防护"


# ---------------- SpEL / 表达式注入 ----------------
#
# 判据是纯客观的"用了哪个 Context 类"，与输入是否可达无关：
#   StandardEvaluationContext / 不带 context 的 getValue()  → 可实例化任意类 → 不安全
#   SimpleEvaluationContext（forReadOnlyDataBinding / forPropertyAccessors）→ 安全
# 模型在这条上会摇摆（SpEL.spel_sec 5 轮里 1 轮判成有漏洞），
# 而它本质和 AES vs DES 一样是"选了哪个 API"的事实题，不该交给概率模型。

EXPR_SINK_RE = re.compile(
    r"parseExpression\s*\(|SpelExpressionParser|ExpressionParser|"
    r"\.getValue\s*\(|\.evaluate\s*\(|GroovyShell|"
    r"ScriptEngine.*\.eval\s*\(|engine\s*\.\s*eval\s*\(", re.I)
EXPR_STANDARD_CTX_RE = re.compile(r"new\s+StandardEvaluationContext\s*\(", re.I)
EXPR_SIMPLE_CTX_RE = re.compile(r"SimpleEvaluationContext|"
                                r"forReadOnlyDataBinding|forPropertyAccessors", re.I)

# 输入本身的精确白名单 —— 与"受限上下文"是**两类不同的事实**：
#   受限 Context  限的是"表达式能访问什么"（属性？任意类？）
#   输入白名单    限的是"能传进来的表达式是哪几条"（枚举/精确比对）
# 两者互不替代。旧判据只认前者，于是 GroovyVul.safe 这种
#     List<String> safeCodeList = Arrays.asList("\"id\".execute()", ...);
#     if (!safeCodeList.contains(cmd)) throw new RuntimeException(...);
#     shell.evaluate(cmd);
# 被两个模型**一致**判成"没有受限 Context ⇒ 未防护"。这不是模型笨：
# 判据里确实没写这一条，它只是严格照办。判据写窄导致的一致误判，
# 修 Prompt 是没用的，必须修判据本身。
#
# 匹配必须带 `!` 或 `== false`：只认出"拒绝路径"，因为只有拒绝路径才
# 意味着"通过了校验的值必然在名单内"。`if (safe.contains(x)) { ... }`
# 是允许路径，后面的代码不必然受它保护。
EXPR_INPUT_WHITELIST_RE = re.compile(
    r"if\s*\(\s*!\s*[\w.]*(?:white|safe|allow|permit|legal|valid)\w*\s*\.\s*"
    r"(?:contains|equals|equalsIgnoreCase)\s*\(|"
    r"if\s*\(\s*[\w.]*(?:white|safe|allow|permit|legal|valid)\w*\s*\.\s*"
    r"(?:contains|equals|equalsIgnoreCase)\s*\([^)]*\)\s*==\s*false",
    re.I)
# 校验失败的处置动作。没有阻断就等于"记了个日志继续执行"，不构成防护。
_BLOCK_STMT_RE = re.compile(r"\b(?:throw|return|continue|break)\b")
# 对表达式实参的未知校验：认得名字的（白名单）已在上一步排除，
# 剩下的校验调用性质不明，退回模型而不是武断判漏洞。
_EXPR_UNKNOWN_GUARD_RE = re.compile(
    r"if\s*\(\s*[^)]*\b(?:cmd|code|expr|script|content|input|param|payload|ex|"
    r"template|el|value)\w*\b[^)]*\)", re.I)


def _guard_blocks(body: str, guard_re: re.Pattern[str]) -> bool:
    """guard 条件成立时，其分支内是否有阻断语句（throw/return/...）。"""
    for m in guard_re.finditer(body):
        seg = body[m.end(): m.end() + 400]
        # 只看条件块内部：截到与之配对的 `}`（这里做近似：取第一段
        # 括号平衡的内容，足够覆盖靶场与真实项目里的常见写法）
        depth, end = 1, len(seg)
        for i, ch in enumerate(seg):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if _BLOCK_STMT_RE.search(seg[:end]):
            return True
    return False


def _has_unknown_expr_guard(body: str) -> bool:
    """存在对表达式实参的校验，但我们判断不了它是否构成防护。"""
    for m in _EXPR_UNKNOWN_GUARD_RE.finditer(body):
        # 已经认出是白名单形态的，不归这里管：它"没阻断"这件事在上一步
        # 已经判过了（没有阻断 = 不构成防护 = 判漏洞），再当成未知防护退回模型，
        # 等于让模型重新猜一个规则已经知道答案的问题。
        if EXPR_INPUT_WHITELIST_RE.search(m.group(0)):
            continue
        return True
    return False


def spel_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not EXPR_SINK_RE.search(body):
        return None
    # 优先看输入白名单：即使配了 StandardEvaluationContext，
    # 只要表达式本身被枚举限死，攻击面也已关闭。
    if _guard_blocks(body, EXPR_INPUT_WHITELIST_RE):
        return False
    if EXPR_SIMPLE_CTX_RE.search(body):
        return False                   # 受限 Context，只允许属性读写
    if EXPR_STANDARD_CTX_RE.search(body):
        return True                    # 完整 Context，T() 可实例化任意类
    # 不带 context 的 parseExpression(x).getValue()：用的是默认 StandardEvaluationContext
    if re.search(r"parseExpression\s*\([^)]*\)\s*\.\s*getValue\s*\(\s*\)", body):
        return True
    # TemplateParserContext 只影响占位符语法，不构成沙箱
    if re.search(r"new\s+TemplateParserContext\s*\(", body) and \
            not EXPR_SIMPLE_CTX_RE.search(body):
        return True
    # 裸 evaluate(cmd) / parseExpression(ex) 后接中间变量：既没有受限 Context，
    # 也没有输入白名单 —— 两类防护都已排除，这是可核对的事实，判漏洞。
    # 只有当存在**我们叫不出名字**的校验调用时，才退回模型（见下）。
    # 只有当存在**我们叫不出名字**的校验调用时，才退回模型（见下）。
    if _has_unknown_expr_guard(body):
        return None
    return True


# ---------------- XXE ----------------
#
# 判据同样是"选了哪个 API"的事实题，不是语义推理：
# 解析 XML 之前有没有关掉外部实体，是可以逐行核对的事实。
#
# 安全写法（任一成立即安全）：
#   4.1  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
#        —— 直接禁掉 DOCTYPE，实体声明无从谈起，最彻底
#   4.2  同时把两个外部实体开关置 false：
#        external-general-entities / external-parameter-entities
#
# 必须区分的坑：
#   `setFeature(..., true)` 与 `setFeature(..., false)` 的意义**相反**。
#   disallow-doctype-decl 置 true 是"禁止"，两个 entities 置 false 是"关闭"。
#   只按"出现过 setFeature"判安全会把 vuln 样本全判成安全 ——
#   所以必须连取值一起判。
#
# XInclude 单独处理：setXIncludeAware(true) 会打开另一条读取外部文件的通道，
# 但它**不绕过** DOCTYPE 禁用（xinclude 处理的是 <xi:include href>，
# 仍需 DOCTYPE 才谈得上实体）。所以判据不变：看实体开关，不看 XInclude。
# 实测 /DocumentBuilder/xinclude/sec 开了 XInclude 但有全部三项防护，是安全的。

XXE_SINK_RE = re.compile(
    r"\.newDocumentBuilder\s*\(|\.newSAXParser\s*\(|"
    r"XMLReaderFactory\s*\.\s*createXMLReader\s*\(|"
    r"new\s+SAXBuilder\s*\(|new\s+SAXReader\s*\(|new\s+Digester\s*\(|"
    r"DocumentHelper\s*\.\s*parseText\s*\(|"
    r"SchemaFactory\s*\.\s*newInstance\s*\(|"
    r"\.parse\s*\(\s*new\s+InputSource|\.build\s*\(\s*new\s+InputSource|"
    r"\.read\s*\(\s*new\s+InputSource|\.parse\s*\(\s*new\s+StringReader|"
    r"\.build\s*\(\s*new\s+StringReader|\.read\s*\(\s*new\s+StringReader|"
    # JAXB：Unmarshaller.unmarshal(XMLStreamReader/InputStream/Reader)
    r"\.unmarshal\s*\(|"
    r"TransformerFactory\s*\.\s*newInstance\s*\(", re.I)

# disallow-doctype-decl = true
XXE_NO_DOCTYPE_RE = re.compile(
    r"""setFeature\s*\(\s*["']http://apache\.org/xml/features/disallow-doctype-decl["']"""
    r"""\s*,\s*true\s*\)""", re.I)
# external-general-entities / external-parameter-entities = false
XXE_NO_EXT_GEN_RE = re.compile(
    r"""setFeature\s*\(\s*["']http://xml\.org/sax/features/external-general-entities["']"""
    r"""\s*,\s*false\s*\)""", re.I)
XXE_NO_EXT_PARAM_RE = re.compile(
    r"""setFeature\s*\(\s*["']http://xml\.org/sax/features/external-parameter-entities["']"""
    r"""\s*,\s*false\s*\)""", re.I)
# 其它等效写法：直接禁用外部 DTD / 安全处理
XXE_OTHER_SAFE_RE = re.compile(
    r"setExpandEntityReferences\s*\(\s*false\s*\)|"
    r"setEntityResolver\s*\(\s*new\s+\w*NoOp\w*|"
    r"XMLConstants\.FEATURE_SECURE_PROCESSING\s*[\"']?\s*,?\s*true|"
    r"FEATURE_SECURE_PROCESSING[\"']\s*,\s*true", re.I)


def xxe_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not XXE_SINK_RE.search(body):
        return None                    # 入口体里没有 XML 解析 sink，交回 LLM

    if XXE_NO_DOCTYPE_RE.search(body):
        return False                   # 禁了 DOCTYPE，最彻底
    if XXE_NO_EXT_GEN_RE.search(body) and XXE_NO_EXT_PARAM_RE.search(body):
        return False                   # 两个外部实体开关都关了
    if XXE_OTHER_SAFE_RE.search(body):
        return False
    return True                        # 有 sink 且没关外部实体


# ---------------- SQL 注入 ----------------
#
# 三条**互不重叠**的客观判据，覆盖 java-sec-code 全部 10 条 sqli 样本：
#
#   A. JDBC 层：SQL 是用字符串拼接拼出来的，还是用 `?` 占位 + setXxx 绑定
#      - `createStatement()` + 拼接          → 可注入
#      - `prepareStatement("... ?")` + setXxx → 预编译占位，不可注入
#      - `prepareStatement(拼接出来的 sql)`   → **仍可注入**（占位符是空的）
#        这一条最容易判错：看到 prepareStatement 就判安全是错的。
#        java-sec-code 的 jdbc_ps_vuln 就是这个坑。
#
#   B. MyBatis 层：Mapper 语句里是 `${}` 还是 `#{}`
#      - `${}` 是字符串替换，值直接拼进 SQL 文本 → 可注入
#      - `#{}` 是 PreparedStatement 占位符        → 不可注入
#      证据来自切片尾部的「跨文件证据」段（Mapper XML 或 @Select 注解），
#      切片器已经把它带上了，这里只是核对到底用的是哪种。
#
#   C. 白名单过滤：入参经 `sqlFilter()` 这类**全串白名单**校验后才进 SQL
#      必须要求"全串匹配"（`matches()`），`contains()` / 黑名单关键字
#      替换都不算 —— 同 deserial 的黑名单问题。
#      反例：mybatisOrderBySec04 的 Mapper 里有 `${order}`，
#      但入口传的是 `sqlFilter(sort)`，而 sqlFilter 用
#      `^[a-zA-Z0-9_/\.-]+$` 做全串校验，order by 注入的所需字符全部被拒。
#      只按 B 判会误报这一条。
#
# 优先级：C（有白名单）> A（JDBC 形态）> B（MyBatis 形态）。

SQLI_JDBC_SINK_RE = re.compile(
    r"\.\s*(?:executeQuery|executeUpdate|execute)\s*\(", re.I)
SQLI_CREATE_STMT_RE = re.compile(r"\.\s*createStatement\s*\(", re.I)
# Spring 的 JdbcTemplate 直接收原始 SQL，不经过 Statement/PreparedStatement。
# 只看这两个 API 会把 `jdbctemplate.queryForMap("..." + id)` 整类漏掉
# （Hello-Java-Sec 的 JDBC.safe4 就是这样，规则返回 None 交模型，模型判错）。
SQLI_JDBCTEMPLATE_RE = re.compile(
    r"\.\s*(?:queryForMap|queryForList|queryForObject|queryForRowSet|"
    r"update|batchUpdate)\s*\(", re.I)
SQLI_PREPARE_RE = re.compile(r"\.\s*prepare(?:Statement|Call)\s*\(\s*([^;]{0,300})", re.I | re.S)
# JPA 的手写查询入口：`entityManager.createQuery(jpql)` / `createNativeQuery(sql)`。
# 它就是 JPQL 世界的 `prepareStatement` —— 传进去的是**语句文本**，不是参数，
# 所以判据与 prepareStatement 完全同构：先回溯源变量，再看文本里有没有拼接。
#
# JavaSecLab `JPAController` 给了三个对照样本：
#     vul1  jpql = "... s.username = '" + username + "'"      → 拼接 ⇒ 注入
#     vul2  jpql = "... ORDER BY s." + orderBy                → 拼接 ⇒ 注入
#     safe  jpql = "... s.username = :username" + setParameter → 绑定 ⇒ 安全
# 三条此前全部退回模型（判据只认 prepareStatement），模型对 JPQL 的
# 命名参数与字符串拼接最容易看反 —— 这正是"规则能确定性判定就别交模型"的场景。
SQLI_JPA_QUERY_RE = re.compile(
    r"\.\s*create(?:Native)?Query\s*\(\s*([^;]{0,200})", re.I)
# 字符串拼接：`"..." + 变量` 或 `变量 + "..."`
SQLI_CONCAT_RE = re.compile(
    r'"[^"]*"\s*\+|\+\s*"[^"]*"')
# 白名单过滤：全串匹配的正则/校验
# matches() 必须**带实参**才算白名单。别写成 `\([^)]*\)` —— 那样空括号
# 也能匹配（`*` 允许零次），等于没改。这里要求括号内至少一个非空白字符。
# 原因：`id.matches()` 在 Java 里没有这种重载，是编译不过的死代码；把它当
# 白名单证据会让真实注入被漏判。而 `matcher(x).matches()` 的无参形式才是
# 合法的全串校验，由第三条正则单独覆盖。
SQLI_WHITELIST_RE = re.compile(
    r"\.\s*matches\s*\(\s*[^)\s][^)]*\)|sqlFilter|checkSql|isValidOrder|"
    r"FILTER_PATTERN\s*\.\s*matcher\s*\([^)]*\)\s*\.\s*matches", re.I)
# MyBatis XML / 注解里的 ${} 与 #{}
MYBATIS_DOLLAR_RE = re.compile(r"\$\{\s*_?\w+\s*\}")
MYBATIS_HASH_RE = re.compile(r"#\{\s*_?\w+\s*\}")


# ---------------- Spring Data 仓库：框架生成的查询必然是参数化的 ----------------
#
# micro_service_seclab 的 `/sqlinjection/jpaone` 与 `/jpaWithAnnotations`：
#
#     public interface PersonRepository extends JpaRepository<Person, String> {
#         public List<Person> findPersonByUsername(String username);            // 派生查询
#         @Query("SELECT nickname FROM Person WHERE nickname = '?1'")
#         public List<Person> findPersonByNickname(String nickname);            // JPQL 绑定
#     }
#
# 这是**可逐行核对的框架契约**，不是语义推断：`findPersonByUsername` 由方法名
# 派生（`username` 是实体属性），Spring Data 生成的永远是 `where username = ?`；
# `@Query` 里的 `?1` 是位置占位符，绑定到 `setParameter`。两条路径都不拼接字符串。
#
# 判据必须同时满足两条，少一条都不判 safe：
#   ① 切片里有 `interface X extends <某个 Spring Data 仓库接口>`
#   ② 该声明段内**没有任何字符串拼接**（`"..." + x`）
#
# ② 是防漏报闸门：`@Query` 里手写 `+` 是真实存在的写法（nativeQuery 拼表名），
# 那种情况参数化与否取决于拼进去的是什么，不能一概放行。
# 反过来，只要没有任何拼接，就不存在注入面 —— 这与"白名单够不够严"不同，
# 是个封闭问题。
_JPA_REPO_DECL_RE = re.compile(
    r"\binterface\s+\w+\s+extends\s+[^{;]*\b(?:JpaRepository|JpaSpecificationExecutor|"
    r"CrudRepository|PagingAndSortingRepository|MongoRepository|"
    r"ReactiveCrudRepository|R2dbcRepository|ElasticsearchRepository)\b")
_CONCAT_ANY_RE = re.compile(r'"[^"\n]*"\s*\+|\+\s*"')


def _jpa_derived_query_safe(source: str) -> bool:
    """切片里有 Spring Data 仓库接口声明，且整段声明没有任何字符串拼接。"""
    marker = "被调方法的接口声明"
    i = source.find(marker)
    if i < 0:
        return False
    seg = source[i:]
    nxt = re.search(r"^//\s*----", seg[len(marker):], re.M)
    if nxt:
        seg = seg[: len(marker) + nxt.start()]
    if not _JPA_REPO_DECL_RE.search(seg):
        return False
    if _CONCAT_ANY_RE.search(seg):
        return False
    return True


def _mybatis_text(source: str) -> str:
    """所有 MyBatis 语句证据：实现体段 **+** 每跳的 `[Hop N] —— mybatis_xml` 段。

    为什么不能只用 `_impl_segment`：真实分层项目里 Mapper 语句是在第 2~3 跳被
    切片器按调用链拉进来的，段头是 `// 来自 XxxMapper.xml [Hop 2] —— mybatis_xml`，
    而 `_impl_segment` 从「跨文件证据：以下为实现体」开始截 —— 那个段**在它后面**。
    于是切片里有 `#{}`、判据读不到，70/70 全部退回模型（newbee-mall 实测）。

    仍然只取**本路由调用链上的**语句段，不是全仓库扫描：段头由切片器写，
    只有被调用到的 Mapper 才会出现。
    """
    parts: list[str] = []
    impl = _impl_segment(source)
    if impl:
        parts.append(impl)
    for m in re.finditer(r"(?m)^// 来自 [^\n]*\[Hop \d+\] —— mybatis_(?:xml|anno)$",
                         source):
        tail = source[m.end():]
        nxt = re.search(r"(?m)^// (?:来自 |---- )", tail)
        parts.append(tail[: nxt.start()] if nxt else tail)
    return "\n".join(parts)


def sqli_verdict(source: str) -> bool | None:
    body = entry_body(source)
    impl = _impl_segment(source)

    # C) 白名单过滤优先：入参被全串白名单约束过，后续拼接不构成注入。
    #    这里曾经要求"必须同时出现 sqlFilter/checkSql/isValidOrder 这几个名字之一"，
    #    等于把判据绑死在某几个函数名上。Hello-Java-Sec 的 JDBC.safe5 用的是
    #    标准库写法 `Pattern.matches("^[a-zA-Z0-9]+$", name)`，名字不在白名单里，
    #    于是白名单没被认出来，一路落到 createStatement + 拼接 → 误报。
    #    `.matches(...)` 在 Java 里**本身就是全串匹配**，不需要再看函数名。
    m_wl = SQLI_WHITELIST_RE.search(body)
    if m_wl and not _TRIVIAL_WHITELIST_RE.search(m_wl.group(0)):
        return False

    # C2) Spring Data 仓库：切片里带着 `extends JpaRepository` 的声明段，
    #     且整段没有任何字符串拼接 → 查询由框架生成，必然参数化。
    #     放在 MyBatis 之前：Mapper 接口与 Repository 接口都只有声明，
    #     但只有后者能靠 extends 子句给出确定性答案。
    if _jpa_derived_query_safe(source):
        return False

    # B) MyBatis：只有能确认用的是 ${} 还是 #{} 才判
    mb = _mybatis_text(source)
    if MYBATIS_DOLLAR_RE.search(mb):
        # `${}` 是字符串替换，但对**数字类型**的参数无注入面：Spring/MyBatis
        # 已经把入参解析成 int/Integer 了，`1 OR 1=1` 根本绑不上。
        # Hello-Java-Sec 的 queryById（/safe/id/{id}）正是这种，作者注明
        # 「使用${}，但写死Int类型，无法注入」。这是可核对的事实，不是语义推断。
        if _dollar_params_all_numeric(body, mb):
            return False
        return True
    if MYBATIS_HASH_RE.search(mb) and not SQLI_JDBC_SINK_RE.search(body):
        return False
    # 语句是纯固定文本（无任何占位符），调用也不带实参 → 没有注入面。
    # 切片器会在 Mapper 语句下方标注「无外部占位符（语句为固定文本）」，
    # 这是比"看到了 #{}"更强的证据：连参数都没有，谈不上注入。
    if "无外部占位符" in mb and not SQLI_JDBC_SINK_RE.search(body):
        return False

    # A0) 入口体里没有 sink，但**跨文件调用链**里有拼接 SQL + 执行方法。
    #
    #     切片器已经把 Controller → Facade → Service → Dao 展开到 4 跳
    #     （`JavaSlicer.MAX_HOPS`），SQL 拼接在第 3~4 跳是常态。此前判据只读
    #     `entry_body`，于是"证据在切片里、判据看不到"—— 规则返回 None，
    #     模型同样看不到 sink 就答 No，真漏洞被静默放行。
    #
    #     三个条件缺一不可，少一个就会误报：
    #       ① 有执行方法（execute/query/update/batchUpdate）
    #       ② 有字符串拼接造 SQL
    #       ③ 拼接的操作数里有**裸变量**，且该变量在段内被声明为形参
    #          （`String id` / `Integer id`）。常量与字段不构成注入。
    if not (SQLI_CREATE_STMT_RE.search(body) or SQLI_JDBCTEMPLATE_RE.search(body)
            or SQLI_JDBC_SINK_RE.search(body)):
        hv = _helper_concat_sql(source)
        if hv is True:
            return True
        if hv is False:
            # 值域锁死（`List<Long>` / `Integer`）—— 与入口体里的
            # `_concat_params_all_numeric` 是同一条事实，只是形参在下一跳。
            return False

    # A) JDBC：看 SQL 是怎么造出来的
    if SQLI_CREATE_STMT_RE.search(body) or SQLI_JDBCTEMPLATE_RE.search(body):
        # createStatement 无法绑定参数，只要 SQL 里出现拼接就可注入。
        # 但三种情况必须让路：
        #   1) 参与拼接的参数全是数字类型（`safe4(Integer id)`）——
        #      和 MyBatis 的 `${}` 同构，Spring 已把它解析成 int，注入不了；
        #   2) 拼接的操作数是**已知 SQL 编码函数**（ESAPI.encodeForSQL）且
        #      拼接点在引号内 —— 见 `_sql_encoded_concat_safe`；
        #   3) 拼接的操作数是**没见过的清洗函数** ——
        #      那是"不确定"，不是"有把握"。
        if SQLI_CONCAT_RE.search(body):
            if _concat_params_all_numeric(body):
                return False
            # 1b) 拼接进来的每个局部变量都能上溯到常量 —— 容器覆盖、恒真分支、
            #     helper 返回字面量。OWASP 的 sqli 把这三类机制整套放进了
            #     同文件的 `private class Test` 里，入口体只剩一句
            #     `bar = new Test().doSomething(request, param)`。
            #     此前这套判据只写在 xss 里，sqli 看到"bar 拼进 SQL"就判 True。
            if _sql_concat_all_constant(body, _sibling_methods(source)):
                return False
            if _concat_only_sanitized(body):
                # 操作数全是函数调用：是已知 SQL 编码且拼接点在引号内 → safe；
                # 是没见过的清洗函数 → "不确定"，退模型。
                return False if _sql_encoded_concat_safe(body) else None
            return True
        return None                    # 常量 SQL，不是注入面
    m = SQLI_JPA_QUERY_RE.search(body)
    if m:
        arg = _resolve_sql_var(body, m.group(1))
        if SQLI_CONCAT_RE.search(arg):
            if _sql_concat_all_constant(body, _sibling_methods(source)):
                return False
            return True
        # `:name`（JPQL 命名参数）与 `?1`（位置参数）都是绑定，不可能注入
        if "?" in arg or re.search(r":\s*\w", arg):
            return False
        # `createQuery(cq)` 的 Criteria API 形态：查询由构造器拼出，不在文本里。
        # 判不了就是判不了。
        return None
    m = SQLI_PREPARE_RE.search(body)
    if m:
        arg = m.group(1)
        # 实参往往只是个变量名（`prepareStatement(sql)`），
        # 真正的拼接和 `?` 都在它的赋值语句里，必须回溯源变量。
        arg = _resolve_sql_var(body, arg)
        # prepareStatement 的参数里出现拼接 → 占位符承载不了，仍可注入。
        # 但操作数全是常量时同样没有注入面（`{call " + bar + "}` 且
        # `bar` 来自 `thing.doSomething(常量)`）—— 与 createStatement 分支
        # 共用同一道闸门，否则 00330 会从这里漏过去。
        if SQLI_CONCAT_RE.search(arg):
            if _sql_concat_all_constant(body, _sibling_methods(source)):
                return False
            return True
        if "?" in arg:
            return False
        return None
    return None


# 毫无约束力的"白名单"：`matches(".*")`、`matches("^.*$")` 匹配一切，
# 把它当防护会让真实注入漏判。只挡这两种最常见的写法。
_TRIVIAL_WHITELIST_RE = re.compile(r'matches\s*\(\s*"\s*(?:\^?\.\*\$?|)\s*"\s*[,)]')

# ---------------- SQL 编码函数（拼接点的确定性 safe） ----------------
#
#     "select * from users where id = '"
#         + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'"
#
# Hello-Java-Sec `JDBC.safe3` 与 JavaSecLab `JdbcController.safe5` 同形态，
# 跨两个靶场一致 —— 这正是"同一判据在两个靶场同时成立"的先例条件。
#
# **单引号上下文是硬前提，对两个函数都一样**：
# `encodeForSQL(OracleCodec, x)` 与 `escapeSql(x)` 做的是同一件事 —— 把 `'`
# 中和成 `''`。这只在**字符串位置**（拼接点前紧邻 `'`）有效；若代码写的是
# 无引号拼接 `"SELECT ... WHERE id = " + encodeForSQL(codec, id)`（数字型
# 注入位），`1 OR 1=1` 原样穿过编码函数。所以判据不是"调了编码函数"，
# 而是"**编码函数的拼接点前面是一个以 `'` 结尾的字面量**"。
# 查不出引号上下文就不表态（None），不猜。
SQL_ENCODE_RE = re.compile(
    r"(?:ESAPI\s*\.\s*encoder\s*\(\s*\)\s*\.\s*)?encodeForSQL\s*\(|"
    r"escapeSql\s*\(", re.I)


def _sql_encoded_concat_safe(body: str) -> bool | None:
    """SQL 拼接的操作数是否全部是**已知 SQL 编码函数**且拼接点在引号内。

    返回 True = 全部满足，判 safe；None = 有编码函数但引号上下文查不出
    （或混着别的未知函数），维持退模型。**不返回 False** —— 这条判据
    只用于放行 safe，发现"裸变量原样进 SQL"是 `_concat_only_sanitized`
    的事，两条判据不要互相越界。
    """
    saw_encode = False
    for rhs in _sql_rhs_iter(body):
        for m in SQL_ENCODE_RE.finditer(rhs):
            before = rhs[: m.start()]
            last_lit = None
            for lm in _STR_LIT_RE.finditer(before):
                last_lit = lm
            # 前一个字面量必须存在且以 `'` 结尾（引号内的拼接点）。
            # 注意 `group(0)` 自带结尾的双引号，要先剥掉再判 ——
            # 直接 `endswith("'")` 永远是 False（实测栽过）。
            if last_lit is None or not last_lit.group(0)[:-1].endswith("'"):
                return None             # 无引号上下文 → 数字注入位，不表态
            saw_encode = True
    return saw_encode

# 拼接右操作数是函数调用（而不是裸变量）时，说明入参经过了某个清洗/编码函数。
# 我们不认识那个函数不代表它没用 —— 这种情况必须交模型，不能判 True。
_ASSIGN_RHS_RE = re.compile(r"(?:String\s+)?\w+\s*\+?=\s*([^;]{0,400});")
_STR_LIT_RE = re.compile(r'"(?:\\.|[^"\\])*"')
# 数字类型的参数声明（入口形参或 Mapper 接口声明）
_NUMERIC_TYPES = r"(?:int|Integer|long|Long|short|Short|byte|Byte|BigDecimal|BigInteger)"

# 只保留"看起来是 SQL 语句"的拼接 RHS。
#
# 不加这一步，`_concat_only_sanitized()` / `_concat_params_all_numeric()`
# 会被**无关的拼接**污染：JavaSecLab 的 `JdbcController.safe5` 里有两处拼接
#
#     String sql = "select * from sqli where id = '" + ESAPI.encodeForSQL(codec, id) + "'";
#     return "查询成功，用户名：" + user + " 密码：" + pass;
#
# 第二条是返回给前端的结果拼接，跟 SQL 毫无关系，但它含两个裸变量
# `user` / `pass` → `_concat_only_sanitized` 见到裸变量就 return False，
# 于是"操作数全是清洗函数"这个事实被另一条语句否掉了，判成误报。
# 这与 memory 第 11 条（切片污染）是同一类错误：判据扫了不该扫的范围。
_SQL_STMT_HINT_RE = re.compile(
    r"\b(?:select|insert|update|delete|from|where|order\s+by|group\s+by|"
    r"values|set|join|limit|union)\b|"
    # 条件片段：SQL 被拆成多段拼接、或者语句头存在常量里时，
    # 当前这一行的字面量只剩 `" AND id = "` 这种尾巴。只认 select/from
    # 会把整行漏掉，于是"这条拼接里有裸变量"的事实根本没被检查。
    #
    # 但 `and` / `or` / `set` 也是英文常用词：`"张三 and 李四"` 会被误认成
    # SQL。误认的代价是**多扫一条无关拼接**，只有当它恰好含裸变量时才退回
    # 模型（保守方向），不会凭空判漏洞 —— 所以宁松不宁漏。
    r"\band\b|\bor\b|\blike\b|\bin\s*\(|"
    # JDBC 的存储过程调用语法 `{call proc(?)}`。OWASP 的 00330/02183 用
    # `String sql = "{call " + bar + "}";` —— 里面既没有 select/from，也没有
    # 等号，不加这一条整条拼接都不会被当成 SQL，闸门连机会都没有。
    r"\bcall\b|"
    # `= '` 这类"等号后面紧跟引号"的形态，是"值要进 SQL"的强特征。
    # 注意字面量本身已经被引号包住，`id = ` 后面那一位在**字面量内部**
    # 是结尾引号，所以这里不该再要求 `'` —— 只认 "等号 + 空格" 即可。
    r"=\s", re.I)


def _sql_rhs_iter(body: str):
    """遍历"看起来是 SQL"的赋值语句右值（含拼接）。

    注意判据要用**字面量内部**的关键字：`"select * from t where id = " + x`
    里的 `select`/`from` 都在字符串里，剥掉字面量再判就会一个都看不到
    （第一版写成 `_STR_LIT_RE.sub(" ", rhs)`，结果 count=0，白改一场）。
    """
    for m in _ASSIGN_RHS_RE.finditer(body):
        rhs = m.group(1)
        if '"' not in rhs or "+" not in rhs:
            continue
        # 只看**字符串字面量**里有没有 SQL 关键字 —— 这才是 SQL 语句的特征
        for lit in _STR_LIT_RE.findall(rhs):
            if _SQL_STMT_HINT_RE.search(lit):
                yield rhs
                break


def _concat_only_sanitized(body: str) -> bool:
    """SQL 拼接的操作数是否**全部**是函数调用（没有任何裸变量参与）。

    只对"字符串 + 函数调用"这种形态成立：
        "select ... id = '" + ESAPI.encoder().encodeForSQL(codec, id) + "'"
    只要还有一处 `+ id +`（裸变量），就说明入参原样进了 SQL，仍可判 True。

    实现上按赋值语句拆操作数，而不是用一条大正则去套调用形态 ——
    `ESAPI.encoder().encodeForSQL(a, b)` 这种链式调用，正则很容易写成只认
    单层调用（我第一版就是这样，结果漏掉了 safe3）。

    **只看像 SQL 的赋值语句**，见 `_sql_rhs_iter()`：否则"查询成功：" + user
    这种结果拼接里的裸变量会把结论推翻。
    """
    found_call = False
    for rhs in _sql_rhs_iter(body):
        bare = _STR_LIT_RE.sub('""', rhs)
        for part in bare.split("+"):
            p = part.strip()
            if not p or p == '""':
                continue                    # 纯字面量
            if "(" in p:
                found_call = True           # 函数调用：可能是清洗
            elif re.fullmatch(r"[A-Za-z_]\w*", p):
                return False                # 裸变量原样进 SQL
    return found_call


def _dollar_params_all_numeric(body: str, impl: str) -> bool:
    """`${x}` 里的每个参数是否都被声明成数字类型。"""
    names = set(re.findall(r"\$\{\s*_?(\w+)\s*\}", impl))
    if not names:
        return False
    hay = body + "\n" + impl
    for n in names:
        if not re.search(rf"\b{_NUMERIC_TYPES}\s+{re.escape(n)}\b", hay):
            return False
    return True


def _concat_params_all_numeric(body: str) -> bool:
    """JDBC 拼接里出现的裸变量是否**全部**是数字类型。

        safe4(Integer id)  →  "select ... id = " + id   ⇒ 不可注入
        vul1(String id)    →  "select ... id = '" + id + "'"  ⇒ 可注入

    为什么这是确定性事实而不是语义推断：入参声明成 `Integer` 之后，
    Spring 在参数绑定阶段就把它解析成数字，`1 OR 1=1` 连绑定都过不了。
    规则只需要核对"形参声明"这一行，不需要理解 SQL 语义。

    **局部变量也算**：JavaSecLab 的 `JdbcController.safe4` 形参是 String，
    但中间做了 `Integer userId = Integer.valueOf(id);`，随后拼进 SQL 的是
    `userId`（Integer 类型）。只认形参声明会把这条判成误报。
    判据同样是可核对的事实：`<类型> <变量> = Integer.valueOf(...)` 这一行
    就在源码里，变量类型一眼可见。
    """
    bare: list[str] = []
    for rhs in _sql_rhs_iter(body):
        for part in _STR_LIT_RE.sub('""', rhs).split("+"):
            p = part.strip()
            if re.fullmatch(r"[A-Za-z_]\w*", p or ""):
                bare.append(p)
    if not bare:
        return False
    for n in bare:
        if re.search(rf"\b{_NUMERIC_TYPES}\s+{re.escape(n)}\b", body):
            continue                       # 形参或局部变量声明为数字类型
        # 局部变量：`Integer x = Integer.valueOf(...)` / `int x = ...`
        if re.search(rf"\b{_NUMERIC_TYPES}\s+{re.escape(n)}\s*=", body):
            continue
        return False
    return True


_SQL_VAR_ASSIGN_RE = r"String\s+{name}\s*=\s*"


def _resolve_sql_var(body: str, arg: str) -> str:
    """把 `prepareStatement(sql)` 的 sql 换成它最近一次赋值的右侧。

    只看实参本身会把 `jdbc_ps_vuln` 判成 None：
        String sql = "select * from users where username = '" + username + "'";
        PreparedStatement st = con.prepareStatement(sql);
    实参 `sql)` 里既没有 `?` 也没有拼接，但 SQL 本身是拼出来的。
    """
    name = arg.strip()
    # 链式调用：`createQuery(jpql).setParameter("x", y)` 的实参段是
    # `jpql)\n.setParameter(...)`，只做 rstrip(")") 会连方法名一起留下，
    # 结果不是纯标识符、原样返回，于是 JPQL 常量 + setParameter 的安全样本
    # 被判成"查不出语句"。先取第一个 `)` 之前的标识符。
    m0 = re.match(r"([A-Za-z_]\w*)\s*\)", name)
    name = m0.group(1) if m0 else name.rstrip(")").strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return arg
    m = re.findall(rf"\b(?:String\s+)?{re.escape(name)}\s*=\s*([^;]+);", body)
    return m[-1] if m else arg


def _impl_segment(source: str) -> str:
    """取切片尾部的「跨文件证据（实现体）」段。

    这一段放的是 Mapper XML / @Select 注解 / 接口实现类的方法体 ——
    判断 ${} vs #{} 只能在这里找，入口方法体只有一行 mapper 调用。

    **必须锚定"以下为实现体"这个完整段头**，不能只找"跨文件证据"：
    切片器还有其他同前缀的段（`跨文件证据：被调方法的接口声明`、
    `跨文件证据：xxx() 的接口实现类方法体`）。只找前缀会把接口声明段
    一并吞进来 —— java-sec-code 的 `UserMapper` Javadoc 里那句
    「If using ${username} ...」正是这样把 `#{}` 安全样本判成了注入。
    判据扫的范围比判据本身更容易错，这是第三次栽在同一处。
    """
    i = source.find("跨文件证据：以下为实现体")
    if i < 0:
        i = source.find("跨文件证据")
    return source[i:] if i >= 0 else ""


_SQL_EXEC_RE = re.compile(
    r"\.\s*(?:execute|executeQuery|executeUpdate|executeBatch|query|queryForList"
    r"|queryForObject|update|batchUpdate)\s*\(", re.I)


# ---------------- 值域判据：类型能不能承载危险字符 ----------------
#
# micro_service_seclab 把这个问题的**唯一正确答案**放在了一行类型声明里：
#
#     in(@RequestBody List<String> user_list)      → 拼接进 SQL  ⇒ 注入
#     longin(@RequestBody List<Long> user_list)    → 拼接进 SQL  ⇒ 不注入
#
# 两个方法**逐字同构**，连 `Joiner.on("','").join(name_list)` 都一模一样，
# 差异只有泛型实参。作者在 `/longin` 上方写着：
#     // 这并不是一个注入，如果SAST扫描器将这个报为SQL注入漏洞，那么这是一个误报问题
#
# 判据不能靠"看它像不像在拼接"，只能靠"**被拼进去的值能不能是 `'`**"。
# 类型就是这件事的事实支点，而且逐行可核对 —— 不需要理解 SQL 语义。
#
# 为什么 `List<Long>` 真的安全：Jackson 把 `["1 or 1=1"]` 反序列化成
# `List<Long>` 时直接抛类型异常，请求到不了业务代码；就算到了，
# `Joiner` 也只是把数字转成字符串，`'` 无从出现。
#
# **未知一律 None，不猜**：`Object`、`var`、没见过的类都在这一档。
# 这条判据只用于**放行 safe**（False），判漏洞仍由污点链负责。
_SAFE_SCALAR_TYPES = frozenset({
    "int", "integer", "long", "short", "byte", "double", "float",
    "boolean", "bool", "bigdecimal", "biginteger", "number",
})
_STR_SCALAR_TYPES = frozenset({
    "string", "char", "character", "charsequence", "text",
    "stringbuilder", "stringbuffer",
})
# 容器/包装：剥一层再看里面的元素类型。`Iterable` 与 `Collection` 都算，
# 因为 `Joiner.join(Iterable)` 吃的是元素。
_CONTAINER_TYPE_RE = re.compile(
    r"^(?:[\w.]*\b)?(?:List|Set|Collection|Iterable|Queue|Deque|"
    r"ArrayList|LinkedList|HashSet|TreeSet|LinkedHashSet|Optional)\s*<(.+)>$",
    re.I)


def _type_carries_taint(ty: str) -> bool | None:
    """声明类型 `ty` 的值能否携带能破坏 SQL 的字符（`'` / `--` / `OR`）。

    True = 可以（String 族）；False = 不可以（数值族）；None = 不知道。
    """
    ty = (ty or "").strip()
    if not ty:
        return None
    # 数组：String[] / Long[]
    if ty.endswith("[]"):
        return _type_carries_taint(ty[:-2])
    m = _CONTAINER_TYPE_RE.match(ty)
    if m:
        return _type_carries_taint(m.group(1))
    bare = ty.rsplit(".", 1)[-1].strip().lower()
    if bare in _SAFE_SCALAR_TYPES:
        return False
    if bare in _STR_SCALAR_TYPES:
        return True
    return None


def _split_args_generic_aware(args: str) -> list[str]:
    """按顶层逗号拆形参，**尖括号深度也算层级**。

    `_split_args` 只跟踪 `([{`，遇到 `Map<String, Object> m` 会在泛型里的
    那个逗号处断成两截，于是 `m` 的类型被读成 `Object>` —— 一个本该是
    「不知道」的类型被读成「Object」。这个靶场没踩到，但同一条链上的
    下一个样本会。
    """
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _param_decl_types(sig: str) -> dict[str, str]:
    """形参名 → 声明类型（**含泛型实参**）。`@RequestBody List<Long> x` → {x: List<Long>}。

    不要与后面那个同名的 `_param_types` 混用：它走 `_PARAM_SEG_RE`
    （`([A-Z]\\w*)(?:<[^>]*>)?\\s+(\\w+)`），泛型实参被 `?` 吃掉，
    `List<Long>` 只剩 `List` —— 而本靶场的 in / longin 之辨**全在泛型实参上**，
    丢掉它等于把唯一的事实支点丢了。函数名分开，免得后写的那份把这份覆盖掉
    （同名定义在 Python 里是静默后写胜出，不报错，极难发现）。
    """
    sig = re.sub(r"@\w+\s*(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?", " ", sig)
    out: dict[str, str] = {}
    for seg in _split_args_generic_aware(sig):
        seg = seg.strip()
        if not seg or seg in ("final",):
            continue
        parts = seg.split()
        if len(parts) < 2:
            continue
        name = parts[-1].strip()
        out[name] = " ".join(parts[:-1]).replace(" final ", " ").strip()
    return out


def _segment_param_types(seg: str) -> dict[str, str]:
    """段内**所有**方法签名的形参类型并集（先到先得）。

    同一段里出现同名形参是常态（`id` 在十来个方法里都有），按方法体精确
    归属会让这段代码膨胀一倍。先到先得在本靶场的实测结果与人工核对一致；
    若将来出现"同名不同类型"导致误判，正确做法是**不表态**而不是挑一个，
    所以这里只用来放行 False，不用来判 True。
    """
    out: dict[str, str] = {}
    for m in re.finditer(r"\b(\w+)\s*\(([^()]*)\)\s*(?:throws[^{;]*)?\{", seg):
        for name, typ in _param_decl_types(m.group(2)).items():
            out.setdefault(name, typ)
    return out


def _concat_operand_taint(rhs: str, seg: str,
                          decls: dict[str, str] | None = None) -> bool | None:
    """SQL 拼接右值的**每一个操作数**是否都只能取到无害值。

    True  = 至少一个操作数能携带 `'`（污点成立）
    False = 所有操作数都能被类型/字面量锁定为无害
    None  = 有操作数查不出来

    与 `_operand_vars` 的分工：那个只认**裸变量**（`+ id +`），因此
    `Joiner.on("','").join(name_list)`、`username.get()`、
    `String.valueOf(id)` 三种形态一概看不见 —— micro_service_seclab 的
    `/in` `/longin` `/optinal_like` `/objectint` 四条就全部卡在这里，
    真漏洞和误报陷阱一起退回模型（模型对"拼进 SQL 的是 List"没有类型
    信息，只能猜）。
    """
    if decls is None:
        decls = _segment_param_types(seg)
    seen: list[bool | None] = []
    for part in _STR_LIT_RE.sub('""', rhs).split("+"):
        p = part.strip()
        if not p or p == '""':
            continue                       # 纯字面量
        if re.fullmatch(r"\d+[lLdDfF]?", p):
            continue                       # 数字字面量
        ids = _expr_identifiers(p)
        if not ids:
            # `Integer.valueOf(1)` / `System.currentTimeMillis()` 这类不引用
            # 任何局部变量的调用：结果与外部输入无关。
            seen.append(False)
            continue
        for v in ids:
            ty = decls.get(v)
            if ty:
                seen.append(_type_carries_taint(ty))
                continue
            # 局部变量：`List<Long> list = ...` / `int n = ...`
            m = re.search(
                rf"\b([A-Za-z_][\w.]*(?:\s*<[^<>]*>)?(?:\[\])?)\s+"
                rf"{re.escape(v)}\s*=(?!=)\s*([^;]+);", seg)
            if m:
                seen.append(_type_carries_taint(m.group(1)))
                continue
            seen.append(None)
    if any(s is True for s in seen):
        return True
    if seen and all(s is False for s in seen):
        return False
    return None


def _helper_concat_sql(source: str) -> bool | None:
    """多跳调用链里是否存在「形参拼进 SQL 并执行」。

    只看切片器产出的「跨文件辅助方法实现」段（`[Hop 1..N]`）。两个条件
    缺一不可，少一个就会误报：

      ① 段内有执行方法（execute / query / update / batchUpdate）
      ② 段内有字符串拼接造 SQL，且 `_concat_operand_taint` 判定成立

    返回值是三态，**False 与 None 的区分是这条判据的重点**：

      True  → 有操作数能把 `'` 带进 SQL，判漏洞
      False → **每一个**操作数都被类型或字面量锁死为无害，可以放行 safe
      None  → 有操作数查不出来（`Object`、没见过的工具类），不表态

    第三态曾经写成 `return False`（等同"不成立"，继续往下走到 None），
    于是"我查不出来"和"我确认它安全"混在一起。micro_service_seclab 的
    `/longin` 恰好落在这个缝里：操作数是 `List<Long>`，值域锁死，
    本该判 safe，却因为"不是裸变量"被判成"不成立"，最终交模型抽签。
    """
    i = source.find("跨文件辅助方法实现")
    if i < 0:
        return None
    seg = source[i:]
    if not _SQL_EXEC_RE.search(seg):
        return None
    decls = _segment_param_types(seg)
    seen: list[bool | None] = []
    for rhs in _sql_rhs_iter(seg):
        t = _concat_operand_taint(rhs, seg, decls)
        if t is True:
            return True
        seen.append(t)
    if seen and all(t is False for t in seen):
        return False
    return None



# ---------------- xss ----------------
#
# 判据与其它类不同：xss 问的是"外部可控字符串是否被**原样写进响应体**"。
# 但存储型 XSS 的写入点和回显点必然分居两个方法，单看写入方它是干净的
# （`XSS.store` 只把值放进 Cookie，返回常量）。这类只能靠跨路由串接证据判定。
#
# 证据形态（切片器 `taint_chain.render_chain_block` 产出）：
#     // ---- 跨路由串接证据 ----
#     // Cookie "xss"：XSS.store 写入 → XSS.show 读出
#     // 读取点方法体：
#     //   public String show(@CookieValue("xss") String xss) { return xss; }
#
# 判定顺序（先否定、后肯定，避免把"有防护"判成漏洞）：
#   1) 本方法有外部入参、且把参数值直接写进响应体 → 反射型，真
#   2) 本方法没有回显，但有串接证据 → 看**读取点**是否原样回显：
#        读取点直接 return 参数 / 写进响应体，且没有编码调用 → 存储型，真
#        读取点做了输出编码 → 假
#   3) 本方法无回显、也无串接 → 假（不是本类目的判定对象）

XSS_ECHO_SINK_RE = re.compile(
    # 五个方法全都要认：`printf` / `format` 在 OWASP 里占 sink 的 41%
    # （字面量格式串 55 条 + 用户可控格式串 51 条），只认 print/write/println
    # 会把它们的真阳性整批漏成"无回显"。
    r"\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println|printf|format)\s*\(|"
    r"\.\s*getOutputStream\s*\(\s*\)\s*\.\s*(?:write|printf|format)\s*\(|"
    # `return xss;` —— 原样交出变量
    r"return\s+[A-Za-z_]\w*\s*;|"
    # `return encode(xss);` 这类"过了一层函数"的返回同样是回显点。
    # 不能因为中间有调用就当作没有回显：是否安全由 encode 检测另行判定，
    # 两件事必须分开判，否则 `return encode(xss)` 会被漏成"无回显"。
    r"return\s+\w+\s*\([^)]*\)\s*;", re.I)

# `java.io.PrintWriter out = response.getWriter(); out.format(...)` ——
# 回显经过一个中间变量，连写形态 `getWriter().format(` 完全匹配不到。
# OWASP 的 01046/01047/01335/01417/01505/01583/02221 全是这个写法，
# 漏掉的后果不是"少报一个 sink"，而是整条落到"无回显 → False"，
# 也就是**静默放行真漏洞**（比误报危险，方向必须写死）。
_WRITER_VAR_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=(?!=)\s*[^;]*\.\s*getWriter\s*\(\s*\)")


def _echo_sink_hit(body: str) -> bool:
    """方法体里是否存在回显点（含 `PrintWriter` 中间变量形态）。"""
    if XSS_ECHO_SINK_RE.search(body):
        return True
    for m in _WRITER_VAR_RE.finditer(body):
        v = m.group(1)
        if re.search(rf"(?<![\w.]){re.escape(v)}\s*\.\s*"
                     r"(?:print|write|println|printf|format)\s*\(", body):
            return True
    return False

XSS_ENCODE_RE = re.compile(
    # `encode(?!Base64)` 是必须的负向前瞻：OWASP 的传播链模板里
    # `Base64.encodeBase64(...)` 是**数据变换**不是输出编码，
    # 宽写成 `encode\w*\(` 会让 00385 这类真漏洞被判成"已编码"→ 静默放行。
    r"encode(?!Base64)\w*\s*\(|escape\w*\s*\(|HtmlUtils\s*\.\s*htmlEscape|"
    r"StringEscapeUtils|ESAPI\s*\.\s*encoder|encodeForHTML|"
    r"Encode\s*\.\s*forHtml|Jsoup\s*\.\s*clean", re.I)
XSS_PARAM_RE = re.compile(
    r"@RequestParam|@PathVariable|@RequestHeader|@CookieValue|@ModelAttribute|"
    r"request\s*\.\s*getParameter\s*\(|request\s*\.\s*getHeader\s*\(", re.I)
# 输入可能来自**别的类**：入口手里只有一个包装对象。
#
#     SeparateClassRequest scr = new SeparateClassRequest(request);
#     String param = scr.getTheParameter("BenchmarkTest01507");
#
# 这里没有任何 `getParameter(`，但有包装对象上的取值调用。
#
# **`new Xxx(request)` 这一句本身不算判据**（曾用它，被记了一次错）：
# 同一个类里可能既有脏源也有安全源。OWASP 的 `SeparateClassRequest`
# 里 `getTheParameter` 走 `request.getParameter`，而 `getTheValue`
# 写着 `// This method is a 'safe' source.` 且 `return "bar";`。
# "请求对象整个传出去"这件事分不出取回来的是哪一种 ——
# 260 条调 `getTheValue` 的用例里 205 条真值是 safe，按"对象出门"判脏
# 会把 00887/00889/00890/00892/00894 这批**本来判对**的样本一起翻成误报。
#
# 所以判据落回**取值方法名**这个可逐行核对的事实上，且只认公认的脏源；
# `getTheValue` 这类"名字像但不是"的一律不认。认错的方向是把 205 条 safe
# 全判成漏洞，代价不对称。
_XSS_FOREIGN_SOURCE_RE = re.compile(
    r"\.\s*(?:getTheParameter|getParameter|getParameterValues|"
    r"getParameterMap|getHeader|getHeaders|getHeaderNames|getCookieValue|"
    r"getQueryString|getInputStream|getReader|getCookies)\s*\(", re.I)
# Spring MVC / JAX-RS 的**裸形参**同样绑定请求参数：
#     public static String reflect(String xss) { return xss; }
# 没有注解不等于没有外部输入。只有框架注入的几个类型（HttpServletRequest /
# HttpServletResponse / Model / Locale ...）不是用户可控值。
FRAMEWORK_INJECTED_TYPES = {
    "HttpServletRequest", "HttpServletResponse", "HttpSession", "ServletRequest",
    "ServletResponse", "Model", "ModelMap", "Locale", "Principal",
    "BindingResult", "Errors", "UriInfo", "WebRequest",
}
# 裸形参 = 一段「类型 变量名」，类型不是框架注入的那些。
# 逐段切分再判断，比堆正则前瞻可靠：正则在"字符串开头 + 负向断言 + 空白"这个
# 组合上很容易因为回溯把匹配吃掉（`String xss` 就死活匹配不上）。
_PARAM_SEG_RE = re.compile(r"([A-Z]\w*)(?:<[^>]*>)?\s+(\w+)")


def _bare_params(sig: str) -> list[str]:
    """返回签名里的裸形参（形如 ['xss']），用于判断入口是否接收外部输入。"""
    out: list[str] = []
    # 去掉注解与其参数，只留下「类型 变量名」序列
    sig = re.sub(r"@\w+\s*(?:\([^)]*\))?", " ", sig)
    for typ, name in _PARAM_SEG_RE.findall(sig):
        if typ in FRAMEWORK_INJECTED_TYPES:
            continue
        out.append(name)
    return out


_CHAIN_SEP = "// ---- 跨路由串接证据 ----"


def _chain_reader_body(source: str) -> str:
    """取出**非 db 介质**的串接证据里贴出的读取点方法体（去掉 `// ` 前缀）。

    db 介质的证据要排除在外：它的连接描述行以 `// 数据库持久层` 开头，同样
    以 `//` 起头，早期实现会把它一起吞进来，于是调用方误以为"有普通串接
    证据"，走进 (2) 分支判 False —— 而 db 证据本该由 (2b) 处理。
    """
    i = source.find(_CHAIN_SEP)
    if i < 0:
        return ""
    seg = source[i:]
    nxt = re.search(r"^//\s*----", seg[len(_CHAIN_SEP):], re.M)
    if nxt:
        seg = seg[: len(_CHAIN_SEP) + nxt.start()]
    j = seg.find("读取点方法体")
    if j < 0:
        return ""
    body_lines = seg[j:].splitlines()[1:]
    # 连接描述行（`// 数据库持久层 "x"：…`）在 "读取点方法体" 之前，不在
    # 这里；这里只看读取点正文。若正文里全是 db 连接留下的痕迹（方法体本身
    # 就是仓储调用），仍要返回空 —— 由 (2b) 处理，不要让 (2) 误判 False。
    out: list[str] = []
    for ln in body_lines:
        s = ln.strip()
        if not s.startswith("//"):
            break
        out.append(s[2:].lstrip())
    joined = "\n".join(out)
    if joined and not _has_plain_chain(source):
        return ""
    return joined


def _has_plain_chain(source: str) -> bool:
    """是否有 cookie/session/request/model 介质的串接连接（不含 db）。"""
    i = source.find(_CHAIN_SEP)
    if i < 0:
        return False
    seg = source[i:]
    nxt = re.search(r"^//\s*----", seg[len(_CHAIN_SEP):], re.M)
    if nxt:
        seg = seg[: len(_CHAIN_SEP) + nxt.start()]
    for ln in seg.splitlines():
        s = ln.strip()
        if s.startswith("// ") and not s.startswith("// 数据库持久层") \
                and "写入 →" in s:
            return True
    return False


def _entry_signature(source: str) -> str:
    """取入口方法的签名括号（用于判断有没有裸形参）。

    **不能写 `\\(([^)]*)\\)`**：形参上的注解带括号，且**先于**形参本身的括号闭合 ——

        public String vul2(@ApiParam(name = "payload", required = true)
                           @RequestParam String payload) {

    非贪婪的 `[^)]*` 会在 `@ApiParam(...)` 的 `)` 处停下，于是拿到的签名是
    `@ApiParam(name = "payload", required = true`，`_bare_params` 一个都析不出。
    症状是 `tainted` 为空集 → 回显值"追不到" → 整条样本退回模型，
    而且**不报错**（只是覆盖率悄悄掉了）。
    JavaSecLab 的 ReflectController.vul1/vul2、StoreController.vul 全栽在这里。

    正确做法是按括号深度配平，取到真正配平的那个右括号。
    """
    body = entry_body(source)
    # 跳过注解：注解名前面的 `@` 是唯一可靠的区分标志。
    # 不跳会匹配到 `@ApiOperation(...)` 或 `@GetMapping("/vul2")`。
    m = re.search(r"(?<![@\w])\b\w+\s*\(", body)
    if not m:
        return ""
    open_idx = m.end() - 1
    depth = 0
    for i in range(open_idx, len(body)):
        ch = body[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return body[open_idx + 1: i]
    return ""


# ---------------- 视图模板证据 ----------------
#
# 切片器会把「`model.addAttribute("k", v)` 写入的键，在 `return "view"`
# 指向的模板里被怎么渲染」贴进来（格式见 core/context/view_templates.py）：
#
#     // ---- 关联视图模板（视图名解析到的模板文件，渲染点原文）----
#     // src/main/resources/templates/vul/xss/other.html:118  不转义渲染 键 "html"
#     // >>  118| <p th:utext="${html}"></p>
#
# 这里解析成 {键: 是否不转义}。**只认证据块内部**，不拿整份模板字符串去扫，
# 理由与 `entry_body` 相同：范围内的事实才是事实。

_TEMPLATE_SEP = "// ---- 关联视图模板"
_TPL_HIT_RE = re.compile(r"不转义渲染\s+键\s+\"(?P<key>[^\"]+)\"")
_TPL_SAFE_RE = re.compile(r"转义渲染\s+键\s+\"(?P<key>[^\"]+)\"")


def _template_render(source: str) -> dict[str, bool]:
    """{model 键: 该键在模板里是否被不转义渲染}。"""
    i = source.find(_TEMPLATE_SEP)
    if i < 0:
        return {}
    seg = source[i:]
    out: dict[str, bool] = {}
    for ln in seg.splitlines():
        m = _TPL_HIT_RE.search(ln)
        if m:
            out[m.group("key")] = True      # 不转义一旦成立就锁定
            continue
        m = _TPL_SAFE_RE.search(ln)
        if m:
            out.setdefault(m.group("key"), False)
    return out


# 模板介质本身不构成漏洞时，返回 False 的理由要能站得住：
#   - 模板里只有 `th:text`（自动转义）→ 输入进不去 HTML 解析
#   - 本方法写入前做了编码 → 模板再怎么渲染都是被转义过的文本
# 这两条都是可逐行核对的事实，不需要模型理解模板语义。
_TPL_VIEW_LIT_RE = re.compile(
    r"\breturn\s+\"[A-Za-z0-9_./-]+\"\s*;|"
    r"new\s+ModelAndView\s*\(\s*\"[A-Za-z0-9_./-]+\"")


# ---------------- `printf` / `format` 的格式串位置 ----------------
#
# 同一个回显方法，脏值落在哪个参数位上，结论完全不同：
#
#   printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj)
#       → 格式串是编译期常量，脏值只作为 `%s` 的**实参**
#
#   printf(bar, obj)
#       → `bar` 自己被当成格式串。`%n` 换行、`%x` 宽度这类转换说明符
#         由用户控制，而且格式串里的字面量部分直接进响应体。
#
# 规则不看"转义没转义"（那需要理解 Formatter 语义），只核一件事：
# **格式串那个位置上是字面量还是变量**。这是可逐行核对的事实，与
# `hash` 类目核对算法名同构。
#
# 调用方把这当成"否定证据"使用：只有确认了"脏值不是格式串"，才允许在
# 同时存在编码调用时判 False。否则退回 None，把 Formatter 语义交给模型。
_FMT_SINK_RE = re.compile(
    r"\.\s*get(?:Writer|OutputStream)\s*\(\s*\)\s*\.\s*(?:printf|format)\s*\("
    r"(?P<args>[^;]*)\)\s*;", re.I)
_FMT_LOCALE_PREFIX_RE = re.compile(r"^\s*(?:java\s*\.\s*util\s*\.\s*)?Locale\s*\.\s*\w+\s*,")
_STR_LIT_ONLY_RE = re.compile(r"^\s*\"[^\"]*\"\s*$")


def _value_never_format_string(body: str) -> bool:
    """本方法里所有 `printf`/`format` 的**格式串位置**都是字面量。

    返回 True 的含义很窄：脏值只可能作为转换说明符的实参传进去，
    不存在"用户控制的格式串"。调用方据此才敢把 ENCODE 当作真防护。
    一处都找不到调用时返回 False —— 宁可退回模型，不做无依据的放行。
    """
    hits = list(_FMT_SINK_RE.finditer(body))
    if not hits:
        return False
    for m in hits:
        args = _FMT_LOCALE_PREFIX_RE.sub("", m.group("args").strip())
        first = args.split(",")[0]
        if not _STR_LIT_ONLY_RE.match(first):
            return False               # 格式串位置是变量（或拼接）→ 不由我们放行
    return True


# ---------------- 数据库介质的读取点 ----------------
#
# 串接层现在会为同一仓储字段上两个不同路由产出连接（见
# `taint_chain.build_chains` 的 db 分支）。证据形态：
#
#     // 数据库持久层 "xssMapper"：StoreController.vul 写入 → StoreController.getXssList 读出
#     // 读取点方法体：
#     //   public R getXssList(...) { ... }
#
# 与 cookie/session 的读取点不同，DB 的读取点**结构上**必须自己判一次：
# "从库里取出来的值，有没有原样进响应体"。判据与反射型一致（回显 + 无编码），
# 但这里额外允许一个前提 —— 读取点自己也有外部参数（列表接口常有查询条件），
# 那不改变结论：值来自库，不由该参数决定。

_DB_CHAIN_SEP = "// 数据库持久层"

# 仓储方法读出来的"值"直接当响应体返回。这是 XSS 类目成立的那一半：
#     return xssMapper.list();          → 库里存的原样字符串就是响应内容
#     return JSON.toJSONString(list);   → 序列化后进响应
_DB_DIRECT_ECHO_RE = re.compile(
    r"return\s+[^;]*\b\w*(?:Mapper|Dao|DAO|Repository|Service)\s*\.\s*\w+\s*\(", re.I)
# 读取点里出现"往仓储发写指令" → 它自己是写入方，不是读取点。
# db 连接是**双向**产出的（同一字段上的调用分不出读写），所以必须在这里
# 把方向判出来：`deleteFeedById` / `add` / `insert` / `update` 都是写。
_DB_WRITE_CALL_RE = re.compile(
    r"\.\s*(?:insert|add|save|update|delete|remove|removeById|deleteById|"
    r"deleteFeedById|batchSave|merge|persist)\w*\s*\(", re.I)
# 从库取值的调用。MyBatis 的方法名由作者自定（`list` / `getStored` /
# `selectAll` / `page`），所以这里不按动词穷举，而是**排除写指令后
# 剩下的仓储调用**就算取值调用 —— 见 `_db_render_points`。
_DB_FETCH_CALL_RE = re.compile(
    r"\.\s*(?!insert|add|save|update|delete|remove|removeById|deleteById|"
    r"batchSave|merge|persist)[A-Za-z_]\w*\s*\(", re.I)
# 读出来的值被塞进**统一响应包装**（R.ok(...) / Result.success(...) /
# ResponseEntity.ok(...)）。项目把数据放进 JSON 字段，响应体本身是固定结构，
# 页面由前端渲染。这类**不构成本类目的证据支点**：
# 值确实进了响应，但"是否原样进 HTML"取决于前端怎么渲染，Java 侧看不到。
# 规则手里没有可核对的事实，按第 5 条只能 None。
_DB_WRAPPED_ECHO_RE = re.compile(
    r"return\s+(?:R|Result|AjaxResult|CommonResult|ResponseEntity|BaseResponse)\s*\."
    r"\s*(?:ok|success|error|fail)\s*\(", re.I)


def _db_writer_takes_value(body: str) -> bool:
    """入口是不是**真的把外部字符串写进库**（而不是只按 id 删除/查询）。

    判据：仓储调用里出现了"值型实参"。只传主键/条件的不算：

        xssMapper.add(user, content, date);      → 有 String 值 → 是写入
        xssMapper.insertAll(content, ua, date);  → 是
        xssService.deleteById(id);               → 只有 int 主键 → 不是

    为什么要这层：`XSS.delete(int id)` 与 `XSS.save` 共用同一个 `xssMapper`
    字段，db 串接是双向的，于是 `delete` 也拿到了"读取点 = getStored 直接
    return list"。不区分"这个路由到底往库里写了什么"，就会把删除接口报成
    存储型 XSS —— 这正是"看见仓储调用就报漏洞"的那种廉价误报。
    """
    for m in re.finditer(
            r"\.\s*(?P<verb>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)", body):
        verb = m.group("verb").lower()
        if not re.match(r"(?:insert|add|save|update|create|persist|batch|merge)", verb):
            continue
        args = m.group("args")
        # 以字面量结尾、或含变量引用 → 有值型实参
        if re.search(r"[A-Za-z_]\w*", args):
            return True
    return False


def _repo_write_in_evidence(source: str) -> bool:
    """切片证据里是否能看到"值真的落库"的实现体。

    形态（`JavaImplResolver` 产出的证据块）：

        // ---- 跨文件证据：insertOne() 的接口实现类方法体 @ …/XssServiceImpl.java ----
        public int insertOne(String content, String ua) {
            final int code = xssMapper.insertAll(content, ua, DateUtil.now());
            return code;
        }

    判据是**证据段内出现了带值实参的仓储写调用**。只扫 `// ----` 之后的部分，
    入口体由 `_db_writer_takes_value` 单独处理 —— 两段语义不同，不能混扫。
    """
    i = source.find("// ----")
    if i < 0:
        return False
    seg = source[i:]
    for m in re.finditer(
            r"\b\w*(?:Mapper|Dao|DAO|Repository)\s*\.\s*(?P<verb>[A-Za-z_]\w*)\s*\("
            r"(?P<args>[^)]*)", seg):
        if not re.match(r"(?:insert|add|save|update|create|persist|batch|merge)",
                        m.group("verb"), re.I):
            continue
        if re.search(r"[A-Za-z_]\w*", m.group("args")) and '"' not in m.group("args")[:1]:
            return True
    return False


def _db_echo(readers: str) -> bool:
    """数据库读取点是否**直接把值交进响应体**。

    三档，都要能逐行核对：
      - 仓储方法的读取结果直接 `return …Mapper.list()`  → 真
      - `return R.ok(listPage)` 这类统一包装              → 假（结构固定，前端渲染）
      - 其余（`log.info(list)`、`list.forEach(...)`）     → 假（没进响应体）

    这条区分不是吹毛求疵：`StoreController.getXssList` 返回的是 MyBatis-Plus
    的 `R.ok().setData(listPage)`，真正触发 XSS 的是前端页面循环渲染后的
    innerHTML —— 模板文件里读不到这条链，Java 侧也没有可核对的"不转义输出"。
    判 True 会变成"看见写库就报漏洞"，那是最廉价也最容易被推翻的误报。
    """
    if _DB_WRAPPED_ECHO_RE.search(readers):
        return False
    if _DB_DIRECT_ECHO_RE.search(readers):
        return True
    # 读取点自己写响应体（getWriter().print(...)）也算回显
    return bool(re.search(r"getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println)\s*\(", readers))


def _db_render_points(readers: list[str]) -> list[str]:
    """从 db 读取点里筛出**真正把库里的值交进响应体**的形态。

    db 连接是双向的：`XSS.save` 与 `XSS.delete` 共用 `xssMapper`，于是
    `save` 的读取点里会包含 `delete`；`delete` 的读取点里也会包含 `save`。
    不筛就会把"有连接"误读成"有回显"。

    判据只有一条且可逐行核对：**方法里既有"从库取值"又有"把值交出去"**。
    `delete` / `save` 都是写指令，没有取值；`getStored` 有取值且直接
    `return xssMapper.list()` —— 这一条算回显（库里原样字符串就是响应体）。

    读取点的第一段是它自己的签名 + 方法体，后面才是证据里附带的其它内容；
    **只看第一段**，避免把后面的写入方法当成读取点。
    """
    out: list[str] = []
    for body in readers:
        head = body.strip().split("// ----")[0].split("// 读取点方法体")[0]
        if _DB_WRAPPED_ECHO_RE.search(head):
            continue                     # 统一包装响应，无法判"不转义"
        has_fetch = bool(_DB_FETCH_CALL_RE.search(head))
        has_out = bool(_DB_DIRECT_ECHO_RE.search(head)) or bool(
            re.search(r"getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println)\s*\(", head))
        if has_fetch and has_out:
            out.append(body)
    return out


def _db_readers(source: str) -> list[str]:
    """取出 db 串接证据里贴出的**每一个**读取点方法体（按 `//   ` 空行分段）。

    早先的实现每遇到一条 `数据库持久层 "x"：…` 就整段收一次，结果同一个读取点
    被重复收 6 遍，而最后那个真正回显的读取点反而没被收进来 —— 于是判定层
    看到"读取点都没有回显"，把存储型 XSS 判成安全。分段必须在**证据块内部**
    按分隔空行切，而不是按描述行切。
    """
    i = source.find(_DB_CHAIN_SEP)
    if i < 0:
        return []
    seg = source[i:]
    j = seg.find("读取点方法体")
    if j < 0:
        return []
    texts: list[str] = []
    cur: list[str] = []
    for ln in seg[j:].splitlines()[1:]:
        s = ln.strip()
        if not s.startswith("//"):
            break
        code = s[2:].lstrip()
        if not code:                      # `//   ` 空行 = 两个读取点之间的分隔
            if cur:
                texts.append("\n".join(cur))
                cur = []
            continue
        cur.append(code)
    if cur:
        texts.append("\n".join(cur))
    return texts


# ---------------- 外部输入来源（Source Gate） ----------------
#
# 污点型类目（needs_taint=True）的定义是"外部可控值流到汇聚点"。
# 若一个入口方法**根本没有外部输入**，它在语义上不可能构成污点型漏洞 ——
# 这不是启发式，是定义。
#
# 但这条闸门有个明确的适用边界，踩过才发现：
#   **它只能用来"降低置信度"，不能直接判 False。**
# 因为靶场里存在真值为 vuln、却故意不接收任何外部输入的样本：
#     @GetMapping("/vul")
#     public void vul() {                    // 无参
#         File file = new File(path);        // path 是类常量
#         new XMLDecoder(new BufferedInputStream(
#             new FileInputStream(file))).readObject();
#     }
# 作者标它为 vuln 的语义是"用了不安全的 API"，不是"外部输入可达"。
# Hello-Java-Sec 的 XMLDecoderVul 一对样本正好相反地证明了这一点：
# vul() 与 safe() **都不接收输入、读同一个常量文件**，真值却一个 True 一个
# False —— 差异不在输入侧，而在 `new XMLDecoder` vs `ObjectInputStream`。
# 所以任何"无外部输入 ⇒ 安全"的硬短路都会把这条真漏洞一起判掉。
#
# 因此本函数只暴露事实，由调用方决定怎么用：
#   - `scenario_hit` 层面：无输入 ⇒ 交模型之前先记账（VulnHypothesis 里体现）
#   - `xss_verdict` 这类本来就要求 has_param 的类目：直接用它
# 不要把它当成 verdict() 的全局短路闸门。

# 除形参与注解之外，request 对象本身还有一批读取入口。
# XSS_PARAM_RE 只覆盖了最常用的两个，这里补齐其余通道。
_REQUEST_READ_RE = re.compile(
    r"request\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|"
    r"getHeader|getHeaders|getHeaderNames|getCookies|getInputStream|getReader|"
    r"getQueryString|getPathInfo|getRequestURI|getRemoteUser)\s*\(",
    re.I)


# ---------------- 容器「先放常量再覆盖」 ----------------
#
# OWASP 里有两组写法看起来一模一样、真值却相反，差别全在**覆盖的顺序**：
#
#   List:  bar = "alsosafe";
#          valuesList.add("safe"); add(param); add("moresafe"); remove(0);
#          bar = valuesList.get(1);
#      → remove(0) 之后剩余是 [param, "moresafe"]，下标 1 是常量 → 真值 False
#      → 若写 get(0)，剩余下标 0 就是 param                   → 真值 True
#      （"remove 之后第一个元素是 param" 可以直接从 add 的顺序核对出来，
#        不需要理解 List 的语义）
#
#   Map:   put("keyA", "a_Value"); put("keyB-N", param); put("keyC", "...");
#          bar = map.get("keyB-N");   // 拿到 param
#          bar = map.get("keyA");     // **被常量覆盖**      → 真值 False
#      → 若 get("keyA") 那行不存在，真值就是 True（00153 就是这样）
#
# 判据只有一个：**回显点之前 `bar` 的最后一次赋值上溯到什么**。
# 上溯到常量字面量 → 判 None（看见了覆盖，但 Formatter 语义仍不归规则管）；
# 仍能上溯到外部输入 → 保持 True。
#
# 为什么不直接判 False：`get(1)` 的"常量"依赖"remove 之后顺序如何"这条推演，
# 样本一旦变体（连 remove 两次、add 在 remove 之后）推演就错。规则只做
# "我现在不知道"的诚实表达，不拿推演冒充事实。

_LIST_ADD_RE = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*\.\s*(?:add|push|offer|addLast)\s*\(\s*(?P<val>[^)]*)\)")
_LIST_REMOVE_RE = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*\.\s*remove\s*\(\s*(?P<idx>\d+)\s*\)")
_MAP_PUT_RE = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*\.\s*put\s*\(\s*\"(?P<key>[^\"]+)\"\s*,\s*(?P<val>[^)]*)\)")
_ASSIGN_RE = re.compile(
    r"^\s*(?:[\w<>\[\],.\s]+?\s+)?(?P<var>[A-Za-z_]\w*)\s*=(?!=)\s*(?P<rhs>.+)$")


def _literal_or_none(expr: str) -> str | None:
    """`"abc"` → abc；其他（变量/方法调用）→ None。"""
    m = re.fullmatch(r"\"([^\"]*)\"", expr.strip())
    return m.group(1) if m else None


def _element_is_constant(val: str, body: str, helpers: str = "",
                        params: set[str] | None = None, skip: str = "",
                        p2a: dict[str, str] | None = None) -> bool:
    """容器元素是否常量：先看字面量，再看能否跨方法上溯到常量。

    为什么需要第二步：OWASP 00867 的容器里装的是
    `param = scr.getTheValue(...)`，而 `SeparateClassRequest.getTheValue`
    的实现体是 `return "bar";` —— 逐行可核对的常量。只看字面量会把它当脏值，
    容器推演就白做了。`skip` 防自引用（`valuesList.add(bar)` 里 bar 就是
    当前正在解析的变量）。

    `p2a` 要先查：在 helper 体里 `param` 是形参，单看形参会一律被判成
    tainted；但调用点已经算过"这次传进来的是常量"（02734）。
    """
    if _literal_or_none(val) is not None:
        return True
    if not re.fullmatch(r"[A-Za-z_]\w*", val) or val == skip:
        return False
    if p2a and val in p2a:
        return p2a[val] == "lit"
    if not helpers:
        return False
    return _value_origin(body, val, helpers, params) == "lit"


def _last_assignment_untainted(body: str, var: str, helpers: str = "",
                               params: set[str] | None = None,
                               p2a: dict[str, str] | None = None) -> bool:
    """`var` 的最后一次赋值能否上溯到**常量字面量**。

    形如 `bar = valuesList.get(1)` / `bar = map.get("keyA")` 的赋值会回溯到
    同方法内该容器的 add / put 记录。回溯不到一律 False（= 不做判断，
    交回原逻辑）—— 绝不在"看不见"的时候断言安全。

    `helpers` 给定时，容器元素可以是"能跨方法上溯到常量的局部变量"
    （见 `_element_is_constant`），否则一律只认字面量。
    """
    lines = body.splitlines()
    last_rhs: str | None = None
    last_i = -1
    for i, ln in enumerate(lines):
        m = _ASSIGN_RE.match(ln)
        if m and m.group("var") == var:
            last_rhs, last_i = m.group("rhs"), i
    if last_rhs is None:
        return False

    if _literal_or_none(last_rhs) is not None:
        return True                     # 直接赋字面量

    m = re.search(r"\b(?P<cont>[A-Za-z_]\w*)\s*\.\s*get\s*\(\s*(?P<arg>[^)]*)\)", last_rhs)
    if not m:
        return False
    cont, arg = m.group("cont"), m.group("arg").strip()
    head = "\n".join(lines[: last_i + 1])

    # Map：按键回溯最后一次 put
    key = _literal_or_none(arg)
    if key is not None:
        val = None
        for pm in _MAP_PUT_RE.finditer(head):
            if pm.group("var") == cont and pm.group("key") == key:
                val = pm.group("val")
        return val is not None and _element_is_constant(val, body, helpers, params, var, p2a)

    # List：按 add 顺序 + remove 推演
    if re.fullmatch(r"\d+", arg):
        seq = [am.group("val").strip()
               for am in _LIST_ADD_RE.finditer(head) if am.group("var") == cont]
        for rm in _LIST_REMOVE_RE.finditer(head):
            if rm.group("var") == cont:
                k = int(rm.group("idx"))
                if 0 <= k < len(seq):
                    seq.pop(k)
        idx = int(arg)
        return idx < len(seq) and _element_is_constant(seq[idx], body, helpers, params, var, p2a)

    return False


def _container_proven_lit(body: str, var: str, helpers: str = "",
                          params: set[str] | None = None,
                          p2a: dict[str, str] | None = None) -> bool:
    """互斥控制流下的唯一例外：**所有路径都汇到常量**。

    形态（OWASP 02370/02457 的 helper，xpathi 类目 4 条 FP 里的两条）：

        String bar = "alsosafe";
        if (param != null) {
            valuesList.add("safe"); valuesList.add(param); valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(1);        // [param, "moresafe"][1] = 常量
        }
        return bar;

    `if (param != null)` 不是常量条件，`_ambiguous_control_flow` 会按
    "取哪个都不对"拦下。这个模板里两条路径确实都汇到常量，但**必须同时**
    满足①②才敢判 lit：

      ① 最后一次赋值是 `cont.get(...)` 且 `_last_assignment_untainted`
         推演为真（容器 add/remove 序列回溯出字面量）；
      ② 进入该 if 之前的旧值（倒数第二次赋值）是字面量 ——
         guard 为假时 var 保持旧值。缺②的话 `String bar = param;` +
         容器覆盖会在 guard 为假时泄漏脏值，这条必须有，否则就是
         记忆第 5 条"兜底分支 return True"的变体。
    """
    spans = _assign_spans(body, var)
    if len(spans) < 2:
        return False
    rhs = _last_assign_rhs(body, var)
    if rhs is None or not re.search(r"\b[A-Za-z_]\w*\s*\.\s*get\s*\(",
                                    _strip_cast(rhs)):
        return False
    if not _last_assignment_untainted(body, var, helpers, params, p2a):
        return False
    prev_rhs = _strip_line_comment(spans[-2].group(1)).strip().rstrip(";").strip()
    return _literal_or_none(_strip_cast(prev_rhs)) is not None


def _const_char_value(body: str, var: str) -> str | None:
    """`var` 能否静态求值为**一个字符**（OWASP 的 `guess.charAt(n)` 模板）。

    这是本项目最喜欢的判据形态：不是"猜分支会不会走到"，而是
    `String guess = "ABC"; char switchTarget = guess.charAt(1);` 本身
    在编译期就是 `'B'` —— 可逐行核对的事实，不需要控制流建模。

    只认两种形态，其余返回 None：
      - `char x = 'B';`
      - `char x = <字符串字面量>.charAt(<数字>);`
        （`<字符串字面量>` 可以是直接写字面量，也可以是同方法内的局部变量，
         只要它最后一次赋值是字面量）
    """
    rhs = _last_assign_rhs(body, var)
    if rhs is None:
        return None
    rhs = _strip_cast(_strip_line_comment(rhs)).strip().rstrip(";").strip()

    m = re.fullmatch(r"'(?:\\.|[^'])'", rhs)
    if m:
        return rhs[1:-1]

    m = re.fullmatch(r"(?P<base>[A-Za-z_]\w*)\s*\.\s*charAt\s*\(\s*(?P<idx>\d+)\s*\)", rhs)
    if m:
        s = _literal_or_none(_last_assign_rhs(body, m.group("base")) or "")
        if s is None:
            return None
        idx = int(m.group("idx"))
        return s[idx] if idx < len(s) else None

    m = re.fullmatch(r'"(?P<s>[^"]*)"\s*\.\s*charAt\s*\(\s*(?P<idx>\d+)\s*\)', rhs)
    if m:
        idx = int(m.group("idx"))
        s = m.group("s")
        return s[idx] if idx < len(s) else None

    return None


def _switch_const_branch_rhs(body: str, var: str) -> str | None:
    """switch 的选择子可静态求值时，取**实际会走的那一支**给 `var` 赋的右值。

    为什么值得为它写一整套解析：OWASP 的 sqli/pathtraver 有一整族样本
    （00340 / 00366 / 00934 / 00935 / 01806 / 01808）长得一模一样 ——
    `charAt(1)` = `'B'` → `case 'B': bar = "bob";`，真值 safe。
    而 01803 / 01807 / 01814 用 `charAt(2)` = `'C'` → `bar = param;`，
    走的是脏值分支。**这两族在语法上天差地别只在那个下标**，
    靠"所有分支都赋字面量"是判不出来的（'C' 分支就赋脏值）。

    Fall-through 要处理：`case 'C': case 'D': bar = param; break;`
    命中 'C' 时段内是空的，赋值在下一段里。
    """
    for m in re.finditer(r"\bswitch\s*\(\s*([A-Za-z_]\w*)\s*\)", body):
        sw = m.group(1)
        if not re.search(rf"(?<![\w.]){re.escape(var)}\s*=(?!=)", _brace_block(body, m.end())):
            continue                     # 这个 switch 不动 var，不是我们要的
        val = _const_char_value(body, sw)
        if val is None:
            continue
        block = _brace_block(body, m.end())
        if not block:
            continue

        segs: list[tuple[list[str], str]] = []
        labels: list[str] = []
        pos = 0
        for lm in re.finditer(r"\b(case\s+(?:'(?:\\.|[^'])'|\d+)\s*:|default\s*:)", block):
            segs.append((labels, block[pos:lm.start()]))
            lbl = lm.group(1)
            if lbl.startswith("default"):
                labels = ["__default__"]
            else:
                c = re.search(r"'(?:\\.|[^'])'", lbl)
                labels = [c.group(0)[1:-1]] if c else [lbl]
            pos = lm.end()
        segs.append((labels, block[pos:]))

        hit = next((i for i, (lbs, _) in enumerate(segs) if val in lbs), None)
        if hit is None:
            hit = next((i for i, (lbs, _) in enumerate(segs) if "__default__" in lbs), None)
        if hit is None:
            continue

        for i in range(hit, len(segs)):
            seg = segs[i][1]
            am = re.search(rf"(?<![\w.]){re.escape(var)}\s*=(?!=)\s*([^;]+);", seg)
            if am:
                return _strip_line_comment(am.group(1)).strip()
            if re.search(r"\bbreak\s*;", seg):
                return None          # 该段自己 break 却没赋值：var 保持旧值
    return None


_JAVA_KEYWORDS = frozenset("""
new return if else for while do switch case default break continue throw throws try
catch finally int long short byte char boolean float double void String Object
null true false this super instanceof final static private public protected
""".split())


_QUALIFIED_RE = re.compile(r"\b(?:[A-Za-z_]\w*\s*\.\s*)+[A-Za-z_]\w*")


def _expr_identifiers(expr: str) -> set[str]:
    """表达式里的**裸局部变量名**（排除类名、方法名、字段访问、关键字）。

    这是"值来源"判定的前置过滤：`new String(Base64.decode(param.getBytes()))`
    里只有 `param` 是变量，`String`/`Base64` 是类名、`decode`/`getBytes`
    是方法名、`TESTFILES_DIR` 这类全大写是常量字段。

    点链要先整体处理，否则 `org.apache.commons.codec.binary.Base64` 的
    包名首段 `org` 会被当成变量（00930 就卡在这里：一个 `org` 让整条
    赋值链判不出常量）。判据是链里有没有大写段 —— 有就是全限定类名
    或常量字段链，整条不参与；没有就是 `obj.method` 形态，保留接收者。
    """
    def _chain(m: re.Match) -> str:
        parts = [p.strip() for p in m.group(0).split(".")]
        if any(p[:1].isupper() for p in parts):
            return " "
        # 末尾补一个点：`param.getBytes(` 抹成 ` param .`，否则残留的 `(`
        # 会让 `param` 被当成方法名排除掉（00930 就卡在这一格）。
        return " " + parts[0] + " . "

    cleaned = _QUALIFIED_RE.sub(_chain, expr)
    out: set[str] = set()
    for m in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)", cleaned):
        name = m.group(1)
        if name in _JAVA_KEYWORDS or name[0].isupper():
            continue                      # 关键字 / 类名 / 全大写常量
        tail = cleaned[m.end():].lstrip()
        if tail.startswith("("):
            continue                      # 方法名
        out.add(name)
    return out


def _all_assigns_lit(body: str, var: str, helpers: str = "",
                     params: set[str] | None = None) -> bool:
    """`var` 的**每一处**赋值右式都只由 lit 变量/字面量构成。

    这是互斥控制流里最通用的一条：不需要知道"走哪条分支"，只需要知道
    **每条分支给的都是常量**，那么走哪条都是常量。OWASP 00930 就是这样：

        String bar = "";
        if (param != null) {
            bar = new String(Base64.decodeBase64(Base64.encodeBase64(
                    param.getBytes())));        // param 上溯到 "bar" 字面量
        }

    `bar` 被赋了两次、`if` 条件非恒定，`_ambiguous_control_flow` 会拦下，
    但两条路径的右式都是常量派生。

    方向写死为否定证据：**任一**赋值不可证常量就返回 False（= 不表态）。
    """
    if params is None:
        params = set(_bare_params(_entry_signature(body)))
    spans = _assign_spans(body, var)
    if not spans:
        return False
    for m in spans:
        rhs = _strip_line_comment(m.group(1)).strip().rstrip(";").strip()
        if not rhs:
            return False
        if _literal_or_none(rhs) is not None:
            continue
        ids = _expr_identifiers(rhs)
        if not ids:
            return False                  # 有无法归类的形态（下标/类型转换等）
        for v in ids:
            if v == var:
                return False              # 自引用：不表态，别递归下去
            if _value_origin(body, v, helpers, params) != "lit":
                return False
    return True


# ---------------- 值来源解析：sqli / pathtraver 共用的「常量顶掉脏值」闸门 ----------------
#
# 为什么要有这一层：容器覆盖、恒真分支、helper 返回常量这三种机制，此前只写在
# `xss_verdict` 里，而且只认变量名 `bar`、只扫入口体。OWASP 的 sqli/pathtraver
# 用的是**同一套模板**，但把同样的代码放进了同文件的 `private class Test`：
#
#     String bar = new Test().doSomething(request, param);   ← 入口体只有这一句
#     ...
#     private class Test {
#         public String doSomething(HttpServletRequest request, String param) {
#             if ((7 * 42) - num > 200) bar = "This_should_always_happen"; // 恒真
#             else bar = param;
#             return bar;
#         }
#     }
#
# 于是 sqli/pathtraver 看到"`bar` 拼进 SQL"就判 True —— 真值是 safe。
# 这不是判据写错，是**判据只挂在一个类目上**。
#
# 方向必须写死在这里：本层是**否定证据**，只能把 True 改成 False，
# 永远不反过来。返回 "unknown" 时调用方维持原判或退回模型。

def _split_ternary(rhs: str) -> tuple[str, str, str] | None:
    """把 `cond ? a : b` 拆成三段（按**顶层** `?` / `:` 切，跳过嵌套与括号）。"""
    depth = 0
    q = -1
    for i, ch in enumerate(rhs):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "?" and depth == 0:
            q = i
            break
    if q < 0:
        return None
    depth = 0
    for j in range(q + 1, len(rhs)):
        ch = rhs[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            return rhs[:q], rhs[q + 1:j], rhs[j + 1:]
    return None


def _const_branch_rhs(body: str, var: str) -> str | None:
    """`var` 的最后一次赋值落在**恒真分支**上时，返回那一支的右值表达式。

    与 `_const_branch_overrides` 同源，区别是它只回答 lit/var 二分，这里要
    拿到原始表达式 —— 因为右值可能又是一个 helper 调用或三元，需要继续上溯。
    """
    lines = body.splitlines()
    env = _numeric_locals(body)
    last_i = -1
    for i, ln in enumerate(lines):
        m = _ASSIGN_RE.match(ln)
        if m and m.group("var") == var:
            last_i = i
    if last_i < 0:
        return None
    for i in range(last_i, -1, -1):
        m = _IF_RE.search(lines[i])
        if not m:
            continue
        cond = _balanced_cond(lines[i], m.end())
        if cond is None or _const_cond_truth(cond, env) is not True:
            return None
        for cand in "\n".join(lines[i: min(last_i + 2, len(lines))]).splitlines():
            am = _ASSIGN_RE.match(cand)
            if am and am.group("var") == var:
                return am.group("rhs").strip().rstrip(";").strip()
            inline = re.search(rf"\b{re.escape(var)}\s*=(?!=)\s*(.+?);", cand)
            if inline:
                return inline.group(1).strip()
        return None
    return None


def _strip_line_comment(s: str) -> str:
    """去掉行尾 `//` 注释，但**跳过字符串字面量里的 `//`**。

    为什么必须做：`entry_body()` 会剥注释，但 `_sibling_methods()` 里的
    helper 实现体是原样的切片文本，注释还在：

        String bar = thing.doSomething(g90580); // reflection

    不剥的话右值变成 `thing.doSomething(g90580); // reflection`，
    既去不掉分号也匹配不上调用形态 —— 02183 就卡在这一行。
    注意不能直接 `split("//")`：`"http://x"` 会被切坏。
    """
    in_str = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '"' and (i == 0 or s[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and s[i:i + 2] == "//":
            return s[:i].rstrip()
        i += 1
    return s


def _assign_spans(body: str, var: str) -> list[re.Match]:
    """**所有**对 `var` 的赋值（含行内 `if (c) x = y;`）。

    `_ASSIGN_RE` 是行首锚定的，对 `if (values != null) param = values[0];`
    完全瞎 —— 于是"最后一次赋值"退回到开头的 `String param = "";`，
    常量判定把**外部输入判成字面量**。OWASP 02272 就是这么变成漏报的：
    真值 vul，规则因为拿到 `""` 判了 safe。
    这是记忆第 30 条那类错误的又一形态：**扫的范围不对，正则再准也白搭**。
    """
    return list(re.finditer(
        rf"(?<![\w.]){re.escape(var)}\s*=(?!=)\s*([^;]+)", body))


def _last_assign_rhs(body: str, var: str) -> str | None:
    """`var` 最后一次赋值的右值（行内赋值也算）。

    必须去掉结尾分号与行尾注释：`(?P<rhs>.+)$` 会把 `;` 和 `// xxx` 一起吃进来，
    于是 `new Test().doSomething(request, param);` 用 `\\)\\s*$` 收尾的调用
    正则匹配不上，规则把它当成"来源不明"，一路退成 unknown。
    """
    rhs = None
    for ln in body.splitlines():
        hits = list(re.finditer(
            rf"(?<![\w.]){re.escape(var)}\s*=(?!=)\s*([^;]+)", ln))
        if hits:
            rhs = _strip_line_comment(hits[-1].group(1)).strip()
    return rhs


def _strip_cast(expr: str) -> str:
    """去掉前置强转：`(String) map.get("k")` → `map.get("k")`。"""
    return re.sub(r"^\s*\([A-Za-z_][\w.<>\[\]]*\)\s*", "", expr.strip())


def _looks_like_external(rhs: str) -> bool:
    """右值是否直接来自请求（含包装对象取值）。"""
    return bool(re.search(r"\b(?:request|req)\b|\bscr\s*\.", rhs))


def _helper_return(body: str) -> str | None:
    """helper 里最后一次 `return X;` 的 X。"""
    hits = re.findall(r"\breturn\s+([^;]+);", body)
    return _strip_line_comment(hits[-1]).strip() if hits else None


def _raw_params(sig: str) -> list[str]:
    """签名里的**全部**形参名（不过滤框架注入类型 —— 这里要的是位置对齐）。"""
    sig = re.sub(r"@\w+\s*(?:\([^)]*\))?", " ", sig)
    return [name for _typ, name in _PARAM_SEG_RE.findall(sig)]


def _split_args(args: str) -> list[str]:
    """按**顶层**逗号拆实参（`(String) x, y` 里的逗号不拆）。"""
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _named_methods_with_sig(helpers: str, name: str) -> list[tuple[list[str], str]]:
    """同名方法的 [(形参名列表, 方法体)]。

    带形参名是为了做**位置映射**：`thing.doSomething(g55109)` 的实参是常量，
    但 helper 里写的是 `String r = i; return r;` —— 不把 `i` 映射回实参，
    就只能把形参一律当外部输入，于是这条 safe 样本判成漏洞。

    同名方法可能不止一个（OWASP 每个文件都有自己的 `private class Test`，
    跨文件还有 `Thing1/Thing2`），所以调用方必须按**实参个数**挑，
    不能拿第一个匹配就用 —— 00330 的 `thing.doSomething(x)` 就撞上了
    隔壁签名两参的 `doSomething(HttpServletRequest, String)`。
    """
    out: list[tuple[list[str], str]] = []
    for m in re.finditer(
            r"\b" + re.escape(name) + r"\s*\(([^)]*)\)\s*(?:throws[^{]*)?\{", helpers):
        depth, end = 1, len(helpers)
        for i in range(m.end(), len(helpers)):
            if helpers[i] == "{":
                depth += 1
            elif helpers[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        out.append((_raw_params(m.group(1)), helpers[m.end():end]))
    return out


def _brace_block(text: str, pos: int) -> str:
    """从 `pos` 之后第一个 `{` 起，取到配平的 `}`（含内部）。找不到返回 ""。"""
    i = text.find("{", pos)
    if i < 0:
        return ""
    depth = 0
    for k in range(i, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:k]
    return text[i + 1:]


def _ambiguous_control_flow(body: str, var: str) -> bool:
    """变量被"多条互斥路径"赋值 → 不判来源（控制流没建模）。

    两个真实踩到的形态：

      - switch：OWASP `01807` 最后一个分支是 `default: bar = "bobs_your_uncle";`，
        而实际选中的 'C' 走 `bar = param;`。"取最后一处赋值"会把**真漏洞判成
        safe**，比漏报危险。
      - 非恒定 if：`if (values != null) param = values[0];` 与开头的
        `String param = "";` 同时存在，取哪个都不对。OWASP `02272` 因此被判成
        safe（真值 vul）—— 那次是**漏报**，比误报更该拦住。

    **判据必须落在"这个 if/switch 真的给 var 赋了值"上。** 第一版写成
    "body 里有非恒定 if 且 var 被赋过多次"，结果 00365 的三次**顺序**赋值
    （`bar = "safe!"` → `get(keyB)` → `get(keyA)`）被一个无关的
    `if (param == null) param = "";` 连带判成互斥，安全样本翻成漏洞。
    """
    if len(_assign_spans(body, var)) <= 1:
        return False
    env = _numeric_locals(body)

    # switch：只看它自己那块里有没有给 var 赋值
    for m in re.finditer(r"\bswitch\s*\(", body):
        if re.search(rf"(?<![\w.]){re.escape(var)}\s*=(?!=)", _brace_block(body, m.end())):
            return True

    # if：行内赋值看同一行；块内赋值看配平的块
    for m in _IF_RE.finditer(body):
        cond = _balanced_cond(body, m.end())
        if cond is None or _const_cond_truth(cond, env) is not None:
            continue                    # 恒真/恒假由 `_const_branch_rhs` 精确处理
        start = m.end() + len(cond) + 1
        tail = body[start:]
        seg = _brace_block(body, start) if tail.lstrip().startswith("{") else tail.split(";")[0]
        if re.search(rf"(?<![\w.]){re.escape(var)}\s*=(?!=)", seg):
            return True
    return False


def _resolve_rhs_origin(rhs: str, body: str, helpers: str, depth: int,
                        var: str = "", params: set[str] | None = None,
                        p2a: dict[str, str] | None = None) -> str:
    """右值表达式的来源：'lit' / 'tainted' / 'unknown'。

    `p2a` = 形参名 → 实参来源（"lit"/"tainted"/"unknown"），用于进 helper 后
    继续追：`doSomething(g55109)` 里的 `i` 应该按 `g55109` 的来源算。
    """
    expr = _strip_cast(_strip_line_comment(rhs))
    params = params or set()
    p2a = p2a or {}

    # 三元：条件可求值就只看被选中那一支
    tri = _split_ternary(expr)
    if tri:
        cond, a, b = tri
        truth = _const_cond_truth(cond, _numeric_locals(body))
        if truth is None:
            return "unknown"
        return _resolve_rhs_origin(a if truth else b, body, helpers, depth + 1,
                                   var, params, p2a)

    if _literal_or_none(expr) is not None:
        return "lit"

    # 容器取值：先放常量再覆盖 / List remove 后下标指向常量 —— 已在
    # `_last_assignment_untainted` 里推演过，直接复用。
    if re.search(r"\b[A-Za-z_]\w*\s*\.\s*get\s*\(", expr):
        return "lit" if _last_assignment_untainted(body, var) else "unknown"

    # helper 调用：实现体在证据段里就进去看它 return 什么。
    # 接收者有三种形态，必须都认：
    #     doSomething(x)              ← 同文件静态方法
    #     new Test().doSomething(x)   ← 内部类实例（OWASP 的 Test）
    #     thing.doSomething(x)        ← 局部变量/字段（ThingInterface）
    # 第一版只写了前两种，`thing.doSomething(g55109)` 直接落到
    # `_looks_like_external`（实参里没有 request，于是 unknown）。
    cm = re.match(
        r"(?:(?:new\s+)?[\w.]+\s*\([^)]*\)\s*\.\s*|[\w.]+\s*\.\s*)?"
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)\s*$",
        expr, re.S)
    if cm and depth < 6:
        name, args = cm.group("name"), cm.group("args")
        actuals = _split_args(args)
        for formals, impl in _named_methods_with_sig(helpers, name):
            if len(formals) != len(actuals):
                continue                  # 同名不同参：不是这个被调用的方法
            ret = _helper_return(impl)
            if ret is None:
                continue
            mapping = {
                f: _resolve_rhs_origin(a, body, helpers, depth + 1, f, params, p2a)
                for f, a in zip(formals, actuals)
            }
            got = _resolve_rhs_origin(ret, impl, helpers, depth + 1,
                                      ret if re.fullmatch(r"[A-Za-z_]\w*", ret) else "",
                                      set(formals), mapping)
            if got != "unknown":
                return got
        # 实现体读不到：只剩"调用点只喂了常量"这一个可核对的事实。
        # **但接收者是请求对象时先判脏**：`request.getParameter("p")` 的实参
        # 也只有字面量，若在这里放行，会把所有读参数的样本判成 safe ——
        # 这是本轮真实踩到的方向性错误（三条真漏洞冒烟直接翻成 False）。
        if _looks_like_external(expr):
            return "tainted"
        if not _looks_like_external(args) and _args_all_constant(
                args, body, helpers, depth, params, p2a):
            return "lit"
        return "unknown"

    # 裸变量：继续上溯一层（`bar = param;` 这种）
    if re.fullmatch(r"[A-Za-z_]\w*", expr) and depth < 6:
        if _looks_like_external(expr):
            return "tainted"
        if expr in p2a:
            return p2a[expr]           # 形参 → 实参来源（在调用点已经算过）
        if expr in params:
            return "tainted"           # helper/入口的形参 = 外部输入
        if _ambiguous_control_flow(body, expr):
            # 互斥路径一般"取哪个都不对"。两类可逐行核对的例外：
            #   ① 最后一次赋值是容器 get 且容器推演为常量、guard 前旧值
            #      也是字面量 —— 两条路径都汇到常量（_container_proven_lit）
            #   ② switch 选择子能静态求值 —— 走哪一支是编译期事实
            #      （_switch_const_branch_rhs，`charAt(1)` 那一族）
            # **必须与 `_value_origin` 里的两条例外保持一致**：两处是不同的
            # 递归入口，只改一处会留下"单独调用正确、真实链路仍 unknown"
            # 的假象（01806 就是这么卡住的）。
            if _container_proven_lit(body, expr, helpers, params, p2a):
                return "lit"
            branch = _switch_const_branch_rhs(body, expr)
            if branch is not None:
                return _resolve_rhs_origin(branch, body, helpers, depth + 1,
                                           expr, params, p2a)
            if _all_assigns_lit(body, expr, helpers, params):
                return "lit"
            return "unknown"
        sub = _const_branch_rhs(body, expr) or _last_assign_rhs(body, expr)
        if sub is None:
            return "unknown"
        return _resolve_rhs_origin(sub, body, helpers, depth + 1, expr, params, p2a)

    if _looks_like_external(expr):
        return "tainted"
    return "unknown"


def _args_all_constant(args: str, body: str, helpers: str, depth: int,
                       params: set[str] | None = None,
                       p2a: dict[str, str] | None = None) -> bool:
    """实参是否**全部**能上溯到常量（字面量，或值为字面量的局部变量）。

    "调用点没把任何外部输入喂进去"是一个可逐行核对的事实：

        String g55109 = "barbarians_at_the_gate";   // 常量
        String bar = thing.doSomething(g55109);     // 实参只有这个常量

    边界（必须写在代码里，否则以后会把它当万能钥匙）：它**不**证明 helper
    内部没有别的输入通道（静态字段、请求上下文、ThreadLocal）—— 那超出单
    方法静态分析的范围。所以只在实现体读不到时使用，且实参不能为空。

    OWASP 的 `00330` / `02183` 就是这个形态，注释也写着
    "This is static so this whole flow is 'safe'"。
    """
    parts = [p.strip() for p in args.split(",") if p.strip()]
    if not parts:
        return False
    for p in parts:
        if _literal_or_none(p) is not None:
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", p):
            got = _resolve_rhs_origin(p, body, helpers, depth + 1, p,
                                      params or set(), p2a)
            if got != "lit":
                return False
            continue
        return False                      # 嵌套调用/表达式：不表态
    return True


def _value_origin(body: str, var: str, helpers: str = "",
                  params: set[str] | None = None) -> str:
    """`var` 在给定作用域里的值来源：'lit' / 'tainted' / 'unknown'。"""
    if params is None:
        params = set(_bare_params(_entry_signature(body)))
    if _ambiguous_control_flow(body, var):
        # 互斥控制流里两类**可判定**的例外：走哪条路径值都确定。
        #   ① 容器先放常量再覆盖（02370 形态，见 _container_proven_lit）
        #   ② switch 选择子可静态求值（01806 的 charAt(1) 形态）
        # 顺序有意义：容器判据更严（要求 guard 前旧值也是字面量），先试它。
        if _container_proven_lit(body, var, helpers, params):
            return "lit"
        branch = _switch_const_branch_rhs(body, var)
        if branch is not None:
            return _resolve_rhs_origin(branch, body, helpers, 0, var, params)
        if _all_assigns_lit(body, var, helpers, params):
            return "lit"
        return "unknown"
    rhs = _const_branch_rhs(body, var) or _last_assign_rhs(body, var)
    if rhs is None:
        # 没有任何赋值：可能是裸形参（真外部输入），也可能是字段
        return "tainted" if var in params else "unknown"
    return _resolve_rhs_origin(rhs, body, helpers, 0, var, params)


def _operand_vars(rhs: str) -> list[str] | None:
    """把拼接右值拆成"需要判定来源"的局部变量；出现调用则返回 None。

    返回 None 表示"这条拼接里有函数调用，不归本闸门管"（`_concat_only_sanitized`
    已经处理那种形态），避免两个判据互相踩。
    """
    bare = _STR_LIT_RE.sub('""', rhs)
    out: list[str] = []
    for part in bare.split("+"):
        p = _strip_cast(part.strip())
        if not p or p == '""':
            continue
        if "(" in p:
            return None
        if re.fullmatch(r"[A-Za-z_]\w*", p):
            out.append(p)
        elif re.fullmatch(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+", p):
            # 字段访问（`Utils.TESTFILES_DIR`）：不归本闸门判，见下
            return None
    return out


def _sql_concat_all_constant(body: str, helpers: str) -> bool:
    """SQL 拼接的操作数是否**每一个**都能上溯到常量。

    只处理纯局部变量的拼接（出现调用/字段访问就退出，交给别的判据）。
    """
    seen = False
    for rhs in _sql_rhs_iter(body):
        vars_ = _operand_vars(rhs)
        if vars_ is None:
            return False
        for v in vars_:
            seen = True
            if _value_origin(body, v, helpers) != "lit":
                return False
    return seen


_FIELD_REF_RE = re.compile(r"^[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+$")

# 所有会"真的碰文件"的构造/调用。`FileOutputStream` 必须单列 ——
# `new\s+File\b` 匹配不到 `new java.io.FileOutputStream(...)`，
# 而 OWASP 00220/00628 正是用 FileOutputStream 承载路径变量的。
_PATH_API_RE = re.compile(
    r"(?:Paths\s*\.\s*get|new\s+(?:java\.io\.)?File(?:Input|Output)?Stream"
    r"|new\s+(?:java\.io\.)?File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(")


def _path_operand_is_constant(expr: str, body: str, helpers: str,
                              params: set[str]) -> bool | None:
    """路径实参/左式是否**只由常量与字段前缀**构成。

    True = 全常量；False = 有脏值或不可判形态；None = 这条表达式里
    一个局部变量都没有（纯字面量/纯字段），本闸门没有判断依据。
    """
    ok, checked = True, False
    for part in _STR_LIT_RE.sub('""', expr).split("+"):
        p = _strip_cast(part.strip())
        if not p or p == '""':
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", p):
            checked = True
            if _value_origin(body, p, helpers, params) != "lit":
                ok = False
        elif _FIELD_REF_RE.match(p):
            leaf = p.split(".")[-1].strip()
            if re.search(rf"\b{re.escape(leaf)}\s*=(?!=)", body):
                ok = False           # 字段被写过，可能承载输入
        elif re.fullmatch(r"\d+", p) or re.fullmatch(r"\"[^\"]*\"", p):
            continue
        else:
            ok = False               # 调用/下标等：不表态
    return ok if checked else None


def _path_concat_all_constant(body: str, helpers: str) -> bool:
    """拼进文件 sink 的那个值是否只由「常量 + 字段前缀」构成。

    两种形态都要覆盖，此前只做了第一种：

      ① 中间变量：`String fileName = Utils.TESTFILES_DIR + bar;`
         之后 `new FileOutputStream(fileName)` —— 只看拼接左式。
      ② **直接构造**：`new java.io.File(bar, "/Test.txt")` /
         `Paths.get(prefix + bar)` —— 没有中间赋值可扫。OWASP 的
         pathtraver 大量用这一形态（00217/00220/00621/00863 …），
         漏掉它就等于这条闸门在这些样本上从来没生效过。

    字段前缀（`Utils.TESTFILES_DIR`）的值不参与判定（那是另一个类的常量，
    本判据不追），但要求它**在本方法内没被重新赋值** —— 否则它可能承载
    外部输入，`this.base = param` 之后拼进路径就是真漏洞。

    必须至少核到一个**局部变量**，否则不算通过：全靠字段/字面量拼出来的
    路径没有判断依据，交给别的判据。
    """
    params = set(_bare_params(_entry_signature(body)))

    # ① 中间变量形态
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);", body):
        var, rhs = m.group(1), m.group(2)
        if "+" not in rhs:
            continue
        if not re.search(rf"{_PATH_API_RE.pattern}[^;]*\b{re.escape(var)}\b", body):
            continue
        # 不要求 RHS 里有字符串字面量：文件路径的前缀常常是字段
        # （`Utils.TESTFILES_DIR + bar`），一个引号都没有。
        if _path_operand_is_constant(rhs, body, helpers, params) is True:
            return True

    # ② 直接构造形态：文件 API 的实参里直接出现裸变量
    for m in _PATH_API_RE.finditer(body):
        args = _balanced_cond(body, m.end())
        if args is None:
            continue
        hits = 0
        verdict = True
        for a in _split_args(args):
            if not a:
                continue
            got = _path_operand_is_constant(a, body, helpers, params)
            if got is None:
                continue
            hits += 1
            if got is False:
                verdict = False
        if hits and verdict:
            return True
    return False


# ---------------- 三元 / 循环：「常量分支可直接判定」 ----------------
#
# OWASP 用一堆"看起来像分支、其实恒真恒假"的写法来承载 true/false 样本，
# 这些条件全部只由编译期常量构成（`(7 * 18) + num > 200`），不可能失败。
#
# 结论的方向是**精确**的，先想清楚再落地：
#
#   恒真分支被选中 → 该分支赋字面量 ⇒ 脏值没进回显 ⇒ 安全（可以判 False）
#   恒真分支被选中 → 该分支赋 param  ⇒ 脏值进回显     ⇒ 真漏洞（维持 True）
#
# 所以这是"否定证据"性质的闸门：它只会把 True 改成 False，绝不反过来。
# 恒假条件、循环（OWASP 的循环一律是 `while(false)`，一次都不执行）、
# 或者条件里出现任何变量，一律不介入 —— 返回"无法判定"。
#
# 之前我把它写成"If 分支里出现字面量赋值就交模型"，方向保守但会白白丢掉
# 一批可判定的安全样本；正确的做法是判**哪一支会被选中**，再读那一支的值。

_CONST_TOKEN_RE = re.compile(r"\d+|true|false|&&|\|\||[()<>=!+\-*/%]|\s+|'.'")
_IF_RE = re.compile(r"\bif\s*\(")
_WHILE_RE = re.compile(r"\bwhile\s*\(")


def _balanced_cond(line: str, start: int) -> str | None:
    """从 `start`（左括号之后）取到配平的右括号，返回括号内文本。"""
    depth = 1
    for k in range(start, len(line)):
        ch = line[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[start:k]
    return None


def _numeric_locals(body: str) -> dict[str, str]:
    """局部变量里哪些是**编译期常量数字**：`int num = 106;` → {num: "106"}。

    OWASP 的条件全部写在这类变量上（`(7 * 18) + num > 200`）。必须代入
    **真实数值**而不是占位符 —— 代入 0 会把 `252 > 200` 从真算成假。
    右侧只要出现标识符或方法调用就不算常量，不代入。
    """
    out: dict[str, str] = {}
    for m in re.finditer(
            r"\b(?:int|long|short|byte|double|float)\s+(\w+)\s*=(?!=)\s*([^;]+);",
            body):
        name, rhs = m.group(1), m.group(2).strip()
        if re.search(r"[A-Za-z_$]", rhs):
            continue                     # 右侧含变量/调用 → 不是编译期常量
        if re.fullmatch(r"[\d\s.+\-*/%()]+", rhs):
            out[name] = rhs
    return out


def _const_cond_truth(cond: str, env: dict[str, bool] | None = None) -> bool | None:
    """只由数字/布尔/算术/比较/位运算符（以及已确认的常量局部变量）组成的条件求值。

    含未确认变量则返回 None。注意**变量替换必须写 `\\b` 边界**：写成
    `expr.replace("true", "")` 会把 `String` 里的 `tru` 一起削掉
    （`String bar` → `S bar`），于是所有含 String 声明的条件都被误判成
    "有变量"。这是踩过的一次。
    """
    expr = cond.strip()
    if not expr:
        return None
    if env:
        for name, val in env.items():
            # 代入**真实数值**而不是占位符：代入 0 会把 `(7*18)+106 > 200`
            # 从真算成假。env 里的值已在 `_numeric_locals` 里核过是纯数字表达式。
            expr = re.sub(rf"\b{re.escape(name)}\b", f"({val})", expr)
    scrubbed = re.sub(r"\b(?:true|false)\b", " ", expr)
    if re.search(r"[A-Za-z_$]", scrubbed):
        return None                      # 有标识符 → 不可常量求值
    # `!` 必须在标识符检查**之后**才换成 `not`，否则 `not` 的字母
    # 会被当成变量，条件永远判不出来。
    py = re.sub(r"\btrue\b", "True", expr)
    py = re.sub(r"\bfalse\b", "False", py)
    py = py.replace("&&", " and ").replace("||", " or ")
    py = re.sub(r"!(?!=)", " not ", py)
    try:
        return bool(eval(py, {"__builtins__": {}}, {}))   # noqa: S307 —— 已白名单化
    except Exception:
        return None


def _assign_kind(line: str) -> str | None:
    """一行赋值右侧是字面量还是有变量。返回 'lit' / 'var' / None。"""
    m = _ASSIGN_RE.match(line)
    if not m:
        return None
    return "lit" if _literal_or_none(m.group("rhs")) is not None else "var"


def _const_branch_overrides(body: str, var: str = "bar") -> str | None:
    """当 `var` 的最后一次赋值落在**恒真分支**上时，返回那一支的值类型。

    返回 'lit'  → 回显的是常量，脏值没进去
    返回 'var'  → 回显的仍是变量（真漏洞维持）
    返回 None   → 判不出来（条件含变量、循环体、结构不认识）

    实现上只处理"最后一次赋值"：它决定了回显时 `var` 里到底是什么。
    往前找最近的一行 `if (cond) ... var = X`，条件是常量就求值。
    """
    lines = body.splitlines()
    env = _numeric_locals(body)
    last_i = -1
    for i, ln in enumerate(lines):
        m = _ASSIGN_RE.match(ln)
        if m and m.group("var") == var:
            last_i = i
    if last_i < 0:
        return None

    # 关键：`_ASSIGN_RE` 是行首锚定的，行内赋值（`if (c) bar = x;`）
    # 单看这一行**匹配不到**，必须回头找它前面最近的 if 行。
    # 反例是 `if (c) bar = "lit"; else bar = param;` —— 看到 else 行
    # 仍要继续往前找 if，不能停在 else 上。
    for i in range(last_i, -1, -1):
        m = _IF_RE.search(lines[i])
        if not m:
            continue
        cond = _balanced_cond(lines[i], m.end())
        if cond is None:
            return None
        truth = _const_cond_truth(cond, env)
        if truth is None or truth is False:
            # None = 条件含变量；False = 恒假（说明还有别的路径给 var 赋值）
            return None
        # 恒真：先看 if 那一行的行内赋值，再看紧跟的块
        blk = "\n".join(lines[i: min(last_i + 2, len(lines))])
        for cand in blk.splitlines():
            am = _ASSIGN_RE.match(cand)
            if am and am.group("var") == var:
                return _assign_kind(cand)
            inline = re.search(rf"\b{re.escape(var)}\s*=(?!=)\s*(.+?);", cand)
            if inline:
                return "lit" if _literal_or_none(inline.group(1)) else "var"
        return None
    return None


def _in_never_run_loop(body: str, var: str = "bar") -> bool:
    """`var` 的回显是否落在 `while(false)` 这类一次都不执行的块里。

    只认条件可常量求值为 False 的 while —— 其它循环语义（break/continue、
    异常退出）规则不碰，返回 False 表示"不介入"。
    """
    lines = body.splitlines()
    for i, ln in enumerate(lines):
        m = _WHILE_RE.search(ln)
        if not m:
            continue
        cond = _balanced_cond(ln, m.end())
        if cond is None or _const_cond_truth(cond, _numeric_locals(body)) is not False:
            continue
        # 从 while 这一行往后数花括号，找块里对 var 的赋值
        depth = 0
        started = False
        for j in range(i, len(lines)):
            if j > i and re.search(rf"\b{re.escape(var)}\b", lines[j]):
                return True
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
    return False


def has_external_input(source: str) -> bool:
    """入口方法是否存在外部可控输入（形参 / 请求读取 / 跨路由串接）。

    只看**入口方法自己的体**：切片里拼进来的辅助方法与兄弟路由的参数
    不属于当前入口的输入面（同 `entry_body` 的理由）。

    保守方向：拿不准时返回 True（当作有输入），因为 False 会让调用方
    倾向于判"安全"，而漏报比多退回模型更难发现。
    """
    body = entry_body(source)
    if not body:
        return True                    # 截不出入口体，不在此处下结论
    if XSS_PARAM_RE.search(body) or _REQUEST_READ_RE.search(body):
        return True                    # 注解绑定或 request 读取
    if _XSS_FOREIGN_SOURCE_RE.search(body):
        return True                    # 值从别的类的 `xxx(request)` 里取出来
    if _bare_params(_entry_signature(body)):
        return True                    # Spring/JAX-RS 裸形参（框架注入类型已排除）
    if _chain_reader_body(source):
        return True                    # 本方法写的值经介质被另一路由读取
    return False


def _has_inline_assign_after(body: str, var: str, pos: int) -> bool:
    """`pos` 之后是否还有对 `var` 的行内赋值（`if (c) bar = x;` 这种）。

    行首锚定的赋值正则抓不到行内赋值，所以"最后一行被识别到的赋值是
    字面量"并不等于"回显时 var 是字面量"：
        String bar;                                   ← 声明
        if ((7*18)+num > 200) bar = param;            ← 行内赋值（正则漏掉）
        else bar = "never";                           ← 正则看到的是这行
    """
    return bool(re.search(
        rf"(?<![\w.]){re.escape(var)}\s*=(?!=)[^;]*;", body[pos + 1:]))


def _echo_value_traced_locally(body: str, var: str = "bar") -> bool | None:
    """回显的 `var` 能否在本方法内追到一个**来自外部输入的赋值**。

    三态，``None`` 是刻意保留的中间档：

        True   —— 能逐行追到（`bar = param` / `bar = scr.getTheParameter(..)`
                  / `bar = request.getParameter(..)`），且链上没有别的加工。
                  调用方据此判 True。
        False  —— 追不到：`var` 由**别的方法**产出（`String bar =
                  doSomething(request, param)`），或从未在本方法赋值。
                  此时"入口体无编码"不等于"链上无编码" —— 编码常在 helper
                  里（`return StringEscapeUtils.escapeHtml(param);`）。
                  调用方不得判 True，只能 None。
        None   —— 追到了输入面，但值确实被"请求对象出门"这一句弱信号推出去了：
                  `String bar = doSomething(request, param)`。输入成立，但是否
                  加工取决于那个方法体；OWASP 里同形态真值相反。调用方只能 None。

    只处理可逐行核对的情形，其余一律 False（= 交模型）：

        String bar = param;                  → 直接来自形参/请求读取
        bar = request.getParameter("x");     → 直接来自请求
        String bar = "safe";  /  bar = "..."; → 字面量：调用方已由
                                               `_last_assignment_untainted`
                                               处理，这里视作"本地可追"
    反例（判 False 的那些）：
        String bar = helper(request, param);  → 值在 helper 里产出，
                                               helper 里可能已经转义
        String bar = thing.doSomething(x);    → 同上（反射调度）

    为什么不需要追"赋值右侧包含变量"这种更宽的定义：本闸门只用于
    **阻止判 True**，判 False 的方向不归它管；宁可把可疑样本交给模型，
    也不要给出一个"范围没看全"的结论。
    """
    # 形参名与请求读取出来的变量：`String param = request.getParameter(...)`
    tainted: set[str] = set()
    for m in re.finditer(
            r"\b(?:String|var|[\w.]+\s+[\w.]+)\s+(\w+)\s*=(?!=)\s*"
            r"(request\s*\.\s*(?:getParameter|getParameterValues|getHeader|"
            r"getHeaders|getQueryString|getCookies)|values\[0\]|headers\.nextElement)",
            body):
        tainted.add(m.group(1))
    # 从包装对象里取值：`String param = scr.getTheParameter("x");`
    # `getTheValue` 刻意不在此列 —— 见 `_XSS_FOREIGN_SOURCE_RE` 上的说明，
    # OWASP 里它是**声明过的安全源**，按名字算脏会整批误报。
    for m in re.finditer(
            r"\b(?:String|var)\s+(\w+)\s*=(?!=)\s*[\w.]+\s*\.\s*"
            r"(?:getTheParameter|getParameter|getHeader)\s*\(", body):
        tainted.add(m.group(1))
    sig = _entry_signature(body)
    tainted.update(_bare_params(sig))
    # 兜底：本方法里任何 `String x = ...(...)` 的右侧只要出现 `request`
    # 或 `scr.` 这类请求包装对象，`x` 也算脏的
    # （`String param = scr.getTheParameter("x")`）。
    # **不要把右侧是"调用本类辅助方法"的那条也算进来** —— 那是被加工过的值，
    # 由 `_echo_value_traced_locally` 单独判定，算进来会让"回显的就是它自己"
    # 被当成"回显来自外部输入"。
    for m in re.finditer(r"\b(?:String|var)\s+(\w+)\s*=(?!=)\s*([^;]+);", body):
        if re.search(r"\brequest\b|\bscr\s*\.", m.group(2)):
            tainted.add(m.group(1))
    if not tainted:
        return False

    # 先处理行内赋值（`if (c) bar = param;`）：行首锚定的赋值正则对它
    # **是瞎的** —— 它只会看到 `else bar = "never";` 那一行，于是把
    # "字面量覆盖"当成定论。这一步必须在读 assigns 之前做。
    for il in body.splitlines():
        if re.search(rf"\bif\s*\([^)]*\)\s*[^;]*\b{re.escape(var)}\s*=(?!=)", il):
            # 恒真分支赋字面量 → False（由调用方的 `_const_branch_overrides`
            # 先拦掉）。这里只剩"分支里赋的是脏值"和"条件解不出来"两种，
            # 都够不上逐行核对的 True，交模型。
            return False if _const_branch_overrides(body, var) == "lit" else None

    assigns = [m for m in re.finditer(
        rf"^\s*(?:(?:final|static|private|public|protected)\s+)*"
        rf"(?:[\w<>\[\],.]+\s+)?{re.escape(var)}\s*=(?!=)\s*(?P<rhs>.+)$",
        body, re.M)]
    # 取**最后一次**赋值：前面的字面量初始化（`String bar = "alsosafe";`）
    # 会被后面的 `bar = valuesList.get(0);` 覆盖，回显时生效的是后者。
    assigns = assigns[-1:]
    if not assigns:
        # 本方法没给 var 赋过值。三种情形要分开：
        #   a) 回显的是**形参/请求读出的变量本身**（`return xss;`）→ 可追
        #   b) 回显的是一个从未赋值的局部（`println(bar)` 而 bar 无赋值）→ 不可追
        #   c) 赋值写在 `if (...)` 行内（`if (c) bar = param;`），行首锚定的
        #      正则抓不到 —— 由 `_const_branch_overrides` 判定那一支生效
        if any(re.search(rf"^\s*return\s+{re.escape(t)}\s*;", body, re.M)
               for t in tainted):
            return True
        return None                  # 没赋过值就回显：范围没看全，交模型

    for m in assigns:
        rhs = m.group("rhs").strip()
        # 右侧是**别的方法的调用**（`doSomething(request, param)`、
        # `new Test().doSomething(request, param)`）时，值经过加工 —— 是否
        # 已转义取决于那个方法体，而它不一定在入口体范围内。
        # 但**参数里有 request 就是输入面成立**的硬证据，返回 None 而不是
        # False：这两种情况的处置一样（交模型），可语义必须分开记，
        # 否则以后想收紧成 False 时看不出哪里丢了信息。
        if re.match(r"(?:new\s+\w+\s*\(\s*[^)]*\)\s*\.\s*)?[A-Za-z_]\w*\s*\(\s*(?:request|scr)",
                    rhs):
            return None
        if _literal_or_none(rhs) is not None:
            return True                  # 字面量：脏值已被常量顶掉
        head = re.match(r"[A-Za-z_]\w*", rhs)
        if head and head.group(0) in tainted and head.group(0) != var:
            return True                  # `var = param;`（右侧就是外部输入变量）
        if re.match(r"\(?\s*\(?\s*(?:[A-Za-z_][\w.]*\s*\)\s*)?[A-Za-z_]\w*\s*\.\s*get\s*\(",
                    rhs):
            return True                  # 容器取值，安全性由上游闸门判定
        if rhs.startswith("request") or rhs.startswith("scr"):
            return True                  # 直接读请求 / 从请求包装对象里取
        # `var = helper(request, param)`：值由本文件（或别的类）的方法产出。
        # 靶场里 `doSomething(request, param)` 的产物确实是脏值，但**是否
        # 被转义取决于那个方法体**，而它不一定被切进 entry_body。看不到
        # 那一层就不下结论 —— 这正是 OWASP 里 100 余条误报的根因形态。
        if re.match(r"(?:new\s+[\w.()]+\s*\.\s*)?[A-Za-z_]\w*\s*\(", rhs):
            return False
        # 其它形态（拼接、三元、下标……）→ 范围没看全，不判 True
        return None


def xss_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None

    has_param = has_external_input(source)
    # 注意用 `_chain_reader_body`（只认 cookie/session/request/model 那条证据块）
    # 而不是"有串接证据" —— db 证据块由下面的 (2b) 专门处理。
    reader = _chain_reader_body(source)

    # 1) 反射型：有外部入参 + 有回显 + 无编码
    if has_param and _echo_sink_hit(body):
        if XSS_ENCODE_RE.search(body):
            # `printf`/`format` 的格式串位置如果是变量，说明用户能控制
            # Formatter 的转换说明符 —— 那是另一套注入面，ENCODE 未必覆盖。
            # 只有确认格式串是字面量，才允许把 ENCODE 当真防护判 False。
            if _FMT_SINK_RE.search(body) and not _value_never_format_string(body):
                return None
            return False
        # 回显的 `bar` 在回显点之前被"确定性覆盖"：容器 get 取到常量、
        # 或恒真分支赋了字面量。这是可逐行核对的事实，不是推演。
        if _last_assignment_untainted(body, "bar"):
            return False
        if _const_branch_overrides(body, "bar") == "lit":
            return False
        if _in_never_run_loop(body, "bar"):
            return False                 # 回显落在一次都不执行的 while 里
        # 回显的 `bar` 来自**别的方法**产出的：本方法里没有任何一处
        # `bar = …`（只有 `String bar = helper(param)` 这种初始化）。
        # 此时"入口体无编码"不等于"链上无编码" —— 编码常常在 helper 里：
        #     String bar = doSomething(request, param);
        #     private static String doSomething(...) {
        #         return StringEscapeUtils.escapeHtml(param);   // 编码在这
        #     }
        # 这正是 OWASP 里 150 余条误报的共同根因，也是"判据扫的范围
        # 先于判据内容"那条铁律的又一例：**范围错了，结论一定是错的**。
        # 只有确认"回显值就是本方法里能追到的那个变量"时，才敢判 True。
        traced = _echo_value_traced_locally(body, "bar")
        if not traced:
            return None
        # `traced is None` 是"请求对象被整个传给了别的方法"这种**弱信号**：
        #     String bar = doSomething(request, param);
        # 输入面成立（request 确实出门了），但回显值是否被加工/转义取决于
        # 那个方法体。OWASP 里 `doSomething` 有的原样返回、有的在内部
        # `escapeHtml` —— 同形态真值相反，规则分不开，只能交模型。
        if traced is None:
            return None
        return True

    # 1b) 反射/存储型，但回显点在**模板文件**里。
    #
    #     这是 Spring MVC 最典型的形态，而 Java 方法体里完全看不到渲染：
    #         model.addAttribute("html", payload);
    #         return "vul/xss/other";        → other.html: th:utext="${html}"
    #
    #     判定支点是模板里的渲染指令本身，两档都能确定：
    #       th:utext / <#noescape> / [[${}]]  → 不转义，输入原样进 DOM → True
    #       只有 th:text / ${} 文本节点        → 框架自动转义        → False
    #     前提是写入端没有先编码（编码了则模板怎么渲染都是文本）。
    if has_param:
        tpl = _template_render(source)
        if tpl:
            if any(unescaped for unescaped in tpl.values()):
                return False if XSS_ENCODE_RE.search(body) else True
            if _TPL_VIEW_LIT_RE.search(body):
                return False           # 命中的键全部走自动转义
            return None                # 键写进了 model，但模板里没找到渲染点

    # 2) 存储型：本方法只写不读，值经介质（cookie/session/request/model）
    #    流到另一个回显点。
    #
    #    **必须要求"确有非 db 的连接"**，不能只看 `reader` 非空：db 介质的
    #    连接描述行同样以 `//` 起头，会让 `reader` 取到内容却没有任何普通
    #    介质连接 —— 于是 (2b) 的 DB 判定被整段跳过，写入方被判 False。
    if reader and _has_plain_chain(source):
        if not _echo_sink_hit(reader):
            return False               # 读取点没有回显，链路不闭合
        if XSS_ENCODE_RE.search(reader):
            return False               # 读取点做了输出编码
        return True

    # 2b) 存储型，介质是数据库：写入方与读取方共用同一个仓储字段。
    #
    #     串接层现在能把"同一 Mapper 字段上的两个路由"配成连接（见
    #     `taint_chain.build_chains` 的 db 分支），于是这里拿到了读取点方法体。
    #     判据与 (2) 一致，但方向不同：(2) 的读取点自己没有外部输入，(2b) 的
    #     读取点通常是列表接口 —— 它有没有参数都不影响结论，值来自库。
    #
    #     仍然不直接判 True 而不看写入端：写入前做了编码（`HtmlUtils.htmlEscape`
    #     再 insert），库里存的已经是转义文本，读取点原样回显也不会执行。
    if has_param and XSS_PERSIST_RE.search(body):
        # 写入前已编码：本方法内即可核对，直接判安全（库里存的就是转义文本）
        if XSS_ENCODE_RE.search(body):
            return False
        # 自己只是"按主键删/按主键取单条"这类操作：没有把外部字符串写进库，
        # 不可能构成存储型 XSS 的写入端。判 None（交模型核对意图），不判 True。
        if _db_writer_takes_value(body):
            readers = _db_render_points(_db_readers(source))
            if readers:
                joined = "\n".join(readers)
                if _db_echo(joined) and not XSS_ENCODE_RE.search(joined):
                    return True
        # 写入端经 Service 转调（`xssService.insertOne(...)` → `xssMapper.insertAll(...)`）：
        # 切片器已经把那层实现体贴进 `// ---- 跨文件证据：insertOne() 的接口实现类
        # 方法体 ----`。读到它，就是可逐行核对的事实 —— 值确实落库了。
        if _repo_write_in_evidence(source):
            readers = _db_render_points(_db_readers(source))
            if readers:
                joined = "\n".join(readers)
                if _db_echo(joined) and not XSS_ENCODE_RE.search(joined):
                    return True
        # 落在这里的两种情况都必须交模型，不能判 False：
        #   a) 有写入、但读取点没把值原样交进响应体（或根本没找到读取点）
        #   b) 本路由只按主键删/查，不写值
        # "看不见读取点"不等于"链不闭合"——读取点在库的另一侧，Java 侧看不到。
        return None

    # 2c) 文件上传介质：上传的文件本身会被浏览器当页面解析。
    #
    #     判据是**用户能否决定落盘扩展名**，这是可核对的事实：
    #       - 走 switch/白名单枚举扩展名 → 攻击面收敛到那几个值，判 False
    #       - 扩展名直接取自 `getOriginalFilename()` 且无枚举 → True
    #     这条与 pathtraver 无关（那条判的是"能不能跳出目录"），
    #     也不与文件类目的其它样本冲突：它只在"上传后返回可访问 URL"时成立。
    if _UPLOAD_SINK_RE.search(body) and XSS_UPLOAD_EXT_RE.search(body):
        if XSS_UPLOAD_EXT_ALLOWED_RE.search(body):
            return None            # 有枚举但要对每个分支逐个核实，交模型
        return True

    # 3) 存储型，介质不在串接建模范围内：写进数据库（Mapper/DAO/Repository）。
    #    跨路由串接只按 cookie/session/request/model 配对，DB 不在其中，所以
    #    `reader` 一定是空的。此时判 False 是错的 —— Hello-Java-Sec 的
    #    `XSS.save`（`xssMapper.add(user, content, date)` + 另一路由 `list()`
    #    未编码回显）就是标准存储型 XSS。看不见读取点不等于不存在。
    #    但如果写入前做了编码（`HtmlUtils.htmlEscape(content)` 再 add），
    #    这在本方法内就是可核对的事实，可以直接判安全。
    if has_param and XSS_PERSIST_RE.search(body):
        return False if XSS_ENCODE_RE.search(body) else None

    # 4) 既无回显也无串接证据 → 本方法确实没有把输入写进响应体。
    #
    #    这里必须返回 False 而不是 None。曾经写成 `False if not has_param else None`，
    #    理由是"有形参但没回显，可能是存储型的写入点，交模型判断" —— 那是错的：
    #    串接索引是全库建好后贴进来的（见 `JavaSlicer._attach_chains`），到这里
    #    还没有证据，说明全库都找不到读取点，链根本不闭合。把 None 漏给模型，
    #    等于让模型对着一个注定无法回答的样本自由裁量，而自由裁量正是抖动来源。
    return False


# 文件落盘 + 返回可按 URL 访问的位置
_UPLOAD_SINK_RE = re.compile(
    r"\.\s*transferTo\s*\(|"
    r"Files\s*\.\s*(?:copy|write|newOutputStream)\s*\(|"
    r"\w*[Uu]til\w*\s*\.\s*upload\w*\s*\(|"
    r"\.\s*store\s*\(", re.I)
# 扩展名由用户决定（取原始文件名、或直接取请求参数当后缀）
XSS_UPLOAD_EXT_RE = re.compile(
    r"getOriginalFilename\s*\(\s*\)|"
    r"getExtension\s*\(|"
    r"getName\s*\(\s*\)\s*\.\s*(?:split|substring)|"
    r"request\s*\.\s*getParameter\s*\(\s*\"(?:type|suffix|ext)", re.I)
# 扩展名走了白名单枚举（switch 分支 / 集合 contains）
XSS_UPLOAD_EXT_ALLOWED_RE = re.compile(
    r"switch\s*\(\s*\w*(?:type|suffix|ext)\w*\s*\)|"
    r"\b(?:allowed|whitelist|whiteList|ALLOWED|exts|suffixes)\w*\s*\.\s*contains\s*\(", re.I)


# 持久层写入：仓库类调用的通用形态（MyBatis Mapper / DAO / JPA Repository）。
# 不写成 `\.add(` —— 那会把 `sb.append` 之外的 `list.add(x)` 也卷进来。
#
# 补上 Service 层：`xssService.insertOne(payload, ua)`。Service 方法名不一定
# 带 save/add/insert（也可以是 `insertOne` / `store` / `persistXxx`），
# 只看动词会漏；判据落在"接收者是不是仓储字段"上，字段命名更有规律
# （与 `taint_chain._REPO_FIELD_RE` 保持同一套后缀）。
XSS_PERSIST_RE = re.compile(
    r"\b\w*(?:Mapper|Dao|DAO|Repository|Service)\s*\.\s*\w+\s*\(", re.I)



# ---------------- redir（开放重定向） ----------------
#
# 判定支点只有两个客观事实，都不需要模型理解语义：
#
#   1) 走的是哪种"跳转"API。只有会向客户端下发 Location 的才算 open redirect：
#        response.sendRedirect(url)            302，下发 Location   → 是
#        response.setHeader("Location", url)   301/302，下发 Location → 是
#        return "redirect:" + url              Spring 视图前缀     → 是
#        request.getRequestDispatcher(url).forward(...)
#                                              服务端内部转发，客户端地址栏不变，
#                                              **不产生任何重定向响应** → 不是
#      java-sec-code 的 URLRedirect.forward 就是最后一种。作者注释写明
#      「can only jump according to the path」，模型看到"路径可控"就判漏洞，
#      是典型的把「输入可控」当成「漏洞成立」。和 AES vs DES 同构：
#      这里的事实是"选了哪个 API"，完全可以规则判定。
#
#   2) 目标 URL 有没有经过白名单校验（SecurityUtil.checkURL 等）。
#
# 顺序上必须先判 1)：forward 型不管 url 怎么脏都不是 open redirect，
# 先判白名单会把 forward 误当成"有漏洞但恰好被拦了"。

REDIR_LOCATION_SINK_RE = re.compile(
    r"\.\s*sendRedirect\s*\(|"
    r"\.\s*setHeader\s*\(\s*\"[Ll]ocation\"|"
    r"\.\s*addHeader\s*\(\s*\"[Ll]ocation\"|"
    r"\.\s*setStatus\s*\(\s*(?:301|302|303|307|308)\s*\)|"
    r"\.\s*sendError\s*\(\s*302|"
    # Spring MVC 的两种视图型跳转：`new ModelAndView("redirect:" + url)` 与
    # `new RedirectView(url)` 都会向客户端下发 302，与 sendRedirect 等价。
    # 只认 `return "redirect:` 字面量会漏掉它们（Hello-Java-Sec 的
    # Redirect.vul2 就是 `return new ModelAndView("redirect://" + url)`）。
    r"new\s+(?:[\w.]*\.)?ModelAndView\s*\(\s*\"redirect\s*:|"
    r"new\s+(?:[\w.]*\.)?RedirectView\s*\(|"
    r"return\s+\"redirect\s*:", re.I)
# 服务端内部转发：不构成 open redirect
REDIR_FORWARD_ONLY_RE = re.compile(
    r"getRequestDispatcher\s*\([^)]*\)\s*\.\s*forward\s*\(|"
    r"RequestDispatcher\s+\w+\s*=", re.I)
# 白名单 / 同源校验
REDIR_WHITELIST_RE = re.compile(
    r"checkURL\s*\(|checkRedirect\s*\(|isValidRedirect\s*\(|"
    r"isAllowedRedirect\s*\(|allowedRedirect|"
    r"\.\s*startsWith\s*\(\s*\"/\"\s*\)|"          # 只允许站内相对路径
    r"\.\s*matches\s*\(", re.I)
# 目标地址是编译期常量：整个实参就是一对双引号，没有任何变量拼接。
#   return "redirect:/index"                  → 常量
#   return "redirect:" + url                  → 非常量（有 + 号）
#   response.sendRedirect("/fixed/page")      → 常量
REDIR_CONST_TARGET_RE = re.compile(
    r"return\s+\"redirect:[^\"$]{0,200}\"\s*;|"
    r"(?:sendRedirect|sendError)\s*\(\s*\"[^\"]*\"\s*\)|"
    r"(?:setHeader|addHeader)\s*\(\s*\"[Ll]ocation\"\s*,\s*\"[^\"]*\"\s*\)", re.I)


def redir_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None

    has_location = bool(REDIR_LOCATION_SINK_RE.search(body))
    has_forward = bool(REDIR_FORWARD_ONLY_RE.search(body))

    # 只有 forward，没有任何下发 Location 的动作 → 不是开放重定向
    if has_forward and not has_location:
        return False
    if not has_location:
        # 入口体里既没有下发 Location 的 API，也没有任何**名字像跳转**的调用
        # （redirect / location / forward / dispatch 都没出现），
        # 那它就不是本类目的判定对象，判"无此漏洞"。
        #
        # 为什么要额外查名字：跳转可能被封装进 helper（`RedirectUtil.go(url)`），
        # 此时方法体里看不到 sink。只要出现了疑似跳转的标识符，就退回模型 ——
        # 沉默（看不到 sink）不等于确认（没有跳转），这条和框架装配同源。
        if re.search(r"(?:redirect|location|forward|dispatch)", body, re.I):
            return None
        return False

    # 目标地址是编译期常量（`return "redirect:/index"`）→ 没有可控输入，不是漏洞。
    # 这里必须放在拼接判断之前：常量字符串既"命中了 redirect: 前缀"又"没有拼接"，
    # 单看 sink 命中会直接判成为真。
    if REDIR_CONST_TARGET_RE.search(body):
        return False

    # 有 Location 下发，且经过白名单 → 安全
    if REDIR_WHITELIST_RE.search(body):
        return False
    return True


# ---------------- ssrf ----------------
#
# 判定支点：请求由外部 URL 发起时，有没有在 **socket 层**对目标地址做校验。
#
# 为什么不能只看"有没有出现 URL / IP 白名单字面量"：
# SSRF 的绕过面太大（十进制 IP、DNS 重绑定、302 跳转、IPv6 映射、file:// 等），
# 字符串级校验看不出来是否充分。java-sec-code 的写法给出了唯一可靠的判据 ——
# 作者把校验实现在 `SecurityUtil.startSSRFHook()`，它挂的是
# `InetAddress` 层的钩子，所有 HTTP 客户端（URLConnection / HttpClient /
# okhttp / Jsoup / hutool / RestTemplate / ImageIO）都绕不过去。
#
# 实测该项目 16 条 ssrf 样本：hook 字段与真值 15/16 吻合，
# 唯一例外 SSRF.openStream 本身就是靶场标注有争议的一条（方法体无任何校验，
# 路由也不含 vuln/sec，真值来源与其他 15 条不同），且不在可判定样本内。
#
# 因此判据只有两条客观事实，与"用了哪个 HTTP 客户端"无关：
#   1) 本方法是否出现 SSRF hook 的启用
#   2) 是否只允许 http/https 协议（阻断 file:// 这条最常被利用的通道）
#
# 顺序：先看 hook（决定性），再看协议限制（仅当 hook 缺失时作为补充证据）。

SSRF_HOOK_RE = re.compile(
    r"startSSRFHook\s*\(|enableSSRFCheck\s*\(|SSRFProtect\w*\s*\.\s*enable|"
    r"installSSRF\w*\s*\(", re.I)
SSRF_SCHEME_RE = re.compile(
    r"SecurityUtil\s*\.\s*isHttp\s*\(|"
    r"\.\s*startsWith\s*\(\s*\"https?://[^\"]+\"|"      # 限定具体前缀，不能是裸协议名
    r"(?:URI|URL)\s*\.\s*getProtocol\s*\(\s*\)\s*\.\s*equalsIgnoreCase\s*\(", re.I)
# 裸协议前缀 `startsWith("http")` / `startsWith("https://")`：
#   "http" / "https" 只说明协议，`http://127.0.0.1` 照样通过 → 挡不住内网 SSRF
#   但 "https://example.com/" 这种带主机的前缀确实限定了目标 → 算有效防护
# 单独识别"形似校验、实则无效"的写法，避免把它当成安全证据。
SSRF_WEAK_SCHEME_RE = re.compile(
    r"\.\s*startsWith\s*\(\s*\"https?(:?//)?\"", re.I)
# 有外部 URL 参与请求发起 —— 没有这一条就不是本类目的判定对象。
#
# 最后一类是必须的：java-sec-code 的真实请求几乎都封装在
# `HttpUtils.URLConnection(url)` / `httpService.RequestHttp(url, headers)`
# 这样的工具/服务方法里，方法体只有一行转发。只匹配 `openConnection` 这类
# 底层 API 会把 16 条样本里的绝大部分判成"不是本类目对象"。
# 判据退一步用「把 URL 变量作为实参传给一个 Http* / *Service 方法」——
# 这个形态在 ssrf 语境下足够特异（传 URL 给方法，且方法名带 Http 语义）。
SSRF_SINK_RE = re.compile(
    r"\.\s*openConnection\s*\(|\.\s*openStream\s*\(|new\s+URL\s*\(|"
    r"\.\s*execute\s*\(\s*(?:new\s+)?Http\w*|\.\s*execute\s*\(\s*url|"
    r"HttpUtil\s*\.\s*(?:get|post|createGet|createPost)\s*\(|"
    r"Jsoup\s*\.\s*connect\s*\(|"
    r"restTemplate\s*\.\s*(?:getForObject|getForEntity|exchange|postForObject)\s*\(|"
    r"IOUtils\s*\.\s*(?:toByteArray|copy)\s*\(\s*(?:new\s+)?URL|"
    # 把 url 变量交给 Http* / *Service / *Utils 方法去发请求
    r"\b\w*(?:Http|http|Service|Utils|Request)\w*\s*\.\s*\w+\s*\(\s*\w*url\w*", re.I)

# ---------------- 弱 sink：同一个方法名在不同上下文里含义相反 ----------------
#
#   ImageIO.read(x)   —— x 是 URL 才是 SSRF；x 是 File / InputStream 就是本地读图
#   .getInputStream() —— 接在 openConnection()/URL 后面才是网络请求；
#                        接在 MultipartFile 后面是读上传的文件
#
# 旧版把这两个直接写进 `SSRF_SINK_RE`（为 java-sec-code 的
# `URL u = new URL(url); ImageIO.read(u);` 加的），于是**任何文件上传接口**
# 都会被判成 SSRF。newbee-mall 实测：`/admin/upload/file` 与 `/admin/upload/files`
# 两条完全本地的图片上传被判 True —— 这是真实项目上才暴露的跨项目误报，
# 靶场永远测不出来（靶场里没人写上传）。
#
# 修法不是删 sink，而是要求"弱 sink 必须带 URL 旁证"：方法体里出现过
# `new URL(` / `openConnection()` / `URL` 变量声明，才认为这个 read 是网络读取。
# 这与记忆里"先看接收者，再看实参"是同一条：`ImageIO.read(...)` 离了 URL
# 什么都不是。
SSRF_WEAK_SINK_RE = re.compile(
    r"ImageIO\s*\.\s*read\s*\(|\.\s*getInputStream\s*\(\s*\)")
SSRF_URL_EVIDENCE_RE = re.compile(
    r"new\s+URL\s*\(|\.\s*openConnection\s*\(\s*\)|"
    r"\b(?:Http)?URLConnection\b|\bURL\s+[A-Za-z_]\w*\s*=")


def _ssrf_sink_hit(body: str) -> bool:
    """本方法体里有没有**够格**的 SSRF sink（弱 sink 需带 URL 旁证）。"""
    if SSRF_SINK_RE.search(body):
        return True
    return bool(SSRF_WEAK_SINK_RE.search(body)
                and SSRF_URL_EVIDENCE_RE.search(body))


# Apache HttpClient 4.x 的**变量形态**：`HttpGet req = new HttpGet(url); client.execute(req);`
# 上面 `SSRF_SINK_RE` 的 `\.\s*execute\s*\(\s*(?:new\s+)?Http\w*` 只认内联写法
# `client.execute(new HttpGet(url))`。真实代码几乎都先声明变量，实参是小写
# 变量名，一个字符都对不上 —— 整条落到"不是本类目对象 → None"。
# micro_service_seclab 的 `/ssrf/four`（DefaultHttpClient）就是这样。
_HTTPCLIENT_REQ_RE = re.compile(
    r"new\s+Http(?:Get|Post|Put|Delete|Head|Patch|RequestBase)\s*\(\s*([^)]*)\)")


def _httpclient_sink_hit(body: str) -> bool:
    """是否存在「用外部值构造 HttpClient 请求并执行」的形态。

    只认构造实参**不是字面量**的写法：`new HttpGet("http://fixed/")` 目标
    写死在代码里，不是本类目的判定对象。这里不判防护，只判"有没有发起请求"。
    """
    if not re.search(r"\.\s*execute\s*\(", body):
        return False
    for m in _HTTPCLIENT_REQ_RE.finditer(body):
        arg = m.group(1).strip()
        if not arg or arg.startswith('"'):
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", arg):
            return True
        if re.search(r"[A-Za-z_]\w*", _STR_LIT_RE.sub(" ", arg)):
            return True
    return False


def ssrf_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    if not _ssrf_sink_hit(body) and not _httpclient_sink_hit(body):
        return None

    if SSRF_HOOK_RE.search(body):
        return False                   # socket 层校验已挂上
    if SSRF_SCHEME_RE.search(body):
        return False                   # 限定了具体协议+主机，或调用了专用校验

    # 只写了裸协议名的 startsWith：形似校验但挡不住内网地址，算裸漏洞
    if SSRF_WEAK_SCHEME_RE.search(body) and not SSRF_SCHEME_RE.search(body):
        return True

    # 关键：出现了**我们不认识的**校验调用时，不能直接判漏洞。
    #
    # 早期版本这里直接 return True，在 java-sec-code 上 16/16 全对，
    # 但那是因为这个靶场只用 startSSRFHook 一种写法。真实项目各有各的
    # `UrlValidator` / `checkInternalIp` / 黑白名单，名字我们不可能穷举；
    # 一味判 True 就是"没见过的一律算漏洞"，换项目必然误报爆炸。
    #
    # 判断依据：入口里出现了针对 url 的校验性调用，且我们没识别出它的性质。
    # 这类样本退回 None，交给模型结合跨文件证据判断 —— 但**先自己去看一眼**
    # 实现体在不在切片里（见 `_ssrf_helper_nature`）。
    if _has_unknown_url_guard(body):
        nat = _ssrf_helper_nature(body, _sibling_methods(source))
        if nat is not None:
            return nat
        return None
    return True


# SSRF 的黑白名单之争，在实现体里有**语法级**的区别，不需要语义推断：
#
#   白名单（值集合）      `url_list.contains(host)` / `WHITE.contains(domain)`
#                        → 把 host 拿去和一组字符串比对，不在集合里就拒
#   黑名单（文本形态）    `Pattern.compile("^(127\\.0\\.0\\.1)|(localhost)|...")`
#                        `matcher.find()` / `matches()`
#                        → 拦的是"像内网地址的字符串"，可被 0x7f.1 / 十进制 IP /
#                          短域名 / DNS 重绑定绕过（Hello-Java-Sec 的
#                          `URLConnection2` 与 `URLConnection3` 就是这对样本）
#
# 判据因此很干脆：读到的实现里**有没有一份字符串集合 + contains/indexOf**。
# 有 → 值级白名单 → safe。只有正则匹配 → 黑名单 → vuln（这条能判 True，
# 与 cmdi/pathtraver 不同：那边"够不够严"是开放问题；这边**正则匹配 IP 段
# 必然可绕**是有确定答案的，靶场也给出了 vul/safe 对照样本）。
_SSRF_HELPER_ALLOW_RE = re.compile(
    r"\b\w*(?:list|set|map|white|allow|permit|domain|hosts?|urls?|trusted)\w*"
    r"\s*\.\s*(?:contains|indexOf)\s*\(\s*\w+\s*\)|"
    r"\.\s*add\s*\(\s*\"[^\"]+\"\s*\)\s*;?", re.I)
_SSRF_HELPER_DENY_RE = re.compile(
    r"Pattern\s*\.\s*compile\s*\(|"
    r"\.\s*matcher\s*\(|"
    r"\.\s*matches\s*\(\s*\"[^\"]*[\\(\[\|]", re.I)
# 只限定协议的方法（isHttp）不是 SSRF 防护，读到时不能当成白名单证据
_SSRF_PROTOCOL_ONLY_RE = re.compile(
    r"startsWith\s*\(\s*\"https?(:?//)?\"|getProtocol\s*\(\s*\)\s*\.\s*equals", re.I)


def _ssrf_helper_nature(body: str, sib: str) -> bool | None:
    """入口调了认不出的 URL 校验，去辅助段读实现体判性质。

    返回 False=safe（值级域名白名单）、None=规则不该下结论。

    **不敢返回 True**，和 `_helper_guard_nature()` 同理，虽然理由不同：

    我一度认为"用正则匹配 IP 段拦内网一定可绕"是确定命题，据此判 True。
    Hello-Java-Sec 立刻给出反例 —— 同一个 `Security.isIntranet(ip)`：

        URLConnection2      if (isIntranet(urltoIp(url)))  → 真值 vul（标"绕过"）
        HTTPURLConnection   ip = urltoIp(url); if (isIntranet(ip)) → 真值 safe

    两条调的是同一个函数、同一个参数来源，只是内联还是先赋中间变量，
    作者一处标 vul 一处标 safe。这说明真值口径本身不是"这个校验够不够严"，
    还掺了别的因素（样本想演示的是不同客户端/不同绕过姿势）。

    规则手里能核对的只有"拦的是值集合还是正则"，而这个事实**不足以**
    区分上面两条。那就只能是 None —— 拿到一个不能推出结论的事实，
    不能当成结论用（第 5 条）。

    能确认的只剩白名单：拦截的是 host 字符串集合（`list.contains(host)`），
    不在集合里直接拒 —— 这是"值的集合"，攻击者构造不出集合外的合法 host。
    """
    if not sib:
        return None
    names = {n for n in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body)
             if n not in {"if", "else", "while", "return", "new", "catch"}}
    if not names:
        return None
    hit_allow = False
    for name in names:
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*\([^)]*\)\s*\{", sib):
            depth, end = 1, len(sib)
            for i in range(m.end(), len(sib)):
                if sib[i] == "{":
                    depth += 1
                elif sib[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            impl = sib[m.end(): end]
            if _SSRF_HELPER_ALLOW_RE.search(impl) and \
                    not _SSRF_HELPER_DENY_RE.search(impl):
                hit_allow = True
    return False if hit_allow else None


# 可能承载"URL 合法性校验"的调用形态。命中即认为存在未识别的防护。
# 判据刻意宽：宁可多退回模型，也不要在不认识的代码上武断判漏洞。
_URL_GUARD_HINT_RE = re.compile(
    r"\b(?:if|while)\s*\([^)]*\b\w*url\w*\b[^)]*\)|"          # if (url ...) / if (!check(url))
    r"\b\w*(?:valid|check|verify|allow|safe|filter|whitelist|blacklist|"
    r"isInternal|isPrivate|isLocal|isHttp|isValid|deny|forbid|restrict)\w*\s*\(",
    re.I)


def _has_unknown_url_guard(body: str) -> bool:
    """入口里出现了针对 url 的校验性调用，且不是我们认识的那几种写法。"""
    for m in _URL_GUARD_HINT_RE.finditer(body):
        seg = m.group(0)
        if SSRF_HOOK_RE.search(seg) or SSRF_SCHEME_RE.search(seg):
            continue
        return True
    return False


# ---------------- cmdi（命令注入） ----------------
#
# 判据只有两个支点，都不需要语义推断：
#   1) 有没有把可控值送进"能执行命令"的 API
#   2) 送进去的值是否被**白名单枚举**限死
#
# 关键区分（这决定规则能不能上真实项目）：
#   `Security.checkOs(cmd)` 返回 `contains("|") || contains(";") || ...` 时，
#   Controller 里写的是 `if (!Security.checkOs(filepath)) { 执行 }`，
#   看起来"不通过就拦住了"，可函数名是 checkXxx、调用形态和真正的白名单
#   一模一样。这类**黑名单**天然可绕（换行、$()、反引号），不是防护。
#   所以判据必须看"拦住的是不是**值的集合**"，而不是"有没有调用校验函数"。
#
# 另有两个"无注入面"的可核对事实：
#   - 实参是纯字符串常量（无变量、无拼接）→ 攻击者影响不到命令
#   - 形参是整型 → 绑定阶段就被解析成数字，字符串拼接无从发生
CMDI_SINK_RE = re.compile(
    r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|"
    r"\bnew\s+(?:ProcessBuilder|Invoker)\s*\(|"
    r"\.\s*command\s*\(|"
    r"\.\s*load(?:Library)?\s*\(|"
    r"ProcessImpl\s*\.\s*start\s*\(|"
    r"\bmethod\s*\.\s*invoke\s*\(|"
    r"ProcessUtils|CommandLine\s*\.\s*parse", re.I)
# 形参级白名单：`if (!commands.contains(command)) return/throw;`
# 与 spel 的判据同构 —— 拒绝路径才是防护，允许路径不是。
#
# 正则细节（踩过）：`[\w.]+` 是**贪婪**的，会把 `commands` 整串吃掉，
# 后面的 `(?:white|safe|...|command)` 就无从匹配 —— 变量名本身就带关键字时
# 反而永远匹配不上。必须写成「关键字可出现在标识符任意位置」的形态：
#   标识符 = \w* KEY \w*      且整体不跨 `.`（点号是成员访问，不是名字的一部分）
_IDENT_WITH = r"\b\w*{kw}\w*\b"
_CMDI_WL_KEY = r"(?:white|safe|allow|permit|legal|valid|command|list|set|dic|map|pool|range)"

CMDI_WHITELIST_RE = re.compile(
    # if (!commands.contains(command))
    r"if\s*\(\s*!\s*" + _IDENT_WITH.format(kw=_CMDI_WL_KEY) + r"\s*\.\s*contains\s*\(|"
    # if (commands.contains(command) == false)
    r"if\s*\(\s*" + _IDENT_WITH.format(kw=_CMDI_WL_KEY) + r"\s*\.\s*"
    r"contains\s*\([^)]*\)\s*==\s*false|"
    # if (WHITE_LIST.indexOf(cmd) < 0)  /  if (safeList.indexOf(cmd) == -1)
    r"if\s*\(\s*" + _IDENT_WITH.format(kw=_CMDI_WL_KEY) + r"\s*\.\s*"
    r"indexOf\s*\([^)]*\)\s*(?:<|==)\s*0\s*\)|"
    # cmd.matches("ls|pwd|cat")：正则本身就是全串匹配的全集白名单
    r"\.\s*(?:matches|equalsIgnoreCase)\s*\(\s*\"[\w|\-. ]+\"\s*\)", re.I)
# 值的枚举定义（`commands.add("ls")` / `Arrays.asList("ls","pwd")`）
CMDI_ENUM_RE = re.compile(
    r"\b\w*(?:white|safe|allow|permit|legal|valid|command|list|set)\w*\s*\.\s*"
    r"(?:add|put|of)\s*\(\s*\"|"
    r"\b[A-Za-z_]\w*\s*=\s*\"[\w\-.]+\"\s*;\s*\n\s*[A-Za-z_]\w*\s*\.\s*add\s*\(|"
    r"Arrays\s*\.\s*asList\s*\(\s*\"", re.I)
# 拼接/传参形态：`exec("ls -l " + x)` 或 `exec(x)`
_CONCAT_HINT_RE = re.compile(r"\"[^\"]*\"\s*\+|\+\s*[A-Za-z_]\w*")


def _param_types(sig: str) -> dict[str, str]:
    """从签名里取 {形参名: 类型}，用于判"数字类型无注入面"。"""
    out: dict[str, str] = {}
    sig = re.sub(r"@\w+\s*(?:\([^)]*\))?", " ", sig)
    for typ, name in _PARAM_SEG_RE.findall(sig):
        out[name] = typ
    return out


def _first_arg(call: str) -> str:
    """从 `名字(...)` 里取出第一个实参（括号平衡），取不到就返回空串。

    直接 `call[call.find("(") + 1:]` 会把后面的 `));\\n return;\\n}` 一起带上，
    导致"实参里有没有字母"的判定被返回值/后续语句污染。
    """
    args = _all_args(call)
    return args[0] if args else ""


def _all_args(call: str) -> list[str]:
    """从 `名字(...)` 里取出**全部**顶层实参（括号平衡、逗号分割）。

    为什么不能只用第一个：`method.invoke(null, new String[]{payload}, ...)`、
    `ProcessBuilder(Arrays.asList("sh","-c", cmd))` 这类调用，污点在第 2 个
    实参甚至嵌套数组里。只看第一个会把 `null` 当成"实参是常量"，
    于是反序列化/反射执行这条真漏洞被判成安全（JavaSecLab 的 vul3 实测）。

    起点必须是**最后一个** `名字` 后面的 `(`，因为正则可能从链式调用的
    开头开始匹配：`Runtime.getRuntime().exec("/bin/ping")` 的第一个 `(` 属于
    `getRuntime()`，从那里切会把整个调用当成空实参。
    """
    # 取最后一个 `标识符(` 的位置
    last = None
    for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", call):
        last = m
    i = last.end() - 1 if last else call.find("(")
    if i < 0:
        return []
    out: list[str] = []
    depth, start = 1, i + 1
    for j in range(start, len(call)):
        ch = call[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(call[start:j])
                return [a for a in out if a.strip()]
        elif ch == "," and depth == 1:
            out.append(call[start:j])
            start = j + 1
    out.append(call[start:start + 200])
    return [a for a in out if a.strip()]


def _args_all_numeric(args: str, types: dict[str, str]) -> bool:
    """实参全是整型形参/数字字面量 → 绑定阶段就已定型，不可能拼接出语法。

    必须剥掉「把数字转成字符串」的转换调用再取标识符，否则
    `exec(Integer.toString(n))` 会把 `Integer`/`toString` 当成两个未知变量，
    判成"有注入面"。转换函数本身不引入可控字符，不是污点来源。
    """
    if not args or not args.strip():
        return False
    # 剥掉数字→字符串的转换包装（保留里面的表达式）
    txt = args
    for _ in range(3):  # 允许一层套一层
        new = re.sub(r"\b(?:Integer|Long|Short|Byte|String|Objects)\s*\.\s*"
                     r"(?:toString|valueOf|toHexString)\s*\(([^()]*)\)", r" \1 ", txt)
        if new == txt:
            break
        txt = new
    # 再剥掉 new String(...) / String.format(...) 这类不改字符集的包装
    txt = re.sub(r"\bnew\s+String\s*\(([^()]*)\)", r" \1 ", txt)
    idents = re.findall(r"\b[A-Za-z_]\w*\b", txt)
    if not idents:
        return bool(re.fullmatch(r"[\s\d+\-*/()\.,]+", txt))
    return all(types.get(i) in _NUMERIC_TYPE_SET for i in idents)


_NUMERIC_TYPE_SET = {"int", "Integer", "long", "Long", "short", "Short",
                     "byte", "Byte", "BigInteger", "BigDecimal"}


def cmdi_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    m = CMDI_SINK_RE.search(body)
    if not m:
        return None

    # 1) 数字类型形参：exec(n) / load(id) 都没有注入面
    #    看**全部**实参而不是第一个 —— `method.invoke(null, new String[]{payload})`
    #    的污点在第 2 个实参上，只看第一个会把 `null` 当成"实参是常量"。
    types = _param_types(_entry_signature(body))
    call = body[m.start(): m.start() + 400]
    arg_list = _all_args(call)
    arg_text = ",".join(arg_list)
    if arg_list and all(_args_all_numeric(a, types) for a in arg_list) and \
            not re.search(r"\"[^\"]*\"\s*\+", arg_text):
        return False

    # 2) 实参是纯常量（没有 + 拼接、没有任何变量）→ 命令固定，不是注入
    #    判"有没有变量"必须先剥掉字符串字面量：`"/bin/ping -c1 127.0.0.1"`
    #    里面的 `bin`/`ping`/`c1` 会被 `[A-Za-z_]\w*` 当成三个变量，
    #    于是常量命令判不出安全（实测把冒烟 [19] 的"常量命令"打回 True）。
    def _has_var_arg(a: str) -> bool:
        stripped = _STR_LIT_RE.sub(" ", a)
        for tok in re.findall(r"[A-Za-z_]\w*", stripped):
            if tok in ("null", "true", "false"):
                continue
            return True
        return False

    if arg_list and not any(_has_var_arg(a) for a in arg_list) \
            and not _CONCAT_HINT_RE.search(call) and not re.search(
                r"exec\s*\(\s*[A-Za-z_]\w*\s*\)", body):
        if re.search(r"exec\s*\(\s*\"[^\"]*\"\s*\)|"
                     r"load\s*\(\s*\"[^\"]*\"\s*\)", body):
            return False

    # 3) 值级白名单 + 阻断
    #    枚举定义可能在**跨文件辅助段**里（`SecurityUtil.checkOs` 的
    #    whitelist 定义），所以两处都要看。只看入口体会把真白名单判成"未知防护"。
    sib = _sibling_methods(source)
    if _guard_blocks(body, CMDI_WHITELIST_RE) and \
            (CMDI_ENUM_RE.search(body) or CMDI_ENUM_RE.search(sib)):
        return False
    # 3b) 入口体里没有可识别的白名单形态，但调了一个 checkXxx，
    #     而它的实现体就在辅助段里且是值级白名单 —— 同样构成防护。
    #     （`if (!SecurityUtil.isAllowed(cmd))` 这种名字不带 command/list，
    #      第 3 步的正则匹配不到，只有读到实现体才知道它拦的是值的集合。）
    #     注意：这里**只采纳 False**。读到黑名单不代表一定可绕，见
    #     `_helper_guard_nature()` 的 docstring。
    if sib and _helper_guard_nature(body, sib) is False:
        return False

    # 4) 有校验调用但我们认不出的性质 —— 退回模型（黑名单 vs 白名单分不清）
    if _has_unknown_input_guard(body):
        return None
    if _guard_blocks(body, CMDI_WHITELIST_RE):
        # 白名单形态但没看到枚举定义（可能在跨文件段），仍按防护计
        return False
    return True


# 辅助方法体里出现这些 → 拦截的是"值的集合"，是真白名单
# 注意：`X.contains(s)` 与 `content.contains(s)` 长得一样，区别只在**接收者**
# 是不是一个枚举容器。只看 `.contains(\w+)` 会把
#   for (String s : black_list) { if (content.contains(s)) ...
# 这种黑名单循环判成白名单（实测：checkOs 被误判）。所以：
#   黑名单判据优先（`contains("字面量")` / 遍历黑名单数组）
#   白名单判据要求接收者看起来是容器名（list/set/map/白名单…）或显式枚举
#
# `switch(x)` 曾经也算白名单证据 —— **删掉了**。它只要出现在文件任何地方
# 就命中，而同文件里往往并排放着别的路由方法（`switch(actionCode)` 之类），
# 于是"当前入口调的命令执行"被判成"有白名单"。这类污染产出的是 False，
# 也就是把真漏洞静默放过，比误报危险。要认 switch 就必须确认它包着
# **被校验的那个变量**，而那需要类型推断，规则手里没有。
_HELPER_ALLOW_RE = re.compile(
    r"\b\w*(?:white|allow|permit|legal|valid|safe|list|set|map|pool|range|"
    r"commands?|allowed)\w*\s*\.\s*(?:contains|indexOf)\s*\(\s*\w+\s*\)", re.I)
# **字符集正则也是"值的集合"**，只是写法不同：
#
#     private static final Pattern FILTER_PATTERN =
#             Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
#     public static String cmdFilter(String input) {
#         if (!FILTER_PATTERN.matcher(input).matches()) return null;
#         return input;
#     }
#
# `Matcher.matches()` 是**全串**匹配（不是 find），配上一个
# `^...+$` 的字符集枚举，等价于"这个串的每个字符都必须在集合里" ——
# 和 `whitelist.contains(cmd)` 拦的是同一件事，只是粒度从"整值"降到"逐字符"。
# 空格、`;`、`|`、`&` 全部拒绝，命令拼接无从下手。
#
# 判据必须同时要求三件事，缺一不可：
#   ① `.matches(` 是**无参**调用（`matcher(x).matches()`），不是
#      `x.matches("regex")` —— 后者是另一种形态，先不管；
#   ② 能找到 `Pattern.compile("…")` 且模式是**锚定**的（`^` 开头或 `$` 结尾）；
#   ③ 模式主体只由字符集/量词构成，**不含 `.` 通配以外的"任意"**，
#      也不能含 `|` —— 有 `|` 就说明是"几个片段之一"，那退化成片段黑名单。
# ①②③ 都满足才认。少一条就不认（返回 None），不猜。
_ANCHORED_REGEX_ALLOW_RE = re.compile(
    r"Pattern\s*\.\s*compile\s*\(\s*\"(?P<pat>[^\"]+)\"\s*\)")
_MATCHES_NOPARAM_RE = re.compile(r"\.\s*matches\s*\(\s*\)")
# 出现这些 → 拦截的是"字符/片段"（黑名单），天然可绕
_HELPER_DENY_RE = re.compile(
    r"\.\s*contains\s*\(\s*\"|"                       # content.contains("|")
    r"\.\s*indexOf\s*\(\s*\"|"                        # content.indexOf("..")
    r"\bblack_?list\b|\bdeny_?list\b|\bblackList\b|"   # 变量就叫黑名单
    r"\.\s*matches\s*\(\s*\"[^\"]*[\[\]\.\*\+\?]", re.I)

# 黑名单前置了「解码 / 规范化 / 归一化」——作者意识到编码绕过并做了还原。
# 这类实现到底够不够（解码一次还是循环解码、Unicode 变体、大小写…）
# 没有可以逐行核对的事实支点，规则不应替模型下结论。
_DECODE_BEFORE_CHECK_RE = re.compile(
    r"URLDecoder\s*\.\s*decode|"
    r"URLEncoder\s*\.\s*decode|"
    r"\.\s*normalize\s*\(\s*\)|"
    r"getCanonicalPath\s*\(\s*\)|"
    r"while\s*\([^)]*indexOf\s*\(\s*'%'\s*\)", re.I)


def _named_method_bodies(sib: str, names: set[str]) -> list[tuple[str, str]]:
    """在证据段里只截出**名字命中**的方法体，返回 [(方法名, 方法体)]。

    为什么必须截：`sib` 是整个 `// ----` 之后的内容 —— 同文件辅助方法整块、
    跨文件实现体、装配证据全在里面。原来 `_helper_guard_nature` 对每个候选
    名字在整段 `sib` 上做正则，等于"在这个 Controller 里所有非路由方法 +
    所有跨文件证据中找白名单"。两个后果都真实出现过：

      - `CommandController.vul3` 的 `switch(actionCode)` 落在同文件另一个路由
        方法里，被当成"当前入口做了枚举校验"，**真漏洞被静默判 safe**；
      - 只要同一个类里有任何一个别的私有方法写了 `ALLOWED.contains(x)`，
        当前入口就会被判 safe —— 而它可能压根没调过那个方法。

    正确做法就是这里的做法：先确定"入口实际调了哪些名字"，再只取这些名字
    的实现体。判断范围先于判断内容（记忆第 30 条）。
    """
    out: list[tuple[str, str]] = []
    for name in sorted(names):
        # 必须允许 throws 子句：OWASP 的 helper 签名是
        #     public String doSomething(HttpServletRequest request, String param)
        #             throws ServletException, IOException {
        # 少这一段，`\s*\{` 匹配不到，helper 一个都截不出来 —— 症状是
        # 规则"读不到实现体"，然后一路退回模型，不报错。
        for m in re.finditer(
                r"\b" + re.escape(name) + r"\s*\([^)]*\)\s*(?:throws[^{]*)?\{", sib):
            depth, end = 1, len(sib)
            for i in range(m.end(), len(sib)):
                if sib[i] == "{":
                    depth += 1
                elif sib[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            out.append((name, sib[m.end():end]))
    return out


def _is_anchored_charset_guard(impl: str, sib: str) -> bool:
    """实现体是不是"锚定字符集正则 + matches() 全串匹配"这种白名单。

    形态（java-sec-code `SecurityUtil.cmdFilter`）：

        Pattern.compile("^[a-zA-Z0-9_/\\.-]+$")   ← 类字段，不一定在 impl 里
        if (!FILTER_PATTERN.matcher(input).matches()) return null;   ← 在 impl 里
        return input;

    为什么算白名单：`matches()` 是全串匹配，配上 `^…+$` 的字符集，等价于
    "每个字符都必须在集合内"。空格 / `;` / `|` / `&` / `$` 全被拒绝，
    `"ls -la " + input` 这种拼接没有注入面。

    为什么不干脆认所有 `.matcher(`：`Pattern.compile(".*")`、
    `Pattern.compile("[abc]")`（未锚定 = `find` 语义）、
    `Pattern.compile("cat|dog")`（片段之一）全都拦不住注入。
    只认**锚定 + 纯字符集**，其余不表态。
    """
    if not _MATCHES_NOPARAM_RE.search(impl):
        return False
    for m in _ANCHORED_REGEX_ALLOW_RE.finditer(sib):
        pat = m.group("pat")
        anchored = pat.startswith("^") or pat.endswith("$")
        if not anchored:
            continue
        # 有 `|` → 是"几个片段之一"，不是字符集枚举
        if "|" in pat:
            continue
        # 主体必须只剩字符类 `[...]`、量词、锚点、转义。
        # 出现裸字母（除转义外）说明它匹配的是**具体字符串**，不是字符集。
        body = pat.replace("^", "").replace("$", "")
        body = re.sub(r"\[[^\]]*\]", " ", body)      # 挖掉字符类
        body = re.sub(r"\\[A-Za-z]|\\[^\w]", " ", body)  # 挖掉转义
        body = re.sub(r"[+*?{}\s]", " ", body)       # 挖掉量词
        if re.search(r"[A-Za-z0-9_.]", body):
            continue                                  # 还剩裸字面 → 不是字符集
        return True
    return False


def _helper_guard_nature(body: str, sib: str) -> bool | None:
    """入口调了认不出的校验函数，但辅助段里能读到它的实现 —— 判性质。

    返回 False=safe（值级白名单可确认）、None=规则不该下结论。
    **不返回 True**：黑名单读到了也不代表"一定可绕"。

    为什么不肯给 True —— 这是本轮踩出来的边界，两次都栽在同一处：

    `java-sec-code` 的 `SecurityUtil.pathFilter(filepath)` 是
    `indexOf('%')` 循环 URLDecode 之后再判 `contains("..")`；
    `Hello-Java-Sec` 的 `Security.checkOs(filepath)` 是
    `black_list = {"|", ",", "&", "&&", ";", "||"}` 循环 `contains(s)`。
    两个都是黑名单，但**两个靶场都把对应路由标成 safe**。

    起初我把"黑名单"判成 True，结果 java-sec-code 的 `getImageSec`
    与 Hello-Java-Sec 的 `processbuilderSafe` 双双误报 —— 一个规则同时
    打坏两个靶场。加一层"有解码前置就退回"后，pathFilter 修好了，
    checkOs 仍然误报。

    根因不是判据写得不够细，而是**这类问题的答案不在"是不是黑名单"上**：
    "这条黑名单够不够严"取决于攻击者能构造出什么编码变体，
    而规则手里只有 `contains("|")` 这一行，没有可逐行核对的事实支点。
    按第 5 条（兜底分支不能 return True），这种情况只能是 None。

    能确认为 False 的只剩真正可核对的那种：拦截的是**值的集合**
    （`whitelist.contains(cmd)` 且拒绝路径阻断），不是字符片段。
    """
    if not sib:
        return None
    # 排除 Java 关键字与常见库方法，减少无谓扫描
    _skip = {"if", "for", "while", "switch", "catch", "return", "new", "super",
             "this", "exec", "start", "command", "getRuntime", "println"}
    names = {n for n in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body)
             if n not in _skip}
    if not names:
        return None
    hit_allow = hit_deny = hit_ambiguous = False
    # 只取**名字命中**的实现体，不在整段证据里乱找（见 _named_method_bodies）
    for _name, impl in _named_method_bodies(sib, names):
        if _HELPER_DENY_RE.search(impl) and not _HELPER_ALLOW_RE.search(impl):
            # 读到的是黑名单（含"先解码再判"那种）—— 够不够严取决于
            # 攻击者能构造什么编码变体，没有可逐行核对的事实支点。
            # 一律不回 True，见函数 docstring。
            hit_ambiguous = True
        elif _HELPER_ALLOW_RE.search(impl) and not _HELPER_DENY_RE.search(impl):
            hit_allow = True
        # 字符集正则白名单：`!FILTER_PATTERN.matcher(input).matches()` 拦
        # 干净退出。注意**不能只看这一个方法体** —— 模式字符串本体
        # （`^[a-zA-Z0-9_/\.-]+$`）定义在类的静态字段上，与方法是同级兄弟，
        # 不在 `impl` 里。所以要到整段 `sib` 里找 `Pattern.compile("…")`。
        if _is_anchored_charset_guard(impl, sib):
            hit_allow = True
    if hit_ambiguous:
        return None
    if hit_allow:
        return False           # 值级白名单
    return None


# ---------------- pathtraver（路径遍历） ----------------
#
# 支点同样是两个可核对事实：
#   1) 可控值有没有进入文件 API
#   2) 路径是否被"限制在基目录内"（规范化 + 前缀校验 / 只取文件名）
#
# 必须区分的半吊子防护（真实项目里非常常见）：
#   `if (!Security.checkTraversal(name)) { ... }` 而实现是
#       return content.contains("..") || content.contains("/");
#   函数名是 checkTraversal，写着"检测非法文件名"，看起来是防护；
#   但靶场里 `safe` 那条**根本没有文件操作**（只是把结果放进 map 返回），
#   而 `download` 那条压根没调用它。两个事实都必须核对，只看函数名会判反。
PATH_SINK_RE = re.compile(
    r"new\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\(|"
    r"Files\s*\.\s*(?:readAllBytes|readAllLines|readString|newInputStream|"
    r"newOutputStream|copy|write|delete|move)\s*\(|"
    r"Paths\s*\.\s*get\s*\(|"
    r"FileUtils\s*\.\s*(?:read|copy|writeFile|open)\w*\s*\(|"
    r"IOUtils\s*\.\s*(?:toByteArray|copy|toString)\s*\(|"
    r"\.\s*listFiles\s*\(|getResourceAsStream\s*\(|ZipFile\s*\(", re.I)
# 真正的路径约束：规范化后再比较，或直接剥掉目录
PATH_SAFE_RE = re.compile(
    r"getCanonicalPath\s*\(\s*\)\s*\.\s*startsWith\s*\(|"
    r"normalize\s*\(\s*\)\s*\.\s*(?:toString\s*\(\s*\)\s*\.\s*)?startsWith\s*\(|"
    r"toRealPath\s*\(\s*\)\s*\.\s*startsWith\s*\(|"
    r"FilenameUtils\s*\.\s*getName\s*\(|"
    r"getFileName\s*\(\s*\)|"
    r"\.\s*getName\s*\(\s*\)\s*;?\s*$", re.I)
# 疑似防护调用（含黑名单），只用于决定"是否退回模型"
_PATH_GUARD_RE = re.compile(
    r"\b\w*(?:check|filter|valid|verify|allow|safe|traversal)\w*\s*\(", re.I)

# ---- 后缀截取：`S = F.substring(F.lastIndexOf("."))` 抹掉了目录能力 ----
#
# 为什么这是确定性事实，而不是"看起来没事"：
# `lastIndexOf(".")` 定位的是**最后一个点**，截出的串必然形如
# 「"." + 一段不含点的尾巴」。尾巴里没有点 ⇒ 拼不出 `..`；
# 以 "." 开头 ⇒ 不可能是绝对路径。所以无论原始文件名里塞多少 `../`，
# 落到 sink 的值最多带 `/`（进子目录），无法上跳基目录。
# 这是字符串的几何性质，与"开发者意图"无关，可逐字符核对。
#
# 但截断必须**真的把值挡在门外**，三条同时成立才算数：
#   ① 存在 `S = F.substring(F.lastIndexOf("."))` 这条赋值；
#   ② 除该赋值与 F 自身的定义外，F 在方法体里一次都不再出现
#      —— 原文名被另外拼进路径，截断就形同虚设（最常见的半吊子写法）；
#   ③ 文件 API 实参里的每个动态变量都能沿「赋值 / append / 构造实参」链
#      走到 S —— 切个后缀只为打日志、路径仍用别的东西拼，不算。
#
# 方向照旧：本判据只出**否定证据**（True→False），不参与"判漏洞"。
_SUFFIX_CUT_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=(?!=)[^;]*?\b([A-Za-z_]\w*)\s*\.\s*substring\s*\(\s*"
    r"\2\s*\.\s*lastIndexOf\s*\(\s*(?:'\.'|\"\.\")\s*\)\s*\)\s*;")


def _var_build_edges(body: str) -> dict[str, set[str]]:
    """变量之间的「由…构成」边：赋值右式 / `append(实参)` / 构造实参。

    只收裸标识符（`_expr_identifiers` 已排除类名与字段链），
    用来回答"这个变量是不是由那个变量拼出来的"。
    """
    edges: dict[str, set[str]] = {}

    def _add(dst: str, names: set[str]) -> None:
        if names:
            edges.setdefault(dst, set()).update(names)

    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);", body):
        _add(m.group(1), _expr_identifiers(m.group(2)))
    # `sb.append(a).append(b).append(c);` —— 链式调用的接收者只有第一个，
    # 后两段前面是 `)` 而不是变量名，按 `.append(` 逐个抓会丢掉 b/c。
    # 因此按语句为单位：语句的**首个变量**就是接收者，整句里所有 append
    # 实参都算它的构成来源（实测 newbee 的 `suffixName` 正是第 3 段）。
    for stmt in body.split(";"):
        if ".append" not in stmt:
            continue
        head = re.match(r"\s*([A-Za-z_]\w*)\s*\.", stmt)
        if not head:
            continue
        names: set[str] = set()
        for am in re.finditer(r"\.\s*append\s*\(", stmt):
            a = _balanced_cond(stmt, am.end())
            if a is not None:
                names |= _expr_identifiers(a)
        _add(head.group(1), names)
    return edges


def _builds_from(edges: dict[str, set[str]], start: str, target: str,
                 depth: int = 3) -> bool:
    """沿「由…构成」边向上走 `depth` 跳，能否到达 target。"""
    if start == target:
        return True
    seen, cur = {start}, {start}
    for _ in range(depth):
        nxt: set[str] = set()
        for v in cur:
            for w in edges.get(v, ()):      # noqa: PLC0206
                if w == target:
                    return True
                if w not in seen:
                    seen.add(w)
                    nxt.add(w)
        if not nxt:
            return False
        cur = nxt
    return False


def _path_suffix_cut_masks_taint(body: str, helpers: str = "") -> bool:
    """写盘路径里唯一来自用户的片段是否被后缀截取锁死（三条全部成立）。"""
    cut = _SUFFIX_CUT_RE.search(body)
    if not cut:
        return False
    suffix_var, src_var = cut.group(1), cut.group(2)

    # ② 原文名不许在别处再用（去掉截断式与 F 的定义后再找一遍）
    residue = _SUFFIX_CUT_RE.sub(" ", body)
    residue = re.sub(rf"\b{re.escape(src_var)}\s*=(?!=)[^;]*;", " ", residue)
    if re.search(rf"(?<![\w.]){re.escape(src_var)}\b", residue):
        return False

    # ③ 文件 API 实参里的每个动态变量都必须由 S 构成（或本身是常量）
    edges = _var_build_edges(body)
    params = set(_bare_params(_entry_signature(body)))
    checked = False
    for api in _PATH_API_RE.finditer(body):
        args = _balanced_cond(body, api.end())
        if args is None:
            return False
        for part in _STR_LIT_RE.sub('""', args).split("+"):
            p = _strip_cast(part.strip())
            if not p:
                continue
            names = _expr_identifiers(p)
            if not names:
                continue        # 字段链（`Constants.FILE_UPLOAD_DIC`）/ 字面量 / 全大写常量
            # `sb.toString()` 是纯取值，不改变内容，按 `sb` 本身继续判；
            # 其它调用（`getXxx()` / `Paths.get(...)`）一律不下结论。
            m_to = re.fullmatch(r"([A-Za-z_]\w*)\s*\.\s*toString\s*\(\s*\)", p)
            if m_to:
                names = {m_to.group(1)}
            elif "(" in p:
                return False
            for v in names:
                checked = True
                if _builds_from(edges, v, suffix_var):
                    continue
                if _value_origin(body, v, helpers, params) == "lit":
                    continue        # 生成名（UUID / 时间戳）也算常量侧
                return False
    return checked


def pathtraver_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    sink_in = body
    if not PATH_SINK_RE.search(body):
        # 入口体没命中 sink 时**不能直接判安全** —— sink 往往在同文件的私有
        # 辅助方法里。`java-sec-code` 的 `getImage(filepath)` 入口体只有一句
        # `return getImgBase64(filepath);`，真正的 `new File` / `Files.readAllBytes`
        # 全在 `getImgBase64` 里。只看入口体会把它误判成"无文件操作"。
        # （这条是本轮真实踩到的回归：规则一度把 2/2 的 pathtraver 打成 1/2。）
        #
        # 依次退到：同文件私有辅助方法（在 source 的 `// ---- 同文件辅助方法`
        # 段里，但 `entry_body` 截掉了）→ 跨文件辅助段。
        sink_in = _all_evidence(source)
        if not PATH_SINK_RE.search(sink_in):
            # 到这里才能说"整份切片里都没有文件 API"。
            # 半吊子样本（`if (!Security.checkTraversal(name)) {...}` 只返回字符串）
            # 就是靠这一条与 `download` 那条真漏洞区分开的。
            if _FILE_API_NAME_RE.search(sink_in):
                return None      # 出现了文件相关名字但没命中 sink 形态，交给模型
            return False

    # 1) 规范化 + 前缀校验 / 只取文件名 → 目录逃逸被物理阻断
    if PATH_SAFE_RE.search(body):
        return False

    # 1c) 只取「最后一个点之后」的后缀再落盘 → `..` 在几何上拼不出来。
    #     必须三条全过（见 _path_suffix_cut_masks_taint）：有截断式、原文名
    #     没在别处再用、目标确实由截断结果构成。少一条都退回原判。
    if _path_suffix_cut_masks_taint(body, _sibling_methods(source)):
        return False

    # 1b) 拼进 sink 的那个变量能上溯到常量（容器先放常量再覆盖 / 恒真分支 /
    #     helper 返回字面量）。同 sqli 的理由：OWASP 把这三类模板复用到了
    #     pathtraver，而闸门此前只挂在 xss 上。
    if _path_concat_all_constant(body, _sibling_methods(source)):
        return False

    # 2) 有疑似校验调用：先尝试在**跨文件辅助段**里读到它的实现体。
    #    读到值级白名单（前缀校验/枚举）→ 判 safe。
    #    读到黑名单（`contains("..")` / `indexOf("/")`）→ **不判漏洞**，
    #    交回模型。"这条黑名单够不够严"取决于能否构造出编码变体，
    #    java-sec-code 的 `pathFilter` 做了循环 URLDecode 前置、
    #    Hello-Java-Sec 的 `checkOs` 直接黑名单，两处都标 safe ——
    #    规则手里没有可逐行核对的支点，只能退回（见 _helper_guard_nature）。
    if _PATH_GUARD_RE.search(body):
        sib = _sibling_methods(source)
        if _helper_guard_nature(body, sib) is False:
            return False       # 值级白名单（前缀校验/枚举）
        return None
    return True


# ---------------- xpathi ----------------
#
# 为什么这个类目到今天才有 verdict：此前 4 条 OWASP FP 全是
# `missing_property`（模型投票抖动），"规则层一条没错"只是没判错——
# 没有 verdict 入口时规则只能返回 None，**可证为常量的 safe 样本照样被
# 送进模型抽签**。2026-10-20 核对了全部 4 条 FP 源码：
# 00117/01893 是恒真分支赋字面量、02370/02457 是容器顶掉脏值，
# 全部落在 `_value_origin` 已实现的机制上。
# 方向照旧写死：只做**否定证据**短路（True→False），判不了的一律 None。

_XPATH_SINK_RE = re.compile(
    r"\b(?:XPathFactory|XPathExpression|newXPath)\b|\.compile\s*\(|\.evaluate\s*\(")


def _xpath_concat_all_constant(body: str, helpers: str) -> bool:
    """拼进 XPath 表达式的操作数是否**每一个**都能上溯到常量。

    形态：`String expression = "...'" + bar + "']";` → `xp.evaluate(expression, doc)`。
    只处理纯局部变量拼接（出现函数调用/字段访问就退出，交给别的判据，
    与 `_sql_concat_all_constant` 同一边界）。
    """
    sink_vars = set(re.findall(r"\.(?:compile|evaluate)\s*\(\s*([A-Za-z_]\w*)", body))
    if not sink_vars:
        return False
    seen = False
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);", body):
        var, rhs = m.group(1), m.group(2)
        if var not in sink_vars or "+" not in rhs:
            continue
        vars_ = _operand_vars(rhs)
        if vars_ is None:
            return False
        for v in vars_:
            seen = True
            if _value_origin(body, v, helpers) != "lit":
                return False
    return seen


def xpathi_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    sink_in = body
    if not _XPATH_SINK_RE.search(body):
        # 入口体没命中 sink 不直接判安全 —— sink 可能在同文件私有方法里
        # （与 pathtraver 的 `getImgBase64` 同理），退到全量证据段再看。
        sink_in = _all_evidence(source)
        if not _XPATH_SINK_RE.search(sink_in):
            # 有 XPath 相关名字但没命中 sink 形态 → 交给模型；
            # 连名字都没有才敢说"这个入口根本不做 XPath"。
            if re.search(r"\bXPath\b|\bevaluate\s*\(", sink_in):
                return None
            return False

    # ① 变量绑定是 XPath 注入的标准修复：$var 由 resolver 绑值，不进表达式串
    if re.search(r"XPathVariableResolver", sink_in):
        return False
    # ② ESAPI 转义后拼进表达式
    if re.search(r"encodeForXPath\s*\(", sink_in):
        return False
    # ③ 拼进表达式的操作数全部上溯到常量
    #   （恒真分支 / 容器顶掉 / helper 返回字面量 —— 4 条 FP 的全部机制）
    if _xpath_concat_all_constant(body, _sibling_methods(source)):
        return False
    return None


# "看起来像在做文件操作"的名字（含变量名、方法名），只用来把"完全没有文件面"
# 与"有文件面但没命中 sink 形态"分开。前者可确定性判安全，后者必须交模型。
_FILE_API_NAME_RE = re.compile(
    r"\b(?:File|Files|Path|Paths|InputStream|OutputStream|FileInputStream|"
    r"FileOutputStream|FileReader|FileWriter|RandomAccessFile|Resource|"
    r"getResource|ClassPathResource|ZipEntry|ZipFile|FileSystem)\b", re.I)


# 证据段头（切片器拼接的几段）。`entry_body()` 会在第一个 `// ----` 处截断，
# 所以"入口体里有没有 sink"和"整份切片里有没有 sink"是两个不同的问题。
_EVIDENCE_SEP_RE = re.compile(r"^\s*//\s*-{2,}", re.M)


def _all_evidence(source: str) -> str:
    """整份切片去掉分隔注释行后的全部代码（入口体 + 同文件辅助 + 跨文件段）。

    为什么需要：sink 经常不在入口方法体里。
    `PathTraversal.getImage(filepath)` 的入口体只有 `return getImgBase64(filepath);`，
    `new File` / `Files.readAllBytes` 全在同文件的私有辅助方法里；
    MyBatis 的 `${}` 在 Mapper 实现体里，`SecurityUtil.pathFilter` 的
    黑名单实现在跨文件辅助段里。判"到底有没有 sink"必须看全量证据，
    判"入口自己做了什么"才用 `entry_body`。

    分隔注释行（`// ---- 同文件辅助方法 ----`）本身不是代码，逐行剥掉；
    但它后面的**注入代码是真实代码**，不剥 —— 与 `wiring_block()` 的处理
    相反，因为那一段是 `//   ` 逐行渲染的，这里不是。
    """
    out: list[str] = []
    for ln in source.splitlines():
        if _EVIDENCE_SEP_RE.match(ln):
            continue
        out.append(ln)
    return strip_comments("\n".join(out), keep_lines=False)


# "认不出性质的输入校验调用"：形参名带 cmd/file/path 的 if 判断，
# 排除已识别的白名单形态。与 ssrf 的 `_has_unknown_url_guard` 同构。
_UNKNOWN_INPUT_GUARD_RE = re.compile(
    r"if\s*\(\s*[^)]*\b\w*(?:cmd|command|file|path|name|input|param)\w*\b[^)]*\)",
    re.I)


def _has_unknown_input_guard(body: str) -> bool:
    for m in _UNKNOWN_INPUT_GUARD_RE.finditer(body):
        if CMDI_WHITELIST_RE.search(m.group(0)):
            continue
        return True
    return False


# ---------------- 对外门面 ----------------

# ---------------- authz：越权与未授权访问 ----------------
#
# 判据来源是**靶场自述原文**，不是想象（JavaSecLab 的 idor 页面）：
#   "服务端把用户可控的对象标识符直接用于查询或操作资源，
#    但没有校验该资源是否属于当前登录用户"
#   "当前用户身份从 Session、JWT、OAuth Token 等可信上下文获取，
#    不从请求参数决定"
#   "管理员接口必须在服务端校验当前用户角色、权限点和资源归属"
#
# 这段自述直接给出了"事实支点"：**当前主体从哪里取** + **有没有与资源标识比对**。
# 两者都是可逐行核对的行，不需要推断业务意图。
#
# 能力边界（必须写在代码里，否则以后会把它当万能钥匙）：
#   ① 只覆盖"方法体或方法注解里能看到校验"的形态。校验写在全局 Filter /
#      Interceptor / Spring Security 配置里的，本函数读不到 —— 那是
#      `framework_wiring` 的活，不能在这里猜。
#   ② **垂直越权不硬判 True**。`@GetMapping("/vul")` 返回 admin 页面、
#      方法体无角色校验，这是"缺少校验"的事实，但"缺少校验"不等于
#      "任何人都能访问"（可能被全局拦截器挡住）。按记忆第 26 条，
#      看到名称类弱证据只能交给模型。

# 从**可信上下文**取当前主体。注意 `getParameter`/`getHeader` 一律不算 ——
# 那正是攻击者能控制的地方，用它当"当前用户"本身就是漏洞。
_AUTHZ_SUBJECT_RE = re.compile(
    r"SecurityContextHolder\s*\.\s*getContext\s*\(\s*\)\s*\.\s*getAuthentication\s*\(\s*\)"
    r"|getAuthentication\s*\(\s*\)\s*\.\s*(?:getName|getPrincipal)\s*\(\s*\)"
    r"|@AuthenticationPrincipal"
    r"|getSession\s*\(\s*\)\s*\.\s*getAttribute\s*\("
    # Spring MVC 的另一种主体获取方式：`HttpSession` 作为**方法形参**注入，
    # 直接 `httpSession.getAttribute(KEY)`。旧判据只认 `request.getSession()`，
    # 于是真实业务项目里**所有**主体获取都看不见（newbee-mall 实测 6 条误报：
    # orderDetailPage / cancelOrder / selectPayType / 购物车增改全被判成越权）。
    r"|\w*[Ss]ession\s*\.\s*getAttribute\s*\("
    r"|@SessionAttribute|@RequestAttribute"
    r"|\bJwtUtils\s*\.|\bjwtUtils\s*\."
    r"|StpUtil\s*\.\s*getLoginId|SecurityUtils\s*\.\s*getSubject", re.I)

# 主体**变量名**：`NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(KEY);`
# 只有拿到变量名，才能查"它有没有被当作资源定位条件"。
_AUTHZ_SUBJECT_VAR_RE = re.compile(
    r"(\w+)\s*=\s*\(?\s*[A-Z][\w.]*\s*\)?\s*\w*[Ss]ession\s*\.\s*getAttribute\s*\(")

# 认证入口（登录/注册/登出/验证码）。它们本身就是**建立身份**的地方，
# 不做授权判定 —— 把 `login(loginName, password)` 的入参当成"直查资源"
# 会稳定误报（旧判据下 newbee-mall 的 /login 与 /register 都判 True）。
_AUTHZ_AUTHN_ROUTE_RE = re.compile(
    r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?\{?[^)]{0,200}?"
    r"\"(?:/?(?:admin/)?(?:login|logout|register|signin|signup|kaptcha|captcha))\"", re.I)

# 声明式角色/权限校验。注解在方法签名上，`entry_body` 里看不到，必须扫 source。
_AUTHZ_ROLE_RE = re.compile(
    r"@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed"
    r"|@RequiresRoles|@RequiresPermissions|@PreFilter|@PostFilter"
    r"|\bhasRole\s*\(|\bhasAuthority\s*\(|\bhasAnyRole\s*\("
    r"|checkPermission\s*\(|checkRole\s*\(", re.I)

# 拒绝分支：只记日志/返回 null 不算，必须是"终止请求"。
_AUTHZ_DENY_RE = re.compile(
    r"return\s+(?:R|Result|AjaxResult|ResponseEntity|ApiResponse)\s*\.\s*"
    r"(?:error|fail|forbidden|unauthorized)\s*\(|"
    r"return\s+\"redirect:/login|"
    r"throw\s+new\s+\w*(?:AccessDenied|Auth|Permission|Forbidden|Security)\w*Exception|"
    # 项目自定义的「抛业务异常」写法：`NewBeeMallException.fail(...)` 内部是
    # `throw new NewBeeMallException(msg)`（newbee-mall 实证），等价于终止请求。
    # 判据要求方法名是 fail/deny/forbidden 这类**语义明确**的终止动作，
    # 不认 `xxxException.warn(...)` 之类的软处理。
    r"\w*(?:Exception|Error)\s*\.\s*(?:fail|deny|forbidden|throw\w*)\s*\(|"
    r"\.\s*sendError\s*\(\s*40[13]", re.I)

# 资源访问：Mapper / Repository / DAO 上的方法调用。
_AUTHZ_RESOURCE_RE = re.compile(
    r"\b\w*(?:Mapper|Repository|Dao|DAO|Service)\s*\.\s*\w+\s*\(", re.I)

# 前缀级鉴权拦截器：`addPathPatterns("/admin/**")`。它由框架层统一拦，
# 方法体里看不到任何主体判断 —— 这正是设计上"全局鉴权覆盖 → None"的情形。
# 必须与 `/**` 的通用拦截器区分：后者多半只做计数/编码，不构成鉴权。
_AUTHZ_GLOBAL_GUARD_RE = re.compile(
    r'addPathPatterns\(\s*"\s*/(?!\*\*)[\w-]+/\*\*\s*"\s*\)')


def _container_flows_to_service(body: str, holder: str) -> bool:
    """容器（或其包装对象）是否**真作为实参**进了 Service/Mapper 调用。

    只往容器里放东西说明不了任何查询范围 —— 得看到它被交出去。
    容器常被包一层：`PageQueryUtil pageUtil = new PageQueryUtil(params);`
    所以同时接受"包装后的变量名"。
    """
    holders = {holder}
    for wm in re.finditer(r"\b(\w+)\s*=\s*new\s+[\w.<>]+\s*\(\s*(\w+)\s*[,)]", body):
        if wm.group(2) in holders:
            holders.add(wm.group(1))
    alt = "|".join(sorted(map(re.escape, holders)))
    return re.search(rf"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\("
                     rf"[^;]{{0,240}}?\b(?:{alt})\b", body) is not None


def authz_verdict(source: str) -> bool | None:
    """越权/未授权的确定性判定：False(有校验) / True(入参直查且无主体) / None。"""
    body = entry_body(source)
    if not body:
        return None

    # 0) 认证入口本身不做授权判定。登录接口的"资源"就是凭据库，身份由口令校验
    #    建立；把 `login(loginName, password)` 的入参当成"直查资源"是口径错误。
    if _AUTHZ_AUTHN_ROUTE_RE.search(body):
        return None

    # 1) 声明式校验：`@PreAuthorize("hasRole('ADMIN')")` 这类。
    #    注解不在 entry_body 里，必须扫整份切片 —— 但只在**入口方法自身**
    #    的注解范围内找，避免把同文件别的方法的注解算到当前路由头上。
    if _AUTHZ_ROLE_RE.search(source):
        return False

    # 2) 主体获取 + 拒绝分支。两个条件缺一不可：
    #    只取主体不比对（`log.info(currentUser)`）不构成校验；
    #    只比对不拒绝（`if (!ok) log.warn(...)`）也不构成校验。
    has_subject = _AUTHZ_SUBJECT_RE.search(body) is not None
    if has_subject and _AUTHZ_DENY_RE.search(body):
        return False

    # 2b) 主体标识被当作**资源定位条件** —— 校验下沉到 Service/Mapper 的
    #     `where user_id = ?` 里，控制器侧没有 if/throw：
    #
    #         getOrderDetailByOrderNo(orderNo, user.getUserId())
    #         item.setUserId(user.getUserId());  再落库
    #
    #     这是可逐行核对的事实（主体值参与了资源选择），比"有没有拒绝分支"
    #     更贴近真实写法。newbee-mall 的订单详情 / 取消 / 购物车增改都是这一形态。
    if has_subject:
        for var in set(_AUTHZ_SUBJECT_VAR_RE.findall(body)):
            key = rf"\b{var}\s*\.\s*get\w*[Ii]d\s*\(\s*\)"
            if re.search(rf"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\("
                         rf"[^;]{{0,240}}?{key}", body):
                return False

    # 2b-2) 主体 ID 先赋给 **DTO/实体属性**，再把整个对象交给 Service ——
    #     与 2c 同构，载体从 Map 换成实体字段：
    #
    #         item.setUserId(user.getUserId());
    #         cartService.saveNewBeeMallCartItem(item);   // → where user_id = ?
    #
    #     两个事实缺一不可，只 set 不传不算数（`log.info(item)` 之后什么都没发生，
    #     主体并没有参与资源选择）。右式必须是**会话/Principal 主体变量**，
    #     严禁认 `@RequestBody Order order` 自带的 `order.getUserId()` ——
    #     那是客户端可控值，把它当主体就是把越权当校验。
    if has_subject:
        for var in set(_AUTHZ_SUBJECT_VAR_RE.findall(body)):
            key = rf"\b{var}\s*\.\s*get\w*[Ii]d\s*\(\s*\)"
            for sm in re.finditer(rf"\b(?<!this\.)([A-Za-z_]\w*)\s*\.\s*set\w*[Ii]d\s*"
                                  rf"\(\s*{key}\s*\)", body):
                if _container_flows_to_service(body, sm.group(1)):
                    return False

    # 2c) 主体值先写进**查询容器**，再整体交给 Service（Map / DTO / PageQueryUtil）：
    #
    #         params.put("userId", user.getUserId());
    #         PageQueryUtil pageUtil = new PageQueryUtil(params);
    #         orderService.getMyOrders(pageUtil);       // → where user_id = ?
    #
    #     与 2b 是同一件事（主体值参与资源选择），只是载体从"实参"换成了
    #     "容器字段"，2b 的「Service 实参里出现 user.getUserId()」便整条落空。
    #     两个事实缺一不可：① 主体 id 被放进某个容器；② 该容器（或包了它的
    #     那个对象）确实作为实参进了 Service/Mapper 调用 —— 只放不传说明不了
    #     任何查询范围。newbee-mall 的 `/orders` 是标准形态。
    if has_subject:
        for var in set(_AUTHZ_SUBJECT_VAR_RE.findall(body)):
            key = rf"\b{var}\s*\.\s*get\w*[Ii]d\s*\(\s*\)"
            for pm in re.finditer(
                    rf"\b(\w+)\s*\.\s*(?:put|putAll|add)\s*\("
                    rf"\s*\"[^\"]*\"\s*,\s*{key}\s*\)", body):
                if _container_flows_to_service(body, pm.group(1)):
                    return False

    # 2d) 主体由**被调方**获取：控制器把 `HttpSession` / `HttpServletRequest`
    #     原样传给 Service，由 Service 内部 `session.getAttribute(...)` 取当前用户
    #     再按该 userId 查库（newbee-mall `updateUserInfo` 就是这一形态）。
    #     方法体内没有主体变量可查，但**也没有把入参当资源键**——证据不足，退回 None。
    #     注意不能据此判 False：`paySuccess(orderNo, payType)` 这种既不取主体、
    #     也不传会话的才是真越权，它不会命中这一条。
    if not has_subject and re.search(
            r"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\([^;]{0,160}?"
            r"\b\w*[Ss]ession\b", body):
        return None

    # 3) 角色常量比对：`if ("admin".equals(currentUsername))`
    #    这是垂直越权安全样本的写法（JavaSecLab VerticalController.safe）。
    if has_subject and re.search(
            r"\"(?:admin|ADMIN|ROLE_\w+)\"\s*\.\s*equals\s*\(", body):
        return False

    # 4) 入参被**原样**用作资源查询条件，且方法内没有任何主体获取 → 水平越权。
    #    判据要求两个事实同时成立，任一缺失就退回 None：
    #      a) 有 Mapper/Repository/Service 调用，且实参里出现裸形参
    #      b) 方法内没有从可信上下文取主体的语句
    #      c) 该路由没有被前缀级鉴权拦截器整体覆盖（后台 `/admin/**`）
    params = _bare_params(_entry_signature(source))
    if params and not has_subject and _AUTHZ_RESOURCE_RE.search(body) \
            and not _AUTHZ_GLOBAL_GUARD_RE.search(source):
        for m in _AUTHZ_RESOURCE_RE.finditer(body):
            args = _balanced_cond(body, m.end())
            if args is None:
                continue
            if any(re.fullmatch(r"[A-Za-z_]\w*", a.strip()) and a.strip() in params
                   for a in _split_args(args)):
                return True

    # 垂直越权 / 未授权 / 校验在全局配置里 —— 方法体看不到，交模型。
    return None


def verdict(category: str, source: str) -> bool | None:
    """对配置型类目给出确定性结论：True(有漏洞) / False(安全) / None(证据不足)。"""
    cfg = parse_config_block(source)

    if category == "crypto":
        alg = extract_cipher_alg(source, cfg)
        return cipher_is_weak(alg) if alg else None

    if category == "hash":
        alg = extract_hash_alg(source, cfg)
        return hash_is_weak(alg) if alg else None

    if category == "weakrand":
        # 只看实际生成安全敏感值的那一处随机源（同文件兄弟方法里的 Random
        # 不能算到当前入口头上）
        body = entry_body(source)
        if re.search(r"new\s+(java\.util\.)?Random\s*\(", body) or "Math.random()" in body:
            return True
        if "SecureRandom" in body:
            return False
        return None

    if category == "securecookie":
        body = entry_body(source)
        cookies = re.findall(r"new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(", body)
        if not cookies:
            return None
        insecure = False
        for m in re.finditer(r"Cookie\s+\w+\s*=\s*new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(", body):
            var = body[m.start():m.end()].split()[1]
            seg = body[m.end(): m.end() + 1500]
            has_secure = re.search(rf"{re.escape(var)}\s*\.\s*setSecure\s*\(\s*true\s*\)", seg)
            has_httponly = re.search(rf"{re.escape(var)}\s*\.\s*setHttpOnly\s*\(\s*true\s*\)", seg)
            if not (has_secure and has_httponly):
                insecure = True
        return insecure

    if category == "cors":
        return cors_verdict(source)

    if category == "deserial":
        return deserial_verdict(source)

    if category == "spel":
        return spel_verdict(source)

    if category == "xxe":
        return xxe_verdict(source)

    if category == "sqli":
        return sqli_verdict(source)

    if category in ("redir", "openredirect"):
        return redir_verdict(source)

    if category == "xss":
        return xss_verdict(source)

    if category == "ssrf":
        return ssrf_verdict(source)

    if category == "cmdi":
        return cmdi_verdict(source)

    if category == "pathtraver":
        return pathtraver_verdict(source)

    if category == "xpathi":
        return xpathi_verdict(source)

    if category == "authz":
        return authz_verdict(source)

    return None
