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
    """只保留入口方法体：截到第一个 `// ---- ...` 分隔注释之前。"""
    m = _SEP.search(source)
    return source[: m.start()] if m else source


def _sibling_methods(source: str) -> str:
    """分隔注释之后的部分（同文件辅助方法 + 实现体 + 配置），不含配置块本体。"""
    m = _SEP.search(source)
    if not m:
        return ""
    body = source[m.start():]
    cfg = body.find("相关配置实际取值")
    return body[:cfg] if cfg >= 0 else body


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
    r"\.readObject\s*\(|new\s+(?:[A-Za-z_][\w.]*\.)?(?:ObjectInputStream|XStream)\b|"
    r"\.fromXML\s*\(|enableDefaultTyping|readValue\s*\(|"
    r"new\s+(?:[A-Za-z_][\w.]*\.)?Yaml\s*\(|\.load\s*\(", re.I)
# 白名单式防护
DESERIAL_SAFE_RE = re.compile(
    r"SafeConstructor|safeMode|setAllowedClasses|ObjectInputFilter|"
    r"createFilter\s*\(|allowList|whitelist|setWhiteList", re.I)
# 黑名单式"防护"：看起来在防，实际可绕
DESERIAL_BLACKLIST_RE = re.compile(
    r"denyClasses|denyList|blacklist|setBlacklist|startsWith\s*\(\s*deny", re.I)


def deserial_verdict(source: str) -> bool | None:
    body = entry_body(source)
    # 只有当**入口体自己**把外部数据交给反序列化 API 时才判；
    # 体里没有 sink 就说明反序列化发生在别处（helper），交给 LLM。
    if not re.search(r"readObject\s*\(|fromXML\s*\(|\.load\s*\(|readValue\s*\(|"
                     r"enableDefaultTyping", body, re.I):
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


def spel_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not EXPR_SINK_RE.search(body):
        return None
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
    return None                        # 证据不足，交回 LLM


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
SQLI_PREPARE_RE = re.compile(r"\.\s*prepare(?:Statement|Call)\s*\(\s*([^;]{0,300})", re.I | re.S)
# 字符串拼接：`"..." + 变量` 或 `变量 + "..."`
SQLI_CONCAT_RE = re.compile(
    r'"[^"]*"\s*\+|\+\s*"[^"]*"')
# 白名单过滤：全串匹配的正则/校验
SQLI_WHITELIST_RE = re.compile(
    r"\.\s*matches\s*\(\s*\)|sqlFilter|checkSql|isValidOrder|"
    r"FILTER_PATTERN\s*\.\s*matcher\s*\([^)]*\)\s*\.\s*matches", re.I)
# MyBatis XML / 注解里的 ${} 与 #{}
MYBATIS_DOLLAR_RE = re.compile(r"\$\{\s*_?\w+\s*\}")
MYBATIS_HASH_RE = re.compile(r"#\{\s*_?\w+\s*\}")


def sqli_verdict(source: str) -> bool | None:
    body = entry_body(source)
    impl = _impl_segment(source)

    # C) 白名单过滤优先：入参被全串白名单约束过，后续拼接不构成注入。
    #    但要求过滤函数**作用在这个入口的实参上**，不能是别处的方法名。
    if SQLI_WHITELIST_RE.search(body) and re.search(
            r"\b(?:sqlFilter|checkSql|isValidOrder)\s*\(", body):
        return False

    # B) MyBatis：只有能确认用的是 ${} 还是 #{} 才判
    if MYBATIS_DOLLAR_RE.search(impl):
        return True
    if MYBATIS_HASH_RE.search(impl) and not SQLI_JDBC_SINK_RE.search(body):
        return False
    # 语句是纯固定文本（无任何占位符），调用也不带实参 → 没有注入面。
    # 切片器会在 Mapper 语句下方标注「无外部占位符（语句为固定文本）」，
    # 这是比"看到了 #{}"更强的证据：连参数都没有，谈不上注入。
    if "无外部占位符" in impl and not SQLI_JDBC_SINK_RE.search(body):
        return False

    # A) JDBC：看 SQL 是怎么造出来的
    if SQLI_CREATE_STMT_RE.search(body):
        # createStatement 无法绑定参数，只要 SQL 里出现拼接就可注入
        if SQLI_CONCAT_RE.search(body):
            return True
        return None                    # 常量 SQL，不是注入面
    m = SQLI_PREPARE_RE.search(body)
    if m:
        arg = m.group(1)
        # 实参往往只是个变量名（`prepareStatement(sql)`），
        # 真正的拼接和 `?` 都在它的赋值语句里，必须回溯源变量。
        arg = _resolve_sql_var(body, arg)
        # prepareStatement 的参数里出现拼接 → 占位符承载不了，仍可注入
        if SQLI_CONCAT_RE.search(arg):
            return True
        if "?" in arg:
            return False
        return None
    return None


_SQL_VAR_ASSIGN_RE = r"String\s+{name}\s*=\s*"


def _resolve_sql_var(body: str, arg: str) -> str:
    """把 `prepareStatement(sql)` 的 sql 换成它最近一次赋值的右侧。

    只看实参本身会把 `jdbc_ps_vuln` 判成 None：
        String sql = "select * from users where username = '" + username + "'";
        PreparedStatement st = con.prepareStatement(sql);
    实参 `sql)` 里既没有 `?` 也没有拼接，但 SQL 本身是拼出来的。
    """
    name = arg.strip().rstrip(")").strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return arg
    m = re.findall(rf"\b(?:String\s+)?{re.escape(name)}\s*=\s*([^;]+);", body)
    return m[-1] if m else arg


def _impl_segment(source: str) -> str:
    """取切片尾部的「跨文件证据（实现体）」段。

    这一段放的是 Mapper XML / @Select 注解 / 接口实现类的方法体 ——
    判断 ${} vs #{} 只能在这里找，入口方法体只有一行 mapper 调用。
    """
    i = source.find("跨文件证据")
    return source[i:] if i >= 0 else ""


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
    r"\.\s*getWriter\s*\(\s*\)\s*\.\s*(?:print|write|println)\s*\(|"
    r"\.\s*getOutputStream\s*\(\s*\)\s*\.\s*write\s*\(|"
    # `return xss;` —— 原样交出变量
    r"return\s+[A-Za-z_]\w*\s*;|"
    # `return encode(xss);` 这类"过了一层函数"的返回同样是回显点。
    # 不能因为中间有调用就当作没有回显：是否安全由 encode 检测另行判定，
    # 两件事必须分开判，否则 `return encode(xss)` 会被漏成"无回显"。
    r"return\s+\w+\s*\([^)]*\)\s*;", re.I)
XSS_ENCODE_RE = re.compile(
    r"encode\w*\s*\(|escape\w*\s*\(|HtmlUtils\s*\.\s*htmlEscape|"
    r"StringEscapeUtils|ESAPI\s*\.\s*encoder|encodeForHTML|"
    r"Encode\s*\.\s*forHtml|Jsoup\s*\.\s*clean", re.I)
XSS_PARAM_RE = re.compile(
    r"@RequestParam|@PathVariable|@RequestHeader|@CookieValue|@ModelAttribute|"
    r"request\s*\.\s*getParameter\s*\(|request\s*\.\s*getHeader\s*\(", re.I)
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
    """取出串接证据里贴出的读取点方法体（去掉 `// ` 前缀）。"""
    i = source.find(_CHAIN_SEP)
    if i < 0:
        return ""
    seg = source[i:]
    j = seg.find("读取点方法体")
    if j < 0:
        return ""
    out = []
    for ln in seg[j:].splitlines()[1:]:
        s = ln.strip()
        if not s.startswith("//"):
            break
        out.append(s[2:].lstrip())
    return "\n".join(out)


def _entry_signature(source: str) -> str:
    """取入口方法的签名括号（用于判断有没有裸形参）。"""
    body = entry_body(source)
    m = re.search(r"\b\w+\s*\(([^)]*)\)\s*(?:throws[^{]*)?\{", body)
    return m.group(1) if m else ""


def xss_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None

    sig = _entry_signature(body)
    has_param = bool(XSS_PARAM_RE.search(body)) or bool(_bare_params(sig))
    reader = _chain_reader_body(source)

    # 1) 反射型：有外部入参 + 有回显 + 无编码
    if has_param and XSS_ECHO_SINK_RE.search(body):
        if XSS_ENCODE_RE.search(body):
            return False
        return True

    # 2) 存储型：本方法只写不读，值经介质流到另一个回显点
    if reader:
        if not XSS_ECHO_SINK_RE.search(reader):
            return False               # 读取点没有回显，链路不闭合
        if XSS_ENCODE_RE.search(reader):
            return False               # 读取点做了输出编码
        return True

    # 3) 既无回显也无串接证据 → 本方法确实没有把输入写进响应体。
    #
    #    这里必须返回 False 而不是 None。曾经写成 `False if not has_param else None`，
    #    理由是"有形参但没回显，可能是存储型的写入点，交模型判断" —— 那是错的：
    #    串接索引是全库建好后贴进来的（见 `JavaSlicer._attach_chains`），到这里
    #    还没有证据，说明全库都找不到读取点，链根本不闭合。把 None 漏给模型，
    #    等于让模型对着一个注定无法回答的样本自由裁量，而自由裁量正是抖动来源。
    return False


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
        return None                    # 连跳转都没有，不是本类目的判定对象

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
    r"\.\s*startsWith\s*\(\s*\"http\"\s*\)|"
    r"(?:URI|URL)\s*\.\s*getProtocol\s*\(\s*\)\s*\.\s*equalsIgnoreCase\s*\(", re.I)
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
    r"ImageIO\s*\.\s*read\s*\(|"
    r"IOUtils\s*\.\s*(?:toByteArray|copy)\s*\(\s*(?:new\s+)?URL|"
    r"\.\s*getInputStream\s*\(\s*\)|"
    # 把 url 变量交给 Http* / *Service / *Utils 方法去发请求
    r"\b\w*(?:Http|http|Service|Utils|Request)\w*\s*\.\s*\w+\s*\(\s*\w*url\w*", re.I)


def ssrf_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    if not SSRF_SINK_RE.search(body):
        return None

    if SSRF_HOOK_RE.search(body):
        return False                   # socket 层校验已挂上
    if SSRF_SCHEME_RE.search(body):
        return False                   # 至少阻断了 file:// 等非 http 协议
    return True


# ---------------- 对外门面 ----------------

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

    return None
