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


# ---------------- 形参主体注解 ----------------
#
# 前后端分离项目里主体在**签名**上，方法体里没有任何 `session.getAttribute`：
#
#     public Result orders(@TokenToMallUser MallUser loginMallUser, ...) {
#         ... orderService.getMyOrders(p, loginMallUser.getUserId()) ...
#
# 切片器会把「哪个注解注入主体」写进注释块（来源是仓库里的
# `implements HandlerMethodArgumentResolver`，见 core/context/argument_resolvers.py）：
#
#     // ---- 形参主体注解（判定"当前用户从哪来"以此为准）----
#     // @TokenToMallUser -> 形参 loginMallUser   由 TokenToMallUserMethodArgumentResolver 注入
#
# 规则读回它，只是把 `loginMallUser` 加入"主体变量"集合 —— **不**因此认为
# 已经做过校验。是否算校验仍由「主体 id 是否作资源键」决定（2b/2b-2/2c）。
# 这个区分很关键：注解形参只说明"知道当前用户是谁"，不说明"检查了资源归属"。
_SUBJECT_PARAM_RE = re.compile(r"^//\s*@(\w+)\s*->\s*形参\s+(\w+)")


def parse_subject_params(source: str) -> dict[str, str]:
    """读回切片里的「主体注解 → 形参名」。没有该块时返回空 dict。"""
    out: dict[str, str] = {}
    in_block = False
    for line in source.splitlines():
        s = line.strip()
        if "形参主体注解" in s and s.startswith("//"):
            in_block = True
            continue
        if in_block:
            if not s.startswith("//"):
                break
            m = _SUBJECT_PARAM_RE.match(s)
            if m:
                out[m.group(1)] = m.group(2)
    return out


# ---------------- CORS ----------------
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
    r"new\s+(?:[A-Za-z_][\w.]*\.)?Yaml\s*\(", re.I)
# 白名单式防护
DESERIAL_SAFE_RE = re.compile(
    r"SafeConstructor|safeMode|setAllowedClasses|ObjectInputFilter|"
    r"createFilter\s*\(|allowList|whitelist|setWhiteList|"
    r"ValidatingObjectInputStream|\.\s*accept\s*\(\s*[\w.]+\.class", re.I)

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
    # Python 分支（Module 25，pygoat 实测）：pickle/yaml 是 Python 生态的
    # 反序列化入口，判据挂 API 语义：
    #   · pickle.loads/load / dill.loads —— 标准库无内置防护，外部数据即
    #     任意对象构造（OWASP 反序列化速查表口径）→ True；
    #   · yaml.unsafe_load / full_load → True（FullLoader 有过 CVE-2020-14343
    #     前科，不与版本挂钩就当不可信）；
    #   · yaml.load(x, Loader=...SafeLoader) 全部调用都带 SafeLoader → False；
    #   · 只有 yaml.safe_load → False（值域锁死在基础类型）。
    # 都没有才走下面的 Java 流程 —— 两套 API 名字不相交，不会互相误吞。
    if re.search(r"\bpickle\s*\.\s*loads?\s*\(|\bcpickle\s*\.\s*loads?\s*\("
                 r"|\bdill\s*\.\s*loads?\s*\("
                 r"|\byaml\s*\.\s*(?:unsafe_load|full_load)\s*\(", body):
        return True
    yl = list(re.finditer(r"\byaml\s*\.\s*load\s*\(", body))
    if yl:
        saw_safe = False
        for m in yl:
            args = _balanced_cond(body, m.end()) or ""
            if re.search(r"Loader\s*=\s*(?:yaml\s*\.\s*)?SafeLoader\b", args):
                saw_safe = True
            else:
                return True
        return False if saw_safe else None
    if re.search(r"\byaml\s*\.\s*safe_load\s*\(", body):
        return False
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
    r"GroovyShell|ScriptEngine.*\.eval\s*\(|engine\s*\.\s*eval\s*\(|"
    r"ImageMath\s*\.\s*eval\s*\(|(?<![\w.])eval\s*\(|"
    # 裸 `.getValue()` 太宽：Cookie.getValue() / Map.Entry.getValue() 都会
    # 命中（RuoYi 实测 2 条 FP）。只认 SpEL 表达式变量名的接收者。
    r"\b(?:ex|exp|expr|expression|spel|parser)\w*\s*\.\s*"
    r"(?:getValue|evaluate)\s*\(", re.I)
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
    # Python 分支（Module 24，pygoat 实测）：xml.sax 的外部实体开关是
    # 解析器事实 —— `setFeature(feature_external_ges, True)` 就是把 XXE
    # 打开的那一行；defusedxml / 显式 False / lxml 的 resolve_entities=False
    # 是关掉的那一行。纯常量 XML（无 request 输入）不在此下结论。
    if re.search(r"\bmake_parser\s*\(|\bparseString\s*\("
                 r"|\betree\s*\.\s*(?:fromstring|parse)\s*\("
                 r"|\bfromstring\s*\("
                 r"|\blxml\b", body):
        if re.search(r"\bdefusedxml\b|feature_external_ges\s*,\s*False"
                     r"|resolve_entities\s*=\s*False|no_network\s*=\s*True", body):
            return False
        if re.search(r"feature_external_ges\s*,\s*True", body) \
                and re.search(r"\brequest\s*\.", body):
            return True
        return None
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
# MyBatis-Plus 条件构造器（Module 29）：参数化条件方法 vs 拼接出口。
# `.apply("/.last("/.inSql("/.orderBySql(" 是 Wrapper 的显式 SQL 拼接出口，
# 实参含拼接或裸变量即注入面；`.eq/.like/...` 则由框架参数化。
_MP_WRAPPER_RE = re.compile(
    r"\.(?:eq|ne|like|notLike|in|notIn|between|notBetween|gt|ge|lt|le|"
    r"allEq|apply|last|inSql|orderBySql|orderBy\w+)\s*\(")
_MP_CONCAT_EXIT_RE = re.compile(
    r"\.(?:apply|last|inSql|orderBySql)\s*\("
    # 前导填充必须与实参字符同类排除引号：否则 `"name = {0}", name` 这种
    # 占位符绑定会把整段字符串吞进填充、再拿第二实参的裸变量凑成"拼接"。
    r"[^()\"]*(?:\"[^\"]*\"\s*\+|\+\s*\"|[^()\"]*\b[a-z_]\w+\b)")
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
    nxt = _SEP.search(seg[len(marker):])
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


# A1) 整句 SQL 由用户控制（Module 46，WebGoat 形态）
#
#     statement.executeQuery(query) —— query 是 String 形参（@RequestParam），
#     **整句 SQL** 由攻击者给。这不是"拼接"形态，而是比拼接更彻底的形态：
#     之前的 JDBC 分支只在 SQLI_CONCAT_RE 命中（看到 `+` 拼接）时才给结论，
#     于是"整句可控"这一整类经典注入全部退回 None（WebGoat SqlInjection
#     Lesson2/3/4/5 等 10 余个关卡实测全退）。
#
#     判据（挂机制不挂名字）：
#       ① sink 是 JDBC 执行方法（executeQuery/executeUpdate/execute）；
#       ② 实参是**标识符**（不是 SQL 字面量、不含 ? 占位符）；
#       ③ 该实参是所在方法的 **String 型形参**（数字型形参注入不了 ——
#          Spring/JDBC 已把入参解析成 int）；
#       ④ 该形参的值确实来自外部输入：它是入口的用户输入形参
#          （@RequestParam/@PathVariable/@RequestBody/@RequestHeader），
#          或它所在方法被入口以"用户输入形参"调用（一跳）。
#
#     ④ 是关键闸门：没有它，形如 `helper(String fixed)` 里 executeQuery(fixed)
#     会被误判成注入。
_SQLI_WHOLE_STMT_SINK_RE = re.compile(
    r"\.\s*(?:executeQuery|executeUpdate|execute)\s*\(\s*([A-Za-z_]\w*)\s*\)")
_USER_INPUT_ANN_RE = re.compile(
    r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|"
    r"ModelAttribute|RequestPart)\b")
_NUMERIC_JAVA_TYPE_RE = re.compile(
    r"\b(?:int|long|short|byte|float|double|Integer|Long|Short|Byte|Float|"
    r"Double|BigInteger|BigDecimal)\b")
_JAVA_METHOD_SIG_RE = re.compile(
    r"(?:^|\n)[ \t]*(?:@\w+(?:\([^()]*\))?[ \t]*\n[ \t]*)*"
    r"(?:public|protected|private|static|final|synchronized|abstract|native|"
    r"default|strictfp|\s)+[\w<>\[\],\.\s]*?\b(\w+)\s*\(([^)]*)\)"
    r"\s*(?:throws\s+[\w,\.\s]+)?\s*\{")


def _java_method_segments(source: str) -> list[tuple[str, str, str, int]]:
    """切出 (方法名, 签名, 方法体, 体起始偏移) 列表。

    只用正则切方法头 + 括号配平找体尾 —— 不引 Java 解析器（依赖树里没有），
    也不做完整语法分析：判据只需要"这个 sink 落在哪个方法的形参域里"。
    """
    segs: list[tuple[str, str, str, int]] = []
    for m in _JAVA_METHOD_SIG_RE.finditer(source):
        name, sig = m.group(1), m.group(2)
        # 找方法体的括号配平
        start = source.find("{", m.end() - 1)
        if start < 0:
            continue
        depth = 0
        end = len(source)
        for i in range(start, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        segs.append((name, sig, source[start:end], start))
    return segs


def _sql_stmt_whole_user_controlled(source: str) -> bool | None:
    """整句 SQL 由外部输入控制 → True；证据不足 → None。"""
    segs = _java_method_segments(source)
    if not segs:
        return None
    entry_name = ""
    for name, _sig, _body, _off in segs:
        entry_name = name
        break                       # 切片里第一个方法通常是入口
    # 入口的用户输入形参
    entry_user_params: set[str] = set()
    entry_has_request = False
    for name, sig, _b, off in segs:
        if name != entry_name:
            continue
        if re.search(r"HttpServletRequest", sig):
            entry_has_request = True
        # HTTP 入口判定：方法体之前最近的一个注解里有没有 @*Mapping。
        # Spring MVC 的**默认参数绑定**事实：HTTP 入口方法上没加注解的
        # String 形参，按参数名从请求参数取值（WebGoat SqlInjectionLesson5
        # 的 `completed(String query)` 就是这种 —— 攻击者整句可控）。
        # 只有确认是 HTTP 入口才敢用这条，否则内部方法的无注解形参会被误当输入。
        head = source[max(0, off - 400):off]
        is_http_entry = bool(re.search(
            r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b", head))
        for pm in re.finditer(r"(@\w+(?:\([^()]*\))?\s*)*([\w<>\[\],\.\s]+?)\s+(\w+)\s*(?:,|$)",
                             sig):
            ann, ty, pname = pm.group(1) or "", pm.group(2) or "", pm.group(3)
            if _NUMERIC_JAVA_TYPE_RE.search(ty):
                continue
            if _USER_INPUT_ANN_RE.search(ann):
                entry_user_params.add(pname)
            elif is_http_entry and re.search(r"\bString\b", ty):
                entry_user_params.add(pname)
    if not entry_user_params:
        return None
    for m in _SQLI_WHOLE_STMT_SINK_RE.finditer(source):
        arg = m.group(1)
        # 定位 sink 所在方法段
        host = None
        for name, sig, body, off in segs:
            if off <= m.start() < off + len(body):
                host = (name, sig, body, off)
                break
        if host is None:
            continue
        hname, hsig, hbody, hoff = host
        ptypes = _param_decl_types(hsig)
        if arg not in ptypes:
            continue                  # 实参不是本段形参（局部变量/字段）
        ty = ptypes.get(arg, "")
        if _NUMERIC_JAVA_TYPE_RE.search(ty):
            return False             # 数字型形参：注入不了
        if hname == entry_name:
            if arg in entry_user_params:
                return True
            continue
        # 一跳：该辅助方法被入口以"用户输入形参"调用
        for cm in re.finditer(rf"(?<![.\w]){re.escape(hname)}\s*\(([^){{]{{0,200}})\)",
                              source):
            cargs = cm.group(1)
            for cm2 in re.finditer(r"([A-Za-z_]\w*)", cargs):
                if cm2.group(1) in entry_user_params:
                    return True
    return None


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

    # C3) MyBatis-Plus 条件构造器（Module 29，eladmin-mp 靶场形态）：
    #     拼接出口 `.apply("col = '" + x + "'")` / `.last("limit " + p)` /
    #     `.inSql(...)` 实参含拼接或裸变量 → True（显式 SQL 拼接出口）。
    #     置于 MyBatis 判定之前：拼接出口是显式注入面，优先级高于 ${}/#{}
    #     的其它证据。False 侧（纯参数化 Wrapper）在 B 之后收口（C4），
    #     避免与集合方法 `.in(`、MyBatis ${} 判定互相打架。
    if _MP_CONCAT_EXIT_RE.search(body):
        return True

    # C2b) MyBatis Generator Example 参数化（Module 38，mall 形态）：
    #     `XxxMapper.selectByExample(new XxxExample())` 是 MBG 生成的
    #     安全查询载体 —— andXxx(constraint, value) 全部走 #{} 预编译
    #     绑定，唯一的字符串替换出口是 XML 里的 `${orderByClause}`。
    #     于是机制判据精确对准这一个出口：
    #       · setOrderByClause(实参) 有一个是**非字符串字面量** → True
    #         （形参/变量拼进 ORDER BY，${} 直替 —— 经典注入面）；
    #       · 全部是字面量（`"sort desc"`）且切片无 JDBC sink → False
    #         （Example 条件绑定参数化，无注入面）。
    #     只看切片里真有 selectByExample 调用 + Example 构造 —— 接口
    #     声明段不算数（ MallExample 只是个 POJO 名字，查询载体事实在
    #     impl 段）。放 C3 之后：显式拼接出口优先级最高。
    #
    #     M64 litemall 淬火：入口形参带 **Bean Validation 白名单注解**
    #     （`@Sort(accepts={"add_time","id"})` + 类级 @Validated —— 框架
    #     在参数解析阶段强制白名单，非法值 400）时，`setOrderByClause
    #     (sort + " " + order)` 的实参变量全部在白名单里 → 不是注入面，
    #     不判 True。切片头 `[param-validated]` 标记由切片器打。
    _param_validated: set[str] = set()
    _pvm = re.search(r"//\s*\[param-validated\]\s*(.+)", source)
    if _pvm:
        _param_validated = {s.strip() for s in _pvm.group(1).split(",")
                            if s.strip()}
    _ob_safety = _ob_exit_safety(source, _param_validated)
    if re.search(r"selectByExample\w*\s*\(", source) and re.search(
            r"Example\s*\(\s*\)", source):
        if _ob_safety == "unsafe":
            return True
        if _ob_safety == "safe" and not SQLI_JDBC_SINK_RE.search(source):
            return False
        if _ob_safety == "none" and not SQLI_JDBC_SINK_RE.search(source):
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
        # M64 litemall 淬火⑤：`${orderByClause}` 是 MBG Example 的**结构
        # 性必然出口** —— 每个 Example 查询的 Mapper XML 里都有它，但它
        # 只能经 `setOrderByClause(...)` 到达。本单元可见调用链（入口体 +
        # Hop 实现体）没有任何 orderByClause 写入、Example 又是切片里
        # 现场构造的（`new XxxExample()`），XML 里的这个 ${} 就不构成
        # 本单元的注入面（delete → deleteByPrimaryKey 这种纯主键流）。
        hits = MYBATIS_DOLLAR_RE.findall(mb)
        if all(h.strip() == "${orderByClause}" for h in hits) \
                and _ob_exit_safety(source, _param_validated) == "safe":
            return False
        if all(h.strip() == "${orderByClause}" for h in hits) \
                and _ob_exit_safety(source, _param_validated) == "none" \
                and re.search(r"new\s+\w+Example\s*\(", source):
            return False
        # M156：${} 必须能被入口**形参**触达才算本单元的注入面。
        # Apollo 实测：importConfigByZip 的切片里带着别的 Mapper 语句
        # ${appId}/${namespaceName}，而这两个名字根本不在本入口签名里 ——
        # 证据段混入即判 True 是"看得见不等于够得着"的典型假阳。
        _params = set(_bare_params(_entry_signature(source)))
        _vars = {re.split(r"[.\[]", h.strip("${} "))[0] for h in hits}
        if not (_vars & _params):
            return None
        return True
    if MYBATIS_HASH_RE.search(mb) and not SQLI_JDBC_SINK_RE.search(body):
        return False

    # C4) MyBatis-Plus 纯参数化 Wrapper（Module 29 False 侧）：走到这里说明
    #     没有 MyBatis ${}/#{证据、没有 JDBC sink，body 里只有条件构造器的
    #     参数化方法（.eq/.like/...）——查询由框架参数化，判 False。
    #     放在 B 之后是刻意的：集合方法 `.in(` 与 Wrapper `.in(` 同貌，
    #     只有排除了 MyBatis 证据链后才允许这条收 False。
    if _MP_WRAPPER_RE.search(body) and not (
            SQLI_CREATE_STMT_RE.search(body)
            or SQLI_JDBCTEMPLATE_RE.search(body)
            or SQLI_JDBC_SINK_RE.search(body)):
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
    # A1) 整句 SQL 由用户控制：sink 实参是 String 型用户输入形参。
    # 放在所有既有分支**之后**：拼接形态/参数化形态的结论一律优先，
    # 本分支只接管"本来会退 None"的整句可控场景（只认 True，不覆盖
    # 任何 False —— 覆盖 False 就是把参数化查询判成有漏洞，方向反了）。
    whole = _sql_stmt_whole_user_controlled(source)
    if whole is True:
        return True
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
    nxt = _SEP.search(seg[len(_CHAIN_SEP):])
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
    nxt = _SEP.search(seg[len(_CHAIN_SEP):])
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
    # M105：接收者不再写死 `request` —— `req` / `httpServletRequest` / `servletRequest`
    # 都是同一机制的常见命名（`req.getParameter("t")` 与
    # `request.getParameter("t")` 没有任何语义差别）。判据挂的是**方法名语义**
    # （getParameter/getHeader/…），不是变量名。
    r"\b(?:req|request|httpServletRequest|servletRequest)\s*\.\s*"
    r"(?:getParameter|getParameterValues|getParameterMap|"
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


# ---------------- RuleDiagnostic：半成品事实移交 ----------------
#
# 规则退回 None 的样本仍可能带着**已经核实了一半的事实**：哪几行是外部输入、
# 哪几行是本类目的敏感汇聚点。这些是逐行可核对的静态事实，直接扔掉等于让
# 模型从零开始再扫一遍 —— 而它恰恰最容易扫错行。把事实作为**纯客观注释**
# 注入送审代码段顶部，只做"定位参考"，不替模型下结论：
#   · 不说"这两行之间有污点流"（那是模型的判断）；
#   · 不说"防护有效/无效"（同上）；
#   · 只说"这几行是输入 / 这几行是汇聚点，请独立判断中间流转与防护"。

# 每个类目的敏感汇聚点特征。只收 sink 层调用，不收中间加工 ——
# 列宽了会稀释引用价值，模型反而两头都看。
_DIAG_SINK_RES: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(
        r"prepareStatement\s*\(|createStatement\s*\(|createQuery\s*\(|"
        r"createNativeQuery\s*\(|executeQuery\s*\(|executeUpdate\s*\(|"
        r"\bexecute\s*\("),
    "cmdi": re.compile(
        r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|"
        r"\bexec\s*\(|ProcessBuilder\s*\("),
    "xss": re.compile(
        r"getWriter\s*\(|println\s*\(|print\s*\(|write\s*\(|"
        r"th:utext|innerHTML", re.I),
    "pathtraver": re.compile(
        r"new\s+File\s*\(|FileInputStream\s*\(|FileOutputStream\s*\(|"
        r"Files\s*\.\s*\w+\s*\(|getPath\s*\(|getCanonicalPath\s*\("),
    "redir": re.compile(
        r"sendRedirect\s*\(|setHeader\s*\(\s*\"Location|addHeader\s*\(\s*\"Location|"
        r"forward\s*\("),
    "ssrf": re.compile(
        r"new\s+URL\s*\(|openConnection\s*\(|openStream\s*\(|HttpClient|RestTemplate"),
    "deserial": re.compile(
        r"ObjectInputStream\s*\(|readObject\s*\(|XMLDecoder\s*\(|"
        r"parseObject\s*\(|YAML\s*\.\s*load\s*\(|fromXML\s*\("),
    "spel": re.compile(
        r"SpelExpressionParser\s*\(|parseExpression\s*\(|"
        r"StandardEvaluationContext\s*\(|evaluateExpression\s*\("),
    "xxe": re.compile(
        r"DocumentBuilder\s*\(|parse\s*\(|newSAXParser\s*\(|XMLReader\s*\("),
    "xpathi": re.compile(
        r"XPath\s*\.\s*compile\s*\(|evaluate\s*\(|newXPath\s*\("),
    "weakrand": re.compile(r"new\s+Random\s*\(|Math\s*\.\s*random\s*\("),
}


def build_solidity_diagnostic(category: str, code: str,
                              *, line_offset: int = 0) -> str:
    """Solidity 退回批的"静态前筛已核实事实"注释头（Module 21）。

    只写**确定性事实**（函数名/合约名关系、签名可见性、modifier 定义体
    是否在切片内），不写倾向性结论 —— 判定仍归模型。特别地，"modifier
    定义体不在切片内"是模型视野的真实边界：不写它，模型会把"名字叫
    onlyOwner"当保护或当缺失，两个方向都在幻想。返回空串表示没有值得
    移交的事实，调用方不拼头。
    """
    func_src, mod_block = _split_sol_modifier_block(code)
    sig = _sol_signature(func_src)
    if not sig:
        return ""
    facts: list[str] = []
    fm = re.search(r"function\s+([A-Za-z_]\w*)", sig)
    cm = re.search(r"contract:\s*(\S+)", code)
    tail = sig[sig.find(")") + 1:] if ")" in sig else sig
    vis = [v for v in ("external", "public", "internal", "private", "view",
                       "pure", "payable", "constant")
           if re.search(rf"\b{v}\b", tail)]
    _VIS_KW = {"external", "public", "internal", "private", "view", "pure",
               "payable", "constant", "returns", "virtual", "override"}
    named = [w for w in re.findall(r"\b([A-Za-z_]\w*)\b", tail) if w not in _VIS_KW]
    mod_missing = bool(named) and not mod_block
    no_vis = not vis
    # 发射纪律：模型自己看得见的事不重复移交。只有"模型看不到或易错"的
    # 事实才值得拼头：① 构造函数关系（0.4.x 语义）；② modifier 体缺失
    # （模型视野的真实边界）；③ 老语法无显式可见性（默认 public 的语义）。
    # 纯 external/public 声明 + 无其它事实 → 空串，不拼无意义头。
    if rel_eq := bool(fm and cm and cm.group(1) != "?"
                      and fm.group(1) == cm.group(1)):
        facts.append("函数名==合约名（0.4.x 构造函数，部署期执行一次，不进运行时字节码）")
    if mod_missing:
        facts.append(f"签名引用 modifier {', '.join(named[:3])} 但定义体不在切片内（无法核验实现）")
    if no_vis:
        facts.append("签名无显式可见性（老语法默认 public，外部可达）")
    if not facts:
        return ""
    return (f"// [静态前筛已核实事实] {' | '.join(facts)}"
            "（注释行不可作为证据引用，请独立判断）")


def _ob_exit_safety(source: str, validated: set[str]) -> str:
    """评估切片里全部 setOrderByClause 实参的"出口安全性"（M64）。

    返回：
      "unsafe"   —— 存在非字面量/非枚举列链/非白名单覆盖的实参（有注入面）
      "safe"     —— 全部实参是字面量 / 枚举列描述链
                    （`Xxx.Column.addTime.desc()`，固定列描述无用户数据）/
                    白名单校验覆盖（`[param-validated]` 标记）/ MBG 管道
                    定义（调用点全字面量）
      "none"     —— 切片里没有任何 setOrderByClause 写入（无可评估事实）
    """
    args = re.findall(r"setOrderByClause\s*\(([^;]*)\)", source)
    if not args:
        return "none"
    for arg in args:
        if re.fullmatch(r'\s*"[^"]*"\s*', arg):
            continue
        if re.fullmatch(r"\s*\w+(?:\.\w+)+\s*\(\s*\)\s*", arg):
            continue          # 枚举列描述链：固定列，无用户数据
        if re.fullmatch(r"\s*orderByClause\s*", arg) and re.search(
                r"public\s+\w+Example\s+orderBy\s*\(\s*String"
                r"\s+orderByClause\s*\)", source):
            ob_calls = re.findall(r"\.orderBy\s*\(([^)]*)\)", source)
            if ob_calls and all(re.fullmatch(r'\s*"[^"]*"\s*', c)
                                for c in ob_calls):
                continue      # MBG 管道定义：全部调用点为字面量
        idents = set(re.findall(r"\b([A-Za-z_]\w*)\b", arg))
        if idents and idents <= validated:
            continue          # 全部白名单校验过（Bean Validation 强制）
        return "unsafe"
    return "safe"


# ---- M67：硬编码密钥与敏感凭证泄露（hardcoded_secret） ----
#
# 真实项目审计里最常见的 P0 之一：JWT 签名密钥 / API Secret / 私钥直接
# 写死在代码里。判据挂"赋值目标 + 赋值来源"的机制：
#   True  —— 密钥型变量名（secret / private_key / signing_key / jwt_secret
#            / access_key_secret 等）被赋**字符串字面量**；JWT/会话签名
#            上下文（单元内出现 jwt.encode/decode、Jwts、Flask SECRET_KEY）
#            无长度门槛（'random' 这种短弱密钥本身就是缺陷——可猜测性
#            才是危害，不是熵）；通用密钥字面量 len ≥ 16；
#   False —— 密钥来自环境/配置读取（os.environ / os.getenv /
#            System.getenv / System.getProperty / @Value("${...}") /
#            .config.get(...)），单元只消费不定义；
#   None  —— 单元里没有密钥型标识符，或只有短通用密钥（交模型）。
#
# 变量名必须**以凭证词结尾**（secret / secret_key / jwtSecret /
# accessKeySecret / privateKey / signingKey ...）。这条锚定是 VAmPI 实测
# 逼出来的：`secret_content="secret for bookTitle"` 是书籍正文字段，不是
# 凭证；早期"标识符里含 secret 即可"的写法会把数据字段判成 P0。
_SECRET_TOKEN = (
    r"(?:jwt[_-]?secret|access[_-]?key[_-]?secret|client[_-]?secret"
    r"|api[_-]?secret|app[_-]?secret|secret[_-]?key|secretkey"
    r"|private[_-]?key|signing[_-]?key|secret)")
SECRET_ASSIGN_RE = re.compile(
    # M97：三条收紧，全部来自 waynboot `WxController.jsSdkInit` 的实测误报：
    #   ① 名字前加 `(?<![\w$])` —— 否则可以从 `appSecret` 中间起配，
    #      把末尾的 `secret` 当成名字；
    #   ② `[:=]` 两侧只允许**行内空白** `[ \t]*` —— `\s*` 会跨行，于是
    #      `appSecret;` 后面下一行的 `resultJsonStr = "https://…"` 被拼成
    #      "secret = …" 的假赋值；
    #   ③ 值不允许跨行 `[^'\"\n]` —— 同理，把下一行的字符串当成密钥值。
    # 收紧后单行写法（`SECRET_KEY = 'random'` / `app.secret_key = "123"`）
    # 一字不受影响，跨语句拼出来的幽灵密钥不再命中。
    r"(?i)(?P<name>(?<![\w$])[\w.$\[\]'\"]*?" + _SECRET_TOKEN + r")"
    r"['\"]?\]?[ \t]*[:=][ \t]*['\"](?P<val>[^'\"\n]{1,})['\"]")
SECRET_ENV_READ_RE = re.compile(
    r"\bos\s*\.\s*environ\b|\bos\s*\.\s*getenv\b|System\s*\.\s*getenv\b"
    r"|System\s*\.\s*getProperty\b|@Value\s*\(\s*\"\$\{"
    r"|\.\s*config\s*\.\s*get\s*\(", re.I)
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)your|changeit|\b123456\b|password|placeholder|dummy|example|xxxxx"
    r"|\$\{|todo|fixme|insert_|default|已脱敏|\btest\b")
SECRET_JWT_CTX_RE = re.compile(
    r"jwt\s*\.\s*(?:encode|decode)|Jwts\s*\.|create_?token"
    r"|config\s*\[[^\]\n]*SECRET_KEY|app\s*\.\s*secret_key", re.I)


def jwt_weakness_verdict(source: str) -> bool | None:
    """JWT 验签绕过（M81）：显式关验签/允许 none/未签名解析器 → True。

    Python PyJWT：
      · `jwt.decode(..., options={"verify_signature": False})` → True
      · `jwt.decode(..., verify=False)` → True
      · `jwt.decode(..., algorithms=["none"])` → True
      · 指定 HS256/RS256 且未关验签 → False（安全）
    Java JJWT/Auth0：
      · `.parseClaimsJwt(`（unsecured parser）→ True
      · `Jwts.parser().parse(` 且无 `setSigningKey` → True
      · `.setSigningKey(...).parseClaimsJws(` → False
    无 JWT 解析调用 → None。
    """
    weak = False
    seen = False
    for m in re.finditer(r"\bjwt\s*\.\s*decode\s*\(", source):
        seen = True
        args = _balanced_cond(source, m.end())
        if args is None:
            continue
        if re.search(r"[\"']verify_signature[\"']\s*:\s*False", args) \
                or re.search(r"\bverify\s*=\s*False", args) \
                or re.search(r"[\"']algorithms[\"']\s*:\s*\[[^\]]*"
                             r"[\"']none[\"']", args, re.I) \
                or re.search(r"\balgorithms\s*=\s*\[[^\]]*[\"']none[\"']",
                             args, re.I):
            weak = True
    if weak:
        return True

    # Java：未签名解析器优先于验签解析器
    if re.search(r"\.parseClaimsJwt\s*\(", source):
        return True
    if re.search(r"\.parseClaimsJws\s*\(", source):
        if re.search(r"setSigningKey|verifyWith", source):
            return False
        return None
    if re.search(r"Jwts\s*\.\s*parser\s*\(|JwtParser", source) \
            and re.search(r"\.parse\s*\(", source):
        if re.search(r"setSigningKey|verifyWith", source):
            return False
        return True
    return False if seen else None


def hardcoded_secret_verdict(source: str) -> bool | None:
    body = re.sub(r"//[^\n]*", "", source)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    if not re.search(r"(?i)secret|private_?key|signing_?key", body):
        return None                          # 不归本类目管
    assigns = list(SECRET_ASSIGN_RE.finditer(body))
    has_literal = False
    for m in assigns:
        val = m.group("val")
        if SECRET_PLACEHOLDER_RE.search(val):
            continue                          # 占位符不算泄露
        # 赋值行右侧是 env/config 读取 → 单元只消费不定义
        line_start = body.rfind("\n", 0, m.start()) + 1
        line_end = body.find("\n", m.start())
        line = body[line_start:line_end if line_end > 0 else len(body)]
        if re.search(r"(?i)[:=]\s*(?:os\.environ|os\.getenv"
                     r"|System\.getenv|System\.getProperty)", line):
            continue
        has_literal = True
        break
    if has_literal:
        # JWT/会话签名上下文无长度门槛；通用密钥 ≥ 16
        if SECRET_JWT_CTX_RE.search(body):
            return True
        if any(len(m.group("val")) >= 16
               and not SECRET_PLACEHOLDER_RE.search(m.group("val"))
               for m in assigns):
            return True
        return None                           # 只有短通用密钥 → 交模型
    # 无字面量赋值：单元从 env/config 读取密钥 → 确定性 safe
    if SECRET_ENV_READ_RE.search(body):
        return False
    return None


def build_rule_diagnostic(category: str, code: str,
                          *, line_offset: int = 0) -> str:
    """为退回 None 的 (类目, 切片) 生成一行"静态前筛已核实事实"注释头。

    扫描 `code`（含入口体，不含证据段之后的实现体 —— 与 `has_external_input`
    同口径：只报告入口自己那一段的行号），提取：
      · 候选输入行：注解绑定 / request 读取 / 包装对象取值 / 裸形参声明行
      · 候选敏感操作行：该类目的 sink 调用行

    `line_offset`：调用方把注释头拼到代码顶部后，代码整体下移 —— 拼 N 行
    头就传 offset=N，保证注释里的 L 编号与模型实际看到的行号自洽。
    返回空串表示"没有值得移交的事实"（无输入行或无 sink 行），调用方不拼。
    """
    body = entry_body(code)
    if not body:
        return ""
    sink_re = _DIAG_SINK_RES.get(category)
    src_lines: list[str] = []
    sink_lines: list[str] = []
    bare = set(_bare_params(_entry_signature(code)))
    # M65：sink 行相关性 —— 候选输入行的标识符集合（含形参），用于过滤
    # "有 sink 但无外部可控输入流向 sink" 的假候选
    input_ids: set[str] = set(bare)
    for i, ln in enumerate(body.splitlines(), 1):
        tag = f"L{i + line_offset}"
        if XSS_PARAM_RE.search(ln) or _XSS_FOREIGN_SOURCE_RE.search(ln):
            src_lines.append(tag)
            input_ids |= set(re.findall(r"\b([A-Za-z_]\w*)\b", ln))
            continue
        if any(re.search(rf"\b{re.escape(p)}\b", ln) for p in bare):
            src_lines.append(tag)
            input_ids |= set(re.findall(r"\b([A-Za-z_]\w*)\b", ln))
        if sink_re and sink_re.search(ln):
            # M65 相关性双闸门：
            # ① 括号内至少一个**非字面量**标识符 —— 纯常量实参的 sink
            #    （`new File("/var/log/app.log")`）不是候选；
            # ② 实参标识符与候选输入行标识符有**交集** —— 验证码图片流、
            #    内部生成的 URL、支付 SDK 表单这类输出与输入行毫无交集
            #    （RuoYi/My-Blog/litemall/mall 四项目实测 6 条假候选全部
            #    落在 ②上）。
            inner = ln[ln.find("("):ln.rfind(")") + 1] if "(" in ln else ln
            arg_ids = set(re.findall(r"\b([A-Za-z_]\w*)\b", inner))
            arg_ids -= {"new", "null", "true", "false", "this"}
            if not arg_ids:
                continue                      # ① 纯字面量/常量实参
            # 取实参里的标识符及其赋值链（一层）
            linked = bool(arg_ids & input_ids)
            if not linked:
                for v in arg_ids:
                    for am in re.finditer(
                            rf"\b{re.escape(v)}\s*=(?!=)[^;]*;", body):
                        if set(re.findall(r"\b([A-Za-z_]\w*)\b",
                                          am.group(0))) & input_ids:
                            linked = True
                            break
                    if linked:
                        break
            if linked:
                sink_lines.append(tag)
    if not src_lines or not sink_lines:
        return ""
    return (f"// [静态前筛已核实事实] 候选输入行: {', '.join(src_lines[:6])}"
            f" | 候选敏感操作行: {', '.join(sink_lines[:6])}"
            f"（僅供双引证定位参考，请独立判断中间流转与防护是否有效）")


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


_VENDOR_FORM_RE = re.compile(
    r"pageExecute\s*\([^)]*\)\s*\.\s*getBody\s*\(|"
    r"buildForm\s*\(|create[A-Za-z]*Form\s*\(", re.I)


def _vendor_form_response(source: str) -> bool:
    """支付 SDK 的 pageExecute/buildForm 生成表单 → 不是本方法的 XSS 回显。

    mall 实测（M74）：`response.getWriter().write(alipayService.pay(param))`
    的返回值来自 Alipay SDK `AbstractAlipayClient.pageExecute` →
    `WebUtils.buildForm`；`buildHiddenField` 对 value 只做 `"` → `&quot;`
    转义，用户可控的 `subject` 放在 `biz_content` 的 hidden input **属性值**
    里，`<`/`>` 在属性值状态不构成标签，无法逃逸。这是可逐行核对的第三方
    库事实，不交模型猜。
    """
    body = entry_body(source)
    if not re.search(r"getWriter\s*\(\s*\)\s*\.\s*write\s*\(\s*"
                     r"\w*[Ss]ervice\s*\.\s*\w+\s*\(", body):
        return False
    return bool(_VENDOR_FORM_RE.search(_all_evidence(source)))


def xss_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    if _vendor_form_response(source):
        return False

    has_param = has_external_input(source)
    # 注意用 `_chain_reader_body`（只认 cookie/session/request/model 那条证据块）
    # 而不是"有串接证据" —— db 证据块由下面的 (2b) 专门处理。
    reader = _chain_reader_body(source)

    # M156：@RestController 的 `return dto;` 是 JSON 序列化，不是 HTML 回显。
    # Apollo 的 ItemController.create/update 因此被判存储型 XSS —— 实际
    # 响应体是 application/json，浏览器不会把它当页面解析。只有真的写
    # response.getWriter()/getOutputStream() 或声明 text/html 才算回显面。
    # 只看**返回类型**：String/void/byte[] 仍可能是 HTML 回显；
    # DTO / ResponseEntity 才是 JSON 序列化。只用注解名一刀切会把
    # "返回拼接字符串"的反射型 XSS 一起洗掉（烟雾 [6]/[10] 实测）。
    _ret_m = re.search(
        r"\b(?:public|protected|private)\s+([\w<>\[\],.?]+)\s+\w+\s*\(", body)
    _ret = _ret_m.group(1) if _ret_m else ""
    _json_type = bool(_ret and _ret not in (
        "String", "CharSequence", "byte[]", "void", "Object"))
    _rest_json = bool(
        ("Controller-Kind: @RestController" in source or "@ResponseBody" in source)
        and _json_type
        and not re.search(r"getWriter\s*\(|getOutputStream\s*\(|"
                          r"produces\s*=\s*\"text/html\"", body))
    # 1) 反射型：有外部入参 + 有回显 + 无编码
    if has_param and not _rest_json and _echo_sink_hit(body):
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


# ---- M90：Python / Django 开放重定向支 ----
#
# 与 Java 支同样的两支判据：① 有没有下发 Location 的 API；② 目标是否被限制
# 为站内。但 Python 侧的"目标可控"形态和 Java 不同，必须单独写：
#
#   跳转 API：`redirect(target)` / `HttpResponseRedirect(target)` /
#            `HttpResponsePermanentRedirect(target)`（Django / Flask 同形）
#   可控来源：`request.POST['path']`、`request.GET.get('next')`、视图形参
#   安全来源：字面量、`url_for(...)` / `reverse(...)`、**以单斜杠开头的固定前缀**
#
# 判据的关键细节：`"/users/" + str(uid) + "/messages"` 与
# `"/users/%s/x" % uid` **不是**开放重定向 —— 结果必然以 `/users/` 起头，
# 换不掉 origin。所以这里认"字面量前缀"：`/` 开头、且第二个字符不是 `/`
# （`//evil.com` 是协议相对 URL，仍可换 origin）→ 直接判同源安全。
# DjanGoat 的 `sessions_index` 反例正好验证：`path = request.POST['path']`
# 整条目标都由外部决定，是真漏洞。
_PY_REDIR_SINK_RE = re.compile(
    r"(?<![\w.])(?:redirect|HttpResponseRedirect|"
    r"HttpResponsePermanentRedirect)\s*\(")
# 框架自己产 URL 的入口 —— 目标由路由名决定，不是外部字符串
_PY_REDIR_GENERATED_RE = re.compile(
    r"^\s*(?:url_for|reverse|resolve_url|get_absolute_url)\s*\(")
# 同源校验 / 白名单（Django 官方推荐的两个 API + netloc 判据）
_PY_REDIR_GUARD_RE = re.compile(
    r"url_has_allowed_host_and_scheme\s*\(|"
    r"\bis_safe_url\s*\(|"
    r"\bis_safe_redirect\s*\(|"
    r"\.\s*netloc\s*(?:==|!=)|"
    r"\ballowed_hosts\s*=|"
    r"\bALLOWED_(?:REDIRECT|HOSTS)\w*")
# 以**单个** `/` 开头的字面量前缀 → 结果必然同源
_PY_REDIR_SAME_ORIGIN_RE = re.compile(r"^\s*[rbuf]?\s*[\"']/(?!/)[^\"']*[\"']")
_PY_REDIR_LITERAL_RE = re.compile(r"^\s*[rbuf]?\s*[\"'][^\"']*[\"']\s*$")
_PY_REQUEST_READ_RE = re.compile(
    r"\brequest\s*\.\s*(?:GET|POST|FILES|cookies|headers|form|args|values|"
    r"body|data|json|query_params|META)\b")


def _py_redir_external(expr: str, body: str, params: set[str],
                       depth: int = 0) -> bool | None:
    """跳转目标是否由外部决定：True 可控 / False 固定 / None 断链。"""
    if depth > 3:
        return None
    e = expr.strip().rstrip(",").strip()
    if not e:
        return None
    if _PY_REDIR_GENERATED_RE.match(e):
        return False                     # url_for / reverse：路由名产 URL
    if _PY_REDIR_SAME_ORIGIN_RE.match(e):
        return False                     # 固定站内前缀，origin 换不掉
    if _PY_REDIR_LITERAL_RE.match(e):
        return False                     # 常量目标
    if _PY_REQUEST_READ_RE.search(e):
        return True                      # request.POST['path'] 等
    if params & set(re.findall(r"\b([A-Za-z_]\w*)\b", e)):
        return True                      # 视图形参（可被 URL 控制）
    if re.fullmatch(r"[A-Za-z_]\w*", e):
        rhs = _last_assign_rhs(body, e)
        if rhs is None:
            return None
        return _py_redir_external(rhs, body, params, depth + 1)
    return None


def _py_redir_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    if not _PY_REDIR_SINK_RE.search(body):
        return None                      # 没有跳转 API → 不归本类目管
    if _PY_REDIR_GUARD_RE.search(body):
        return False                     # 已有同源/白名单校验
    params = _py_func_params(source)
    verdicts: list[bool | None] = []
    for m in _PY_REDIR_SINK_RE.finditer(body):
        args = _ssti_call_args(body, m.end() - 1)
        if args:
            verdicts.append(_py_redir_external(args[0], body, params))
    if any(v is True for v in verdicts):
        return True
    if verdicts and all(v is False for v in verdicts):
        return False
    return None


def redir_verdict(source: str) -> bool | None:
    if _looks_python(source):
        return _py_redir_verdict(source)
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
    # 真 HTTP 客户端接收者把 url 变量交给任意方法 —— 强 sink
    # （M63 三分机制：客户端名词是"发请求"的接收者语义；Python
    # `requests.get(url)` 与 Java `httpUtil.get(url)` 都落这里）
    r"\b(?:requests|httpx|urlLib|httpClient|httpUtil|okhttp|webClient"
    r"|restTemplate|httpService)\w*\s*\.\s*\w+\s*\(\s*\w*url\w*")

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
    r"ImageIO\s*\.\s*read\s*\(|\.\s*getInputStream\s*\(\s*\)"
    # 非 HTTP 客户端的 *Service/*Utils/*Request 接收者 + url 形参 —— **弱
    # sink**：`StringUtils.hasText(linkUrl)`（空值校验）、
    # `blogService.getBlogDetailBySubUrl(subUrl)`（DB 查询）都命中这个宽
    # 形态（My-Blog 实测两例）。弱 sink 必须带 URL 旁证才成立（铁律 5）。
    # 校验谓词在方法名层面排除（has/is/check/valid 前缀是谓词语义）。
    r"|\b\w*(?:Http|http|Service|Utils|Request)\w*\s*\.\s*"
    r"(?!has[A-Z]|is[A-Z]|check[A-Z]|validat|empty|blank|equals)"
    r"\w+\s*\(\s*\w*url\w*")
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
    # M156：只认 Runtime/System 的本地库加载。裸 .load( 会把
    # appService.load(appId) 当成 Runtime.load —— Apollo 实测 2 条假阳。
    r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)|System|Runtime"
    r"|rt|runtime)\s*\.\s*load(?:Library)?\s*\(|"
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
    # M64 淬火⑨：IOUtils 读 `request.getInputStream()` 是读 **HTTP 请求体**
    # （litemall payNotify 微信回调解析），不是文件路径面 —— 排除。
    r"IOUtils\s*\.\s*(?:toByteArray|copy|toString)\s*\("
    r"(?!\s*request\s*\.\s*getInputStream)"
    r"|"
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


def _sink_call_args(line: str, start: int) -> str:
    """取 sink 调用括号内的实参文本（从 match 起点后第一个 `(` 起配平）。"""
    i = line.find("(", start)
    if i < 0:
        return line[start:]
    depth = 0
    for j in range(i, len(line)):
        if line[j] == "(":
            depth += 1
        elif line[j] == ")":
            depth -= 1
            if depth == 0:
                return line[i + 1:j]
    return line[i + 1:]


_PATH_REQUEST_READ_RE = re.compile(
    r"\brequest\s*\.\s*(?:getParameter|getParameterMap|getParameterValues|"
    r"getHeader|getQueryString|getPathInfo|getRequestURI|getInputStream|"
    r"getCookies)\s*\(", re.I)


def _path_sink_param_linked(body: str, source: str,
                            params: set[str]) -> bool:
    """路径 sink 与外部输入的相关性（M64 淬火⑧，litemall 实测）。

    sink 行（或 sink 变量的赋值链）里出现**入口形参名**才构成路径遍历面。
    litemall 的 `new FileInputStream(file)` 里 file 来自微信二维码生成的
    内部临时路径（`createWxaCodeUnlimit("goods," + goodId, ...)`），与
    username/id 等形参毫无交集 —— 形态上命中弱 sink，机制上无遍历面。
    不相关 → 交模型（不硬判 safe）。

    M69 RuoYi 实测：只看整行标识符会把局部变量 `File file = new
    File(filePath)` 里的 `file` 当成入口形参 `MultipartFile file`（同名
    遮蔽），把只会删服务端头像文件的路径判成遍历。只取 **sink 调用括号
    内的实参**，局部变量声明名不参与匹配。
    """
    if not params:
        return True                # 无形参可判 → 不设门
    for seg in (body, _sibling_methods(source)):
        for line in seg.splitlines():
            for m in PATH_SINK_RE.finditer(line):
                args = _sink_call_args(line, m.start())
                ids = set(re.findall(r"\b([A-Za-z_]\w*)\b", args))
                if ids & params or _PATH_REQUEST_READ_RE.search(args):
                    return True
                # sink 实参里的每个标识符都上溯一层赋值链（`String filePath =
                # ... + filename;` —— 参数不直接出现在实参里，但出现在
                # 它的赋值右值里）
                for v in ids:
                    for am in re.finditer(
                            rf"\b{re.escape(v)}\s*=(?!=)[^;]*;", seg):
                        if (set(re.findall(r"\b([A-Za-z_]\w*)\b",
                                           am.group(0))) & params
                                or _PATH_REQUEST_READ_RE.search(am.group(0))):
                            return True
    return False


def _path_sink_identifiers(text: str) -> set[str]:
    """所有文件 sink 语句（所在行）上出现的标识符集合（M97）。

    用于回答一个很窄的问题：入口体与 sink 语句**有没有用到同一个名字**。
    没有 ⇒ 路径与入口外部输入之间没有任何可见的关联。
    """
    out: set[str] = set()
    for m in PATH_SINK_RE.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        line = text[start: end if end >= 0 else len(text)]
        out |= set(re.findall(r"\b([A-Za-z_]\w*)\b", line))
    return out


def pathtraver_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    # Python 分支（Module 24，pygoat 实测）：裸 `open(path)` / `send_file`
    # 的路径若来自 request 输入且无清洗 → True。os.path.join(常量, 输入)
    # **不**清洗 `..` 与绝对路径（输入以 / 开头时 join 直接丢弃前缀）——
    # "有常量前缀"不构成防护。清洗只认 secure_filename / basename；
    # send_from_directory 是 Flask 专门防遍历的 API（越界即 404）→ safe。
    # Image.open 这类方法调用不算（ lookbehind 排除 `.open(`）。
    if re.search(r"(?<![\w.])open\s*\(|\bsend_file\s*\(", body):
        if re.search(r"\b(?:secure_filename|os\.path\.basename)\s*\(", body):
            return False
        if re.search(r"\brequest\s*\.\s*(?:form|args|values|files|cookies)\b", body):
            return True
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

    # M97：sink 只出现在**跨跳辅助段**里时，要求它跟入口体真有交集。
    #
    # 这是 waynboot 实测出来的形态：`DictTypeController.export` 的入口体里
    # 一个文件 API 都没有，唯一的 `new File(...)` 来自 Hop 2 的
    # `ExcelUtil.getAbsoluteFile(String filename, String path)`：
    #     String downloadPath = path + File.separator + filename;
    #     File desc = new File(downloadPath);
    # 而 `path` / `filename` 在中转层由**服务端配置 + 常量**填充（路径不是
    # 用户可控的），入口体里根本没有这些名字。判 True 是把"切片把无关实现体
    # 拼进来了"当成"用户能控制路径"。
    #
    # 判据：sink 行上的标识符与入口体标识符**零交集** ⇒ 外部输入与路径 sink
    # 无关联 ⇒ 退回 None（不硬判 False —— 我们只是看不到关联，没证明无关）。
    #
    # 反例保护：java-sec-code 的 `return getImgBase64(filepath);` 入口体里有
    # `filepath`，与 sink 行交集非空 ⇒ 不受本早退影响（回归门禁盯着这条）。
    if sink_in is not body:
        _sink_ids = _path_sink_identifiers(sink_in)
        if _sink_ids and not (_sink_ids & _path_sink_identifiers(body)):
            return None

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
    # M64 淬火⑧：路径 sink 必须与外部输入相关（sink 行/赋值链含形参）。
    # 放在全部确定性 safe 判定之后：常量上溯/规范化已证明 safe 的不受
    # 影响（My-Blog 上传的 new File(常量+Random文件名) 保持 False）；
    # 弱形态（new FileInputStream(file) 等）与形参无交集时不是本单元的
    # 遍历面 → 退 None 交模型。
    if not _path_sink_param_linked(body, source,
                                   set(_bare_params(_entry_signature(source)))):
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
    r"|StpUtil\s*\.\s*getLoginId|SecurityUtils\s*\.\s*getSubject"
    # M98：mall4j / 常见国产脚手架的 `SecurityUtils.getUser()` —— 与 Shiro 的
    # `SecurityUtils.getSubject()` 同一机制（从服务端 ThreadLocal / 会话取
    # 当前登录主体，客户端伪造不了），只是方法名不同。C 端 22 个"按
    # userId 查自己的地址/订单/购物车"的接口此前因主体源缺失整批判 True。
    r"|SecurityUtils\s*\.\s*getUser\s*\("
    r"|\bgetLoginIdAsLong\s*\(|\bgetLoginIdAsString\s*\("
    # Shiro 体系（RuoYi 实测，Module 23）：BaseController/ShiroUtils 的
    # 主体获取助手。裸 getSysUser() 只在 Shiro 项目里是主体链
    # （ShiroUtils.getSysUser → getSubject().getPrincipal()），Java 线
    # 其余靶场无此命名冲突。
    r"|ShiroUtils\s*\."
    r"|\bgetSysUser\s*\(\s*\)", re.I)

# 主体**链式取值**赋给局部变量：`Long userId = ShiroUtils.getSysUser().getUserId();`
# / `SysUser user = getSysUser();`。供 2g（主体值直接作 Service 实参）使用。
_AUTHZ_SUBJECT_CHAIN_VAR_RE = re.compile(
    r"(\w+)\s*=\s*[^;\n]*\b(?:getSysUser\s*\(\s*\)|getSubject\s*\(\s*\)"
    r"|getPrincipal\s*\(\s*\)|ShiroUtils\s*\."
    # M98：mall4j 形态 —— `String userId = SecurityUtils.getUser().getUserId();`
    # SecurityUtils 已在 `_AUTHZ_SUBJECT_RE` 里是可信主体源，但"赋给局部变量"
    # 这条正则此前没登记它，于是 2g（主体值直接作 Service 实参）整批落空，
    # C 端 22 个按主体查库的接口被当成"入参直查"判 True。
    r"|SecurityUtils\s*\.)", re.I)
# Module 38：Spring Security 服务端取主体（mall-portal 形态）——
# `memberService.getCurrentMember().getId()` 直接作 Service 实参。
# getCurrentMember 实现里是 SecurityContextHolder 取当前用户（服务端
# 事实，客户端伪造不了），机制与 getSysUser/getPrincipal 同类。链式
# 取值（无局部变量）时 2g 的"赋局部变量"落空，需单独认直接实参形态。
_AUTHZ_MEMBER_CHAIN_RE = re.compile(
    r"\bgetCurrentMember\s*\(\s*\)\s*\.\s*get\w*[Ii]d\s*\(\s*\)")

# 主体**变量名**：`NewBeeMallUserVO user = (NewBeeMallUserVO) httpSession.getAttribute(KEY);`
# 只有拿到变量名，才能查"它有没有被当作资源定位条件"。
_AUTHZ_SUBJECT_VAR_RE = re.compile(
    r"(\w+)\s*=\s*\(?\s*[A-Z][\w.]*\s*\)?\s*\w*[Ss]ession\s*\.\s*getAttribute\s*\(")

# 认证入口（登录/注册/验证码）。它们本身就是**建立身份**的地方，
# 不做授权判定 —— 把 `login(loginName, password)` 的入参当成"直查资源"
# 会稳定误报（旧判据下 newbee-mall 的 /login 与 /register 都判 True）。
#
# `logout` **不**在此列：注销是"使用/销毁当前身份"，不是"建立身份"，走正常判据链
#   · 主体自己的 token/session 作资源键（`logout(adminUser.getAdminUserId())`）
#     → 2b 判 False；
#   · 接收外部可控 userId 注销他人会话且无主体 → 4) 判 True；
#   · 只 `session.invalidate()` / `removeAttribute` 的 → 证据不足退 None。
# 旧口径把 logout 一并排除，newbee-mall-api 的 /manage-api/v1/logout 因此静默退回。
_AUTHZ_AUTHN_ROUTE_RE = re.compile(
    r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?\{?[^)]{0,200}?"
    r"\"(?:/?(?:admin/)?(?:login|register|signin|signup|kaptcha|captcha))\"", re.I)

# 声明式角色/权限校验。注解在方法签名上，`entry_body` 里看不到，必须扫 source。
_AUTHZ_ROLE_RE = re.compile(
    r"@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed"
    r"|@RequiresRoles|@RequiresPermissions|@PreFilter|@PostFilter"
    # M97：国产主流鉴权框架 **Sa-Token**。注解式（`@SaCheckPermission` /
    # `@SaCheckRole` / `@SaCheckLogin` / `@SaIgnore`）在方法签名上，
    # `entry_body` 里看不到，必须扫 source；编程式 `StpUtil.checkXxx()`
    # 与注解同义（会话身份已在 StpUtil 里）。
    r"|@SaCheckPermission|@SaCheckRole|@SaCheckLogin|@SaCheckSafe"
    r"|@SaCheckDisable|StpUtil\s*\.\s*check(?:Permission|Role|Login|Safe|Disable)"
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
    # M153：Servlet 常量写法（kkFileView）—— sendError(SC_UNAUTHORIZED)
    # 与字面量 401 同义；只认数字会让共享密钥门的拒绝分支看不见。
    r"\.\s*sendError\s*\(\s*(?:40[13]"
    r"|(?:javax\.servlet\.http\.)?HttpServletResponse\s*\.\s*"
    r"SC_(?:UNAUTHORIZED|FORBIDDEN))", re.I)

# 资源访问：Mapper / Repository / DAO 上的方法调用。
_AUTHZ_RESOURCE_RE = re.compile(
    r"\b\w*(?:Mapper|Repository|Dao|DAO|Service)\s*\.\s*\w+\s*\(", re.I)

# 前缀级鉴权拦截器：`addPathPatterns("/admin/**")`。它由框架层统一拦，
# 方法体里看不到任何主体判断 —— 这正是设计上"全局鉴权覆盖 → None"的情形。
# 必须与 `/**` 的通用拦截器区分：后者多半只做计数/编码，不构成鉴权。
_AUTHZ_GLOBAL_GUARD_RE = re.compile(
    r'addPathPatterns\(\s*"\s*/(?!\*\*)[\w-]+/\*\*\s*"\s*\)')


# 除 `_AUTHZ_DENY_RE` 之外的终止写法：返回失败结果对象。
# 只在"已经比对了资源归属"的前提下使用（见 2e），不单独构成校验证据。
_AUTHZ_ABORT_EXTRA_RE = re.compile(
    r"\w*Result\w*\s*\.\s*gen\w*(?:[Ff]ail|[Ee]rror)\w*\s*\("
    r"|\breturn\s+\w+\s*\.\s*(?:fail|error)\w*\s*\("
    r"|\bthrow\s+new\s+\w+", re.I)


# 会话自毁类调用：只针对**当前请求自身**的会话/凭据，不触及其它主体。
_LOGOUT_DESTROY_RE = re.compile(
    r"\.\s*invalidate\s*\(\s*\)"
    r"|\.\s*removeAttribute\s*\("
    r"|SecurityUtils\s*\.\s*getSubject\s*\(\s*\)\s*\.\s*logout\s*\("
    r"|SecurityContextLogoutHandler\s*\(\s*\)\s*\.\s*logout"
    r"|\.\s*logout\s*\(\s*\)", re.I)
# 注销/删凭据类调用（实参里可能带主键 —— 主体自己的 id 算安全，外部裸形参不算）。
_LOGOUT_CRED_CALL_RE = re.compile(
    r"\.\s*(?:logout|deleteToken|removeToken|destroyToken|destoryToken)\s*\(", re.I)


def _ownership_compared(body: str, subject: str) -> bool:
    """主体 id 是否在 `if (` 里与**另一个对象**的 id 做过比较。

    三件事实：① 条件里出现 `subject.getXxxId()`；② 条件里还出现**另一个变量**
    的 id 取值（`user.getUserId().equals(user.getUserId())` 自比不算校验，
    `!user.getUserId().equals(addr.getUserId())` 才算）；③ 位置在 `if` 条件内。

    用「取 if 条件体再查」而不是一条长正则：长度正则写不对就会漏掉
    `Objects.equals(a, b)` 这种非 `equals` 调用形态，而漏掉的表现是
    「规则退回 None」—— 静默、不报错。
    """
    k = rf"\b{re.escape(subject)}\s*\.\s*get\w*[Ii]d\s*\(\s*\)"
    for m in _IF_RE.finditer(body):
        cond = _balanced_cond(body, m.end())
        if not cond:
            continue
        if re.search(k, cond):
            others = set(re.findall(
                r"([A-Za-z_]\w*)\s*\.\s*get\w*[Ii]d\s*\(\s*\)", cond))
            if others - {subject}:
                return True
            continue
        # M98：主体 id 已经**落到局部变量**上的形态（mall4j 实测）。
        #     `String userId = SecurityUtils.getUser().getUserId();`
        #     `if (!Objects.equals(order.getUserId(), userId)) throw …`
        # 此时条件里没有 `subject.getXxxId()`，只有裸变量 userId ——
        # 上面那条 `k` 正则接不住，而这是"归属写死在 Controller 里比对"
        # 的标准写法之一（另一侧仍是**另一个对象**的 id 取值）。
        if re.search(rf"\b{re.escape(subject)}\b", cond):
            others = set(re.findall(
                r"([A-Za-z_]\w*)\s*\.\s*get\w*[Ii]d\s*\(\s*\)", cond))
            if others:
                return True
    return False


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


_AUTHZ_PUBLIC_WRITE_RE = re.compile(
    r"\b(?:insert|update|delete|remove|save|upload|create|edit|modify)\w*\s*\(",
    re.I)
_AUTHZ_ADMIN_PREFIXES = ("/admin", "/sys", "/system", "/manage", "/monitor")
# 用户私有资源：这些 Service/Mapper 背后是"归属于某个主体"的表。命中即不是
# 公共目录 —— 只读也一样（`orderService.getOrderByOrderNumber` 就是真实 IDOR 面）。
_AUTHZ_PRIVATE_RES_RE = re.compile(
    r"\b(?:order|cart|address|addr|user|account|wallet|pay|member)\w*"
    r"\s*(?:Service|Mapper|Dao|DAO)\b|\buser_?id\b|\bmember_?id\b"
    r"|\bbuyer_?id\b", re.I)
# M104：**正面**目录白名单。这一条是"公共目录"的**必要证据**，不是可选加分。
#
# 教训（M104 第一版）：曾用"不含私有资源词"作判据 —— 那是**否定式**，任何
# 认不出的查询都会落进来，于是冒烟里三条本该 True/None 的样本（裸形参直查、
# 非 Unique 命名、垂直越权视图路由）全被翻成 False。否定式证据在安全判定里
# 永远不够用：看不见 ≠ 不存在。
#
# 现在要求**先认出它是目录**：路由前缀或 Service/Mapper 名里出现商品/公告/
# 验证码/分类/品牌/轮播/搜索这类**全站共享**的实体名。认不出就照原样走
# True/None，绝不因为"没提 user_id"就判安全。
_AUTHZ_CATALOG_RES_RE = re.compile(
    r"\b(?:prod|product|goods|goodsInfo|sku|spu|notice|noticeInfo|captcha"
    r"|category|cate|brand|banner|advert|advertisement|seckill|flashsale"
    r"|comment|review|search|dict|config)\w*\s*(?:Service|Mapper|Dao|DAO)\b",
    re.I)
_AUTHZ_CATALOG_ROUTE_RE = re.compile(
    r"(?i)^/(?:prod|product|goods|sku|spu|notice|captcha|category|cate|brand"
    r"|banner|advert|seckill|flashsale|comment|search|dict|config|home|index)"
    r"(?:/|$)")


def _is_public_catalog_read(source: str, body: str) -> bool:
    """公共目录只读查询判定（M104）。

    四件事实缺一不可：
      ① 无写动作；
      ② 非管理端路由；
      ③ 不碰用户私有资源（order/cart/address/user/... 或 user_id 条件列）；
      ④ **正面认出它是目录**（路由前缀或 Service/Mapper 名命中文档实体）。

    第 ④ 条是必要条件、且是**正面证据**：认不出就不豁免。否定式判据
    （"没提 user_id 就算公共"）会把所有认不出的查询判成安全，M104 第一版
    正是这么把三条冒烟护栏翻红的。
    """
    if _AUTHZ_PUBLIC_WRITE_RE.search(body):
        return False
    rm = re.search(r"//\s*Full-Route:\s*(\S+)", source)
    route = (rm.group(1) if rm else "")
    if any(route.lower().startswith(p) for p in _AUTHZ_ADMIN_PREFIXES):
        return False
    if _AUTHZ_PRIVATE_RES_RE.search(body):
        return False
    return bool(_AUTHZ_CATALOG_RES_RE.search(body)
                or (_route_check_catalog(route)))


def _route_check_catalog(route: str) -> bool:
    """路由前缀是否指向全站共享目录（M104 的正面证据之一）。"""
    return bool(route) and bool(_AUTHZ_CATALOG_ROUTE_RE.match(route))


# 全局鉴权拦截器：名字带鉴权语义 + 注册在 `/**` 或前缀上（M110）。
_AUTHZ_AUTH_INTERCEPTOR_RE = re.compile(
    # `new X()` 与裸注入 `x` 两种写法都要认：xxl-job 写的是
    # `addInterceptor(new CookieInterceptor())`，缺了可选的 `()` 就漏。
    r"addInterceptor\s*\(\s*(?:new\s+)?([A-Za-z_]\w*)\s*(?:\(\s*\))?\s*\)"
    r"\s*[^;]{0,120}?addPathPatterns\s*\(", re.S)


def _authz_auth_interceptor(source: str) -> bool:
    """装配证据里是否有**名字带鉴权语义**的全局拦截器（M110）。

    机制：Spring 的 `HandlerInterceptor` 只要注册在路由上就会对匹配的请求
    生效；名字里带 permission/auth/login/token/security/jwt/sso/oauth 的
    拦截器，其职责就是鉴权（这是框架层的命名约定，不是业务猜测）。

    刻意**不看**通用拦截器（encoding/metrics/trace/log）：那类拦截器不鉴权，
    把它们当保护会把所有"靠全局拦截器"的项目一律豁免成 None，等于把判据关掉。
    """
    for m in _AUTHZ_AUTH_INTERCEPTOR_RE.finditer(source):
        name = m.group(1).lower()
        if any(t in name for t in ("permission", "auth", "login", "token",
                                   "security", "jwt", "sso", "oauth",
                                   "session")):
            return True
    return False


def _drf_authz_verdict(source: str, body: str, action: str) -> bool | None:
    """DRF 类视图的鉴权判定（M121）。

    DRF 把鉴权声明放在**类属性** `permission_classes` 上，方法体里看不到 ——
    切片器已把它写进头部（`// Permission-Classes:` + `// View-Action:`）。

    判据分读写两种动作，因为它们的安全含义完全不同：

      · **读动作**（`list`/`retrieve`/`get`）：`AllowAny` /
        `IsAuthenticatedOrReadOnly` / `IsAuthenticated` 都表示"这个读是被允许的"，
        django-realworld 的 `ArticleViewSet.retrieve` 就是公开读 → **False**。
      · **写动作**（`create`/`update`/`partial_update`/`destroy`/`post`/…）：
        `IsAuthenticated` / `IsAuthenticatedOrReadOnly` 只要求**登录**，不核对
        **归属** —— 任何登录用户都能改别人的文章，这是 BOLA → **True**。
        只有 `IsAdminUser` / `IsOwnerOrReadOnly` / `IsAuthorOrReadOnly`，
        或方法体里出现 `request.user` 与资源属主的比较，才算核对了归属 → False。

    "只要求登录 ≠ 核对归属"这条区分是本判据的核心：把它混为一谈，
    要么给 django-realworld 报假阳（retrieve），要么漏掉真阳（update）。
    """
    perms = ""
    pm = re.search(r"//\s*Permission-Classes:\s*(.+)", source)
    if pm:
        perms = pm.group(1).strip()
    pl = perms.lower()
    reads = {"list", "retrieve", "get"}
    writes = {"create", "update", "partial_update", "destroy",
              "post", "put", "patch", "delete"}
    act = action.lower()
    if act in reads:
        if any(t in pl for t in ("allowany", "isauthenticated",
                                 "isadminuser")):
            return False
        return None
    if act not in writes:
        return None
    # 显式核对归属的三条证据
    if any(t in pl for t in ("isadminuser", "isownerorreadonly",
                             "isauthororreadonly", "isowner")):
        return False
    if re.search(r"request\s*\.\s*user\b[^;\n]{0,80}?(?:!=|==)"
                 r"|\b(?:!=|==)[^;\n]{0,80}?request\s*\.\s*user\b", body):
        return False
    if re.search(r"\.\s*author\b[^;\n]{0,60}(?:!=|==)[^;\n]{0,60}"
                 r"request\s*\.\s*user", body):
        return False
    # **先取现成资源**才谈得上越权。`create` / "收藏" / "关注" / 登录注册
    # 都不从 queryset 取别人的对象 —— 结构上没有可被越权的资源，
    # 判 True 只会造出一批假阳（django-realworld 实测 8 条里只有 1 条真）。
    if not re.search(r"self\s*\.\s*queryset\s*\.\s*get\s*\("
                     r"|self\s*\.\s*get_object\s*\("
                     r"|\bget_object_or_404\s*\(", body):
        return False
    if "isauthenticated" in pl:
        return True                    # 登录即可写 = 未核对归属
    if "allowany" in pl:
        return True                    # 匿名即可写
    return None


def authz_verdict(source: str) -> bool | None:
    """越权/未授权的确定性判定：False(有校验) / True(入参直查且无主体) / None。"""
    body = entry_body(source)
    if not body:
        return None

    # M121：DRF 类视图（切片头带 `// View-Action:`）走专门的口径。
    _va = re.search(r"//\s*View-Action:\s*(\w+)", source)
    if _va:
        return _drf_authz_verdict(source, body, _va.group(1))

    # 0) 认证入口本身不做授权判定。登录接口的"资源"就是凭据库，身份由口令校验
    #    建立；把 `login(loginName, password)` 的入参当成"直查资源"是口径错误。
    #    logout 不在此列（"使用身份"≠"建立身份"，见正则上方注释）。
    if _AUTHZ_AUTHN_ROUTE_RE.search(body):
        return None

    # 0b) @AnonymousAccess 显式匿名声明（eladmin-mp 形态，Module 29）：
    #     作者把接口设计为匿名可达，"未授权访问"是设计意图不是缺陷——
    #     与登录入口同语义，不做授权判定，退 None。
    if "@AnonymousAccess" in source:
        return None

    # 1a) FastAPI `Depends(require_superuser)` / `Depends(get_current_user)`
    #     是框架级认证/权限依赖（M80 实测）。依赖名必须是认证语义；
    #     只认 `Depends(get_db)` 这类资源依赖时不得误判安全。
    # M154：必须扫 source —— 路由级 dependencies 与 Annotated 别名都展开在
    # 切片头部的 Auth-Dependency 证据里，不在 entry_body 内。
    if re.search(r"Depends\s*\(\s*(?:require|get_current|current_user|auth"
                 r"|permission|login_required)\w*", source, re.I):
        return False

    # 1a-3) xxl-job 的 @XxlSso 注解（M170）：
    #   @XxlSso(role = Consts.ADMIN_ROLE) 是管理员角色门 -> False；
    #   @XxlSso(login = false) 是作者显式声明的匿名入口 -> None（设计意图，
    #   不按"缺鉴权"判 True）。
    if "@XxlSso" in source:
        if re.search(r"@XxlSso\s*\([^)]*login\s*=\s*false", source):
            return None
        if re.search(r"@XxlSso\s*\([^)]*role\s*=", source):
            return False

    # 1a-4) xxl-job 的 JobGroupPermissionUtil.validJobGroupPermission：
    #   用当前登录用户的 jobGroup 权限校验目标 group；机制等价于资源归属
    #   校验（不是"知道是谁"，而是"这个组归不归你管"）。
    if re.search(r"validJobGroupPermission\s*\(", body):
        return False
    # triggerJob 用 loginCheckWithAttr 建立身份，再把 loginInfo 交给
    # Service 做 group 权限判定；切片里看不到 Service 实现，判 None。
    if re.search(r"XxlSsoHelper\s*\.\s*loginCheckWithAttr\s*\(", source):
        return None

    # 1) 声明式校验：`@PreAuthorize("hasRole('ADMIN')")` 这类。
    #    注解不在 entry_body 里，必须扫整份切片 —— 但只在**入口方法自身**
    #    的注解范围内找，避免把同文件别的方法的注解算到当前路由头上。
    if _AUTHZ_ROLE_RE.search(source):
        return False

    # 1a-2) 认证由**部署 profile** 决定的仓库（M156 Apollo）：
    # anyRequest().hasAnyRole(...) 只在 auth/ldap/oidc profile 下生效，
    # 默认配置直接放行。没有方法级 @PreAuthorize 的入口，静态切片无法
    # 证明"线上缺鉴权"——退 None，不判 True。
    if "[auth-profile-dependent]" in source:
        return None

    # 1b) 共享密钥门（M153 kkFileView 实测）：
    #         if (WebUtils.validateKey(key)) { response.sendError(401); return; }
    #     谓词实现是 `return !"false".equals(configKey) && !configKey.equals(key)`
    #     —— 服务端配置值参与比较，客户端伪造不了，机制与主体鉴权同类。
    #     判据必须看**实现体**（切片证据段里有 configKey.equals），只认
    #     validateKey 这个名字等于"认名字不认机制"。
    if _AUTHZ_DENY_RE.search(body):
        for pm in re.finditer(
                r"if\s*\(\s*!?\s*([\w.]+)\s*\(\s*(\w+)\s*\)\s*\)", body):
            var = pm.group(2)
            if re.search(
                    rf"(?:config|expected|stored|server|secret)\w*\s*\.\s*"
                    rf"equals\s*\(\s*{re.escape(var)}\b", source, re.I):
                return False

    # 2) 主体获取 + 拒绝分支。两个条件缺一不可：
    #    只取主体不比对（`log.info(currentUser)`）不构成校验；
    #    只比对不拒绝（`if (!ok) log.warn(...)`）也不构成校验。
    has_subject = _AUTHZ_SUBJECT_RE.search(body) is not None
    if has_subject and _AUTHZ_DENY_RE.search(body):
        return False

    # 形参注入的主体：`@TokenToMallUser MallUser loginMallUser`。
    # 它只证明"知道当前用户是谁"，**不构成任何校验** —— 所以只并进
    # "主体变量"集合，供下面三条"主体参与资源选择"的判据使用。
    ann_params = parse_subject_params(source)
    subject_vars = set(_AUTHZ_SUBJECT_VAR_RE.findall(body)) | set(ann_params.values())
    has_any_subject = has_subject or bool(ann_params)

    # 2b) 主体标识被当作**资源定位条件** —— 校验下沉到 Service/Mapper 的
    #     `where user_id = ?` 里，控制器侧没有 if/throw：
    #
    #         getOrderDetailByOrderNo(orderNo, user.getUserId())
    #         item.setUserId(user.getUserId());  再落库
    #
    #     这是可逐行核对的事实（主体值参与了资源选择），比"有没有拒绝分支"
    #     更贴近真实写法。newbee-mall 的订单详情 / 取消 / 购物车增改都是这一形态。
    if has_any_subject:
        for var in subject_vars:
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
    if has_any_subject:
        for var in subject_vars:
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
    if has_any_subject:
        for var in subject_vars:
            key = rf"\b{var}\s*\.\s*get\w*[Ii]d\s*\(\s*\)"
            for pm in re.finditer(
                    rf"\b(\w+)\s*\.\s*(?:put|putAll|add)\s*\("
                    rf"\s*\"[^\"]*\"\s*,\s*{key}\s*\)", body):
                if _container_flows_to_service(body, pm.group(1)):
                    return False

    # 2g) 主体值经链式取值赋给局部变量，再**直接作为 Service 实参**
    #     （RuoYi 实测形态，Module 23）：
    #
    #         Long userId = ShiroUtils.getSysUser().getUserId();
    #         noticeReadService.markRead(noticeId, userId);   // 标记"自己"已读
    #         SysUser user = getSysUser();
    #         return passwordService.matches(user, password); // 校验"自己"的密码
    #
    #     资源操作的主键来自会话主体——markRead 是"把自己标记为已读"，
    #     checkPassword 是"验证当前会话用户的密码"——没有可被水平越权的
    #     他人资源键。判 False 需要：① 确有主体获取（has_any_subject）；
    #     ② 主体链取值赋给局部变量；③ 该变量出现在 Service/Mapper 调用
    #     实参里。三者缺一会把"客户端 DTO 自带 userId"（checkXxxUnique
    #     的 user.getUserId()，RuoYi 同文件就有）误当主体——那个不能进
    #     这条，所以正则只认 getSysUser/getSubject/getPrincipal/ShiroUtils
    #     这四个可信源，裸 getUserId() 不算。
    if has_any_subject:
        subj_local = set(_AUTHZ_SUBJECT_CHAIN_VAR_RE.findall(body))
        if subj_local:
            for sm in re.finditer(
                    r"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\(([^;]{0,240})",
                    body):
                if any(re.search(rf"\b{v}\b", sm.group(1)) for v in subj_local):
                    return False

    # 2g-2) Spring Security 服务端主体链直接作实参（mall-portal 形态，
    #     Module 38）：`memberService.getCurrentMember().getId()` 作为
    #     Service 实参 —— 资源操作的主键来自服务端会话主体，没有可被
    #     水平越权的他人资源键。getCurrentMember 的实现（mall-security
    #     UserService）从 SecurityContextHolder 取当前登录用户，客户端
    #     伪造不了 —— 机制与 2g 的四个可信源同类，只是链式直接进实参、
    #     没有局部变量中转，2g 的"赋局部变量"形态接不住。
    for sm in re.finditer(
            r"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\(([^;]{0,240})",
            body):
        if _AUTHZ_MEMBER_CHAIN_RE.search(sm.group(1)):
            return False

    # 2h) 只读唯一性校验助手（RuoYi checkXxxUnique 实测形态，Module 28）：
    #
    #         @PostMapping("/checkLoginNameUnique")
    #         public boolean checkLoginNameUnique(SysUser user) {
    #             return userService.checkLoginNameUnique(user);
    #         }
    #
    #     返回值只是 boolean 存在性（"0"/"1" 语义），不回显数据库实体详情、
    #     不执行写操作——前端表单重复性提示，水平越权面为零。判 False 需要
    #     三个可核对的事实缺一不可：① 入口签名返回 boolean；② body 无写
    #     操作（insert/update/delete/save/remove/add）；③ 对 Service/Mapper
    #     的**全部**调用都是 check*Unique 形态——有一条别的 Service 调用
    #     （如 selectMenuById、checkCronExpressionIsValid）就不豁免，
    #     那些是未标注授权的实体读取面，维持 True 单列供人工复核。
    if (re.search(r"public\s+boolean\s+\w+\s*\(", source)
            and not re.search(r"\b(?:insert|delete|update|save|remove|add)"
                              r"\w*\s*\(", body, re.I)
            and re.search(r"\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*"
                          r"check\w*Unique\s*\(", body)
            and not re.search(r"\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*"
                              r"(?!check\w*Unique\b)\w+\s*\(", body)):
        return False

    # 2e) 主体 id 与**查回来的资源**的归属字段做相等比较，且比对为真时终止请求：
    #
    #         MallUserAddress addr = service.getMallUserAddressById(addressId);
    #         if (!loginMallUser.getUserId().equals(addr.getUserId())) {
    #             return ResultGenerator.genFailResult(...);   // 或 throw
    #         }
    #
    #     这是水平越权最标准的防护写法，却正好落在前面几条的缝里：
    #     资源查询的实参里没有主体 id（2b 落空）、没有 setter（2b-2 落空）、
    #     没有容器（2c 落空），而拒绝动作常写成 `genFailResult`，
    #     不在 `_AUTHZ_DENY_RE` 认的那几种里。newbee-mall-api 的
    #     deleteAddress / getMallUserAddress 两条就这么被判成"证据不足"。
    #
    #     三件可核对的事实缺一不可：
    #       ① 比较的一侧是主体变量的 getXxxId()
    #       ② 另一侧是**另一个对象**的取值（自己跟自己比不构成任何校验）
    #       ③ 比较在 `if (` 条件里，且方法内存在终止动作（只比对只打日志不算）
    if has_any_subject:
        abort = (_AUTHZ_DENY_RE.search(body) is not None
                 or _AUTHZ_ABORT_EXTRA_RE.search(body) is not None)
        if abort:
            for var in subject_vars:
                if _ownership_compared(body, var):
                    return False

    # 2d) 主体由**被调方**获取：控制器把 `HttpSession` / `HttpServletRequest`
    #     原样传给 Service，由 Service 内部 `session.getAttribute(...)` 取当前用户
    #     再按该 userId 查库（newbee-mall `updateUserInfo` 就是这一形态）。
    #     方法体内没有主体变量可查，但**也没有把入参当资源键**——证据不足，退回 None。
    #     注意不能据此判 False：`paySuccess(orderNo, payType)` 这种既不取主体、
    #     也不传会话的才是真越权，它不会命中这一条。
    if not has_any_subject and re.search(
            r"\b\w*(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\([^;]{0,160}?"
            r"\b\w*[Ss]ession\b", body):
        return None

    # 3) 角色常量比对：`if ("admin".equals(currentUsername))`
    #    这是垂直越权安全样本的写法（JavaSecLab VerticalController.safe）。
    if has_any_subject and re.search(
            r"\"(?:admin|ADMIN|ROLE_\w+)\"\s*\.\s*equals\s*\(", body):
        return False

    # 4) 入参被**原样**用作资源查询条件，且方法内没有任何主体获取 → 水平越权。
    #    判据要求两个事实同时成立，任一缺失就退回 None：
    #      a) 有 Mapper/Repository/Service 调用，且实参里出现裸形参
    #      b) 方法内没有从可信上下文取主体的语句
    #      c) 该路由没有被前缀级鉴权拦截器整体覆盖（后台 `/admin/**`）
    params_sig = _entry_signature(source)
    params = _bare_params(params_sig)
    if params and not has_any_subject and _AUTHZ_RESOURCE_RE.search(body) \
            and not _AUTHZ_GLOBAL_GUARD_RE.search(source):
        # 4-豁免）仓库级全局鉴权机器标记（Module 38）：切片头有
        # "全局鉴权：Spring Security 过滤器统一认证"标记时，认证由
        # JwtAuthenticationTokenFilter 统一强制 —— controller 逐方法
        # 的"无主体形参直查"不再构成"未授权访问"结论，降 None。
        # （mall-admin 全部 controller 都无方法级注解，但未登录请求在
        # 过滤器层就被 401；不豁免会把整个安全的生产级项目判成漏洞。）
        if "[global-authz]" in source:
            return None
        # 4-豁免）**全局鉴权拦截器**（M110，jeecg-boot/xxl-job 实测形态）。
        #
        # 装配证据里出现"名字带鉴权语义的拦截器注册在 /** 上"：
        #     [interceptor] interceptor urlPatterns=['/**'] 来源 WebMvcConfig.java
        #     registry.addInterceptor(permissionInterceptor).addPathPatterns("/**");
        #     registry.addInterceptor(cookieInterceptor).addPathPatterns("/**");
        #
        # xxl-job 的 160 个后台接口全部靠这个 `PermissionInterceptor` 统一拦，
        # controller 方法体里一个主体判断都没有 —— 方法层看不见 ≠ 没有鉴权。
        # 与 `[global-authz]` 同一口径：**退 None，不判 False**（静态切片无法
        # 证明拦截器实现真的会拒绝）。
        #
        # 只认**名字里带鉴权语义**的拦截器（permission/auth/login/token/
        # security/jwt/sso/oauth）。`encodingInterceptor` / `metricsInterceptor`
        # 这类通用拦截器不算 —— 那正是 `_AUTHZ_GLOBAL_GUARD_RE` 当初排除
        # `/ **` 的理由，现在用"名字语义"把这个口子补回来。
        if _authz_auth_interceptor(source):
            return None
        # M64 litemall 淬火⑦：显式 token 鉴权模块 —— 模块鉴权模型是
        # "逐路由显式声明主体"（@LoginUser resolver），未声明主体的路由
        # 就是匿名面（C 端浏览），形参直查不构成"缺鉴权"结论。
        if "[explicit-auth-module]" in source:
            return None

        # 4-豁免）**公共目录只读查询**（M104，mall4j 实测形态）。
        #
        # 判据挂"被查的到底是什么资源"，不挂路由名。三件可核对的事实缺一不可：
        #   ① 纯读：方法体里没有任何写动作（insert/update/delete/save/remove/
        #      upload/create/edit/modify 一个都没有）；
        #   ② 非管理端：`// Full-Route:` 不以 /admin /sys /system /manage
        #      /monitor 开头；
        #   ③ 资源不属任何主体：方法体里既不取当前主体（本分支已由
        #      `not has_any_subject` 保证），也不碰用户私有资源
        #      （order/cart/address/user/account/wallet/pay/member 的
        #      Service/Mapper），更不含 user_id/member_id/buyer_id 条件列。
        #
        # 为什么判 False 而不是 None：authz 类目问的是"访问**归属于某个主体**
        # 的资源有没有核对归属"。商品详情、公告、验证码、销量榜是全站共享的
        # 公共目录 —— **不存在"A 用户越权读 B 用户商品"这个定义**，越权面为零。
        #
        # 反例保护（必须留在 True / None）：
        #   · `DeliveryController.checkDelivery` —— 按 orderNumber 查**订单**
        #     （order 命中私有资源词），猜单号就能查别人的物流 → 真 IDOR；
        #   · 后台 `FileController.upload*` —— 有 upload 写动作 → ①不过；
        #   · 任何带主体的接口 —— 根本进不到本分支。
        if _is_public_catalog_read(source, body):
            return False

        # M63 My-Blog 淬火：**公开内容路由豁免**。类目 sink 定义是"访问
        # 归属于某个主体的资源"—— 博客文章/标签/分类/搜索页按内容主键
        # 查公开内容（/blog/{id}、/tag/{name}、/search），匿名访问本来就是
        # 设计意图，不构成越权面；RuoYi 的 /system/** 后台路由不受此豁免。
        # 判别信号 = 路由语境（内容型前缀 / 根级单段通配 {subUrl}），
        # 与 M15 的主体命名语义同一口径。豁免 → None（不硬判安全）。
        _rp = (re.search(r"//\s*(?:Full-Route|Alias-Route):\s*(\S+)", source)
               or [None, ""])[1] if False else ""
        _rpm = re.search(r"//\s*(?:Full-Route|Alias-Route):\s*(\S+)", source)
        _rp = _rpm.group(1) if _rpm else ""
        if re.match(r"(?i)^/(?:blog|article|post|news|tag|category|archives"
                    r"|search|about|link)(?:/|$)", _rp) \
                or re.fullmatch(r"/\{[^}]+\}", _rp):
            return None

        for m in _AUTHZ_RESOURCE_RE.finditer(body):
            args = _balanced_cond(body, m.end())
            if args is None:
                continue
            for a in _split_args(args):
                a = a.strip()
                if re.fullmatch(r"[A-Za-z_]\w*", a) and a in params:
                    return True

    # 2f) 会话自毁分支：logout / signout 入口的**全部动作**只是销毁当前请求
    #     自己的会话与凭据 ——
    #
    #         session.invalidate();
    #         session.removeAttribute("loginUser");
    #         SecurityUtils.getSubject().logout();
    #         new SecurityContextLogoutHandler().logout(request, response, auth);
    #
    #     没有任何"外部可控主键被交给注销/删凭据"的调用 → 判 False。
    #     放在分支 4 之后：`userService.logout(userId)` 这种把外部裸形参送进
    #     注销的形态在 4) 已判 True（无主体）—— 2f 不能把它翻成安全。
    #     带主体的 `xxx.logout(adminUser.getAdminUserId())` 早已被 2b 判 False。
    #     两者都没命中而凭据调用实参不可解析时，不表态（退 None）。
    if _LOGOUT_DESTROY_RE.search(body):
        # 路由/方法名是否为 logout：方法名取入口体的第一个调用头（与
        # `_entry_signature` 同一正则，取 group(0) 里的名字）；路由取入口
        # 注解行。两者任一命中即可 —— 同一机制有两种命名位。
        head = source.split("// ----", 1)[0]     # 注解 + 签名（不含证据段）
        mm = re.search(r"(?<![@\w])\b([A-Za-z_]\w*)\s*\(", body)
        method_name = (mm.group(1) if mm else "")
        route_name = ""
        for am in re.finditer(
                r"@(?:Request|Get|Post|Put|Delete|Patch)Mapping\s*\([^)]*\)", head):
            route_name += am.group(0)
        gate = f"{method_name} {route_name}".lower()
        if re.search(r"\blog\s?out\b|\bsign\s?out\b", gate):
            suspicious = False
            for cm in _LOGOUT_CRED_CALL_RE.finditer(body):
                cargs = _balanced_cond(body, cm.end())
                if not cargs or not cargs.strip():
                    continue                  # 无实参：销毁自身凭据
                if any(a.strip() in params for a in _split_args(cargs)):
                    suspicious = True         # 外部裸形参被交给注销/删凭据
                    break
                # 实参存在但解析不出裸形参 → 不在 2f 下结论
                if not any(re.fullmatch(r"[A-Za-z_]\w*", a.strip())
                           for a in _split_args(cargs)):
                    suspicious = True
                    break
            if not suspicious:
                return False

    # 2i) **公共目录只读查询**豁免（M104）。判据实现在 `_is_public_catalog_read`，
    # 由 4) 入参直查分支调用 —— 这里再兜一次 `has_any_subject` 为假但走不到 4)
    # 的形态（无 Mapper 调用、或无裸形参），保持口径一致。
    if not has_any_subject and _is_public_catalog_read(source, body):
        return False

    # 垂直越权 / 未授权 / 校验在全局配置里 —— 方法体看不到，交模型。
    return None


# ---------------- 语言识别与 Python / Solidity 分支 ----------------
#
# `verdict()` 只拿得到切片文本。语言靠结构特征判定：
#   Python —— `^def `（顶层/缩进皆可）且无 Java 可见性修饰符开头的方法；
#   Solidity —— `pragma solidity` / `contract X {`。
# 误判方向要可控：Java 源码绝不会有 `^\s*def\s+\w+\(`，Python 源码不会有
# `public class`。两条都过不了就不会进错分支，宁可退 None 交模型。

def _looks_python(source: str) -> bool:
    if re.search(r"\b(?:public|private|protected)\s+(?:class|static|\w+\s+\w+\s*\()", source):
        return False
    return bool(re.search(r"(?m)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(", source))


def _looks_solidity(source: str) -> bool:
    if re.search(r"\bpragma\s+solidity\b|\bcontract\s+[A-Za-z_]\w*", source):
        return True
    # 函数级切片（smartbugs 逐函数审计）：文件头不在切片里，
    # 靠"Solidity 签名 + Solidity 专属词法"识别。Java/Python 都没有
    # `function` 关键字，这一条是硬门槛；后一条只是佐证。
    #
    # Module 18 补词表：原先只认 uint/address/payable/msg.sender/selfdestruct/
    # mapping(/require(，于是 `function supportsToken() external pure
    # returns(bytes32)` 这种**一个都没有**的切片被判成"不是 Solidity"，
    # verdict 直接退 None —— 与 Module 13 那个"函数级切片恒 False"是同一类
    # 静默漏斗。真实靶场里它侥幸没暴露，是因为切片首行注释 `// contract: X`
    # 命中上面那条正则；换句话说，判据靠注释在撑。现在把类型/修饰符
    # 词表补齐，去掉这个依赖。
    return bool(re.search(r"\bfunction\s+\w+\s*\([^)]*\)", source)
                and re.search(r"\b(?:uint\d*|int\d*|address|bytes\d*|string|bool|payable"
                              r"|msg\s*\.\s*sender|tx\s*\.\s*origin|block\s*\."
                              r"|selfdestruct|keccak256|mapping\s*\(|require\s*\("
                              r"|external|public|internal|private|view|pure|constant)\b",
                              source))


def _py_func_params(source: str) -> set[str]:
    """入口（切片里第一个 def）的裸形参名 —— 客户端可控值。"""
    m = re.search(r"(?m)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(", source)
    if not m:
        return set()
    sig = _balanced_cond(source, m.end())
    if sig is None:
        return set()
    out = set()
    for part in _split_args(sig):
        pm = re.search(r"([A-Za-z_]\w*)\s*(?::[^=]+)?\s*(?:=[^,]*)?$", part.strip())
        if pm and pm.group(1) not in {"self", "cls", "request", "response", "db"}:
            out.add(pm.group(1))
    return out




_PY_SQL_SINK_RE = re.compile(r"\.\s*execute(?:script)?\s*\(|\.\s*executemany\s*\(")
# SQLAlchemy 2.0 Core/ORM 表达式：`session.execute(select(Model).where(...))`
# 是绑定参数，不是 SQL 文本（M80 FastAPI 实测）。
_PY_ORM_EXPR_RE = re.compile(
    r"^\s*(?:select|insert|update|delete)\s*\(", re.I)


def python_sqli_verdict(source: str) -> bool | None:
    """Python SQLi：参数化/ORM → False；格式化拼接且非常量/数值转换 → True。

    可逐行核对的事实（与 Java `${}` vs `#{}` 同构）：
      · `execute(sql, (x,))` / `execute(sql, {...})` —— 参数化 → safe
      · `cursor.execute("... WHERE id = " + int(x) + ...)` —— 值域锁死 → safe
      · `f"... WHERE id = {x}"` / `"... %s" % x` / `"... " + x` / `.format(x)`
        且 x 非纯数值转换 → True
    三态：无 sink → None；每个 sink 都安全 → False；任一 sink 可注入 → True。
    """
    if not _PY_SQL_SINK_RE.search(source):
        # 只有 ORM 调用：filter/filter_by/get 按字段绑定，天然参数化
        if re.search(r"\.\s*(?:filter|filter_by|get|query|first|all)\s*\(", source):
            return False
        # M120：**非 execute 形态的参数化封装**。fastapi-realworld 的
        # `databases` 库走自己的方法名：
        #     await self._force_fetch(query, values={"slug": slug})
        # SQL 里是 `:slug` 占位符，值是**另一个实参** —— 与
        # `execute(sql, (x,))` 完全同构，只是方法名不在 sink 词表里。
        # 判据挂机制：SQL 字面量里有占位符（`:name` / `$1` / `%(x)s` / `?`）
        # 且同一次调用还带第二个实参。
        for m in re.finditer(r"\b\w*(?:fetch|execute|select|query|run)\w*\s*\(",
                             source, re.I):
            args = _balanced_cond(source, m.end())
            if args is None:
                continue
            parts = _split_args(args)
            if len(parts) < 2 or not parts[1].strip():
                continue
            first = parts[0]
            if re.search(r"[:$][A-Za-z_]\w*|\$\d+|%\([^)]*\)s|\?", first):
                return False           # 占位符 + 独立实参 = 绑定
        return None
    saw_safe = False
    for m in _PY_SQL_SINK_RE.finditer(source):
        args = _balanced_cond(source, m.end())
        if args is None:
            continue
        parts = _split_args(args)
        if not parts:
            continue
        if len(parts) >= 2 and parts[1].strip():
            saw_safe = True            # 带参数元组/字典 → 参数化
            continue
        sql = parts[0].strip()
        if _PY_ORM_EXPR_RE.match(sql):
            saw_safe = True            # SQLAlchemy 2.0 表达式，绑定参数
            continue
        nat = _py_value_text_capable(sql, source, pos=m.start())
        if nat is True:
            return True
        if nat is False:
            saw_safe = True
    return False if saw_safe else None


def _py_entry_region(source: str) -> str:
    """入口方法自身区域：跨文件辅助/证据/配置段之前（Module 24）。

    赋值链只在该区域内追。pygoat 实测反例：切片后段带着 User 模型类，
    `username = db.Column(...)` 会把入口的
    `username = request.form.get(...)` 遮蔽成 None —— "最后一次赋值
    wins" 的约定只在入口体内部成立，辅助段里同名赋值是**别的函数**的
    局部变量，不是这条链的事实。
    """
    for marker in ("// ---- 跨文件辅助", "// ---- 跨文件证据", "// ---- 相关配置"):
        i = source.find(marker)
        if i >= 0:
            source = source[:i]
    return source


def _py_local_region(source: str, pos: int) -> str:
    """sink 所在函数的局部区域（Module 24 修正版）。

    从 sink 位置向上找最近的段标记（`// ----` 头或 `// 来自 x:N [Hop n]`），
    区域从标记之后开始到 sink 为止；sink 在入口体里则从头开始。
    两个反例一起解：
      · pygoat：sink 在入口体，hop 段的 User 模型 `username = db.Column(...)`
        不得遮蔽入口的 `request.form` 赋值（段在 sink 之后，天然排除）；
      · 多跳：sink 在 dao 的 Hop 2 段里，`sql = "..."` 赋值就在同段——
        只看入口区域会把它切掉（冒烟 [62] 的真实回归）。
    """
    starts = [m.start() for m in re.finditer(r"// ----|// 来自 ", source)
              if m.start() < pos]
    seg = starts[-1] if starts else 0
    return source[seg:pos]


def _py_value_text_capable(expr: str, source: str, depth: int = 0,
                           pos: int | None = None) -> bool | None:
    """SQL 文本表达式能否携带运行时值（三态）。None=查不出，保守不判。"""
    if depth > 3:
        return None
    e = expr.strip()
    if not e:
        return None
    # 顶层括号包裹（pygoat 实测：`sql_query = (\n  f"SELECT ... {x}"\n)`，
    # 长表达式按 PEP 8 折行是最常见的写法）—— 剥到最内层再走正常分支。
    while e.startswith("(") and e.endswith(")"):
        inner = _balanced_cond(e, 1)
        if inner is None or inner.strip() != e[1:-1].strip():
            break
        e = e[1:-1].strip()
    # 纯字面量（无任何插值/拼接痕迹）。Python 字符串单双引号都合法 ——
    # vulpy 的 `request.form.get('username')` 里实参就是单引号字面量，
    # 只认双引号会让"实参是常量"判成 None（实测 bad 侧真漏洞因此丢判）。
    if re.fullmatch(r"(?:f|rf|fr|r)?['\"][^'\"]*['\"](?:\s*%s*)?", e) and "{" not in e \
            and "+" not in e and "%" not in e and ".format(" not in e:
        return False
    # f-string / % / + / .format
    # f-string 必须有 f 前缀：普通字符串里的 '{}' 占位符（vulpy 的
    # "... username = '{}'".format(x)）会让 `{` 出现在表达式里，若只看
    # 花括号就把 .format 调用误路由进来 —— 花括号里没有内容可分析，
    # 返回 None，真漏洞静默丢失（vulpy bad 实测）。
    if re.match(r"(?:[rR][fF]|[fF][rR]?)[\"']", e) and "{" in e:
        # f-string：花括号里的表达式
        natures = []
        for im in re.finditer(r"\{([^{}]+)\}", e):
            natures.append(_py_interp_text_capable(im.group(1), source, depth))
        if natures and all(n is False for n in natures):
            return False
        if any(n is True for n in natures):
            return True
        return None
    if "%s" in e or "'%" in e or '"%' in e or re.search(r"\"\s*%\s", e):
        # 顶层 % 运算符：必须找**字符串字面量之外**的 % —— SQL 里满是
        # '%s' 占位符，瞎抓第一个 % 会把 `s" % uid` 当成插值列表。
        in_s = in_d = False
        last = -1
        for i, ch in enumerate(e):
            if ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "'" and not in_d:
                in_s = not in_s
            elif ch == "%" and not in_s and not in_d:
                last = i
        if last != -1:
            rhs = e[last + 1:].strip()
            if rhs.startswith("(") and rhs.endswith(")"):
                rhs = rhs[1:-1]
            natures = [_py_interp_text_capable(a, source, depth)
                       for a in _split_args(rhs)]
            if natures and all(n is False for n in natures):
                return False
            if any(n is True for n in natures):
                return True
        return None
    if ".format(" in e:
        call_args = _balanced_cond(e, e.find(".format(") + len(".format("))
        if call_args is not None:
            natures = [_py_interp_text_capable(a, source, depth)
                       for a in _split_args(call_args)]
            if natures and all(n is False for n in natures):
                return False
            if any(n is True for n in natures):
                return True
        return None
    if "+" in e:
        parts = [p for p in e.split("+") if p.strip()]
        natures = [_py_value_text_capable(p, source, depth + 1) for p in parts]
        if natures and all(n is False for n in natures):
            return False
        if any(n is True for n in natures):
            return True
        return None
    # 裸变量：沿赋值链追；追不到时看它是不是**函数形参** ——
    # 形参就是客户端可控值（多跳切片里 dao.fetch(uid) 的 uid 正是这种）。
    # 裸变量：沿赋值链追；追不到时看它是不是**函数形参** ——
    # 形参就是客户端可控值（多跳切片里 dao.fetch(uid) 的 uid 正是这种）。
    if re.fullmatch(r"[A-Za-z_]\w*", e):
        region = _py_local_region(source, pos) if pos is not None \
            else _py_entry_region(source)
        lines = region.split("\n")
        pat = re.compile(rf"^[ \t]*{re.escape(e)}\s*=[^=]")
        rhs = None
        d = 0
        i = 0
        while i < len(lines):
            ln = lines[i]
            if d == 0:
                m = pat.match(ln)
                if m:
                    # 语句级赋值（括号深度 0 处）才作数：多行调用里的
                    # 关键字实参 `sql_query=sql_query,` 与赋值同貌，
                    # pygoat 实测会把右值遮成 'ql_query,'。
                    # 从 '=' 之后吃到括号配平（PEP 8 多行右值）。
                    buf = [ln[m.end():]]
                    dd = ln.count("(") + ln.count("[") - ln.count(")") - ln.count("]")
                    j = i + 1
                    while dd > 0 and j < len(lines):
                        buf.append(lines[j])
                        dd += lines[j].count("(") + lines[j].count("[") \
                            - lines[j].count(")") - lines[j].count("]")
                        j += 1
                    rhs = "\n".join(buf).strip()
                    i = j
                    continue
            d += ln.count("(") + ln.count("[") - ln.count(")") - ln.count("]")
            if d < 0:
                d = 0
            i += 1
        if rhs is not None:
            return _py_value_text_capable(rhs, source, depth + 1)
        if re.search(rf"(?m)^\s*(?:async\s+)?def\s+\w*\s*\([^)]*\b{re.escape(e)}\b",
                     source):
            return True
        return None
    # 方法调用：int()/float()/len() 锁死值域；str(x)/foo(x) 取实参值域。
    if re.fullmatch(r"(?:int|float|len|bool)\s*\([^()]*\)", e):
        return False
    # Flask 请求读取就是外部输入（vulpy：request.form.get('username')）。
    # 判据挂机制不挂写法：form/args/values/cookies/headers/json/data/files。
    # M88 增量：Django 的 `request.GET` / `request.POST` / `request.FILES` /
    # `request.body` / `request.META`，以及 DRF 的 `request.query_params`。
    # 前三者在 Django 里是 QueryDict（`.get('x')` / `['x']` 两种取法），
    # `request.body` 是原始字节流 —— 与 Flask 的 `request.data` 同级。
    if re.search(r"\brequest\s*\.\s*(?:form|args|values|cookies|headers|json|"
                 r"data|files|GET|POST|FILES|body|META|query_params)\b", e):
        return True
    mm = re.match(r"[\w.]+\s*\(", e)
    if mm:
        args = _balanced_cond(e, mm.end())
        # 关键字实参取值：`f(sql=sql)` 的值域跟 `sql` 走，不是跟着字面名
        # "sql=sql" 走（pygoat 实测：kwargs 形态在真实代码里常见）。
        parts2 = []
        for a in _split_args(args or ""):
            a = a.strip()
            km = re.match(r"[A-Za-z_]\w*\s*=\s*(.+)$", a, re.S)
            parts2.append(km.group(1).strip() if km else a)
        natures = [_py_interp_text_capable(a, source, depth + 1)
                   for a in parts2]
        if natures and all(n is False for n in natures):
            return False
        if any(n is True for n in natures):
            return True
    return None


def _py_interp_text_capable(expr: str, source: str, depth: int = 0) -> bool | None:
    """插值表达式（f-string 花括号 / % 元组元素 / format 实参）的值域。"""
    e = expr.strip()
    if re.fullmatch(r"-?\d+(?:\.\d+)?", e):
        return False
    if re.fullmatch(r"(?:int|float)\(([^()]*)\)", e):
        return False                      # int()/float() 转换锁死值域
    if re.fullmatch(r"[A-Za-z_]\w*", e):
        region = _py_entry_region(source)
        rhs = None
        for am in re.finditer(rf"^[ \t]*{re.escape(e)}\s*=\s*(.+)$", region, re.M):
            rhs = am.group(1)
        if rhs is not None:
            return _py_value_text_capable(rhs, source, depth + 1)
        return True                       # 裸形参/字段：客户端可控
    return _py_value_text_capable(e, source, depth + 1)


_PY_TPL_STRING_RE = re.compile(r"\brender_template_string\s*\(|\bMarkup\s*\(|\bmarkupsafe\s*\.\s*Markup\s*\(")
_PY_TPL_SAFE_RE = re.compile(r"\brender_template\s*\(")


def python_xss_verdict(source: str) -> bool | None:
    """Python XSS（Module 11）：Jinja2 模板机制的确定性判定。

    可逐行核对的事实：
      · `render_template("x.html", k=v)` —— Jinja2 默认对变量自动转义，
        文件模板不走 `|safe` 过滤器的形态判 safe（模板内容有 |safe 时
        由切片证据段另行暴露，此处按机制判 False）
      · `render_template_string(f"...{x}...")` / `Markup(x)` —— 字符串
        模板**没有**文件模板的自动转义语境（vulnhuntr 的经典结论：
        SSTI/XSS 双漏洞），实参可携带外部输入 → True
    三态：无 sink → None；sink 实参全常量/数值 → False；任一可达 → True。
    """
    if not (_PY_TPL_STRING_RE.search(source) or _PY_TPL_SAFE_RE.search(source)):
        return None
    saw_safe = False
    for m in _PY_TPL_STRING_RE.finditer(source):
        args = _balanced_cond(source, m.end())
        if args is None:
            continue
        parts = [p for p in _split_args(args) if p.strip()]
        if not parts:
            continue
        natures = [_py_value_text_capable(p, source) for p in parts]
        if natures and all(n is False for n in natures):
            saw_safe = True
            continue
        if any(n is True for n in natures):
            return True
        return None                      # 查不出 → 交模型，不假装安全
    for m in _PY_TPL_SAFE_RE.finditer(source):
        args = _balanced_cond(source, m.end())
        if args is None:
            continue
        parts = [p for p in _split_args(args) if p.strip()]
        if len(parts) >= 2 and not parts[0].strip().startswith(("f", 'f"')):
            saw_safe = True              # 文件模板 + 显式变量 → 自动转义
    return False if saw_safe else None


_PY_CMDSINK_RE = re.compile(
    r"\bos\s*\.\s*system\s*\(|\bos\s*\.\s*popen\s*\(|"
    r"subprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)\s*\(")
_PY_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
_PY_SHLEX_RE = re.compile(r"shlex\s*\.\s*(?:quote|split|join)\s*\(")


def python_cmdi_verdict(source: str) -> bool | None:
    """Python CMDi：列表传参（shell=False）→ False；字符串命令拼接进
    `os.system` / `shell=True` 且无 shlex → True。

    三态：无 sink → None；外部输入进字符串命令且无 shlex → True；
    全部 sink 都走列表传参或 shlex 加固 → False。
    """
    if not _PY_CMDSINK_RE.search(source):
        return None
    if _PY_SHLEX_RE.search(source):
        return False
    tainted = False
    safe = False
    for m in _PY_CMDSINK_RE.finditer(source):
        args = _balanced_cond(source, m.end())
        if args is None:
            continue
        call_seg = source[m.start(): m.end() + len(args or "") + 40]
        parts = _split_args(args)
        if not parts:
            continue
        first = parts[0].strip()
        is_list = first.startswith("[")
        has_shell_true = _PY_SHELL_TRUE_RE.search(call_seg) is not None
        if is_list and not has_shell_true:
            safe = True                   # 列表传参：参数边界由 execve 保证
            continue
        nat = _py_value_text_capable(first, source, pos=m.start())
        if nat is True:
            tainted = True
        elif nat is None and _py_func_params(source):
            # 有形参且命令里出现标识符 → 交保守判：字符串命令 + 有输入面
            tainted = True
        else:
            safe = safe or nat is False
    if tainted:
        return True
    return False if safe else None


_PY_SUBJECT_RE = re.compile(
    r"Depends\s*\(\s*get_current_user\s*\)|@login_required|@jwt_required|"
    r"\bcurrent_user\b|\bg\s*\.\s*user\b|\bg\s*\.\s*current_user\b|"
    r"\brequest\s*\.\s*user\b|get_jwt_identity\s*\(|@requires_auth", re.I)
# Module 37：JWT 主体链第二形态（VAmPI）。Connexion/OpenAPI 无装饰器，
# 主体经 `User.decode_auth_token(token)` 解出 claim 再取 `resp['sub']`
# 作查询键 —— 机制与 get_jwt_identity 完全同类（"是谁"由 token 决定）。
_PY_SUBJECT_RE_JWT = re.compile(
    r"\bdecode_auth_token\s*\(|\[\s*['\"]sub['\"]\s*\]", re.I)
_PY_OWNERSHIP_RE = re.compile(
    r"current_user\s*\.\s*id\s*==|==\s*current_user\s*\.\s*id|"
    r"current_user\s*\.\s*id\s*!=|!=\s*current_user\s*\.\s*id|"
    r"\.filter(?:_by)?\s*\([^)]*(?:user_id|owner_id)\s*=\s*current_user\s*\.\s*id|"
    r"\.filter\s*\([^)]*==\s*current_user\s*\.\s*id|"
    r"(?:user_id|owner_id)\s*=\s*current_user\s*\.\s*id|"
    r"abort\s*\(\s*40[13]\s*\)"
    # M137：Flask 的 `g.current_user` 主体形态 —— flasky 的归属校验写成
    #   `if g.current_user != post.author and not g.current_user.can(ADMIN):`
    #   `return forbidden('Insufficient permissions')`
    # 主体比较与拒绝分支都在，只是主体不在 `current_user` 而是 `g.current_user`；
    # 另外 `comment.author = g.current_user` 是"新记录归属当前用户"的写法，
    # 同样把资源绑到了主体上（写自己的资源不是越权面）。
    r"|\bg\s*\.\s*current_user\b\s*[!=]="
    r"|\.\s*(?:author|user|owner|user_id|owner_id)\s*=\s*g\s*\.\s*current_user\b"
    r"|return\s+[\w.]*forbidden\s*\("
    r"|raise\s+\w*(?:Forbidden|PermissionDenied)\w*"
    # M168：Flask-JWT-Extended 的 current_user.profile 主体形态。
    r"|(?:author|user|owner)_id\s*=\s*current_user\s*\."
    r"|(?:author|user|owner)\s*=\s*current_user\b"
    r"|current_user\s*\.\s*\w+\s*\.\s*(?:append|add|remove|follow|unfollow)\b"
    r"|current_user\s*\.\s*profile\s*[,)]"
    r"|\.\s*(?:favourite|favorite|unfavourite|unfavorite|follow|unfollow)"
    r"\s*\(\s*profile\b",
       re.I)


def _py_public_catalog_read(source: str, body: str) -> bool:
    """公开内容只读面（M137，Flask 教程应用的 `/user/<username>` 形态）。

    与 Java 侧 `_is_public_catalog_read` 同一套**正面证据**口径：

      ① 无写动作（`db.session.add/commit/delete`、`.save()`、`.update(`、
         INSERT/UPDATE/DELETE 语句都没有）；
      ② 不碰主体私有资源（password / email / token / secret / order /
         cart / wallet / admin 一律视为私有面）；
      ③ **正面认出路由指向公开内容**（`// Route:` 里出现 posts / comments /
         followers / timeline / user 这类"人人可见"的实体名）。

    第 ③ 条是必要条件：认不出就不豁免，仍按 True/None 走 —— 否定式
    （"没提到 user_id 就算公开"）会把 VAmPI 那种真正的对象级越权洗成安全。
    """
    if not body:
        return False
    if _PY_WRITE_CALL_RE.search(body):
        return False
    if _PY_PRIVATE_RES_RE.search(body):
        return False
    rm = re.search(r"//\s*Route:\s*(\S+)", source)
    route = rm.group(1) if rm else ""
    if not route:
        return False
    return bool(_PY_PUBLIC_ROUTE_RE.search(route))


_PY_WRITE_CALL_RE = re.compile(
    r"db\s*\.\s*session\s*\.\s*(?:add|add_all|delete|commit|merge|bulk_\w+)\s*\("
    r"|\.\s*(?:save|delete|update|upsert)\s*\(\s*\)"
    r"|\.\s*(?:update|delete)\s*\([^)]"
    r"|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.I)
_PY_PRIVATE_RES_RE = re.compile(
    r"\b(?:password|passwd|token|secret|api_key|email|credit|wallet|payment"
    r"|order|cart|invoice|admin|permission|role)s?\b", re.I)
_PY_PUBLIC_ROUTE_RE = re.compile(
    r"(?:^|/)(?:posts?|comments?|followers?|followed_by|timeline|users?|profiles?"
    r"|index|home|feed|articles?|tags?)(?:/|$|\?)", re.I)


def python_authz_verdict(source: str) -> bool | None:
    """Python Authz：FastAPI `Depends(get_current_user)` / Flask
    `@login_required` + 归属比对（current_user.id 参与查询或比较）→ False；
    路由形参直接查改删且无任何主体 → True；其余退 None。"""
    # FastAPI 依赖注入的认证/权限门（M80）：
    # `current_user: User = Depends(require_superuser)` 是框架级授权声明；
    # 但 `Depends(get_current_user)` 只证明"知道是谁"，主体可能继续下沉到
    # Service 做归属比对 —— 不能直接判安全（否则会吃掉 BOLA 的 None）。
    body = entry_body(source)
    # M137：装饰器守卫证据头（`@admin_required` / `@permission_required`）。
    #
    # 只认**管理员面**（admin_required）→ 确定性 False：管理员对全站资源做
    # 特权操作是设计意图，不是越权（flasky 的 edit_profile_admin 就是这个语义）。
    # `permission_required(Permission.WRITE)` **不能**直接判 False —— 它只证明
    # "这个角色能写"，不证明"只能写自己的"；把它当安全会把 BOLA 洗白。
    # 那类仍走下面的主体/归属判据（`g.current_user != post.author` 等）。
    _guards = re.findall(r"//\s*Auth-Guard:\s*(\w+)", source)
    if "admin_required" in _guards:
        return False
    # M154：M80 只认了 body 里的 Depends(...) —— FastAPI 模板把权限声明写在
    # 路由装饰器上（dependencies=[Depends(get_current_active_superuser)]），
    # body 里一个字符都没有。改为扫 source，并补上 superuser 这一族。
    if re.search(r"Depends\s*\(\s*(?:require|permission|login_required"
                 r"|auth_required|authorize|superuser"
                 r"|get_current_(?:active_)?superuser)\w*", source, re.I):
        return False
    has_subject = (_PY_SUBJECT_RE.search(source) is not None
                   or _PY_SUBJECT_RE_JWT.search(source) is not None)
    if has_subject:
        if _py_public_catalog_read(source, body):
            return False
        if _PY_OWNERSHIP_RE.search(source):
            return False
        # Module 37 a) admin 门（VAmPI delete_user 形态）：主体链取到
        # 当前用户后，特权动作之前有 `user.admin` 真值检查 —— 调用者
        # 身份进入了授权判定，机制上等价于 ownership 比对 → False。
        if re.search(r"\bif\s+(?:not\s+)?[\w.]+\.admin\s*:|\bif\s+[\w.]+\.admin\b",
                     source):
            return False
        # Module 37 b) 资源形参直写（BOLA 写路径，VAmPI update_password
        # vuln 分支）：主体链虽然在场，但写/删操作的目标记录由 **URL
        # 资源形参** 定位（filter_by(attr=形参) 或 delete_xxx(形参)），
        # 主体没有参与目标定位 —— 谁登录的都能改别人的 → True。
        # 只读形参查询不算写路径（那是 get_by_username 的只读 BOLA，
        # 由下方无主体分支覆盖）。
        params = _py_func_params(source)
        res_params = {p for p in params
                      if re.search(r"(?:id|no|name|key|slug|uuid)$", p)}
        for p in res_params:
            if re.search(rf"filter_by\s*\([^)]*=\s*{p}\b", source) and re.search(
                    r"\.\s*(?:password|email|admin|balance)\s*=[^=]"
                    r"|\bdelete\w*\s*\(\s*[^)]*\b" + p + r"\b", source):
                return True
        # M154：只服务"当前主体"的自助路由（read_user_me / delete_user_me /
        # create_item）。判 False 需要的两个可核对事实：
        #   ① 没有 URL 资源形参（user_id / id / name ...）；
        #   ② 主体只以 current_user 出现，操作对象就是它（或新建记录归属它）。
        # 没有"他人资源键"就没有水平越权面；这与"有主体但不比对"不同。
        if not res_params and re.search(r"\bcurrent_user\b", body):
            return False
        # 有主体但方法体看不出比对：主体可能下沉到 Service —— 不表态
        if re.search(r"(?:service|repo|dao|crud|manager|store)\s*\.\s*\w+\s*\(",
                     source, re.I):
            return None
        # Module 37 b2) 成对双形态只读 BOLA（get_by_title 形态）：同一
        # 切片里既有主体键查询（filter_by(user=user / username=resp['sub'])
        # —— fixed 分支）又有 **URL 资源形参**直接定位目标的查询
        # （filter_by(book_title=str(形参)) —— vuln 分支），且无 admin 门。
        # 这是作者指名的 vuln 开关双形态：形参定位绕过了主体归属 → True。
        # （资源形参不在任何查询里、只有主体键查询的单元不命中 ——
        # 那是 me/update_email 的"查自己"形态，走下方 c 分支 False。）
        # 值位置精确判定：形参必须是查询的**值**（`= 形参` / `= str(形参)`
        # / 位置实参），键名同名不算（update_email 的 filter_by(username=
        # resp['sub']) 左边键名与形参同名，但值是主体取值 —— 不命中）。
        for p in params:
            if re.search(rf"filter(?:_by)?\s*\([^)]*(?:=\s*str\s*\(\s*{p}\b"
                         rf"|=\s*{p}\b|\(\s*{p}\b|,\s*{p}\b)", source):
                return True
        # Module 37 c) 主体键 ORM 查询（me/update_email 形态）：JWT 主体
        # 取值（resp['sub']）直接作 filter_by 查询键 —— 查的就是"谁登录
        # 谁的记录"，写也只能写自己 → False（铁律 12：主体链取值作
        # Service/ORM 实参 → False）。
        if _PY_SUBJECT_RE_JWT.search(source) and re.search(
                r"filter_by\s*\([^)]*=\s*\w+\[\s*['\"]sub['\"]\s*\]", source):
            return False
        return None
    params = _py_func_params(source)
    resource_params = {p for p in params
                       if re.search(r"(?:id|no|name|key|slug|uuid)$", p)}
    if resource_params and re.search(
            r"\.\s*(?:query|get|filter|filter_by|delete|update|execute|first|"
            r"scalar|one)\s*\(", source):
        # M137：公开内容只读面（`/user/<username>` / `/posts/<id>/comments/`）。
        # 正面认出是公开内容 + 无写动作 + 不碰私有资源 → 不是对象级越权面。
        if _py_public_catalog_read(source, body):
            return False
        return True
    return None


_SOLIDITY_MOD_SEP = "// ---- 修饰符定义（本合约，供核验）----"
# 父合约**修饰符**实现体（M39）与父合约**普通函数**实现体（M54）是两种
# 不同的证据，必须用不同段头隔开 —— 否则父合约函数体会被 modifier 扫描
# 误当成"本合约的 modifier 保护"（判反方向）。
_SOLIDITY_INH_MOD_SEP = "// ---- 父合约继承证据 ["
_SOLIDITY_INH_FUNC_SEP = "// ---- 父合约函数证据 ["
_SOLIDITY_SAME_FILE_SEP = "// ---- 同文件辅助函数证据 ["


def _split_sol_sections(source: str) -> tuple[str, str, str]:
    """把切片拆成（函数自身源码, 修饰符证据块, 父合约函数证据块）。

    **函数体到第一个证据段头为止**（M54 实测教训）：父合约的代码是
    **别的函数**的代码，混进本函数的源码里会让判据看到不属于本函数的
    Sink/漏洞行 —— 0x52d2 的 `withdrawTokens` 就因为父合约证据段里带着
    兄弟合约 `getTokens` 的 `addr.call.value(0 wei)()` 被误判成
    unchecked_low_level_calls（真漏洞在 getTokens，不在 withdrawTokens）。
    """
    pos: list[tuple[int, str]] = []
    for sep in (_SOLIDITY_MOD_SEP, _SOLIDITY_INH_MOD_SEP,
                _SOLIDITY_INH_FUNC_SEP, _SOLIDITY_SAME_FILE_SEP):
        i = source.find(sep)
        if i >= 0:
            pos.append((i, sep))
    if not pos:
        return source, "", ""
    cut = min(p[0] for p in pos)
    func_src, tail = source[:cut], source[cut:]
    # 证据段的拼装顺序（切片层）：修饰符证据 → 父合约函数证据 →
    # 同文件辅助函数证据。把后两段切出来，修饰符证据块里就不会混进
    # 别的函数的代码（否则 modifier 扫描会误认父合约的检查为本合约的保护）。
    i_func = tail.find(_SOLIDITY_INH_FUNC_SEP)
    i_same = tail.find(_SOLIDITY_SAME_FILE_SEP)
    ends = [i for i in (i_func, i_same) if i >= 0]
    if ends:
        return func_src, tail[:min(ends)], tail[min(ends):]
    return func_src, tail, ""


def _split_sol_modifier_block(source: str) -> tuple[str, str]:
    """把切片拆成（函数自身源码, 修饰符证据块）。无块时块为空串。

    修饰符证据块 = 本合约 modifier 定义体 + 父合约 modifier 实现体
    （M39/M54）；**不含**父合约普通函数实现体。
    """
    func_src, mod_ev, _func_ev = _split_sol_sections(source)
    return func_src, mod_ev


def _sol_signature(source: str) -> str:
    """函数签名段：从 `function` 关键字到其后的第一个 `{`。

    不能整体 split("{")[0]：合成夹具/整合约文本里 contract 的 `{`
    出现在函数声明之前，会切掉整个签名段（实测 [57] 三条断言静默
    退 None 后修正）。
    """
    m = re.search(r"\bfunction\s+[A-Za-z_]\w*", source)
    if not m:
        return ""
    brace = source.find("{", m.start())
    return source[m.start(): brace if brace != -1 else len(source)]


# 只读函数标记（Module 18）。`constant` 是 0.4.x 的写法，`view`/`pure` 是
# 0.4.16 之后；三个都是**编译器强制**的限制，不是注释或约定：
#   view/constant → 函数体不得修改状态（写状态变量直接编译不过）
#   pure          → 连读状态都不许
# 于是它能确定性排除两类漏洞，不需要问模型：
#   · 重入：受害者必须在外部调用**之后**写状态才有可重入的窗口，
#     不写状态就没有这个窗口；
#   · 越权：特权操作（转币/销毁/改 owner/铸币）全都是状态写入，
#     只读函数做不了这些事。
# 这条按「能确定性判定的不交 LLM」归到规则层，而不是往提示词里加排除条款 ——
# 提示词是**建议**，编译器是**事实**。实测这一条收掉 smartbugs 退回批里
# 37/182 条 safe（access_control 20 / reentrancy 17），全部真值 safe。
_SOLIDITY_READONLY_RE = re.compile(r"\b(?:constant|view|pure)\b")


def _sol_is_readonly(sig: str) -> bool:
    """签名段带 constant/view/pure → 编译器保证不改状态。"""
    return bool(_SOLIDITY_READONLY_RE.search(sig))


def _sol_is_internal_only(sig: str) -> bool:
    """签名显式声明 internal / private → 外部调不到，攻击面为零。

    重入需要"外部入口 + 外部调用"两个条件，越权需要"外部可调的特权
    动作"—— 两者都以"函数对外可达"为前提。可见性在编译期固化，属于
    **编译器强制**的事实，不是提示词能商量的判断。

    为什么必须只看 `)` 之后的尾段：参数名/返回类型里出现 internal 这种
    词法是可能的（`function f(bool internal_)`），把函数体里的 `internal`
    当可见性会把带保护的业务函数整片误判 safe。没有显式可见性的老语法
    （`function foo()`，默认 public）**不在这里排除** —— 默认可达是事实，
    不能靠"没写"推"不可达"。
    """
    tail = sig[sig.find(")") + 1:] if ")" in sig else sig
    return bool(re.search(r"\b(?:internal|private)\b", tail))


def _sol_mutex_modifier_names(mod_block: str) -> set[str]:
    """识别"状态位互斥锁" modifier（M79 UniswapV3 `lock()` 实测）。

    通用结构（不看名字）：
        require(<state>, ...) / if (<state>) ...   // 前置检查
        <state> = false;                           // `_` 之前加锁
        _;
        <state> = true;                            // `_` 之后解锁

    只认**同一个状态变量**在 `_;` 前后分别被置 false/0 与 true/1，且前面
    有 require/if 读取；只有赋值没有前检 → 不算锁（防"半吊子互斥"误判安全）。
    """
    names: set[str] = set()
    for mm in re.finditer(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?"
                          r"\s*[^{]*\{", mod_block):
        body = _sol_block_body(mod_block, mm.end() - 1)
        if not body:
            continue
        pre, sep, post = body.partition("_;")
        if not sep:
            continue
        locked = set(re.findall(
            r"([\w.\[\]]+)\s*=\s*(?:false|0)\s*;", pre))
        unlocked = set(re.findall(
            r"([\w.\[\]]+)\s*=\s*(?:true|1)\s*;", post))
        if not (locked & unlocked):
            continue
        if not re.search(r"\b(?:require|if)\s*\(", pre):
            continue
        names.add(mm.group(1))
    return names


def solidity_reentrancy_verdict(source: str) -> bool | None:
    """Solidity 重入：CEI 顺序是逐行可核对的事实。

    · 签名带 `nonReentrant`（或体内有重入锁）→ False
    · 签名引用**状态位互斥锁 modifier**（M79：`lock()` 结构）→ False
    · 只读函数（view/pure/constant）→ False（编译器保证不写状态，无重入窗口）
    · 显式 internal/private → False（外部调不到，没有入口就没有重入）
    · 所有外部转账调用的行号**严格大于**状态扣减行号 → False（CEI 正序）
    · 外部调用在扣减**之前**且无锁 → True
    · 缺少任一侧证据 → None

    Module 13（smartbugs 实测）：老语法 `msg.sender.call.value(x)()`
    （0.4.x 时代的主流写法）必须与 `.call{value:` 同等对待，否则
    PrivateBank/CashOut、SimpleBank/Collect 这批经典真漏洞全部静默退回。
    """
    func_src, mod_block = _split_sol_modifier_block(source)
    sig = _sol_signature(func_src)
    if _sol_is_readonly(sig) or _sol_is_internal_only(sig):
        return False
    if re.search(r"\bnonReentrant\b|locked|entered|_status\s*==\s*1|_reentrancyGuard",
                 func_src):
        return False
    # M79：自定义状态位互斥锁（UniswapV3 `lock()`）—— 看 modifier 体结构，
    # 不看名字；只有签名真的引用了该 modifier 才生效。
    for mname in _sol_mutex_modifier_names(mod_block):
        if re.search(rf"\b{re.escape(mname)}\b", sig):
            return False
    # 外部调用分类：硬外转（可携带任意 gas，回调能重入）vs 津贴外转。
    # `.transfer(x)` / `.send(x)` 单参形态是 address 内建方法 —— EVM 固定
    # 只给 2300 gas 津贴，fallback 连发起一次新的外部调用都不够，重入在
    # VM 层就不可能（nssc Reentrancy.sol 注释指名："send() and transfer()
    # are safe against reentrancy"）。双参 `.transfer(to, amount)` 是
    # ERC20/777 token 调用 —— 777 有 tokensReceived 钩子，**不是**津贴
    # 形态，照旧进 CEI 行序判定。
    ext_calls: list[tuple[int, str]] = []
    for m in re.finditer(r"\.\s*call\s*\{[^}]*value:|\.send\s*\(\s*[^(),]*\)"
                         r"|\.transfer\s*\(\s*[^(),]*\)"
                         r"|\.\s*call\s*\.\s*value\s*\(|\.\s*call\s*\.\s*gas\s*\("
                         r"|\.send\s*\(|\.transfer\s*\(",
                         func_src):
        text = m.group(0)
        if re.search(r"\bcall\b", text):
            kind = "hard"
        elif re.fullmatch(r"\.\s*(?:send|transfer)\s*\(\s*[^(),]*\)", text):
            kind = "stipend"
        else:
            kind = "token"          # 多参 transfer/send：ERC20/777，可回调
        ext_calls.append((func_src[:m.start()].count("\n") + 1, kind))
    # 状态扣减/累加：映射/变量减法与清零（`balances[x] -=` / `acc.balance = 0`）。
    # 扣减只认函数自身源码 —— 修饰符定义块里的同名赋值不是本函数的 CEI 证据。
    ded_lines = []
    # 映射索引写（`x[k] += / -= / = 0`）：Solidity 映射不可能是局部变量，
    # 索引写必然是状态变更 —— 机制层证据，不依赖命名关键词
    # （M36：ERC777 claim 的 `_mints[account] += amount`，mints 不在
    # 旧关键词表里，导致唯一真值退回）。
    for m in re.finditer(r"^\s*[\w\[\]\.]+\[[^\]]*\]\s*(?:\+=|-=)\s*[^;]+;|"
                         r"^\s*[\w\[\]\.]+\s*(?:-=|\s*=\s*0\s*;)", func_src, re.M):
        ln = func_src[:m.start()].count("\n") + 1
        line = func_src.splitlines()[ln - 1]
        if re.search(r"[Bb]alance|[Dd]eposit|shares|stake|funds|credit|[Cc]redit"
                     r"|\[[^\]]*\]\s*(?:\+=|-=)", line):
            ded_lines.append(ln)
    if not ext_calls or not ded_lines:
        return None
    hard = [ln for ln, k in ext_calls if k == "hard"]
    token = [ln for ln, k in ext_calls if k == "token"]
    stipend = [ln for ln, k in ext_calls if k == "stipend"]
    if not hard and not token and stipend:
        # 全部外转都是津贴形态：VM 层重入不可能，CEI 行序无关紧要。
        # （Module 21：nssc 探针抓出的真误报 withdrawBalance_fixed_2。）
        return False
    ext_lines = sorted(hard + token + stipend)
    if min(ext_lines) > max(ded_lines):
        return False                    # 先扣减后外转：CEI 正序
    if max(ext_lines) < min(ded_lines):
        return True                     # 先外转后扣减：经典重入面
    return None                         # 交错：行序不足以下结论


_SOLIDITY_OWNERISH_RE = re.compile(
    r"\b(?:owner|creator|owner_|contract_owner|admin)\b(?:\s*\.\s*balance)?\s*"
    r"(?<!=[=!<>])=(?!=)", re.I)
# 局部变量声明的类型前缀 —— 用来区分"状态变量写"与"局部变量声明"。
#
# M54 实测（Top200 33 条误报）：OpenZeppelin ERC20 里
#   `address owner = _msgSender();`
# 是**局部变量声明**（函数内的临时量），不是 owner 态写。按名字判
# "owner 态被改"会凭空造 33 条漏洞。
#
# 区分机制（不挂名字，挂**语法位置**）：Solidity 里状态变量的赋值
# **左侧没有类型前缀**（`owner = newOwner;`），局部变量声明**有**
# （`address owner = ...;`）。所以看赋值左侧的**前一个 token** 是不是
# 类型关键字即可。
_SOL_DECL_TYPE_WORDS = frozenset({
    "address", "bool", "var", "string", "bytes", "byte", "uint", "int",
    "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
    "int8", "int16", "int32", "int64", "int128", "int256",
    "bytes1", "bytes2", "bytes3", "bytes4", "bytes8", "bytes16", "bytes20",
    "bytes24", "bytes28", "bytes32", "payable", "memory", "calldata",
    "storage", "mapping",
})


def _sol_owner_state_write(func_src: str) -> bool:
    """是否存在 **owner 态（状态变量）** 的写。

    与 `_SOLIDITY_OWNERISH_RE` 的差别只有一个：排除**局部变量声明**
    （`address owner = _msgSender();`）。状态变量赋值左侧没有类型
    前缀，局部变量声明有 —— 看左侧前一个 token 是不是类型关键字。
    """
    for m in _SOLIDITY_OWNERISH_RE.finditer(func_src):
        toks = re.findall(r"[A-Za-z_]\w*", func_src[:m.start()])
        if toks and toks[-1] in _SOL_DECL_TYPE_WORDS:
            continue                    # 局部变量声明 → 不是状态写
        return True
    return False


_SOLIDITY_SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")
_SOLIDITY_DRAIN_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance"
    r"|\.call\s*\{[^}]*\}\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance",
    re.S)
_SOLIDITY_MSGSENDER_CHECK_RE = re.compile(
    r"require\s*\(\s*(?:msg\s*\.\s*sender\s*==|msg\s*\.\s*sender\s*!=|\w+\s*==\s*msg\s*\.\s*sender)"
    r"|assert\s*\(\s*msg\s*\.\s*sender\s*=="
    # `if (msg.sender != owner) { throw; }` —— **花括号块**形态
    # （M54 实测：CrowdsaleToken 的 onlyOwner 写成块，里面是 throw）。
    # 块里必须真的有中止语义（revert/throw/return），否则不是保护。
    r"|if\s*\(\s*msg\s*\.\s*sender\s*!=\s*[\w.]+\s*\)\s*\{[^}]{0,200}?"
    r"\b(?:revert|throw|return)\b"
    r"|if\s*\(\s*msg\s*\.\s*sender\s*!=\s*\w+\s*\)\s*(?:revert|throw|return)")
# 块形态的**语义核验**：`if (msg.sender != X) { ... }` 的块里到底有没有
# 中止语义。上面的正则只保证"块里有 revert/throw/return 字样"，
# 但 `if (msg.sender != owner) { log("not owner"); }` 只是记录日志，
# 不是保护 —— 需要单独核验块里是**中止**（revert/throw/return）
# 而不是普通语句。
_SOL_BLOCK_ABORT_RE = re.compile(
    r"\b(?:revert\s*\(|"
    # M87：0.8.x 的**自定义错误**中止。`revert NotOwner();` /
    # `revert InsufficientBalance(from, to);` 是 0.8.4 起的标准守卫写法，
    # 与 `revert("msg")` / 裸 `revert;` 并列的**第三种**语法形态。
    # 此前它靠 `revert\b` 碰巧命中 —— 显式列出后，判据才是"挂了机制"
    # 而不是"撞上了巧合"（一旦有人给 `revert\b` 加负向断言就会静默失效）。
    r"revert\s+[A-Za-z_]\w*|"
    r"revert\b|throw\b|return\b|selfdestruct\s*\(|"
    r"require\s*\([^;]*(?:false|0)\s*\))", re.S)


# M96：身份**函数**形态的恒等校验 —— `require(_msgSender() == address(POOL))`。
#
# Aave V3 / OpenZeppelin / solmate 都把调用者身份封成零参函数（`_msgSender()`、
# `msgSender()`、`_sender()`）。此时比较的一侧不是 `msg.sender` 字面量，
# `_SOLIDITY_MSGSENDER_CHECK_RE` 看不见 —— 于是把 `onlyPool` 修饰的函数
# 判成"缺访问控制"（实测 Aave `AToken.transferOnLiquidation`：修饰符
# 定义体就在父合约证据段里，`require(_msgSender() == address(POOL), ...)`）。
#
# 判据挂机制：require/assert 的条件里出现**恒等**比较（`==`）且一侧是
# 身份函数。只认 `==` 不认 `!=` —— `require(_msgSender() != address(0))`
# 是"调用者非零地址"，不是授权判定（把它算成保护会造出假阴性）。
_SOL_IDENTITY_FN_RE = re.compile(
    r"\bmsg\s*\.\s*sender\b|_msgSender\s*\(\s*\)|msgSender\s*\(\s*\)|"
    r"_sender\s*\(\s*\)")


def _sol_identity_call_check(text: str) -> bool:
    """require/assert 条件里是否有"身份函数 == 主体"的恒等比较（M96）。"""
    for m in re.finditer(r"\b(?:require|assert)\s*\(", text):
        close = _sol_match_paren(text, m.end() - 1)
        if close < 0:
            continue
        cond = text[m.end():close]
        if "==" not in cond:
            continue
        if not _SOL_IDENTITY_FN_RE.search(cond):
            continue
        return True
    return False


def _sol_predicate_authz_check(text: str) -> bool:
    """**谓词式**授权（M108，synthetix 实测形态）。

        modifier onlyOwner() { require(isOwner(), "caller is not the owner"); _; }
        function isOwner() public view returns (bool) {
            return _msgSender() == _owner;
        }

    身份比较被封进一个谓词函数，外层只看得到 `require(isOwner(), …)` ——
    任何"在 require 里找 `==`"的判据都看不见它，于是 `transferOwnership`
    被判成"缺访问控制"（sushiswap-zapper 两条误报就是这么来的）。

    判据挂机制：① 在全文里找出**函数体内部做了身份比较**的谓词函数名；
    ② 该函数名出现在 require/assert 条件里，或出现在 `if (...)` 条件里且
    该 if 的分支**会中止**。
    """
    preds: set[str] = set()
    for m in re.finditer(
            r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{", text):
        blk = _sol_block_body(text, m.end() - 1)
        if not blk:
            continue
        if _SOL_IDENTITY_FN_RE.search(blk) and re.search(r"[!=]=", blk):
            # 排除"只比零地址"的谓词：那不是身份判定
            if not re.fullmatch(r"[\s\S]*?[!=]=\s*address\s*\(\s*0\s*\)"
                                r"[\s\S]*", blk):
                preds.add(m.group(1))
    if not preds:
        return False
    for name in preds:
        if re.search(rf"\b(?:require|assert)\s*\([^;]{{0,160}}?\b{name}\s*\(",
                     text):
            return True
        for m in _IF_RE.finditer(text):
            close = _sol_match_paren(text, m.end() - 1)
            if close < 0:
                continue
            cond = text[m.end():close]
            if not re.search(rf"\b{name}\s*\(", cond):
                continue
            blk = _sol_block_body_at(text, close + 1)
            if blk and _sol_block_aborts(blk):
                return True
    return False


def _sol_inverted_identity_guard(text: str) -> bool:
    """**反向条件**式授权：`if (X != _msgSender()) { revert }`（M108）。

    与 `require(X == _msgSender())` **完全等价** —— 中止发生在"不相等"分支。
    M96 记的是"只认 `==` 不认 `!=`"，那句针对的是 `require`：`require(sender
    != address(0))` 是零地址检查，不是授权。但**反过来**写在 if 里就翻面了：

        require(a != b)      → 要求"不等"，不是授权
        if (a != b) revert   → 要求"相等"，是授权

    synthetix 的 `acceptPoolOwnership` 就是后者：
        if (pool.nominatedOwner != ERC2771Context._msgSender()) {
            revert AccessError.Unauthorized(...);
        }

    排除项：对手方是 `address(0)` / 同义零地址（那是零地址检查）。

    M108 补丁：**身份别名**。synthetix 的 `SnapshotRewardsDistributor` 写成

        address sender = ERC2771Context._msgSender();
        if (sender != rewardsManager) { revert ... }

    条件里没有身份函数，只有别名变量 `sender` —— 必须先把别名认出来，
    否则这条守卫看不见（与 M95 的 `_sol_identity_alias_check` 同一机制，
    只是那边认 `==`、这边认 if 里的 `!=`）。
    """
    aliases = set(_sol_identity_aliases(text))
    for m in _IF_RE.finditer(text):
        close = _sol_match_paren(text, m.end() - 1)
        if close < 0:
            continue
        cond = text[m.end():close]
        blk = _sol_block_body_at(text, close + 1)
        if not blk or not _sol_block_aborts(blk):
            continue
        for part in re.split(r"\|\||&&", cond):
            if "!=" not in part:
                continue
            if re.search(r"address\s*\(\s*0\s*\)|\b0x0+\b", part):
                continue
            if _SOL_IDENTITY_FN_RE.search(part):
                return True
            if any(re.search(rf"\b{re.escape(a)}\b", part) for a in aliases):
                return True
    return False


def _sol_identity_aliases(text: str) -> list[str]:
    """收集 `address x = <身份函数>;` 形态的别名变量名（M108）。"""
    out: list[str] = []
    for m in re.finditer(
            r"\baddress\s+(?:payable\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);", text):
        if _SOL_IDENTITY_FN_RE.search(m.group(2)):
            out.append(m.group(1))
    return out


def _sol_negated_identity_call(text: str) -> bool:
    """`if (!<校验>(<身份函数>, …)) { revert }` 型授权（M108）。

        if (!_isApprovedOrOwner(ERC2771Context._msgSender(), tokenId)) {
            revert AccessError.Unauthorized(ERC2771Context._msgSender());
        }

    与 `require(_isApprovedOrOwner(_msgSender(), tokenId))` **同义** ——
    只是把"取反 + 中止"写成了 if。旧判据只认 require 形态，synthetix 的
    ERC721.transferFrom 因此被判成缺访问控制。

    判据挂机制（两条同时成立）：
      ① `if (!<call>(...))` 形状，且该 if 的分支**会中止**；
      ② 该 call 的实参里有**身份函数**（`_msgSender()`/`msg.sender`/`_sender()`）。
    实参里没有身份就不是授权判定 —— 那是普通过滤条件，不算保护。
    """
    for m in _IF_RE.finditer(text):
        close = _sol_match_paren(text, m.end() - 1)
        if close < 0:
            continue
        cond = text[m.end():close]
        cm = re.search(r"!\s*([A-Za-z_]\w*)\s*\(", cond)
        if not cm:
            continue
        blk = _sol_block_body_at(text, close + 1)
        if not blk or not _sol_block_aborts(blk):
            continue
        cclose = _sol_match_paren(cond, cm.end() - 1)
        args = cond[cm.end():cclose] if cclose > 0 else ""
        if _SOL_IDENTITY_FN_RE.search(args):
            return True
    return False


def _sol_block_body_at(text: str, pos: int) -> str:
    """从 `pos` 起**跳过空白**再取 `{...}` 块（M108）。

    `_sol_block_body` 要求下标正好落在 `{` 上。守卫写法的 `)` 与 `{` 之间
    常有空格或换行（`if (!f(x)) {` / `if (a != b)\\n{`），直接传 `close+1`
    会拿到空白 → 返回空串 → 判定静默失效（不是报错，是永远判 False）。
    """
    i = pos
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    return _sol_block_body(text, i)


def _sol_block_aborts(body: str) -> bool:
    """`if (...) { ... }` 块里是否有**中止**语义。

    判据（挂机制不挂名字）：块里出现 revert / throw / return（裸 return
    也算 —— 它终止了本函数）/ selfdestruct。

    注意 `return` 的歧义：`return;` 与 `return x;` 都终止本函数，
    在 modifier 语境下等价于"不执行 `_`"—— 也就是**拒绝了非 owner 的
    调用**，是保护。但 `if (c) { return someValue; }` 在普通函数里
    只是提前返回 —— 修饰符语境下仍是"非 owner 走别的分支"，
    保护性成立（owner 才会继续执行 `_`）。
    """
    return bool(_SOL_BLOCK_ABORT_RE.search(body))
# 权限映射成员检查（M36，430 桶榜首确定性子簇）：msg.sender 作映射键且
# 做"非零成员"判定 —— `owners[msg.sender] != 0` / 裸真值
# `require(approvedPlayers[msg.sender])` / 连接词前缀
# `require(owners[msg.sender] && ...)`。调用者身份进入了授权判定，机制
# 与恒等检查等价。**余额比较不算**（`balances[msg.sender] >= _value`
# 是资金充足性检查，右侧是数量不是成员资格）——所以只认 `)` 结尾、
# `!= 0 / != address(0)`、或 `&&` 连接三种形态，任何 `< > <= >=` 关系
# 比较都不匹配。
_SOLIDITY_MSGSENDER_MEMBER_RE = re.compile(
    r"(?:require|assert|if)\s*\(\s*\w+\s*\[\s*msg\s*\.\s*sender\s*\]\s*"
    # 末尾可以是 `)`（无消息）/ `,`（require 带错误消息）/ `!= 0` / `&&`
    # —— M54 实测：`require(_executionOperators[msg.sender], "only ...")`
    # 的逗号形态原先不匹配 ⇒ 权限映射检查被漏掉。
    r"(?:\)|,|!=\s*(?:0|address\s*\(\s*0\s*\))|&&)")


# ---- M136：调用者键控的**授权映射**（MakerDAO dss `wards[msg.sender] == 1`）----
#
# `_SOLIDITY_MSGSENDER_MEMBER_RE` 只认"裸真值 / != 0 / &&"三种形态，碰上
# dss 的显式等值写法就漏了：
#
#     modifier auth {
#         require(wards[msg.sender] == 1, "Vat/not-authorized");
#         _;
#     }
#
# 于是 `rely` / `deny` / `file` / `cage` 这些只该管理员调的函数会被判成
# "缺访问控制" —— 判反方向（把安全判成漏洞）。
#
# 判据挂机制，且**必须同时满足两条**，否则会把余额检查误当授权：
#   ① 槽位是**调用者键控**的（`<映射>[msg.sender]`）；
#   ② 与**真值常量**做**恒等**比较（`== 1` / `== true`，或反向
#      `if (wards[msg.sender] == 0) { revert }` 的中止块）。
# 只认 `==`：`balances[msg.sender] >= amount` 是资金充足性检查，
# 授权与否跟它无关 —— 把它算成保护会吃掉真正的越权（铁律 22 的反面）。
_SOL_CALLER_MAP_EQ_RE = re.compile(
    r"(?:require|assert)\s*\(\s*[^;]{0,120}?"
    r"[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*\[\s*msg\s*\.\s*sender\s*\]"
    r"\s*==\s*(?:1|true)\b"
    r"|(?:require|assert)\s*\(\s*(?:1|true)\s*==\s*"
    r"[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*\[\s*msg\s*\.\s*sender\s*\]",
    re.S)
_SOL_CALLER_MAP_NEG_RE = re.compile(
    r"if\s*\(\s*[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*\[\s*msg\s*\.\s*sender\s*\]"
    r"\s*==\s*(?:0|false)\s*\)", re.S)


def _sol_caller_map_auth(text: str) -> bool:
    """`wards[msg.sender] == 1` 型授权映射守卫（M136，MakerDAO dss）。

    机制：**调用者键控的授权表**在条件里与真值常量做等值比较。
    正向形态（`require(wards[msg.sender] == 1, ...)`）本身就中止；
    反向形态（`if (wards[msg.sender] == 0) { revert ... }`）还要求块内
    真的**中止**（`if` 里只写日志不是保护）。
    """
    if _SOL_CALLER_MAP_EQ_RE.search(text):
        return True
    for m in _SOL_CALLER_MAP_NEG_RE.finditer(text):
        blk = _sol_block_body(text, m.end() - 1)
        if blk and _sol_block_aborts(blk):
            return True
    return False

# ---- M54：tx.origin 恒等比较（带"另一侧"捕获） ----
#
# 判据要区分**比较的另一侧**：另一侧是 msg.sender ⇒ "拒绝合约调用"
# 语义（收紧访问控制，不是漏洞）；另一侧是存储的主体（owner 等）
# ⇒ 钓鱼反模式（Phishable）。
#
# 两种书写顺序都要抓：`tx.origin == X` 与 `X == tx.origin`。
# 另一侧的形态：标识符 / `this.owner` / `_owner` / `owner()`。
_SOL_TXORIGIN_EQ_RE = re.compile(
    r"(?:require|assert|if)\s*\([^;]{0,160}?"
    r"(?:([A-Za-z_][\w.]*)\s*==\s*tx\s*\.\s*origin"
    r"|tx\s*\.\s*origin\s*==\s*([A-Za-z_][\w.]*))", re.S)

# ---- M54：委托形态（限定调用） ----
#
# `X.transferFrom(from, ...)` / `X._transfer(from, ...)` —— 接收者是
# **另一个合约**（`IERC20(target)` / `token` / `super`）⇒ 转出逻辑在
# 对方那边，本合约看不到授权判定 ⇒ 缺证据。
#
# 与本地调用区分：`transferFrom(from, ...)` / `_transfer(from, ...)`
# （前面没有限定符）是本合约的辅助函数 ⇒ 实现体在切片里 ⇒ 可核验。
_SOL_DELEGATED_FROM_RE = re.compile(
    # 接收者形态：`标识符` / `标识符(实参)`（`IERC20(target).transferFrom`）
    # / `super`。
    r"(?:[A-Za-z_]\w*(?:\s*\([^()]{0,80}\))?\s*\.\s*|super\s*\.\s*)"
    r"(?:transferFrom|_transfer|_safeTransfer)\s*\(\s*_?from\b")

# ---- M54：owner 写委托形态 ----
#
# `transferOwnership(...)` 作为**裸调用**（前面没有限定符）才是本合约
# 自己的 owner 写；`X.transferOwnership(...)`（限定调用）是把 owner 写
# **委托**给别的合约/库 —— 写在哪、谁有权限都在对方那边，本合约看不到
# ⇒ 不能据此判越权（缺证）。
#
# 例（Top200 ContractOwnershipBase）：
#   ContractOwnershipStorage.layout().transferOwnership(_msgSender(), newOwner);
# —— owner 实际写在**另一个文件**的 library 里（该库内部有
# `require(sender == s.contractOwner)` 的授权判定）。
#
# 判反风险锚点：smartbugs access_control 真阳 19 条里，
# `transferOwnership(` 调用形态 **0 条**（裸调用 / 限定调用都没有），
# 且真阳的 owner 写都是**裸标识符赋值**（owner = xxx）——
# 那条判据（`_sol_owner_state_write`）不受影响。
_SOL_BARE_TRANSFER_OWNERSHIP_RE = re.compile(
    r"transferOwnership\s*\(")
# 裸调用判定：调用点**前面**不是限定形式。
# Python 后向断言必须定宽，所以用"取前缀再判断"而不是 lookbehind。
#
# 限定形式可以是任意长的链：`X.y()` / `X.layout()` / `X.layout().y()`
# —— 所以前缀要匹配"以 `.` 或 `)` 结尾的限定链"。
_SOL_CALL_PREFIX_RE = re.compile(
    r"((?:[A-Za-z_]\w*(?:\s*\([^()]{0,80}\))?\s*\.\s*)*"
    r"(?:[A-Za-z_]\w*\s*\([^()]{0,80}\)\s*\.\s*)?)$")

# ---- M54：间接身份检查（父合约函数体核验） ----
#
# OpenZeppelin 的 `require(_owner == _msgSender())` 里没有 msg.sender 字面，
# 但 Context 基类的 `_msgSender()` 实现体就是 `return msg.sender;`。
# "看实现体不看名字"铁律要求核验实现体 —— 切片层（M54）把父合约的
# 函数体拼进"父合约继承证据"段，规则层据此认出身份检查。
#
# 机制口径（不挂名字）：比较式的一侧是**某个函数调用**，而该函数在
# 切片证据段里的实现体**返回 msg.sender** → 它就是身份获取。
_SOL_IDENTITY_FUNC_BODY_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{[^}]*\breturn\s+"
    r"\(?\s*msg\s*\.\s*sender\s*\)?\s*;", re.S)
_SOL_COMPARE_CALL_RE = re.compile(
    r"(?:require|assert|if)\s*\([^;]{0,160}?\b([A-Za-z_]\w*)\s*\(\s*\)"
    r"\s*(?:==|!=)\s*[^;]{0,80}?\)", re.S)
# 比较的**另一侧**是身份函数调用：`require(_owner == _msgSender(), '...')`
# —— 调用后面可能还有 require 的错误消息参数（逗号 + 字符串）。
_SOL_COMPARE_CALL_RE2 = re.compile(
    r"(?:require|assert|if)\s*\([^;]{0,160}?(?:==|!=)\s*"
    r"\b([A-Za-z_]\w*)\s*\(\s*\)\s*(?:,|\))", re.S)

# 谓词式身份函数：`function isOwner() ... { return msg.sender == _owner; }`
# —— 实现体里**拿 msg.sender 做比较**（不一定是 return msg.sender）。
# 比较式在函数体内（`msg.sender == x` / `x == msg.sender`），
# 但函数名不在比较的一侧 —— 消费点在 require(f()) 里。
_SOL_PREDICATE_BODY_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{[^}]*?"
    r"msg\s*\.\s*sender\s*(?:==|!=)[^;}]*;[^}]*\}", re.S)


def _sol_indirect_identity_check(func_src: str, mod_ev: str,
                                func_ev: str) -> bool:
    """切片里是否存在**间接身份检查**（比较的一侧是身份获取函数）。

    两种机制，都挂**机制**不挂名字：

    A. **取值式**：比较的一侧是某个函数 f()，f 的实现体返回 msg.sender
       （OpenZeppelin `require(_owner == _msgSender())` + Context 的
       `return msg.sender;`）。
       判据：① 实现体在切片证据段里；② 本合约自己的代码里拿 f() 做比较。

    B. **谓词式**：本合约代码里出现 `require(f())`，而 f 的实现体里
       **拿 msg.sender 做比较**（`isOwner()` → `return msg.sender == _owner;`）。
       判据：① f 的实现体在切片证据段里；② 它的实现体含 msg.sender 比较；
       ③ 本合约代码里 `require(f())` / `assert(f())` 消费了它。
       —— 谓词式没有"比较的一侧"，比较**藏在 f 里面**。

    C. **modifier 调用链**（M54）：`modifier onlyOwner() { _checkOwner(); _; }`
       —— modifier 体里调的 `_checkOwner()`，其实现体（证据段里）
       含 `require(owner() == _msgSender())`。这条链是**三层**：
       modifier → 辅助函数 → 身份函数 → `return msg.sender;`。
       判据：① modifier 体调用的函数 f；② f 的实现体在证据段里；
       ③ f 的实现体里有身份检查（取值式或谓词式）。
       —— 与 A/B 的区别：A/B 要求"比较式在本合约代码里"，
       C 允许比较式在**modifier 调用链的实现体**里。因为 modifier
       展开后那段代码就**跑在本函数体之前**，它就是本函数的实际保护。

    **比较式只在 func_src + mod_ev 里找**（M54 实测教训）：父合约**函数**
    实现体里的比较是父合约自己的检查，保护不了子合约的函数 —— 拿它给
    子函数判"有保护"是判反方向。父合约**修饰符**里的比较则可以（父合约
    的 onlyOwner 就是子合约函数的实际保护）。C 分支是这条原则的延伸：
    修饰符**调用链**上的辅助函数（modifier 展开即执行）也算。
    """
    own = func_src + "\n" + mod_ev
    evid = own + "\n" + func_ev

    # ---- A. 取值式：实现体返回 msg.sender ----
    identity_funcs = {m.group(1)
                      for m in _SOL_IDENTITY_FUNC_BODY_RE.finditer(evid)}
    if identity_funcs:
        for pat in (_SOL_COMPARE_CALL_RE, _SOL_COMPARE_CALL_RE2):
            for m in pat.finditer(own):
                if m.group(1) in identity_funcs:
                    return True

    # ---- B. 谓词式：辅助函数实现体里拿 msg.sender 做比较 ----
    for m in _SOL_PREDICATE_BODY_RE.finditer(evid):
        fname = m.group(1)
        # 消费点：本合约代码里 require(f()) / assert(f()) / if (f())
        if re.search(rf"(?:require|assert|if)\s*\(\s*{re.escape(fname)}\s*\(",
                     own):
            return True

    # ---- C. modifier 调用链上的身份检查 ----
    # modifier 体里调用的函数 f，其实现体里的身份检查就是本函数的保护。
    # 判据按**调用链**（modifier → f），不按函数名。
    for f in _sol_modifier_callees(mod_ev):
        body = _sol_func_body_by_name(evid, f)
        if not body:
            continue
        # C-a 取值式：body 里比较的一侧是身份函数
        for pat in (_SOL_COMPARE_CALL_RE, _SOL_COMPARE_CALL_RE2):
            for m in pat.finditer(body):
                if m.group(1) in identity_funcs:
                    return True
        # C-b 谓词式：body 里 require(g())，g 的实现体拿 msg.sender 比较
        for m in _SOL_PREDICATE_BODY_RE.finditer(evid):
            g = m.group(1)
            if g == f:
                return True
            if re.search(rf"(?:require|assert|if)\s*\(\s*{re.escape(g)}\s*\(",
                         body):
                return True
    # ---- D. 身份沿调用链传递到权限判定（角色检查形态） ----
    #   modifier onlyRole(role) → _checkRole(role)
    #   → _checkRole(role, _msgSender()) → if (!hasRole(role, account)) revert
    # 身份被**当实参传下去**，形参参与下游的中止性判定。
    if _sol_identity_propagated_auth(mod_ev, evid, identity_funcs):
        return True
    return False


# ---- M54：身份沿调用链传递到权限判定 ----
#
# OpenZeppelin 的角色检查把身份**当实参传下去**：
#   modifier onlyRole(bytes32 role) { _checkRole(role); _; }
#   → function _checkRole(role) { _checkRole(role, _msgSender()); }
#   → function _checkRole(role, account) { if (!hasRole(role, account)) revert; }
# 身份（`_msgSender()`）是**实参**，account 形参在下游参与中止性判定。
#
# 与 A/C 的区别：A/C 是"比较的一侧是身份函数"（身份直接参与比较），
# 这里是"身份被传下去，形参参与判定"（身份经**位置对应**落到形参）。
#
# 判据（挂机制不挂名字）：
#   ① modifier 调用链的某个实现体里，调用 g(..., X, ...) 的实参 X
#      是身份来源（msg.sender 字面 / 身份函数调用）；
#   ② g 的形参**按位置**对应到 X；
#   ③ g 的实现体里，该形参参与了**中止性判定**（出现在 if/require
#      条件里，且条件为假时中止）。
_SOL_ABORT_CONTEXT_RE = re.compile(
    r"(?:require|assert|if)\s*\(", re.S)


def _sol_identity_propagated_auth(mod_ev: str, evid: str,
                                  identity_funcs: set[str]) -> bool:
    """身份沿调用链传递到权限判定 ⇒ 本函数受保护。

    机制（挂机制不挂名字）：
      ① modifier 调用链的某个实现体里，调用 `g(..., X, ...)` 的实参 X
         是**身份来源**（msg.sender 字面，或返回 msg.sender 的函数）；
      ② g 的**形参按位置**对应到 X（实参下标 → 形参下标）；
      ③ g 的实现体里，该形参参与了**授权判定**（中止型或放行型）。

    **多跳**（M54）：角色检查链是三层的 ——
      modifier onlyRole → `_checkRole(role)` →
      `_checkRole(role, _msgSender())` →
      `if (!hasRole(role, account)) revert`
    身份在**第二跳**才被传下去（第一跳的实参是 role，不是身份），
    且第三跳才出现消费点。所以要沿链**递归**（带 `_visited` 防环）。

    判反风险锚点：smartbugs access_control 真阳 19 条里，modifier 调用
    链把身份当实参传下去再判定的形态 **0 条**（probe_m54_ac_risk2.py
    的 M2 命中 0 条）。
    """
    return _sol_idprop_walk(mod_ev, evid, identity_funcs,
                            _sol_modifier_callees(mod_ev), set(), 0)


def _sol_idprop_walk(mod_ev: str, evid: str, identity_funcs: set[str],
                     funcs: set[str], visited: set[tuple],
                     depth: int) -> bool:
    """沿调用链递归找"身份 → 形参 → 授权判定"。

    **层次语义**（M54）：
      · 第 0 层的"调用点"在 **modifier 体**里 —— 形参实参对应要用
        modifier 体里的**调用表达式**（`require(isAuthorized(msg.sender,
        msg.sig))`），不是函数定义体；
      · 第 1 层起进函数**定义体**，找下一跳的调用表达式。

    visited 按 **(函数名, 实参个数)** 记 —— 同名重载是**不同**的
    实现体（`_checkRole(role)` 与 `_checkRole(role, account)`），
    按函数名去重会把重载那一跳误判成环。

    depth 上限 3（modifier → g → g2 → g3）。
    """
    if depth > 3:
        return False
    for f in funcs:
        # 第 0 层：调用点在 modifier 体；之后：调用点在函数定义体
        if depth == 0:
            call_sites = _sol_modifier_bodies(mod_ev)
            bodies_here = call_sites
        else:
            bodies_here = [_sol_func_body_by_name(evid, f)]
            call_sites = bodies_here
        for body in bodies_here:
            if not body:
                continue
            for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
                g = m.group(1)
                args = _sol_parse_args(body, m.end() - 1)
                if not args:
                    continue
                key = (g, len(args))
                if key in visited:
                    continue
                # **按实参个数**取重载版本（位置对应必须用对的实现体）
                gbody = _sol_func_body_by_name(evid, g, argc=len(args))
                if not gbody:
                    continue
                params = _sol_param_list(gbody)
                if not params:
                    continue
                for i, arg in enumerate(args):
                    if i >= len(params):
                        break
                    pname = params[i]
                    if not pname:
                        continue
                    if not _sol_arg_is_identity(arg, identity_funcs):
                        continue
                    # 形参 pname 在 g 的实现体里参与了授权判定？
                    if _sol_param_in_abort_cond(gbody, pname):
                        return True
                # 下一跳：g 的实现体里调的其它函数
                visited.add(key)
                nxt: set[str] = set()
                for m2 in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", gbody):
                    g2 = m2.group(1)
                    if g2 in identity_funcs:
                        continue
                    a2 = _sol_parse_args(gbody, m2.end() - 1)
                    if not a2:
                        continue
                    if (g2, len(a2)) in visited:
                        continue
                    if _sol_func_body_by_name(evid, g2, argc=len(a2)):
                        nxt.add(g2)
                if nxt and _sol_idprop_walk(mod_ev, evid, identity_funcs, nxt,
                                            visited, depth + 1):
                    return True
    return False


def _sol_arg_is_identity(arg: str, identity_funcs: set[str]) -> bool:
    """实参是否是**身份来源**。

    两种形态：① msg.sender 字面；② 返回 msg.sender 的函数调用
    （`_msgSender()`）。后者靠 identity_funcs（实现体核验过的）。
    """
    a = arg.strip()
    if re.fullmatch(r"msg\s*\.\s*sender", a):
        return True
    for f in identity_funcs:
        if re.fullmatch(rf"{re.escape(f)}\s*\(\s*\)", a):
            return True
    return False


def _sol_param_in_abort_cond(body: str, pname: str) -> bool:
    """形参 pname 是否参与了**授权判定**。

    两种机制，都算保护：

    ① **中止型**：pname 出现在 `require(...)` / `assert(...)` 的条件里，
       或 `if (...)` 条件里且条件为假时**中止**（revert/throw/return）。
       典型：`_checkRole(role, account) { if (!hasRole(role, account)) revert; }`

    ② **放行型**：pname 出现在某个 `if (...)` 条件里，且该分支
       **放行**（`return true`）—— 这是"授权通过则继续"的写法。
       典型（DSAuth）：`isAuthorized(src, sig) { if (src == owner) return true; }`
       modifier 侧是 `require(isAuthorized(msg.sender, msg.sig))`。

    判反风险锚点：smartbugs access_control 真阳 19 条里，"modifier 调用
    链把 msg.sender 当实参传下去"的形态 **0 条**
    （probe_m54_ac_risk2.py 的 M2 + 本轮锚点脚本）。
    """
    pat = re.compile(rf"\b{re.escape(pname)}\b")
    for m in _SOL_ABORT_CONTEXT_RE.finditer(body):
        open_i = m.end() - 1
        close = _sol_match_paren(body, open_i)
        if close < 0:
            continue
        cond = body[open_i + 1:close]
        if not pat.search(cond):
            continue
        is_require = m.group(0).startswith(("require", "assert"))
        if is_require:
            # require/assert 的条件里出现该形参 —— 判定参与了授权
            return True
        # 条件为假时中止？
        # **不能用固定长度截断** —— 块体可能很长（OZ 的 revert 带
        # 复杂错误信息），截断后配平不到 `}` ⇒ 取不到块 ⇒ 判不出中止。
        tail = body[close + 1:]
        stripped = tail.lstrip()
        blk = _sol_block_body(stripped, 0) if stripped[:1] == "{" else ""
        if blk:
            if _sol_block_aborts(blk):
                return True
            # 放行型：条件为真时 return true
            if re.search(r"\breturn\s+true\b", blk):
                return True
        elif re.match(r"\s*(?:revert|throw|return)\b", tail):
            return True
    return False


# ---- M54：签名授权机制 ----
#
# ECDSA 签名恢复：`ecrecover(digest, v, r, s)` 恢复出签名者地址。
# 恢复出来的地址与某个主体比较 ⇒ 该主体的支配权由**私钥**约束。
#
# 判据（挂机制不挂名字）：
#   ① 函数体/辅助函数体里出现**签名恢复**调用；
#   ② 恢复出的地址（或其载体变量）与某个主体做了**相等比较**，
#      且该比较出现在**会中止**的语境（require/assert/revert）。
#
# 与"直接身份检查"的区别：比较的一侧不是 msg.sender，而是
# **签名恢复的结果** —— 调用者不需要是那个主体，持有其私钥即可。
_SOL_SIG_RECOVER_RE = re.compile(
    r"\b(?:ecrecover|recover|recoverPlain|tryRecover)\s*\(")
# 恢复结果被赋给某个变量：`address recovered = ecrecover(...)`
_SOL_SIG_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\s*\.\s*)?"
    r"(?:ecrecover|recover|recoverPlain|tryRecover)\s*\(")
# 相等比较（恢复结果 vs 主体）
_SOL_SIG_CMP_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:==|!=)\s*([A-Za-z_]\w*)")


def _sol_signature_authorized(func_src: str, inh_ev: str) -> bool:
    """签名授权机制：from 的支配权由 ECDSA 签名约束（permit 形态）。

    实现要点：
      ① 找出所有**恢复结果变量**（被赋值为 ecrecover(...) 的标识符）；
      ② 在同一段文本里找这些变量参与的**相等比较**；
      ③ 比较必须出现在**会中止**的语境里（require/assert/if+revert）。

    只看**函数体 + 同文件/父合约辅助函数体**（inh_ev）—— 签名校验
    必须在能看到的实现体里，否则不算证据。
    """
    evid = func_src + "\n" + inh_ev
    if not _SOL_SIG_RECOVER_RE.search(evid):
        return False
    recovered: set[str] = set()
    for m in _SOL_SIG_ASSIGN_RE.finditer(evid):
        recovered.add(m.group(1))
    if not recovered:
        # 形态 A：签名恢复结果**直接**参与比较
        #   `require(ecrecover(digest, v, r, s) == signer)`
        for m in re.finditer(
                r"(?:require|assert)\s*\([^;]{0,200}?"
                r"(?:ecrecover|recover)\s*\([^;]{0,200}?\)\s*==\s*"
                r"([A-Za-z_]\w*)", evid, re.S):
            return True
        return False
    # 形态 B：恢复结果变量参与比较
    for m in _SOL_SIG_CMP_RE.finditer(evid):
        lhs, rhs = m.group(1), m.group(2)
        if lhs not in recovered and rhs not in recovered:
            continue
        # 比较必须伴随中止语义：往前找最近的 require/assert/if
        head = evid[max(0, m.start() - 160):m.start()]
        if re.search(r"(?:require|assert)\s*\([^;]{0,160}$", head) or \
                re.search(r"\bif\s*\([^;]{0,160}$", head):
            return True
    return False


def _sol_block_body(text: str, open_idx: int) -> str:
    """取 `text[open_idx]` 处 `{` 开始的配平块内容（不含大括号）。

    open_idx 必须是 `{` 的下标。配平失败返回空串。
    """
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "{":
        return ""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:j]
    return ""


def _sol_modifier_bodies(text: str) -> list[str]:
    """提取文本里所有 modifier 的**配平实现体**。

    不能用 `re.finditer(r"modifier\\s+\\w+[^{]*\\{(.*)", text, re.S)` ——
    `(.*)` 贪婪匹配到文件尾，会把**所有** modifier 的体拼成一段，
    于是 A modifier 的检查被算成 B modifier 的保护。
    必须按大括号配平逐个切（M54 实测）。
    """
    out: list[str] = []
    for mm in re.finditer(r"\bmodifier\s+[A-Za-z_]\w*\s*(?:\([^)]*\))?\s*"
                          r"[^{]*\{", text):
        body = _sol_block_body(text, mm.end() - 1)
        if body:
            out.append(body)
    return out


def _sol_modifier_callees(mod_ev: str) -> set[str]:
    """modifier 定义体里调用的函数名集合。

    口径：modifier 体（`modifier X(...) { ... _; }`）里出现的**函数调用**。
    modifier 展开后这些调用就执行在本函数体之前 —— 它们调用到的函数
    实现体里的检查，就是本函数的实际保护。

    只取"被调用"的标识符（后面紧跟左括号），排除 require/assert/
    revert 这类内建 —— 内建不是"可查实现体的辅助函数"。
    """
    out: set[str] = set()
    for body in _sol_modifier_bodies(mod_ev):
        for c in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body):
            if c in {"require", "assert", "revert", "if", "for", "while",
                     "return", "_"}:
                continue
            out.add(c)
    return out


def _sol_func_body_by_name(text: str, fname: str,
                           argc: int | None = None) -> str:
    """按名字从文本里取函数的实现体（签名 + 体）。

    找不到返回空串。实现体是"函数名之后第一个大括号到配平结束"。

    **argc**（M54）：按**实参个数**挑重载版本。同名重载（`_checkRole(role)`
    与 `_checkRole(role, account)`）的实现体不同，位置对应必须用对版本
    —— 传了 argc 就只在形参数匹配的版本里找；形参数不等就返回空串
    （位置对应不了，宁可缺证据）。
    """
    for fm in re.finditer(rf"\bfunction\s+{re.escape(fname)}\s*\(", text):
        close = _sol_match_paren(text, fm.end() - 1)
        if close < 0:
            continue
        if argc is not None:
            args = _sol_split_top_commas(text[fm.end():close])
            # 无名形参可能写成纯类型 —— 数量对即可
            if len(args) != argc:
                continue
        op = text.find("{", close)
        if op < 0:
            continue
        depth = 0
        for j in range(op, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    return text[fm.start():j + 1]
    return ""


# ---- M44：调用者自域状态写（Caller-Scoped State Mutation）----
#
# 静态盲点：普通用户态业务函数（transfer/approve/deposit/withdraw）
# 既不是 view/pure，也不带 onlyOwner，但它们改的只是 balances[msg.sender]
# 或 allowance[msg.sender][...] —— **调用者自己名下的槽位**，不是合约级
# 特权操作（改 owner / selfdestruct / 提走全合约 ETH / 改全局费率）。
# 早退判 False 不用模型就能再砍一大截退回桶。
#
# 判据挂"值位置"不挂名字：外转金额必须绑定自域槽位。形参金额形态
# （msg.sender.transfer(amount)）**不满足** —— 金额可能来自合约整体
# 资产（smartbugs wallet_04_confused_sign：require(amount >= balances
# [msg.sender]) 比较方向写反，任何人可提走合约里的钱 —— 官方 access_control
# 真值行，反查命中这条时整条规则直接作废）。
_SOL_PRIV_SINK_RE = re.compile(
    r"\bselfdestruct\s*\(|\bsuicide\s*\(|\bdelegatecall\s*\(|"
    r"\btransferOwnership\s*\(|"
    r"\b(?:owner|creator|admin|paused|frozen|locked)\b\s*=(?!=)", re.I)
_SOL_DRAIN_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance"
    r"|\.\s*call\s*\{[^}]*\}\s*\([^;]*(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance",
    re.S)
# 状态写：映射索引写 / 标量写。前面有类型词的是局部声明（先剥掉）
_SOL_ASSIGN_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])((?:[A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])*)|(?:[A-Za-z_]\w*))"
    r"\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")
_SOL_LOCAL_DECL_RE = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|bytes32|string|var|"
    r"mapping\s*\([^)]*\))\s+(\w+)\s*=\s*")
_SOL_EXT_OUT_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\(([^;()]*)\)"
    r"|\.\s*call\s*\{\s*value\s*:\s*([^;{}]*)\}"
    r"|\.\s*call\s*\.\s*value\s*\(([^;()]*)\)")
_SOL_SELF_SLOT_RE = re.compile(r"\w\s*\[\s*msg\s*\.\s*sender\s*\]")
# 资金充足性校验：槽位 >= 数量 或 数量 <= 槽位
_SOL_BAL_GUARD_RE = re.compile(
    r"\w\s*\[\s*msg\s*\.\s*sender\s*\]\s*>=\s*"
    r"|\w\s*<=\s*\w+\s*\[\s*msg\s*\.\s*sender\s*\]")

# ---- M52：隐式只读 + 双边守恒代币流转 ----
#
# 静态盲点：老合约（0.4.x 时代）大量函数**漏标 view/pure**（编译器强制
# 事实只对"标了"的生效），实际函数体里既无特权 Sink 也无状态写 —— 纯
# 计算/纯事件函数。这类函数在 access_control 维度上确定性 safe。
#
# 双边守恒代币流转：ERC20 标准转账 `balances[from] -= v; balances[to] += v;`
# —— 同一个映射上一减一增、值守恒，没有任何"谁能动别人钱"的可能。
#
# 三条必须守住的底线（每条都对应一个真被判反过的样本）：
#  ① **映射 `=` 写也算状态写**（mapping_write.sol:set 官方标 vul，
#     `map[key] = value;` 是任意位置写，不是守恒）；
#  ② **纯调用形态不算只读**（parity_wallet_bug_1.sol:initWallet 官方标
#     vul：函数体自己只调 initDaylimit/initMultiowned，状态写在被调函数
#     里 —— "入口体没 X 就判安全"是陷阱）；
#  ③ **取出自己余额但不清零不算安全**（wallet_02:refund 官方标 vul，
#     `msg.sender.transfer(balances[msg.sender])` 是 SWC-105 未保护提款：
#     可重复调用掏空合约 —— 外转额绑自域槽位还不够，必须**有配对扣减**）。
# ④ **扣减方必须是 msg.sender 或已扣减 allowance 的授权方**：
#     任意 from 的 transferFrom 是 M30 的 True 语义（另有一支）。
# ⑤ **标量写（totalSupply / count 等）不算守恒**：铸币/记账走标量，
#     不是映射一减一增。
_SOL_MAP_WRITE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]*?)\s*\]\s*(\+=|-=|\*=|/=|=(?!=))\s*([^;]*);")
# 数组 length 写：bonusCodes.length-- / bonusCodes.push(x)
_SOL_ARRAY_WRITE_RE = re.compile(
    r"\.\s*(?:length|push|pop)\s*(?:\+\+|--|\+=|-=|=|\()")
# 同合约其它函数的调用（保守：只看"形如 name(...)"且不是控制关键字/内建）
_SOL_INTERNAL_CALL_KW = frozenset({
    "require", "assert", "revert", "throw", "keccak256", "sha3", "now",
    "address", "uint256", "uint", "bytes32", "string", "bytes", "bool",
    "int256", "int", "ecrecover", "selfdestruct", "suicide", "transfer",
    "send", "call", "blockhash", "gasleft", "this", "super",
})
# 自取形态但**没有配对扣减**（SWC-105 未保护提款）—— 官方标 vul
_SOL_SELF_OUT_NO_DEDUCT_RE = re.compile(
    r"\.\s*(?:transfer|send)\s*\(\s*\w+\s*\[\s*msg\s*\.\s*sender\s*\]")


def _sol_strip_comments(src: str) -> str:
    """剥注释（保留换行以免把两行粘成一行）。"""
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src,
                 flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _sol_calls_other_function(body: str) -> bool:
    """函数体里是否调用了**本合约其它函数**（可能写状态）。

    只看"标识符(形态"的调用，且排除控制关键字与内建。切片里被调函数
    可能不在本单元源码中（跨文件/同文件另一函数），无法静态确认其
    是否写状态 —— 按保守口径：一旦有这种调用就不判只读。

    `emit X(...)` 是**事件发出**不是函数调用 —— 事件不改状态，必须排除
    （否则所有只发事件的纯计算函数都被误排除，判据白写）。

    函数**声明头部**（`function calc(uint x) public {`）也不是调用 —— 必须
    先剥掉，否则每个函数都"调用了自己"。
    """
    body = re.sub(r"\bemit\s+[A-Za-z_]\w*", " ", body)
    # 剥函数声明头部：`function name(...)` / `function name(...) returns (...)`
    body = re.sub(r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)", " ", body)
    for m in re.finditer(r"(?<![\w.$])([a-z_]\w*)\s*\(", body):
        name = m.group(1)
        if name in _SOL_INTERNAL_CALL_KW:
            continue
        return True
    return False


def _sol_has_state_write(body: str) -> bool:
    """剥局部声明后，函数体是否有任何状态写。

    覆盖：标量写（`total = x`）、映射写（`m[k] = v` / `m[k] -= v`）、
    数组 length 写（`a.length--`）、数组 push/pop。
    """
    body = _SOL_LOCAL_DECL_RE.sub("", body)
    if _SOL_ASSIGN_RE.search(body):
        return True
    if _SOL_ARRAY_WRITE_RE.search(body):
        return True
    return False


def _sol_bilateral_conserving(func_src: str) -> bool:
    """双边守恒代币流转 → 确定性 safe。

    要求（缺一不可）：
      · 无特权 Sink（selfdestruct/delegatecall/owner 覆写/排空余额）；
      · 无任何外部资金转出（transfer/send/call.value）—— 有外转就不是
        单纯的内部账目搬移；
      · 有映射减（`m[k] -= v`）且有映射增（`m[k2] += v`）；
      · 减增**在同一映射**上（allowance 是附属额度映射，单独允许）；
      · 扣减方键是 msg.sender **或** allowance 已被同步扣减
        （ERC20 transferFrom 语义：allowance[sender][msg.sender] -= v
        且 balanceOf[sender] -= v）；
      · 没有"只减不增"（SWC-105：取出自域余额却不清零）；
      · 没有标量写（铸币/记账走标量，不是守恒）。
    """
    body = _sol_strip_comments(func_src)
    if _SOL_PRIV_SINK_RE.search(body) or _SOL_DRAIN_RE.search(body):
        return False
    # 有任何外部资金转出 → 不是内部账目搬移
    if _SOL_EXT_OUT_RE.search(body):
        return False
    # 取出自域余额但无配对扣减 —— SWC-105 未保护提款（官方标 vul）
    if _SOL_SELF_OUT_NO_DEDUCT_RE.search(body):
        return False
    body = _SOL_LOCAL_DECL_RE.sub("", body)
    # 标量写：铸币/记账不是守恒
    for lhs, _op, _rhs in _SOL_ASSIGN_RE.findall(body):
        if "[" not in lhs:
            return False
    minus, plus = [], []
    for name, key, op, _rhs in _SOL_MAP_WRITE_RE.findall(body):
        if op == "-=":
            minus.append((name, key.strip()))
        elif op == "+=":
            plus.append((name, key.strip()))
        elif op == "=":
            # 映射 `=` 写：任意位置写（mapping_write.sol:set 官方标 vul）
            # —— 只有当它和另一处 `=` 构成"整体赋值"才算守恒，但无法静态
            # 区分，整体判不守恒（保守）。
            return False
    if not minus or not plus:
        return False
    core_minus = [x for x in minus if x[0] != "allowance"]
    core_plus = [x for x in plus if x[0] != "allowance"]
    if not core_minus or not core_plus:
        return False
    mnames = {n for n, _k in core_minus}
    pnames = {n for n, _k in core_plus}
    if not mnames <= pnames:
        return False                 # 减的映射没被等额加回来
    # 扣减方：msg.sender 自域，或 allowance 已同步扣减的授权方
    sender_keyed = any(re.search(r"msg\s*\.\s*sender", k)
                       for _n, k in core_minus)
    if not sender_keyed:
        # transferFrom 形态：allowance[from][msg.sender] -= v 必须存在，
        # 且 balanceOf 扣减方与 allowance 扣减方一致。
        alw = [(n, k) for n, k in minus if n == "allowance"]
        if not alw:
            return False
        if not any(re.search(r"msg\s*\.\s*sender", k) for _n, k in alw):
            return False
        # allowance 扣减方（_from）必须与余额扣减方同键
        alw_keys = {k for _n, k in alw}
        bal_keys = {k for _n, k in core_minus}
        if not (alw_keys & bal_keys):
            return False
    # 增加方键：必须是形参/局部量（recipient），不能是固定地址常量
    for _n, key in core_plus:
        if not re.match(r"^\w+$", key):
            return False
    return True


def _sol_implicit_view(func_src: str) -> bool:
    """隐式只读函数 → 确定性 safe。

    老合约漏标 view/pure，但函数体里既无特权 Sink、无外部资金转出、
    也无任何状态写 —— 它在 access_control 维度上没有任何"特权动作"，
    判 True 会凭空造漏洞。

    底线：一旦有对其它函数的调用就不判只读（状态可能写在被调函数里，
    parity_wallet_bug_1.sol:initWallet 官方标 vul 就是这种）。
    """
    body = _sol_strip_comments(func_src)
    if _SOL_PRIV_SINK_RE.search(body) or _SOL_DRAIN_RE.search(body):
        return False
    if _SOL_EXT_OUT_RE.search(body):
        return False
    if _sol_calls_other_function(body):
        return False
    if _sol_has_state_write(body):
        return False
    return True


# allowance 扣减形态：授权槽位被扣减。两种键形态：
#   ① `_allowed[from][msg.sender] -= v`（老 ERC20：键含 msg.sender）
#   ② `_spendAllowance(from, spender, v)`（OZ 4.x：辅助函数，键含 spender）
#
# M54 实测修正：槽位名拼写是 **allowance**（`_allowances` / `allowance`），
# 不是 **allowed**。原来的 `_?allowed\w*` 匹配不到 `allowance[...]`
# —— Top200 靶场 35 条 transferFrom 误报全落在这上面。
# 正确口径是 `_?allow\w*`（覆盖 allowance / allowed / allowances）。
_SOL_ALLOWANCE_WRITE_RE = re.compile(
    r"_?allow\w*\s*\[[^\]]*\]\s*\[[^\]]*\]\s*(?:-=|=)", re.I)
_SOL_ALLOWANCE_CALL_RE = re.compile(
    r"\b_?spendAllowance\s*\(", re.I)
_SOL_ALLOWANCE_SPENDER_RE = re.compile(
    r"_?allowance\w*\s*\([^)]*\bspender\b", re.I)
# M54：allowance 槽位的**扣减/读取**形态。上面那条只认"直接写"（`-=` / `=`），
# 但 ERC20 的扣减有三种等价写法：
#   ① `_allowed[from][msg.sender] = _allowed[from][msg.sender].sub(v)`（写）
#   ② `_approve(from, msg.sender, _allowed[from][msg.sender].sub(v))`
#      —— 槽位值作为**实参**传给扣减辅助函数，槽位本身没被写
#   ③ `require(_value <= allowed[_from][msg.sender])` —— 只读校验额度
# ② ③ 都读同一个槽位，键里同样带 msg.sender ⇒ 授权约束成立。
#
# 口径（挂机制不挂名字）：**allowance 槽位被读写**（下标里带 msg.sender
# 或 spender）⇒ from 的支配权受授权约束。
_SOL_ALLOWANCE_SLOT_RE = re.compile(
    r"_?allow\w*\s*\[[^\]]*\]\s*\[[^\]]*\]", re.I)


def _sol_allowance_scoped(func_src: str, mod_ev: str, inh_ev: str) -> bool:
    """from 的支配权是否**受 allowance 授权约束**（不是"任意 from"）。

    机制（挂机制不挂名字）：函数体（或它调用的同文件/父合约辅助函数）
    里有 **allowance 槽位的扣减** —— 键里带着 msg.sender 或 spender，
    或调用了 `_spendAllowance(owner, spender, amount)` 这类扣减函数。

    找到了 ⇒ 转出 from 的钱需要 allowance 授权 ⇒ access_control 维度
    确定性 safe（真正的漏洞在 allowance 扣减自身，不在 transferFrom）。
    """
    evid = func_src + "\n" + mod_ev + "\n" + inh_ev
    if _SOL_ALLOWANCE_WRITE_RE.search(evid):
        return True
    if _SOL_ALLOWANCE_CALL_RE.search(evid):
        return True
    # 辅助函数里 `allowance(owner, spender)` 读了授权额 —— 读了说明
    # 这个槽位参与了授权判定（配合 _spendAllowance 已是上一条）。
    if _SOL_ALLOWANCE_SPENDER_RE.search(evid):
        return True
    # M54：槽位**被读**也算 —— 扣减可能以实参形式出现（`sub(v)`），
    # 或只做额度校验（`require(v <= allowed[from][msg.sender])`）。
    # 只认**二维下标**形态（`slot[owner][spender]`）—— 一维的
    # `allowed[from]` 不是额度表（老 ERC20 的 `allowed[from][msg.sender]`
    # 才是），且一维形态易与别的映射混淆。
    for m in _SOL_ALLOWANCE_SLOT_RE.finditer(evid):
        tail = evid[m.end():m.end() + 40]
        # 槽位的下标里必须带 msg.sender 或 spender 才是"额度表"
        slot = m.group(0)
        if re.search(r"msg\s*\.\s*sender|spender", slot, re.I):
            return True
        # 槽位值被 `.sub(...)` 扣减（OZ 4.x `_allowed[from][msg.sender]
        # .sub(value)`），下标里没有 msg.sender 但槽位名是 allowance
        # 且紧跟 .sub → 仍是额度扣减
        if re.match(r"\s*\.\s*sub\s*\(", tail) and _SOL_ALLOWANCE_SLOT_RE.match(
                slot):
            return True
    return False


def _sol_self_scoped_safe(func_src: str) -> bool:
    """函数只改调用者自己名下的槽位 → 不是管理端接口 → 确定性 safe。

    三档全部要求"无特权 Sink"（selfdestruct / delegatecall / owner 类
    标量覆写 / 全合约余额排空）：
      A 纯自域写    —— 所有状态写键均为 msg.sender，无外转；
      B 自域外转    —— 外转金额绑定自域槽位（取回自己的钱，CEI 正序形态）；
      C 对等转账    —— 写 recipient 键，且有 msg.sender 侧资金充足性校验。

    判 False 的前提是"这个类目上无越权"。对等转账缺余额校验（可凭空造币）
    或外转金额来自形参/合约整体 → 不满足，退回 None 交模型。
    """
    body = re.sub(r"/\*.*?\*/", "", func_src, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)
    if _SOL_PRIV_SINK_RE.search(body) or _SOL_DRAIN_RE.search(body):
        return False
    # 局部变量绑定自域槽位（档 B 的"金额取自自己的槽位"）
    local_self = {m.group(1) for m in
                  re.finditer(r"\b(\w+)\s*=\s*\w+\s*\[\s*msg\s*\.\s*sender\s*\]",
                              body)}
    # 剥掉局部声明的赋值目标（它们不是状态写）
    body = _SOL_LOCAL_DECL_RE.sub("", body)
    # 外转：金额实参必须绑定自域槽位
    for m in _SOL_EXT_OUT_RE.finditer(body):
        arg = next((g for g in m.groups() if g), "")
        if _SOL_SELF_SLOT_RE.search(arg):
            continue
        if any(re.search(rf"\b{re.escape(v)}\b", arg) for v in local_self):
            continue
        return False                     # 金额来自形参/合约整体 → 非自域
    writes = _SOL_ASSIGN_RE.findall(body)
    if not writes:
        return False
    for lhs, _op, _rhs in writes:
        if "[" not in lhs:
            return False                 # 标量状态写（全局会计变量）→ 非自域
        key = lhs[lhs.index("[") + 1:].split("]")[0].strip()
        if re.search(r"msg\s*\.\s*sender", key):
            continue                     # 自域槽位
        # 他域写：只允许"对等转账"（recipient 键）且有资金充足性校验
        if not re.search(r"^(?:to|_to|recipient|_recipient|dst|receiver)$",
                         key):
            return False
        if not _SOL_BAL_GUARD_RE.search(body):
            return False
    return True


def _sol_delegated_from_transfer(func_src: str) -> bool:
    """`from` 的转出是否**委托**给本切片看不见的实现。

    判据（挂机制不挂名字）：转出调用是**限定调用** —— 接收者是别的
    合约（`IERC20(target).transferFrom(...)` / `token.transferFrom(...)`
    / `super.transferFrom(...)`）。本地调用（`_transfer(from, ...)`）
    的实现体在切片里，可核验 ⇒ 不算委托。

    委托 ⇒ 授权判定在对方那边 ⇒ 本合约层面缺证据 ⇒ 退 None。
    """
    return bool(_SOL_DELEGATED_FROM_RE.search(func_src))


def _sol_bare_transfer_ownership(func_src: str) -> bool:
    """函数体里是否有**裸调用**的 `transferOwnership(...)`。

    裸调用 = 本合约自己的 owner 写；限定调用（`X.transferOwnership(...)`
    / `super.transferOwnership(...)`）= 把 owner 写**委托**给别的合约
    —— 写在哪、谁有权限都在对方那边 ⇒ 本合约看不到 ⇒ 不能据此判越权。

    只看**函数体内部**（第一个 `{` 之后）—— 函数**声明**里的
    `function transferOwnership(...)` 不是调用。
    """
    body_start = func_src.find("{")
    body = func_src[body_start:] if body_start >= 0 else func_src
    for m in _SOL_BARE_TRANSFER_OWNERSHIP_RE.finditer(body):
        prefix = body[:m.start()]
        pm = _SOL_CALL_PREFIX_RE.search(prefix)
        if pm and pm.group(1):
            continue                       # 限定调用 → 不算本合约的 owner 写
        return True
    return False




# ---- M155：库式鉴权（solady / 内联汇编）----
#
# solady 把权限检查封进 internal helper，用 Yul 直接读存储槽：
#     function _checkOwner() internal view virtual {
#         assembly { if iszero(eq(caller(), sload(_OWNER_SLOT))) { revert(...) } }
#     }
#     function _checkRoles(uint256 roles) ... {
#         assembly { if iszero(and(sload(keccak256(...)), roles)) { revert(...) } }
#     }
# 入口只写 onlyOwner / onlyRoles(roles)，函数体里既没有 msg.sender
# 也没有 require —— 只看入口体的判据会整片退 None/True。
#
# 判据挂机制不挂名字：沿"入口/修饰符调用的 helper"找到实现体，核验里面
# 真的有 caller() 与存储槽比较 + revert，或 role 位与掩码相交 + revert。
_SOL_YUL_CALLER_GUARD_RE = re.compile(
    r"eq\s*\(\s*caller\s*\(\s*\)\s*,\s*sload\s*\(")
_SOL_YUL_ROLE_GUARD_RE = re.compile(
    r"and\s*\(\s*sload\s*\(\s*keccak256|sload\s*\(\s*keccak256[\s\S]{0,120}?"
    r",\s*roles\s*\)")
_SOL_DELEGATED_AUTHZ_RE = re.compile(
    r"_isAuthorized\s*\(|_checkAuthorized\s*\(|isApprovedOrOwner\s*\("
    r"|getApproved\s*\([^)]*\)\s*==\s*(?:msg\s*\.\s*sender|caller\s*\(\s*\))"
    r"|isApprovedForAll\s*\(")
# 注意别叫 _SOL_ABORT_RE：文件后段（委托调用判据）已有同名常量，
# 重复赋值会被 doctor 的正则卫生检查判为遮蔽冲突。
_SOL_YUL_ABORT_RE = re.compile(r"\b(?:revert|throw)\b|\brequire\s*\(")


def _sol_helper_body(source: str, name: str) -> str:
    """按名字找同一切片里的函数实现体（证据段已把 helper 拼进来）。"""
    m = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{;]*\{{",
                  source)
    if not m:
        return ""
    brace = source.index("{", m.start())
    return _sol_block_body(source, brace) or ""


def _sol_yul_guard(body: str) -> bool:
    if not _SOL_YUL_ABORT_RE.search(body):
        return False
    # solady ERC721 的形态是 eq(caller(), from) / eq(caller(), approved)
    # 再套 iszero(or(...)) —— 比较的右侧是局部变量而不是 sload(...)。
    # 只要 caller() 参与相等比较且本函数会 revert，就是身份门。
    return bool(_SOL_YUL_CALLER_GUARD_RE.search(body)
                or _SOL_YUL_ROLE_GUARD_RE.search(body)
                or re.search(r"eq\s*\(\s*caller\s*\(\s*\)\s*,", body))


def _sol_delegated_authz(body: str) -> bool:
    return bool(_SOL_DELEGATED_AUTHZ_RE.search(body)
                and _SOL_YUL_ABORT_RE.search(body))


def _sol_protected_by_helpers(source: str, func_src: str, mod_block: str) -> bool:
    """入口体或修饰符里调用的 helper 是否真的做了身份/角色校验。"""
    for block in (func_src, mod_block):
        if not block:
            continue
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", block):
            name = m.group(1)
            if name in {"require", "if", "for", "while", "return", "emit",
                        "revert", "assert", "keccak256", "ecrecover", "add",
                        "sub", "mul", "div", "and", "or", "eq", "iszero",
                        "sload", "sstore", "mload", "mstore", "caller"}:
                continue
            hb = _sol_helper_body(source, name)
            if hb and (_sol_yul_guard(hb) or _sol_delegated_authz(hb)):
                return True
    return False


def solidity_access_verdict(source: str) -> bool | None:
    """Solidity 访问控制（Module 13 按 smartbugs 真实合约重写）。

    判据挂机制不挂名字：
      · 修饰符**实现体**里真有 msg.sender 检查 → False（只有名字不算，
        空实现/确认型 modifier 防不了越权）；
      · 函数体内 `require(msg.sender == …)` → False；
      · `tx.origin ==` **不算**保护（钓鱼反模式，Phishable 正是标注漏洞）；
      · 只读函数 / 显式 internal·private → False（编译器强制，见下方注释）；
      · 构造函数（函数名 == 合约名，0.4.x 无 visibility 时代）→ False
        （部署期由 EVM 执行一次，代码不进运行时字节码，外部永远调不到）；
      · **函数名 != 合约名**（错名构造函数，Rubixi/incorrect_constructor）
        且写 owner 态 / selfdestruct，而没有任何保护 → True；
      · external/public + selfdestruct / 转出 this.balance 且无 msg.sender
        检查 → True；其余 None。
    """
    func_src, mod_block, _inh_func_block = _split_sol_sections(source)
    sig = _sol_signature(func_src)
    m = re.search(r"function\s+([A-Za-z_]\w*)", sig)
    if not m:
        return None
    # 只读函数（view/pure/constant）：特权操作全都要写状态（转币、销毁、
    # 改 owner、铸币），编译器禁止只读函数写状态 → 确定性 safe。
    # 放在构造函数判断之前：错名构造函数不可能是 view/pure。
    #
    # internal/private 同理：外部调不到的"特权动作"不构成越权。两条都是
    # **编译器强制**的事实（Module 19：smartbugs 里 16 条显式 internal
    # 单元真值全 safe，排除面干净）。
    if _sol_is_readonly(sig) or _sol_is_internal_only(sig):
        return False
    fname = m.group(1)
    cm = re.search(r"contract:\s*(\S+)", source)
    contract_name = cm.group(1) if cm else ""
    is_constructor = bool(contract_name and contract_name != "?"
                          and fname == contract_name)

    # 保护判定：函数体内 + 修饰符**实现体**里的 msg.sender 恒等检查。
    # tx.origin 不算保护（钓鱼反模式）；纯状态门 modifier（parity 的
    # only_uninitialized 只查 m_numOwners）也**不算**保护 —— 把状态门
    # 当保护会把 initWallet 判反，方向错误比退回恶劣得多。
    protected = bool(_SOLIDITY_MSGSENDER_CHECK_RE.search(func_src)
                     or _SOLIDITY_MSGSENDER_MEMBER_RE.search(func_src)
                     # M136：`wards[msg.sender] == 1` 型授权映射
                     or _sol_caller_map_auth(func_src)
                     or _sol_identity_call_check(func_src)
                     # M108：谓词式 / 反向条件式授权
                     #
                     # 谓词要拿**整条切片**去找定义：`require(isOwner(), …)`
                     # 里的 `isOwner` 是零参函数，它的体在切片的辅助/父合约
                     # 证据段里（`return _msgSender() == _owner;`），只看
                     # func_src 永远解析不到。切片是按单元拼的，证据段里不会
                     # 混进无关合约的函数，所以这个范围是安全的。
                     or _sol_predicate_authz_check(source)
                     or _sol_inverted_identity_guard(func_src)
                     or _sol_negated_identity_call(func_src))
    if not protected and _sol_identity_alias_check(func_src):
        protected = True
    # M115：**库函数式守卫**。synthetix/DeFi 把权限检查封进库，调用点只有
    #     `OwnableStorage.onlyOwner();` / `FeatureFlag.ensureAccessToFeature(…)`。
    # 判据挂机制：库名以 Storage/Lib/Library 结尾 **且** 被调方法以 only 开头 ——
    # 两个约束一起才分得开"库里的权限门"与"普通库调用"。
    if not protected and re.search(
            r"\b\w*(?:Storage|Lib|Library)\s*\.\s*only\w+\s*\("
            r"|\bFeatureFlag\s*\.\s*ensureAccessToFeature\s*\(", func_src):
        protected = True
    if not protected and re.search(
            r"require\s*\(\s*\w*[Ii]sApprovedOrOwner\b"
            r"|require\s*\(\s*_?msgSender\s*\(\s*\)", func_src):
        # 所有权/审批校验（ERC721 fixed 形态：require(_isApprovedOrOwner(
        # _msgSender(), tokenId))）——调用者身份进入了授权判定，机制与
        # msg.sender 恒等检查等价（Module 30）。
        protected = True
    if not protected and mod_block:
        for body in _sol_modifier_bodies(mod_block):
            if (_SOLIDITY_MSGSENDER_CHECK_RE.search(body)
                    or _SOLIDITY_MSGSENDER_MEMBER_RE.search(body)
                    # M136：dss 的 `modifier auth { require(wards[msg.sender] == 1) }`
                    or _sol_caller_map_auth(body)
                    or _sol_identity_call_check(body)
                    or _sol_predicate_authz_check(body)
                    or _sol_inverted_identity_guard(body)):
                protected = True
                break
            # M54：块形态 `if (msg.sender != owner) { throw; }` ——
            # 正则只保证"块里有中止字样"，还要核验块里**确实是中止**
            # （`if (c) { log("x"); }` 只是日志，不是保护）。
            mm = re.search(r"if\s*\(\s*msg\s*\.\s*sender\s*!=\s*[\w.]+\s*\)"
                           r"\s*\{", body)
            if mm:
                blk = _sol_block_body(body, mm.end() - 1)
                if blk and _sol_block_aborts(blk):
                    protected = True
                    break
            # modifier 里的门形态是 `if (msg.sender == owner) _;` ——
            # 守护动作是占位符 `_` 而不是 revert（rubixi）。恒等比较在
            # 条件里就足以证明"查了身份"。
            if re.search(r"\b(?:require|if)\s*\(\s*msg\s*\.\s*sender\s*==", body):
                protected = True
                break
    # M54：间接身份检查 —— 比较的一侧是"返回 msg.sender 的函数"
    # （OpenZeppelin `require(_owner == _msgSender())`）。切片层把父合约
    # 的函数体拼进了"父合约函数证据"段，这里核验**实现体**而不是名字。
    if not protected and _sol_indirect_identity_check(func_src, mod_block,
                                                       _inh_func_block):
        protected = True
    # M54：**签名授权**机制 —— 用 ECDSA 签名代替 msg.sender 身份。
    # `transferWithAuthorization(from, to, v, ..., v, r, s)` 这类
    # "permit" 形态：from 的支配权由**签名**约束（谁持有 from 的私钥，
    # 谁签了这笔转账），不是"任意 from"。
    #
    # 机制口径（挂机制不挂名字）：函数体（或它调的辅助函数）里做了
    # **签名恢复**（ecrecover / recover）并把恢复出的地址与某个主体
    # 比较 —— 恢复出的地址不是 msg.sender，是签名者。
    #
    # 判反风险锚点（probe_m54_ac_risk2.py + 本轮锚点脚本）：
    # smartbugs access_control 真阳 19 条里含签名恢复的 **0 条**
    # ⇒ 本早退不会把真阳判反。
    if not protected and _sol_signature_authorized(func_src, _inh_func_block):
        protected = True
    # M155：库式/Yul 鉴权 —— 入口或 modifier 调用的 helper 实现体里
    # 有 caller()+sload 比较 + revert，或 role 掩码相交 + revert。
    if not protected and _sol_protected_by_helpers(source, func_src, mod_block):
        protected = True
    if protected:
        return False

    # M30 之 1）tx.origin 鉴权反模式：require/if 里拿 tx.origin 做恒等
    # 校验且函数内没有任何 msg.sender 保护 → 确定性 True（作者指名口径：
    # DeFiVulnLabs txorigin.sol、smartbugs phishable/mycontract）。放行
    # 到这里说明 protected 已排除——两者并存时 msg.sender 校验优先
    # （真实的"双保险"写法不是漏洞）。
    #
    # **M54 二分：比较的另一侧是不是 msg.sender**。两种 tx.origin 恒等
    # 比较的语义**完全相反**：
    #   ① `require(tx.origin == msg.sender)` —— **拒绝合约调用**语义。
    #      它要求"直接调用者 == 原始交易发起者"，也就是**只允许 EOA
    #      直调**，合约代理调用会被拒。这是**收紧**访问控制的正确写法，
    #      不是钓鱼（Top200 的 BridgeToken.unwrap 7 条全落在这）。
    #   ② `require(tx.origin == owner)` —— **钓鱼**语义。攻击者诱导
    #      owner 发交易，tx.origin 是 owner（钓鱼合约是 msg.sender），
    #      于是钓鱼合约通过校验 —— 这才是 Phishable 反模式。
    #
    # 判据挂机制不挂名字：**比较的另一侧**是不是"当前调用者身份"
    # （msg.sender）。是 ⇒ 拒绝合约调用 ⇒ 不是漏洞；否 ⇒ 与某个
    # **存储的主体**比较 ⇒ 钓鱼面 ⇒ True。
    # 判反风险锚点（probe_m54_ac_risk2.py M4）：smartbugs access_control
    # 真阳里的 tx.origin 比较**另一侧全是 owner**（2/2）⇒ 本二分
    # 不会把真阳判反。
    for m in _SOL_TXORIGIN_EQ_RE.finditer(func_src):
        other = (m.group(1) or m.group(2) or "").strip()
        if re.fullmatch(r"msg\s*\.\s*sender", other):
            # 拒绝合约调用：调用者被绑定 ⇒ 有保护（不是漏洞）
            return False
    if _SOL_TXORIGIN_EQ_RE.search(func_src):
        return True

    # M30 之 2）任意 from 的 transferFrom / _transfer：签名收 `address from`
    # 形参、函数体把它直转出去（token.transferFrom(from, ...) 或
    # _transfer(from, ...)），且无任何保护 → 确定性 True（DeFiVulnLabs
    # NFT-transfer.sol 的 VulnerableERC721；成对 fixed 有
    # require(_isApprovedOrOwner(...))，已在 protected 分支判 False）。
    # 注意触发条件要求 from 来自**本函数形参**——调用别处变量的
    # transferFrom 是普通 ERC20 用法，不构成"任意 from"。
    #
    # **allowance 扣减是授权机制**（M54 实测，Top200 45 条误报）：
    # 标准 ERC20 的 `transferFrom(from, to, v)` 形如
    #   require(v <= _allowed[from][msg.sender]);
    #   _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(v);
    #   _transfer(from, to, v);
    # —— 它把 from 的支配权**按 msg.sender 的 allowance 授权**转出，
    # 不是"任意 from"。OZ 4.x 的写法是 `_spendAllowance(from, spender, v)`
    # （辅助函数在同文件证据段里）。
    # 机制口径：**扣减 allowance 槽位**（键含 msg.sender 或 spender）
    # ⇒ from 的支配权受授权约束 ⇒ 不是任意 from。
    if re.search(r"address\s+(?:payable\s+)?_?from\b", sig) and re.search(
            r"\b(?:transferFrom|_transfer|_safeTransfer)\s*\(\s*_?from\s*[,)]",
            func_src):
        if not _sol_allowance_scoped(func_src, mod_block, _inh_func_block):
            # M54：**委托形态** —— `from` 的转出被交给**本切片看不见**的
            # 实现（外部合约 / 代理目标）。授权判定（allowance 扣减、
            # 所有者校验）在**对方那边**完成 ⇒ 本合约层面缺证据 ⇒
            # 按"缺证退 None"铁律退回交模型，**不判 True**。
            #
            # 例（Top200 ProxyERC20）：代理合约把调用者身份透传给目标
            # 合约后转发 `IERC20(target).transferFrom(from, to, value)`，
            # 目标合约按真实 msg.sender 做 allowance 判定。
            #
            # 判据（挂机制不挂名字）：转出调用是**限定调用**
            # （`接收者.方法(...)`）⇒ 被调方是别的合约。
            #
            # 判反风险锚点（probe_m54_ac_delegate2.py）：
            #   A. smartbugs access_control 真阳 19 条里"from 形参 +
            #      外部转出"形态 **0 条**；
            #   B. DeFiVulnLabs NFT-transfer.sol 两条真值（74=True /
            #      92=False）走的是**本地** `_transfer(from, ...)` 形态，
            #      不受本早退影响（实测仍 74=True / 92=False）。
            if _sol_delegated_from_transfer(func_src):
                return None
            # M95：**本合约内的转发壳** —— 非限定调用（`transferFrom(from, ...)`）
            # 把动作交给同合约的另一个函数，而那个函数体里**看得见调用者身份的
            # 流转**（msg.sender / _msgSender()）⇒ 权限判定在下一层。
            #
            # OpenZeppelin ERC721 就是这条链：
            #   safeTransferFrom(from,to,id) → transferFrom(...)
            #   → _update(to, id, _msgSender()) → _checkAuthorized → revert
            # 本单元自己没有把 from 直转出去，转出发生在有校验的那一层 ——
            # 判 True 是"把缺证据当成有漏洞"。按铁律退回 None。
            #
            # 判反锚点：DeFiVulnLabs 的 VulnerableERC721 里 `_transfer` **不用**
            # msg.sender，本条不成立 ⇒ 真阳仍判 True（实测 74=True / 92=False）。
            if _sol_unqualified_callee_uses_sender(func_src, _inh_func_block):
                return None
            return True

    # M34：借贷池回调缺 initiator 校验（DeFiVulnLabs Flashloan-flaw 精准
    # 收割，M33 退回池榜首可证子簇）。`executeOperation` 是 Aave flashLoan
    # 的协议回调接口（机制形态：external 回调 + initiator/receiver 形参，
    # 与 receive() 同类的"协议强制入口"）。回调由池子直调，"这笔闪贷是谁
    # 发起的"只能由合约自己核验——
    #   · require(<initiator> == address(this)) → False（成对修复形态）；
    #   · 无 initiator 比较 → True（任何人可直调回调把借出资产转走，
    #     作者注释：Missing flash loan initiator check）。
    if fname == "executeOperation" and re.search(
            r"address\s+(?:payable\s+)?_?initiator\b", sig):
        if re.search(r"require\s*\([^;]*\b_?initiator\s*==\s*"
                     r"address\s*\(\s*this\s*\)", func_src):
            return False
        return True

    # M44：调用者自域状态写 —— 普通用户态业务函数（transfer/approve/
    # deposit/withdraw 自取）不是管理端接口，access_control 维度确定性
    # safe。放在 True 优先分支之后：tx.origin / 任意 from / 借贷回调
    # 缺 initiator 都有明确的 True 语义，不能被"自域"覆盖。
    if _sol_self_scoped_safe(func_src):
        return False

    # M52：双边守恒代币流转 —— ERC20 标准转账（同一映射一减一增、值守恒）
    # 不存在"谁能动别人钱"，access_control 维度确定性 safe。
    # 放在 M44 之后：M44 覆盖的是"只改自域槽位"，本条覆盖"改两个槽位
    # 但严格守恒"，两者都不与特权语义冲突。
    if _sol_bilateral_conserving(func_src):
        return False

    # M52：隐式只读函数 —— 老合约漏标 view/pure，但函数体里既无特权
    # Sink、无外部资金转出、无任何状态写，也**不调用其它函数**（状态
    # 可能写在被调函数里）。这类函数在 access_control 维度没有任何特权
    # 动作，判 True 会凭空造漏洞。
    if _sol_implicit_view(func_src):
        return False

    # 危险动作（只看函数自身源码）
    #
    # M143：**一次性初始化入口**先退 None。带 `initializer` / `reinitializer(n)`
    # 的函数只能跑一次，它的风险形态是"部署竞态 / 未初始化的代理被抢跑"，
    # 与"任意时刻可调的特权入口缺授权"不是同一类判断（前者需要看部署流程，
    # 后者看入口守卫）。把前者判 True 是把"缺证据"当"有漏洞"；
    # 判 False 又会把真·抢跑问题洗白 —— 按铁律退回 None，交人工。
    # 只认 `initializer` / `reinitializer`：`onlyInitializing` 是**内部**
    # 初始化辅助函数的标记（本来就是 internal → 上面已判 False）。
    _sig_tail = sig[sig.find(")") + 1:] if ")" in sig else sig
    if re.search(r"\b(?:initializer|reinitializer)\b", _sig_tail):
        return None

    danger = bool(_SOLIDITY_SELFDESTRUCT_RE.search(func_src))
    owner_write = _sol_owner_state_write(func_src) \
        or _sol_bare_transfer_ownership(func_src)
    drain = bool(_SOLIDITY_DRAIN_RE.search(func_src))
    if not (danger or owner_write or drain):
        return None

    # 签名带 modifier 但切片里没有它的定义体（合成夹具/切片截断）——
    # "看实现体不看名字"铁律下既不能当保护也不能当没有：退回交模型。
    # （smartbugs 切片器会把用到的 modifier 体拼进切片，不受影响。）
    _VIS_KW = {"external", "public", "internal", "private", "view", "pure",
               "payable", "constant", "returns", "virtual", "override"}
    tail = sig[sig.find(")") + 1:] if ")" in sig else ""
    named_mods = [w for w in re.findall(r"\b([A-Za-z_]\w*)\b", tail)
                  if w not in _VIS_KW]
    if named_mods and not mod_block:
        return None

    if is_constructor:
        # 函数名 == 合约名 → 0.4.x 构造函数：部署期由 EVM 执行一次，代码
        # 不进入运行时字节码，外部**永远调不到**。写 owner 是初始化。
        # Module 19 从 None 改 False：这是编译器/VM 层的确定性事实，退回
        # 模型只会让模型在 `function Wallet(...)` 的 assembly 里幻想出越权
        # （smartbugs 实跑里正是这么误报的）。
        return False

    # 错名构造函数：写 owner 态但函数名 != 合约名 —— 任何人部署后可调
    # 用它把自己变成 owner（Rubixi 的 DynamicPyramid）。
    if owner_write:
        return True
    if danger or drain:
        if re.search(r"\b(?:external|public)\b", sig):
            return True
    return None


# ---- M53：Solidity 算术溢出/下溢（SWC-101，arithmetic 类目） ----
#
# 判据挂**编译器事实 + 表达式形态**，不挂变量名：
#   · 0.8+ 起编译器**内置**溢出回滚（unchecked 块除外）→ 确定性 safe；
#   · 0.4.x ~ 0.7.x 无内置检查 → 溢出可能发生；
#   · 算术全部走 SafeMath（.add/.sub/.mul/.div）→ 确定性 safe；
#   · `a -= b` 前紧邻 `require(a >= b)` / `if (a < b) revert/return`
#     → 有前置上下界校验 → 确定性 safe；
#   · 表达式右操作数是**外部形参**（值从外部进来，可控）→ 确定性 True。
#
# 探针实测出来的三条关键分辨线（每条都对应一个官方 safe 样本）：
#   ① `balances[msg.sender] += msg.value`（timelock:deposit，官方 safe）
#      —— 右操作数是 msg.value 不是形参，外部不可控（投入多少是多少）；
#   ② `balances[msg.sender] = 0`（timelock:withdraw，官方 safe）
#      —— `=` 不是算术复合赋值，无溢出面；
#   ③ `uint256 c = a * b; require(a == 0 || c / a == b);`
#      （BECToken:mul，官方 safe）—— 纯 SafeMath 库实现。
# 反过来 `uint res = count - input;`（overflow_single_tx:overflowlocalonly，
# 官方标 vul）—— **局部变量也算**：溢出表达式本身是漏洞，不因为结果
# 没逃逸到状态就不算。
_ARITH_OP_ASSIGN_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*(\+=|-=|\*=|/=)\s*([^;]+);")
# 二元算术表达式：`uint res = count - input;` / `uint256 amount = cnt * _value;`
_ARITH_BINOP_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*)\s*([-+*])\s*([A-Za-z_]\w*)\s*;")
_SAFE_MATH_RE = re.compile(r"\.\s*(?:add|sub|mul|div)\s*\(")
_UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")


def _sol_unchecked_zones(body: str) -> list[str]:
    """提取文本里所有 `unchecked { ... }` 的**配平块体**（M87）。

    0.8+ 的溢出语义是"编译器检查 + unchecked 块内部豁免"：
      · 块**外**的算术由编译器插入回滚，属确定性 safe；
      · 只有块**内**的算术才可能回卷（SWC-101 在 0.8 的唯一残存面）。

    没有这个分区，判据会把块外的算术式也当成候选 —— 实测（probe_m87）
    两个合成样本都因此被判 True：`unchecked { counter++; }` 之后的
    `uint256 x = total + amount;` 明明是编译器保护的安全写法。

    返回空列表表示"文本里有 `unchecked` 字样但没有可配平的块"
    （例如注释里的提及）—— 调用方据此退回全量分析。
    """
    zones: list[str] = []
    for m in _UNCHECKED_RE.finditer(body):
        blk = _sol_block_body(body, m.end() - 1)      # m.end()-1 就是 `{`
        if blk.strip():
            zones.append(blk)
    return zones


# M87：0.8.x 的**镜像形态**前置守卫 `if (A > B) revert CustomError();`
#
# 语义等价于 `if (B < A) revert ...`（即 `B < A` 时中止 ⇒ 后续 `B -= A`
# 不可能下溢）。`_ARITH_GUARD_RE` 只收 `<` 方向，因为 0.4.x 时代没有
# 自定义错误、老代码习惯写 `if (a < b) throw;`；0.8 起审计习惯倒过来写
# `if (amount > balance) revert InsufficientBalance();`。
#
# **只在 0.8+ 生效**（见 solidity_arithmetic_verdict）：老版本靶场的真值
# 是既有门禁锁死的，判据不得因一条新形态而漂移。
_ARITH_GUARD_MIRROR_RE = re.compile(
    r"if\s*\(\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*>\s*"
    r"([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*\)\s*\{?\s*(?:revert|throw|return)"
    r"|if\s*\(\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*>=\s*"
    r"([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*\)\s*\{?\s*(?:revert|throw|return)")
# 前置上下界校验：require(a >= b) / require(b <= a) / if (a < b) revert|return
#
# require 可带**错误消息**第二参数：`require(b <= a, errorMessage);`
# —— OpenZeppelin SafeMath 的标准写法（Top200 靶场 95 条 sub 误报
# 全落在这个形态上）。比较式后面允许跟 `, "msg"` 或 `, errVar`。
#
# M54 实测补三种形态（Top200 134 条 arithmetic 误报全在这三种上）：
#   ① **assert** 与 require 同级：`assert(x >= y);`（SafeMath 库自身
#      的实现就是 `assert(x >= y); uint256 z = x - y;`）；
#   ② **if 条件的余额充足性**：`if (balances[msg.sender] >= _value &&
#      _value > 0) { balances[msg.sender] -= _value; ... }`
#      —— 这是老 ERC20 的标准写法，余额充足性就是下溢保护；
#   ③ **跨行 require**：`require(\n  senderBalance >= amount,\n  "msg"\n);`
#      —— 原来的正则要求 `)` 紧跟比较式，跨行形态全漏。
# 三种都挂**机制**（比较式 + 被比较量），不挂变量名。
_ARITH_GUARD_RE = re.compile(
    r"require\s*\(\s*([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*>=\s*"
    r"([A-Za-z_]\w*)\s*\)\s*;?"
    r"|require\s*\(\s*([A-Za-z_]\w*)\s*<=\s*"
    r"([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*\)\s*;?"
    r"|require\s*\(\s*([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*>=\s*"
    r"([A-Za-z_]\w*)\s*,\s*"
    r"|require\s*\(\s*([A-Za-z_]\w*)\s*<=\s*"
    r"([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*,\s*"
    r"|if\s*\(\s*([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*<\s*"
    r"([A-Za-z_]\w*)\s*\)\s*(?:revert|throw|return)"
    # ① assert 与 require 同级（SafeMath 库自身的标准写法）
    r"|assert\s*\(\s*([A-Za-z_]\w*)\s*>=\s*([A-Za-z_]\w*)\s*\)\s*;?"
    r"|assert\s*\(\s*([A-Za-z_]\w*)\s*<=\s*([A-Za-z_]\w*)\s*\)\s*;?"
    # ② if 条件的余额充足性（老 ERC20 标准写法：>= 或 <=）
    r"|if\s*\(\s*([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*>=\s*"
    r"([A-Za-z_]\w*)"
    r"|if\s*\(\s*([A-Za-z_]\w*)\s*<=\s*"
    r"([A-Za-z_]\w*(?:\s*\[\s*[^\]]*\s*\])?)\s*\)")
_SOL_PRAGMA_RE = re.compile(r"//\s*pragma:\s*solidity\s+([^;]+);")
_SOL_FUNC_PARAMS_RE = re.compile(r"\bfunction\s+[A-Za-z_]\w*\s*\(([^)]*)\)")
# M143：`fallback` / `receive` / `constructor` **不写 function 关键字**。
# 代理合约的 delegatecall 常常就写在 `fallback()` 里，形参表取不到就判不出
# "目标是入口形参"（整条判据退 None）。
_SOL_SPECIAL_PARAMS_RE = re.compile(
    r"\b(?:fallback|receive|constructor)\s*\(([^)]*)\)")
# 调用实参内的算术表达式：`msg.sender.transfer(numTokens * PRICE_PER_TOKEN);`
# 官方真值标的就是这一行（tokensalechallenge:sell L33）—— 溢出发生在
# 实参求值时，跟同函数里另一条被 require 保护的减法无关。
_ARITH_CALLARG_RE = re.compile(
    r"\.\s*(?:transfer|send|call)\s*\(\s*([^;()]*?)\s*([-+*])\s*([^;()]*?)\s*\)")

# 回卷校验（wrap-around check）：`require(A + B > A)` / `require(A + B >= A)` /
# `if (A + B < A) throw` —— 对**加法表达式本身**的溢出回验（老 ERC20 标准写法，
# TetherToken:issue / BAToken / HBToken / ZRXToken）。同理减法回卷 `A - B <= A`。
# 挂机制（A + B 与 A 的比较）不挂名字。
_ARITH_WRAP_RE = re.compile(
    r"([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*\+\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)"
    r"\s*(?:>=|<=|<|>|==|!=)\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)"
    r"|([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*-\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)"
    r"\s*(?:>=|<=|<|>|==|!=)\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)")
# 二元算术左值为全局关键字（now/block.timestamp 等）—— 非状态槽、非声明结果，
# 时间戳溢出不在本类目的确定性范围内。
_ARITH_KEYWORD_LHS = {"now", "block", "msg", "tx", "address", "uint", "uint256",
                      "int", "int256", "this"}


# ---- M136：内联算术安全封装（MakerDAO dss 的 `_add` / `_sub` / `_mul`）----
#
# dss 不用 SafeMath 库，而是在合约里手写三个 internal 包装函数：
#
#     function _add(uint x, int y) internal pure returns (uint z) {
#         z = x + uint(y);
#         require(y >= 0 || z <= x);      // 加法回卷回验
#         require(y <= 0 || z >= x);
#     }
#
# 老版本 dss 写的是 `require((z = x + y) >= x);`（同一机制的内联形态）。
# 两种写法都不是 `.add()`，`_SAFE_MATH_RE` 看不见；`_ARITH_GUARD_RE` 也
# 看不见（它只认 `require(a >= b)` 这种裸标识符比较，结果是新算出来的 z）。
# 于是这两个函数在 arithmetic 维度退 None —— 判据没看懂"结果被回验"。
#
# 判据挂机制（不挂函数名、不挂变量名）：
#   ① 某个**局部结果变量**被赋值为含算术运算的表达式；
#   ② 紧随其后的 require/assert 条件里，该结果变量与**表达式中的某个
#      操作数**做关系比较（`<=` / `>=` / `<` / `>` / `==` / `!=`）。
# 这就是回卷校验（wrap-around check）的定义式形态：把"算出来的值"和
# "参与运算的原始量"比大小，越界即回滚。
_SOL_ARITH_ASSIGN_RE = re.compile(
    r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([^;=]*[-+*][^;=]*);")
_SOL_ARITH_CHECK_RE = re.compile(
    r"(?:require|assert)\s*\(([^;]{0,240}?)\)\s*;", re.S)
# 内联在条件里的赋值形态：`require((z = x + y) >= x);`（老 dss 写法）
_SOL_INLINE_COND_ARITH_RE = re.compile(
    r"(?:require|assert)\s*\(\s*\(?\s*([A-Za-z_]\w*)\s*=\s*([^;()]*[-+*][^;()]*)"
    r"\)?\s*(?:<=|>=|<|>|==|!=)\s*([A-Za-z_]\w*)")


def _sol_inline_arith_results(body: str) -> set[str]:
    """返回"被回卷校验覆盖的结果变量名"集合（M136）。

    只看**纯局部变量**左值（`z = ...`）：映射/数组槽位的复合赋值
    （`balances[x] += y`）不在此列 —— 那类的结果就是槽位本身，回验它
    是马后炮，判据不给它记保护。
    """
    out: set[str] = set()
    for m in _SOL_INLINE_COND_ARITH_RE.finditer(body):
        result, expr, cmp_var = m.group(1), m.group(2), m.group(3)
        operands = set(re.findall(r"\b([A-Za-z_]\w*)\b", expr)) - {result}
        if cmp_var in operands:
            out.add(result)
    for m in _SOL_ARITH_ASSIGN_RE.finditer(body):
        result, expr = m.group(1), m.group(2)
        operands = set(re.findall(r"\b([A-Za-z_]\w*)\b", expr)) - {result}
        if not operands:
            continue
        tail = body[m.end(): m.end() + 400]
        for cm in _SOL_ARITH_CHECK_RE.finditer(tail):
            cond = cm.group(1)
            rel = re.search(rf"\b{re.escape(result)}\b\s*(?:<=|>=|<|>|==|!=)"
                            rf"|(?:<=|>=|<|>|==|!=)\s*\b{re.escape(result)}\b",
                            cond)
            if not rel:
                continue
            if any(re.search(rf"\b{re.escape(o)}\b", cond) for o in operands):
                out.add(result)
                break
    return out


def _sol_pragma_major(source: str) -> int | None:
    """从切片头部的 `// pragma: solidity X;` 注释读主版本号。

    切片层（M53）把这个事实写进头部 —— 函数级切片本来没有文件头，
    而"0.8 内置溢出回滚 / 0.4 不检查"是**编译器事实**，不能靠猜。
    读不到（合成夹具/旧切片）→ 返回 None（判据退回 None，不硬判）。

    注意 `^0.8.19` 的**主版本号是 8**（0.x 系列里 x 才是主版本），
    所以要取小数点后的那个数，不是小数点前的 0。
    """
    m = _SOL_PRAGMA_RE.search(source)
    if not m:
        return None
    spec = m.group(1).strip()
    vm = re.search(r"(\d+)\s*\.\s*(\d+)", spec)
    if not vm:
        return None
    minor = int(vm.group(2))
    major = int(vm.group(1))
    # 0.x 系列的"主版本"是小数点后的数（0.8 → 8）；1.x 起是正常语义
    if major == 0:
        return minor
    return major


def _sol_param_names(source: str) -> set[str]:
    """函数签名里的形参名集合。

    M143：`fallback` / `receive` / `constructor` 没有 `function` 关键字，
    主正则匹配不到时回落到特殊入口正则。
    """
    m = _SOL_FUNC_PARAMS_RE.search(source) or _SOL_SPECIAL_PARAMS_RE.search(source)
    if not m:
        return set()
    out = set()
    for p in m.group(1).split(","):
        p = p.strip()
        if not p:
            continue
        out.add(p.split()[-1])          # "uint256 input" → "input"
    return out


def solidity_arithmetic_verdict(source: str) -> bool | None:
    """Solidity 算术溢出/下溢（Module 53，smartbugs arithmetic 类目）。

    判据挂编译器事实 + 表达式形态：

      False（确定性 safe）：
        · pragma 0.8+ 且算术表达式不在 unchecked 块内（编译器内置回滚）；
        · 算术全部走 SafeMath（.add/.sub/.mul/.div）；
        · 每条算术表达式都有对应的溢出校验（前置上下界校验，或结果变量
          被随后的 require 消费 —— SafeMath 库的标准写法）；
        · 右操作数不含外部形参（外部不可控，如 `+= msg.value`）；
        · 没有任何算术表达式（不归本类目管）。

      True（确定性 vul）：
        · pragma 0.4.x~0.7.x（读不到版本 → 退 None，不硬判）；
        · 存在算术表达式（复合赋值 / 二元算术 / 调用实参内的算术），
        · 其右操作数含**外部形参**（值从外部进来，可控），
        · 且该表达式**没有**任何溢出校验。

    **逐表达式独立判定** —— 不能因函数里某一条表达式受保护就放过另一条：
    tokensalechallenge:sell 里 `balanceOf[msg.sender] -= numTokens` 有
    require 保护（官方没标它），但 `msg.sender.transfer(numTokens *
    PRICE_PER_TOKEN)` 的实参溢出**才是官方标注的漏洞行**（官方标 L33）。

    其余 → None（退回交模型）。
    """
    func_src, _mod = _split_sol_modifier_block(source)
    body = re.sub(r"//[^\n]*", "", func_src)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    if not body.strip():
        return None

    # internal/private 的可见性检查放在**保护分析之后**：受保护的
    # internal 函数（SafeMath 库自身实现）仍判 False；只有"未保护且
    # internal"才退 None —— 不可从外部直接到达（须经 public 包装，
    # 包装侧守卫本单元看不到），确定性不成立。Top200 上 73 条 OZ
    # `_transfer`/`_mint`/`_burn`/`tryMul` 误报全落在这里；smartbugs
    # 20 条真阳全部 public/default（锚点探针实测 0 条 internal）。
    vm = re.search(r"function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*([^{;]*)", func_src)
    # 构造函数只在部署时执行一次，实参由部署者指定，溢出只会让部署
    # 回滚 —— 不构成部署后可利用面（编译器/VM 强制事实，铁律 22）。
    # smartbugs 20 条真阳无一是构造函数（锚点探针实测）。
    if vm:
        fname = re.search(r"function\s+([A-Za-z_]\w*)", func_src)
        cm = re.search(r"//\s*contract:\s*([A-Za-z_]\w*)", source)
        if fname and ((cm and fname.group(1) == cm.group(1))
                      or fname.group(1) == "constructor"):
            return False

    # 0.8+ 编译器内置溢出检查（unchecked 块除外）—— 编译器强制的事实
    major = _sol_pragma_major(source)
    if major is not None and major >= 8 and not _UNCHECKED_RE.search(body):
        return False
    if major is None:
        # 读不到 pragma（合成夹具/旧切片）→ 不猜版本
        return None

    # ---- M87：0.8+ 的 `unchecked` 分区 -------------------------------
    # 有 unchecked 块时**只有块内**算术可能回卷：块外由编译器插桩回滚。
    # 表达式从块内收集；守卫仍从**全函数体**收集 —— 守卫写在块外正是
    # `if (amount > balance) revert ...; unchecked { balance -= amount; }`
    # 的标准形态（probe_m87 P2c）。
    scoped_unchecked = major >= 8
    expr_src = body
    if scoped_unchecked:
        zones = _sol_unchecked_zones(body)
        if zones:
            expr_src = "\n".join(zones)

    params = _sol_param_names(func_src)

    # M136：先算"被回卷校验覆盖的结果变量"—— 它既用于 `exprs` 为空的
    # 纯封装函数，也并入后面的 `checked_results`（局部声明形态的后置回验）。
    inline_results = _sol_inline_arith_results(body)

    # ---- 收集算术表达式：(左值/宿主, 运算符, 右操作数文本, 是否复合赋值) ----
    # 复合赋值（`x += y`）与局部声明（`uint c = a * b;`）的**校验口径不同**：
    # 前者的结果就是 x 本身（回验 x 是马后炮），后者的结果是新算出来的
    # c（回验 c 才是有效的溢出证明 —— SafeMath 库的标准写法）。
    exprs: list[tuple[str, str, str, bool]] = []
    for m in _ARITH_OP_ASSIGN_RE.finditer(expr_src):
        exprs.append((m.group(1).strip(), m.group(2), m.group(3).strip(), True))
    # 二元算术：`uint res = count - input;` / `uint256 amount = cnt * _value;`
    for m in _ARITH_BINOP_RE.finditer(expr_src):
        exprs.append((m.group(1), m.group(2), m.group(3), False))
    # 调用实参内的算术：`msg.sender.transfer(numTokens * PRICE_PER_TOKEN);`
    for m in _ARITH_CALLARG_RE.finditer(expr_src):
        exprs.append(("", m.group(2), m.group(1), False))

    if not exprs:
        # 0.8+ 的 unchecked 分区里没有任何算术式（只有普通赋值或循环游标
        # `i++` / `i += 1`）⇒ 编译器保护块外 + 块内无回卷面 ⇒ 确定性 safe。
        # 老版本（scoped_unchecked=False）保持原语义：不归本类目管 → None。
        #
        # M136：整函数就是一个**内联算术封装**（dss 的 `_add`/`_sub`：
        # `z = x + uint(y); require(y >= 0 || z <= x);`）—— 表达式形态
        # 不被上面的收集器识别，但回卷校验已被 `_sol_inline_arith_results`
        # 证实存在 ⇒ 确定性 safe。
        if inline_results:
            return False
        return False if scoped_unchecked else None

    # ---- 溢出校验集合 ----
    # ① **前置上下界校验**：require(a >= b) / require(b <= a) /
    #    if (a < b) revert —— 保护的是**被减的那个量**。
    #    注意区分"余额充足性"与"溢出"：
    #      require(balanceOf[msg.sender] >= _value) 是**余额充足性**检查
    #      （槽位 vs 数量），它保证减法结果非负，但**不防加法溢出**
    #      （insecure_transfer 官方标 vul：balanceOf[_to] += _value 会溢出）。
    #      所以只有"被减量与减数直接比较"才算前置溢出校验。
    guards: set[str] = set()
    for m in _ARITH_GUARD_RE.finditer(body):
        for g in m.groups():
            if g:
                guards.add(g.strip())
    # M87：0.8+ 的镜像形态守卫 `if (amount > balance) revert CustomError();`。
    # 只在 0.8+ 收 —— 老版本靶场真值已由既有门禁锁死，判据不得漂移。
    if scoped_unchecked:
        for m in _ARITH_GUARD_MIRROR_RE.finditer(body):
            for g in m.groups():
                if g:
                    guards.add(g.strip())
    # ⑤ if 花括号块形态的守卫：`if (balances[msg.sender] < _value) { throw; }`
    #    （GnosisToken 老式写法）—— 块内有中止语义才算守卫。
    #    条件允许 **析取尾随**（`A < B || C < D`）—— 首个析取支仍是
    #    完整的"槽位 < 数量"比较，块内中止即生效。
    for im in re.finditer(
            r"if\s*\(\s*([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*<\s*"
            r"([A-Za-z_]\w*(?:\s*\[[^\]]*\])?)\s*(?:\|\|[^)]*)?\)\s*\{", body):
        blk = _sol_block_body(body, im.end() - 1)
        if blk and _sol_block_aborts(blk):
            guards.add(im.group(1).strip())
            guards.add(im.group(2).strip())
    # ② **后置结果校验**：只对"局部变量声明"形态的结果有效。
    #    SafeMath 库标准写法：`uint256 c = a * b; require(a == 0 || c / a == b);`
    #    —— c 是**新算出来的结果**，回验 c 就能证明没溢出。
    #    但**复合赋值**（`x -= y` / `x += y`）的结果就是 x 本身，"回验 x"
    #    是马后炮（溢出已经写进 x 了），不能算保护 ——
    #    `require(balances[msg.sender] - _value >= 0)` 正是这种：0.4.x 下
    #    减法自身溢出成巨值，`>= 0` 恒真，形同虚设（token.sol 官方标 vul）。
    #    反例：`require(balanceOf[msg.sender] >= _value)` 是余额充足性检查，
    #    不含结果变量、也不是回验式，不是溢出保护。
    checked_results: set[str] = set()
    for m in re.finditer(r"(?:require|assert)\s*\(([^;()]*)\)", body):
        arg = m.group(1)
        if not re.search(r"[-+*/]|\|\||&&", arg):
            continue                          # 没有运算 → 不是回验式校验
        for name in re.findall(r"\b([A-Za-z_]\w*)\b", arg):
            checked_results.add(name)
    # M136：内联算术封装 —— 结果变量被紧随其后的 require 与操作数比大小
    # （dss `z = x + uint(y); require(y >= 0 || z <= x);`）。
    checked_results |= inline_results
    # ③ SafeMath 调用：`.sub(x)` / `.add(x)` —— 库自带溢出检查
    safemath = bool(_SAFE_MATH_RE.search(body))
    # ④ 回卷校验：比较式中出现 `A + B` 或 `A - B`，被比较量与表达式左值
    #    同名同槽 → 该表达式有显式溢出回验（TetherToken:issue 等）。
    for wm in _ARITH_WRAP_RE.finditer(body):
        for g in wm.groups():
            if g:
                guards.add(g.strip())

    has_unprotected_param_expr = False
    has_slot_add_uncovered = False
    for lhs, _op, rhs, is_compound in exprs:
        # 该表达式的右操作数是否含外部形参（值可控）
        if not any(re.search(rf"\b{re.escape(p)}\b", rhs) for p in params):
            continue                          # 外部不可控 → 不是本类目的面
        # 该表达式是否被校验覆盖？
        base = lhs.split("[")[0].strip() if lhs else ""
        if base and (base in guards or lhs in guards):
            continue                          # 前置上下界校验覆盖
        # 后置回验校验只对**局部声明**的结果有效（复合赋值的结果就是
        # 左值本身，回验它是马后炮 —— 见上面 checked_results 的注释）
        if base and not is_compound and base in checked_results:
            continue                          # 后置回验校验覆盖（SafeMath 写法）
        if safemath and not lhs:
            continue                          # 实参里的算术但整体走 SafeMath
        if lhs and not is_compound and lhs.split("[")[0].strip() in _ARITH_KEYWORD_LHS:
            continue                          # 全局关键字左值（now 等）→ 非状态槽
        has_unprotected_param_expr = True
        # "部分守护 + 未覆盖的加减法"：函数里存在溢出/充足性守卫，但该
        # 表达式没有被任何守卫覆盖 —— 与 smartbugs 真阳 insecure_transfer
        # （官方标 vul）机械同形，而 Top200 已审计代币同形标 safe ——
        # 两侧真值冲突 ⇒ 确定性不成立，退回模型（铁律：口径冲突不硬判）。
        # 完全无守卫的加减法（timelock / integer_overflow_minimal 形态）
        # 仍判 True —— 那是 smartbugs 真阳的主流形态。
        if _op in ("+=", "-=") and guards:
            has_slot_add_uncovered = True

    if has_unprotected_param_expr:
        if has_slot_add_uncovered:
            return None
        if vm and re.search(r"\b(?:internal|private)\b", vm.group(1)):
            return None                       # 未保护 + 不可外部直达 → 退回
        return True
    # 有算术表达式但要么外部不可控、要么全被校验覆盖 → 确定性 safe
    return False


# ---- M54：底层调用返回值"是否被消费"（Consumed Return Value）----
#
# 判据的**机制内核**：unchecked_low_level_calls（SWC-104）的危害是
# "底层调用失败被**静默忽略**" —— 返回值被丢弃，失败后代码照常往下走。
# 只要返回值没有丢弃，危害就不成立。反过来（= 被消费）有四种形态：
#
#   ① 内联消费：`if (x.call(...))` / `require(x.send(...))`
#   ② 同函数消费：赋值给局部变量 V，V 被 require/if/assert 读
#   ③ **跨函数消费**：V 作为实参传给辅助函数 F，F 的实现体里对应
#      形参为 false 时会**中止**（revert/require/assert）——
#      OpenZeppelin `verifyCallResultFromTarget(target, success, ...)`
#      的 `if (success) {...} else { _revert(...); }` 就是标准形态。
#   ④ **上交消费**：V 被函数 return 出去（显式 return 或命名返回值）——
#      失败与否交给调用方判断，入口函数这一层没有丢弃它。
#
# ③ 必须**看实现体**（切片证据段里的 helper body），不按名字认
#    （铁律：判据挂机制不挂名字）。④ 的"上交"不等于调用方一定检查，
#    但入口函数这一层确实没有丢弃 —— 丢弃发生在别的调用点，超出本单元。

# 失败即中止的语义标记：revert / require / assert。
_SOL_ABORT_RE = re.compile(r"\brevert\b|\brequire\s*\(|\bassert\s*\(", re.S)

# Solidity 类型关键字 —— 用于分辨"命名返回值"里哪个是名字哪个是类型。
_SOL_TYPE_WORDS = frozenset({
    "bool", "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
    "int", "int8", "int16", "int32", "int64", "int128", "int256",
    "address", "bytes", "byte", "string", "bytes32", "bytes4", "bytes1",
    "bytes8", "bytes16", "bytes20", "bytes24", "bytes28", "bytes3",
    "memory", "calldata", "storage", "payable", "indexed", "returns",
})


def _sol_strip_noise(text: str) -> str:
    """去注释与字符串字面量（保行保偏移）。

    "失败即中止"要看 `revert` / `require` / `assert` 关键字 —— 但错误
    消息里常写着这些词（"revert" 出现在字符串里），不去噪就会把
    `require(x, "must revert")` 当成中止语义。
    """
    text = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)
    text = re.sub(r"/\*.*?\*/",
                  lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    text = re.sub(r'"(?:[^"\\]|\\.)*"',
                  lambda m: '"' + " " * max(0, len(m.group(0)) - 2) + '"', text)
    text = re.sub(r"'(?:[^'\\]|\\.)*'",
                  lambda m: "'" + " " * max(0, len(m.group(0)) - 2) + "'", text)
    return text


def _sol_split_top_commas(s: str) -> list[str]:
    """按**顶层**逗号切分（跳过括号内的逗号）。"""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(c)
    parts.append("".join(buf))
    return parts


def _sol_match_paren(text: str, open_idx: int) -> int:
    """text[open_idx] 处是 '(' —— 返回配平后的 ')' 下标；找不到返回 -1。"""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] in "([{":
            depth += 1
        elif text[j] in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _sol_parse_args(text: str, open_idx: int) -> list[str] | None:
    """text[open_idx] 处是 '(' —— 返回顶层实参列表。配平失败返回 None。"""
    close = _sol_match_paren(text, open_idx)
    if close < 0:
        return None
    return _sol_split_top_commas(text[open_idx + 1:close])


def _sol_find_func_body(text: str, fname: str) -> str:
    """在 text 里找 `function fname(...)` 的**整段**（签名 + 实现体）。

    必须带签名 —— 上层要按**实参位置 → 形参位置**对应，
    只给实现体就没法定位形参。
    """
    m = re.search(rf"\bfunction\s+{re.escape(fname)}\s*\(", text)
    if not m:
        return ""
    close = _sol_match_paren(text, m.end() - 1)
    if close < 0:
        return ""
    b = text.find("{", close)
    if b < 0:
        return ""
    depth = 0
    for j in range(b, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[m.start():j + 1]
    return ""


def _sol_param_list(body: str) -> list[str]:
    """从函数体（以 `function name(...)` 开头）解析**有序**形参名列表。

    与 `_sol_param_names`（集合版，用于"是否含外部形参"）分开：
    这里是**按位置**对应 —— 实参下标 → 形参下标，不能只按名字碰巧对上。

    无名形参（只写类型）返回空串占位 —— 上层据此判定"无法按位置对应"。
    """
    m = re.match(r"\s*function\s+[A-Za-z_]\w*\s*\(", body)
    if not m:
        return []
    args = _sol_parse_args(body, m.end() - 1)
    if args is None:
        return []
    names: list[str] = []
    for a in args:
        toks = re.findall(r"[A-Za-z_]\w*", a)
        if not toks:
            names.append("")
            continue
        last = toks[-1]
        names.append("" if last in _SOL_TYPE_WORDS else last)
    return names


def _sol_named_returns(text: str) -> dict[str, str]:
    """解析签名里的**命名返回值**：{名字: 类型}。

    `returns (bool success, bytes memory returnData)` → {"success": "bool",
    "returnData": "bytes memory"}；`returns (bool, bytes memory)` → {}。
    """
    out: dict[str, str] = {}
    for m in re.finditer(r"\breturns\s*\(", text):
        args = _sol_parse_args(text, m.end() - 1)
        if args is None:
            continue
        for a in args:
            toks = re.findall(r"[A-Za-z_]\w*", a)
            if len(toks) < 2:
                continue
            name = toks[-1]
            if name in _SOL_TYPE_WORDS:
                continue
            out[name] = " ".join(toks[:-1])
    return out


def _sol_branch_texts(text: str, pos: int) -> tuple[str, str]:
    """pos 处开始的一个 if 分支 → (then 文本, else 文本)。"""
    p = pos
    while p < len(text) and text[p] in " \t\r\n":
        p += 1
    then_txt = ""
    if p < len(text) and text[p] == "{":
        depth = 0
        for j in range(p, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    then_txt = text[p:j + 1]
                    p = j + 1
                    break
    else:
        s = text.find(";", p)
        then_txt = text[p:s + 1] if s >= 0 else ""
        p = s + 1 if s >= 0 else p
    else_txt = ""
    m2 = re.match(r"\s*else\b", text[p:])
    if m2:
        q = p + m2.end()
        while q < len(text) and text[q] in " \t\r\n":
            q += 1
        if re.match(r"if\b", text[q:]):
            else_txt = ""                    # else if 交给外层循环
        elif q < len(text) and text[q] == "{":
            depth = 0
            for j in range(q, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        else_txt = text[q:j + 1]
                        break
        else:
            s = text.find(";", q)
            else_txt = text[q:s + 1] if s >= 0 else ""
    return then_txt, else_txt


def _sol_has_abort(text: str, evidence: str) -> bool:
    """这段代码里有没有"失败即中止"的语义。

    两种认法：① 段内直接有 revert/require/assert；② 段内调用了某个
    helper，而**该 helper 的实现体**（在证据段里）有中止语义 ——
    OpenZeppelin 的 `_revert(returndata, errorMessage)` 就是这种。
    """
    t = _sol_strip_noise(text)
    if _SOL_ABORT_RE.search(t):
        return True
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", t):
        body = _sol_find_func_body(evidence, m.group(1))
        if body and _SOL_ABORT_RE.search(_sol_strip_noise(body)):
            return True
    return False


def _sol_helper_aborts_on_false(body: str, pname: str,
                                evidence: str) -> bool:
    """helper 实现体里，形参 pname 为 false 时会中止吗？

    判据：`if (pname)` 的 else 分支 / `if (!pname)` 的 then 分支里有
    中止语义（revert/require/assert，或调用了带中止语义的 helper）。
    """
    b = _sol_strip_noise(body)
    for m in _IF_RE.finditer(b):
        open_i = m.end() - 1
        depth = 0
        end_i = -1
        for j in range(open_i, len(b)):
            if b[j] == "(":
                depth += 1
            elif b[j] == ")":
                depth -= 1
                if depth == 0:
                    end_i = j
                    break
        if end_i < 0:
            continue
        cond_txt = b[open_i + 1:end_i]
        if not re.search(rf"\b{re.escape(pname)}\b", cond_txt):
            continue
        then_txt, else_txt = _sol_branch_texts(b, end_i + 1)
        neg = bool(re.search(rf"!\s*{re.escape(pname)}\b", cond_txt)) or \
            bool(re.search(rf"{re.escape(pname)}\s*==\s*false", cond_txt))
        fail = then_txt if neg else else_txt
        if fail and _sol_has_abort(fail, evidence):
            return True
    return False


def _sol_value_consumed_by_helper(func_src: str, evidence: str,
                                   var: str) -> bool:
    """返回值变量 var 是否被**传给辅助函数**并由它消费（失败即中止）。

    位置对应：实参下标 → helper 形参下标 —— 不能只按名字碰巧对上。
    """
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", func_src):
        fname = m.group(1)
        args = _sol_parse_args(func_src, m.end() - 1)
        if not args:
            continue
        idx = -1
        for i, a in enumerate(args):
            if re.fullmatch(r"\s*" + re.escape(var) + r"\s*", a):
                idx = i
                break
        if idx < 0:
            continue
        body = _sol_find_func_body(evidence, fname)
        if not body:
            continue
        params = _sol_param_list(body)
        if idx >= len(params) or not params[idx]:
            continue
        if _sol_helper_aborts_on_false(body, params[idx], evidence):
            return True
        # M95：**看过即消费** —— helper 里把该 bool 用于分支/事件/返回，
        # 即使处理策略不是 revert（ERC-7579 的 try-execute 刻意不 revert），
        # 也不构成"返回值被静默丢弃"。
        if _sol_var_inspected_by_helper(body, params[idx]):
            return True
    return False


def _sol_body_callees(text: str) -> set[str]:
    """函数体里调用的函数名集合（不含内建关键字）。

    与 `_sol_modifier_callees` 同口径，只是起点换成**函数体**：用于"权限
    判定在下一层"这类转发壳（ERC721.safeTransferFrom → transferFrom）。
    """
    out: set[str] = set()
    for c in re.findall(r"\b([A-Za-z_]\w*)\s*\(", text):
        if c in {"require", "assert", "revert", "if", "for", "while",
                 "return", "_", "emit"}:
            continue
        out.add(c)
    return out


def _sol_unqualified_callee_uses_sender(func_src: str, evidence: str) -> bool:
    """本合约内的非限定调用里，是否有被调函数体**用了调用者身份**（M95）。

    判据（挂机制不挂名字）：
      ① 调用是**非限定**的（`f(` 而不是 `x.f(`）—— 限定调用是别的合约，
         归 `_sol_delegated_from_transfer` 管；
      ② 被调函数的实现体**在证据段里**（看不见就不算证据）；
      ③ 那个实现体里出现 msg.sender / _msgSender() / msgSender()。

    满足三条只说明"身份在下一层参与了"，**不能**证明下一层的判定充分 ——
    所以调用方给 None（缺证据），不给 False。
    """
    for m in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", func_src):
        fname = m.group(1)
        if fname in {"require", "assert", "if", "for", "while", "return"}:
            continue
        body = _sol_find_func_body(evidence, fname)
        if not body:
            continue
        if re.search(r"\bmsg\s*\.\s*sender\b|_msgSender\s*\(\s*\)|"
                     r"\bmsgSender\s*\(\s*\)", body):
            return True
    return False


_SOL_IDENTITY_ALIAS_SRC_RE = re.compile(
    r"\b(?:address|Account)\s+(?:payable\s+)?([A-Za-z_]\w*)\s*=\s*"
    r"(?:payable\s*\(\s*)?(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\)|"
    r"msgSender\s*\(\s*\))")
# 条件表达式入口（if / require / assert / while）。
# 抽成顶层正则而不是函数内内联字面量 —— 内联会与顶层同名 pattern 冲突，
# 被正则卫生审计记成"内联遮蔽"（M95 实测）。
_SOL_COND_EXPR_RE = re.compile(r"\b(?:if|require|assert|while)\s*\(")


def _sol_identity_alias_check(func_src: str) -> bool:
    """身份**别名**形态的身份校验（M95）。

    OpenZeppelin Ownable2Step 的标准写法：
        address sender = _msgSender();
        if (pendingOwner() != sender) { revert OwnableUnauthorizedAccount(sender); }
        _transferOwnership(sender);

    身份先落到局部变量上、再参与比较。`_SOLIDITY_MSGSENDER_CHECK_RE` 只认
    `msg.sender` 字面，看不见这条路径 —— 于是把 OZ 的核心安全合约判成
    "缺访问控制"，方向完全反了。

    判据挂机制：局部变量被赋值为**身份来源**，随后该变量出现在 require/
    assert/if 的比较式里，且条件不成立时中止。
    """
    for m in _SOL_IDENTITY_ALIAS_SRC_RE.finditer(func_src):
        var = m.group(1)
        pat = re.compile(rf"\b{re.escape(var)}\b")
        for im in _SOL_COND_EXPR_RE.finditer(func_src):
            close = _sol_match_paren(func_src, im.end() - 1)
            if close < 0:
                continue
            cond = func_src[im.end():close]
            if not pat.search(cond) or not re.search(r"==|!=", cond):
                continue
            tail = func_src[close + 1:]
            stripped = tail.lstrip()
            if stripped[:1] == "{":
                blk = _sol_block_body(stripped, 0)
                if blk and _sol_block_aborts(blk):
                    return True
            elif re.match(r"\s*(?:revert|throw|return)\b", tail):
                return True
        for rm in re.finditer(r"\b(?:require|assert)\s*\(", func_src):
            close = _sol_match_paren(func_src, rm.end() - 1)
            if close < 0:
                continue
            cond = func_src[rm.end():close]
            if pat.search(cond) and re.search(r"==|!=", cond):
                return True
    return False


def _sol_var_inspected_by_helper(body: str, pname: str) -> bool:
    """helper 体里是否**看过**这个 bool（哪怕处理方式不是 revert）。

    SWC-104 的危害是"失败被**静默忽略**"。把一个 bool 送进 if/require/assert
    条件、emit 实参或 return，说明调用方处理了它；只是处理策略不一定是退回。

    实测样本：OpenZeppelin `draft-ERC7579Utils._validateExecutionMode`：
        if (execType == EXECTYPE_DEFAULT) { Address.verifyCallResult(success, ...); }
        else if (execType == EXECTYPE_TRY) { if (!success) emit ERC7579TryExecuteFail(...); }
    TRY 模式的语义就是"失败不 revert、发事件交给上层"（ERC-7579 规范），
    判成"返回值被丢弃"属误报。
    """
    b = _sol_strip_noise(body)
    pat = re.compile(rf"\b{re.escape(pname)}\b")
    for m in _SOL_COND_EXPR_RE.finditer(b):
        close = _sol_match_paren(b, m.end() - 1)
        if close < 0:
            continue
        if pat.search(b[m.end():close]):
            return True
    if re.search(rf"\bemit\s+\w+\s*\([^;]*\b{re.escape(pname)}\b", b):
        return True
    if re.search(rf"\breturn\b[^;]*\b{re.escape(pname)}\b", b):
        return True
    return False


def _sol_handed_to_opaque(func_src: str, evidence: str, var: str) -> bool:
    """返回值变量是否被**交给实现体看不见的函数**（M95：证据不足 ⇒ 不下结论）。

    与 `_sol_value_consumed_by_helper` 的分工要分清：
      · `_sol_value_consumed_by_helper` 要求"**看见** helper 体，且它失败会
        中止（revert/require/assert）"—— 能证明 checked；
      · 本函数只要求"真的把变量递出去了，但看不到对方怎么处理"—— 只能证明
        **没有丢弃**（丢弃才是 SWC-104 的危害），不能证明 checked。

    OpenZeppelin 的 `Address.verifyCallResult(success, returndata)` 是前者，
    但 `Address.sol` 的实现体常常不在切片证据里（跨文件辅助段有预算上限），
    于是两种证明都拿不到。此时唯一诚实的结论是 None。
    """
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", func_src):
        fname = m.group(1)
        if fname in ("if", "for", "while", "require", "assert", "return"):
            continue
        args = _sol_parse_args(func_src, m.end() - 1)
        if not args:
            continue
        if not any(re.fullmatch(r"\s*" + re.escape(var) + r"\s*", a)
                   for a in args):
            continue
        if not _sol_find_func_body(evidence, fname):
            return True
    return False


def _sol_return_yields(text: str, var: str) -> bool:
    """函数是否把 var **作为返回值**交出去（显式 return 或元组元素）。"""
    for m in re.finditer(r"\breturn\b([^;]*);", text):
        expr = m.group(1).strip()
        if expr.startswith("(") and expr.endswith(")"):
            inner = expr[1:-1]
            depth = 0
            ok = True
            for c in inner:
                if c in "([{":
                    depth += 1
                elif c in ")]}":
                    depth -= 1
                    if depth < 0:
                        ok = False
                        break
            if ok and depth == 0:
                parts = _sol_split_top_commas(inner)
            else:
                parts = [expr]
        else:
            parts = [expr]
        for p in parts:
            if re.fullmatch(r"\s*" + re.escape(var) + r"\s*", p):
                return True
    return False


def solidity_unchecked_call_verdict(source: str) -> bool | None:
    """Solidity 未检查底层调用返回值（Module 30，smartbugs
    unchecked_low_level_calls 类目）。
    判据挂机制，**按调用点逐个判**（同一函数可能混合 checked/unchecked
    两个调用点——0x5249 的 transfer 正是这样，官方真值只标 unchecked
    那一行；任一调用点未检查即 True，全部检查完才 False）：
      · 内联消费 `if (x.call{...}(...))` / `require(x.send(...))` → checked；
      · 返回值赋给变量且该变量被 require/if/assert 消费 → checked；
      · 返回值**传给辅助函数**且该函数失败即中止 → checked（M54）；
      · 返回值被 **return 上交**给调用方 → checked（M54）；
      · 赋值但从不检查 / 裸调用（fire-and-forget）→ unchecked；
      · 没有底层调用 → None（不归本类目管）。
    """
    func_src, _mod_ev, func_ev = _split_sol_sections(source)
    sites = list(re.finditer(
        r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(", func_src))
    if not sites:
        return None
    named = _sol_named_returns(func_src)
    any_unchecked = False
    any_opaque = False
    for m in sites:
        stmt_start = max(func_src.rfind(";", 0, m.start()),
                         func_src.rfind("{", 0, m.start()),
                         func_src.rfind("}", 0, m.start())) + 1
        end = func_src.find(";", m.start())
        stmt = func_src[stmt_start: end + 1 if end >= 0 else len(func_src)]
        # 行注释用**等长空白**替换（保偏移量）：语句头可能是注释
        # （TownCrier request 实测），直接 strip 会把 if 头顶进噪声。
        stmt = re.sub(r"//[^\n]*", lambda mm: " " * len(mm.group(0)), stmt)
        # M95：`return addr.call{...}(...)` —— 返回值被**直接上交**给调用方。
        #
        # OpenZeppelin `RelayedCall.relayCall` 就是这一形态：
        #   `return getRelayer(salt).call{value: value}(abi.encodePacked(...));`
        # 结果进的是函数的**命名返回值**，本单元没有任何"丢弃"行为 ——
        # SWC-104 的危害是"失败被静默忽略"，上交显然不是忽略。
        # 此前它落到"没有赋值目标 ⇒ 裸调用"的分支里被判 True。
        if re.match(r"\s*return\b", stmt):
            continue                                    # 上交 → checked
        # 内联消费的语义：调用点位于控制关键字（if/require/...）的**条件
        # 括号平衡区间内**才算被检查。`if (cond) owner.send(...)` 的调用
        # 是 if 的语句体，不在条件里 —— 未检查（finalize 实测判反教训）。
        in_cond = False
        cm2 = re.match(r"\s*(?:if|require|assert|while|for)\s*\(", stmt)
        if cm2:
            depth, j, cond_open = 0, cm2.end() - 1, None
            for j in range(cm2.end() - 1, len(stmt)):
                if stmt[j] == "(":
                    depth += 1
                elif stmt[j] == ")":
                    depth -= 1
                    if depth == 0:
                        cond_open = (cm2.end() - 1, j)
                        break
            if cond_open and cond_open[0] < (m.start() - stmt_start) < cond_open[1]:
                in_cond = True
        if in_cond:
            continue                                    # 条件内消费 → checked
        # 赋值形态 → 变量名被 require/if/assert 消费才算 checked。
        # 两种赋值形态都要认：
        #   `bool success = addr.call{...}("");`      —— 普通声明
        #   `(bool success, ) = addr.call{...}("");`   —— **元组解构**
        #     （OpenZeppelin Address.sendValue 的标准写法，Top200 靶场
        #      102 条误报实测全落在这个形态上）
        # 第三种：**元组赋给已有变量**（`(success, returnData) = call(...)`，
        # 目标是函数的命名返回值）—— 类型从命名返回值反查。
        # 用 search 而非 match：stmt 前面常有注释行（已替换成等长空白）
        # 与空行，match 锚定开头会漏掉整条赋值。
        cands: list[tuple[str, bool]] = []           # (变量名, 是否 bool)
        am = re.search(r"\(?\s*(?:bool|var)\s+(\w+)", stmt)
        if am:
            cands.append((am.group(1), True))
        else:
            tm = re.search(r"\(([^()]*)\)\s*=", stmt)
            if tm:
                for part in _sol_split_top_commas(tm.group(1)):
                    toks = re.findall(r"[A-Za-z_]\w*", part)
                    if not toks:
                        continue
                    last = toks[-1]
                    if len(toks) >= 2 and last not in _SOL_TYPE_WORDS:
                        cands.append((last, "bool" in named.get(last, "")))
                    elif last in named:
                        cands.append((last, "bool" in named.get(last, "")))
            else:
                sm = re.match(r"\s*([A-Za-z_]\w*)\s*=", stmt)
                if sm:
                    cands.append((sm.group(1),
                                  "bool" in named.get(sm.group(1), "")))
        for var, is_bool in cands:
            if not is_bool:
                continue
            if re.search(rf"(?:require|if|assert)\s*\([^;]*\b{var}\b",
                         func_src):
                continue                                # 同函数消费 → checked
            if _sol_value_consumed_by_helper(func_src, func_ev, var):
                continue                                # 跨函数消费 → checked
            if _sol_return_yields(func_src, var):
                continue                                # 上交调用方 → checked
            if var in named and "bool" in named.get(var, ""):
                continue                                # 命名返回值 → 上交
            # M95：把 success **交给实现体看不见的函数** ⇒ 证据不足。
            #
            # OpenZeppelin 的 `Address.verifyCallResult(success, returndata)`
            # 是标准消费点（失败即 revert），但 Address.sol 的**实现体**常常
            # 不在切片证据里（跨文件辅助段有预算）。此前这种情况既拿不到
            # "跨函数消费"的证据，又落进"丢弃"的结论 —— 把 3 个 OZ 核心
            # 合约（Governor.relay / TimelockController._execute /
            # GovernorTimelockAccess._executeOperations）判成漏洞。
            # 正确语义：**看不见证据就不下结论**（None），不硬判 True。
            if _sol_handed_to_opaque(func_src, func_ev, var):
                any_opaque = True
                break
            any_unchecked = True
            break
        else:
            if not cands:
                any_unchecked = True                    # 裸调用 → unchecked
    if any_unchecked:
        return True
    return None if any_opaque else False



# ---------------- M89：服务端模板注入（SSTI，第 24 类） ----------------
#
# 判据内核（挂机制不挂名字）：**模板源本身**是否由外部输入决定。
#
# 这一类最容易做歪的地方是把"模板里渲染了外部数据"当成漏洞 —— 那是所有
# 模板的正常用法。FREE 的两侧在这里分叉：
#
#   数据进模板（safe）：`ctx.put("username", username)` +
#                       `Velocity.evaluate(ctx, out, "t", "Hello, $username")`
#                       `render_template("a.html", name=name)`
#   → 用户输入落在**求值后的字符串值**里，模板语法层没有它。
#
#   模板源被污染（vul）：`"Hello, " + username`（拼进模板文本）
#                       `templateString.replace("<USERNAME>", username)`
#                       `render_template_string(request.args["t"])`
#   → 用户输入落在**模板语法**里，`#set($e=...)` / `${...}` 会被引擎执行。
#
# 只做确定性两档：认出模板源固定 → False；认出模板源含外部输入 → True；
# 其余（模板源来自文件/拼接链里有一条断链）→ None 退回模型。
_SSTI_SKIP_PARAM_TYPES = frozenset({
    "HttpServletRequest", "HttpServletResponse", "ServletRequest",
    "ServletResponse", "Model", "ModelMap", "HttpSession", "MultipartFile",
    "Principal", "BindingResult", "Locale", "UriComponentsBuilder",
})
# 请求读取（Java）—— 与 has_external_input 同口径
_SSTI_JAVA_REQ_RE = re.compile(
    r"request\s*\.\s*(?:getParameter|getHeader|getQueryString|getInputStream|"
    r"getReader|getCookies|getRequestURI)", re.I)
# Velocity：evaluate(ctx, out, tag, templateSource)
_SSTI_VELOCITY_RE = re.compile(r"\bVelocity\s*\.\s*evaluate\s*\(")
# FreeMarker：StringTemplateLoader.putTemplate(name, templateSource)
_SSTI_PUTTPL_RE = re.compile(r"\bputTemplate\s*\(")
# FreeMarker：new Template(name, new StringReader(templateSource), ...)
_SSTI_NEWTPL_RE = re.compile(r"\bnew\s+(?:[A-Za-z_]\w*\s*\.\s*)*Template\s*\(")
# Velocity merge：RuntimeServices.parse(reader, name) —— reader 里装着模板源
_SSTI_RT_PARSE_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*[Rr]untimeServices|[Rr]untimeServices)\s*\.\s*parse\s*\(")
# Python：模板源入口（`render_template` 是固定文件，**不在此列**）
_SSTI_PY_RES: tuple[tuple[re.Pattern[str], bool], ...] = (
    (re.compile(r"\brender_template_string\s*\("), False),
    (re.compile(r"\b(?:jinja2\s*\.\s*)?Template\s*\("), True),
    (re.compile(r"\.\s*from_string\s*\("), True),
)


def _ssti_split_args(s: str) -> list[str]:
    """引号与括号感知的顶层逗号切分（注解里也可能带逗号）。"""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf))
    return [x.strip() for x in out]


def _ssti_call_args(text: str, open_idx: int) -> list[str]:
    """取 `text[open_idx]` 处 `(` 开始的实参列表（引号感知配平）。"""
    depth = 0
    quote = ""
    i = open_idx
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return _ssti_split_args(text[open_idx + 1:i])
        i += 1
    return []


def _ssti_java_params(source: str) -> set[str]:
    """Java 签名里的**字符串形参**（框架注入类型已排除）。

    入参必须是**完整切片源码**：`_entry_signature` 内部先截入口体再找签名，
    重复套用一次就会把签名当成"没有括号"而返回空集（实测症状：模板源
    认出来了但形参集为空，于是 `"Hello, " + username` 追不到外部输入，
    整批退成 None —— 静默漏报，不报错）。
    """
    sig = _entry_signature(source)
    if not sig:
        return set()
    out: set[str] = set()
    for a in _ssti_split_args(sig):
        a = re.sub(r"@\w+\s*(?:\((?:[^()]|\([^()]*\))*\))?", " ", a)
        toks = re.findall(r"[A-Za-z_]\w*", a)
        if len(toks) < 2:
            continue
        typ, name = toks[-2], toks[-1]
        if typ in _SSTI_SKIP_PARAM_TYPES or name in _SSTI_SKIP_PARAM_TYPES:
            continue
        out.add(name)
    return out


_SSTI_LITERAL_RE = re.compile(
    r"(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[A-Z][A-Z0-9_]*|-?\d+)"
    r"(?:\s*\+\s*(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|"
    r"[A-Z][A-Z0-9_]*|-?\d+))*\s*")


def _ssti_origin(expr: str, body: str, params: set[str],
                 depth: int = 0) -> bool | None:
    """模板源表达式的外部可控性：True 可控 / False 固定 / None 断链。"""
    if depth > 3:
        return None
    e = expr.strip().rstrip(";").strip()
    if not e:
        return None
    # 纯字面量/常量拼接 → 模板源固定
    if _SSTI_LITERAL_RE.fullmatch(e):
        return False
    if _SSTI_JAVA_REQ_RE.search(e):
        return True
    if params & set(re.findall(r"\b([A-Za-z_]\w*)\b", e)):
        return True
    var: str | None = None
    if re.fullmatch(r"[A-Za-z_]\w*", e):
        var = e
    else:
        # `x.toString()` / `x.replace(a,b)` / `String.valueOf(x)` /
        # `new StringReader(x)` —— 取被包/被调的那个载体变量
        mm = re.fullmatch(
            r"(?:String\s*\.\s*valueOf|new\s+StringReader|new\s+String|"
            r"StringBuilder)\s*\(\s*([A-Za-z_]\w*)\s*\)", e)
        if mm:
            var = mm.group(1)
        else:
            mm2 = re.match(r"([A-Za-z_]\w*)\s*\.\s*\w+\s*\(", e)
            if mm2:
                var = mm2.group(1)
    if var is None:
        return None
    rhs = _last_assign_rhs(body, var)
    if rhs is None:
        return None
    return _ssti_origin(rhs, body, params, depth + 1)


def _ssti_template_sources(body: str) -> list[str]:
    """全量提取"交给引擎当模板源"的实参表达式（Java 三种机制）。"""
    out: list[str] = []
    for m in _SSTI_VELOCITY_RE.finditer(body):
        args = _ssti_call_args(body, m.end() - 1)
        if len(args) >= 4:
            out.append(args[3])
    for m in _SSTI_PUTTPL_RE.finditer(body):
        args = _ssti_call_args(body, m.end() - 1)
        if len(args) >= 2:
            out.append(args[1])
    for m in _SSTI_NEWTPL_RE.finditer(body):
        for a in _ssti_call_args(body, m.end() - 1):
            if re.search(r"new\s+StringReader\s*\(", a):
                out.append(a)
    for m in _SSTI_RT_PARSE_RE.finditer(body):
        args = _ssti_call_args(body, m.end() - 1)
        if len(args) >= 1:
            out.append(args[0])
    return out


def _java_ssti_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not body:
        return None
    params = _ssti_java_params(source)
    srcs = _ssti_template_sources(body)
    if srcs:
        verdicts = [_ssti_origin(x, body, params) for x in srcs]
        if any(v is True for v in verdicts):
            return True
        if all(v is False for v in verdicts):
            return False
        return None
    # 没有显式模板引擎 API 时，才看「视图名注入」变体
    return _thymeleaf_viewname_verdict(source, body, params)


# ---- M103：Thymeleaf「视图名注入」变体（Spring MVC 专属机制） ----
#
#   @Controller                                  ← **不是** @RestController
#   public String vul1(@RequestParam String para) {
#       return "vul/ssti/" + para;                // 返回值被当成**视图名**解析
#   }
#
# M89 时期这条判不了：唯一的判别证据是类级注解，而**方法级切片里没有类级注解**
# （实测 HJS + JavaSecLab 共 17 个 SSTI 单元，`@Controller` 命中 0/17）。缺了它
# 就分不开 @Controller 与 @RestController —— HJS 自己摆着只差一个 `@ResponseBody`
# 的成对样本（fragmentVul / fragmentSafe），按"方法无 @ResponseBody"判会把所有
# REST 控制器的字符串拼接判成注入。
#
# M103 把这条证据补上了：切片器在头部写 `// Controller-Kind: @Controller`。
# 现在判据是三件可核对的事实缺一不可：
#   ① 头部写着 `@Controller`（不是 @RestController）；
#   ② 方法自身没有 `@ResponseBody`（有则返回值进响应体，不走视图解析）；
#   ③ `return "<字面量>" + <形参>`，且字面量不是 redirect:/forward:（那归 redir）。
# 误报闸：`if (white_list.contains(para))` 这类包含性白名单必须判 False。
_SSTI_CTRL_KIND_RE = re.compile(r"//\s*Controller-Kind:\s*@(\w+)")
_SSTI_THYMELEAF_RET_RE = re.compile(
    r"\breturn\s+(?:\"([^\"\n]*)\"|([A-Z][A-Z0-9_]*))\s*\+\s*"
    r"([A-Za-z_]\w*)\s*;")
_SSTI_VIEW_LITERAL_SKIP = ("redirect:", "forward:")


def _thymeleaf_viewname_verdict(source: str, body: str,
                                params: set[str]) -> bool | None:
    m = _SSTI_CTRL_KIND_RE.search(source)
    if not m:
        return None                      # 切片没有类级证据 → 不判（M89 的行为）
    if m.group(1) != "Controller":
        return False                     # @RestController：返回值是响应体，不是视图名
    if re.search(r"@ResponseBody\b", body):
        # 方法级 @ResponseBody 同样让返回值直接进响应体（HJS 的 fragmentSafe
        # 与 fragmentVul 只差这一个注解）→ 视图解析不发生 → 确定性 safe。
        return False
    if not re.search(r"\b(?:public|protected)\s+(?:static\s+)?String\s+\w+\s*\(",
                     body):
        return None                      # 返回类型不是 String → 不是视图名
    hits: list[str] = []
    for rm in _SSTI_THYMELEAF_RET_RE.finditer(body):
        lit = rm.group(1)
        var = rm.group(3)
        if lit is not None and lit.strip().lower().startswith(
                _SSTI_VIEW_LITERAL_SKIP):
            continue                     # redirect:/forward: 归 redir 类目
        if var not in params:
            continue
        hits.append(var)
    if not hits:
        # 返回值全是**纯字面量**（`return "vul/ssti/vul";`）→ 视图名固定，
        # 模板源是磁盘上的文件 → 确定性 safe。注意只认"return 里就是字面量"：
        # `String v = "x" + p; return v;` 的 return 是裸变量，这里**不判**
        # （间接可控的视图名看不见，宁可退 None 也不下 False）。
        _rets = re.findall(r"\breturn\s+([^;]+);", body)
        if _rets and all(re.fullmatch(r'\s*"[^"\n]*"\s*', r) for r in _rets):
            return False
        return None
    for var in hits:
        if not re.search(
                rf"if\s*\([^)]*\.\s*contains\s*\(\s*{re.escape(var)}\s*\)", body):
            return True                  # 有视图名拼接且无白名单 → 注入
    return False                         # 全部命中都被白名单挡住


# ---- M103 之后的取舍说明 ----
#
# M89 时这里写着"不判视图名注入"，理由是方法级切片里没有类级 @Controller 证据。
# M103 把这个证据补上了（切片器写 `// Controller-Kind:`），缺口已闭合 ——
# 但**没有证据时仍然不判**：合成夹具/旧切片没有这行头时 `_thymeleaf_viewname_verdict`
# 返回 None，行为与 M89 一致。这条"缺证据不下结论"的口径不能因为补了证据就丢。



def _py_ssti_verdict(source: str) -> bool | None:
    """Python：模板源是否来自外部输入。

    只认三种"把字符串当模板编译"的入口；`render_template("a.html", k=v)`
    是**固定文件 + 数据**，根本不在 sink 列表里（那是正常用法，不是注入）。
    `Template(` 的裸写形态只在源码里出现 `jinja2` 时才收 —— 否则
    `django.template.Template(`、`string.Template(` 之类会被误吞。
    """
    has_jinja = "jinja2" in source
    srcs: list[str] = []
    for rx, needs_jinja in _SSTI_PY_RES:
        if needs_jinja and not has_jinja:
            continue
        for m in rx.finditer(source):
            args = _ssti_call_args(source, m.end() - 1)
            if args:
                srcs.append(args[0])
    if not srcs:
        # 用了模板但**只走固定文件渲染**（`render_template("a.html", k=v)`）：
        # 模板源是磁盘上的文件，用户输入只落在 data 位 → 确定性 safe。
        # 与"根本不用模板"（None）区分开：后者不归本类目管。
        # 复用 xss 支已有的 `_PY_TPL_SAFE_RE`，不再内联同一 pattern
        # （内联会在正则卫生审计里被记成"遮蔽冲突"）。
        return False if _PY_TPL_SAFE_RE.search(source) else None
    verdicts = [_py_value_text_capable(x, source) for x in srcs]
    if any(v is True for v in verdicts):
        return True
    if verdicts and all(v is False for v in verdicts):
        return False
    return None


def ssti_verdict(source: str) -> bool | None:
    """服务端模板注入（M89，第 24 类）。True 有漏洞 / False 安全 / None 断链。"""
    if _looks_python(source):
        return _py_ssti_verdict(source)
    if _looks_solidity(source):
        return None
    return _java_ssti_verdict(source)


# ---------------- M105：HTTP 响应头注入（CWE-113，第 25 类） ----------------
#
# 机制：把外部可控字符串直接放进响应头 value，CR/LF 会被 HTTP 层解释成
# 新的响应头 / 响应体开头（响应拆分）。
#
# 判据只认两件**可逐字核对**的事实：
#   ① 有响应头下发（`response.setHeader` / `addHeader`）；
#   ② 该调用的 value 实参里**直接**出现请求读取或本函数裸形参。
#
# 剥掉"方法调用链"是这一步的关键：`file.getName()`、`data.length`、
# `realFilePath.getFileName().toString()` 这类**服务端对象取值**不含外部输入，
# 但把 `file`/`data` 当标识符会误判成形参。所以先删掉 `x.y(...)` 形态再取标识符。
_HDR_SINK_RE = re.compile(r"\.\s*(?:setHeader|addHeader)\s*\(", re.I)
# 清洗证据：CR/LF 过滤或编码包装。命中即算防护。
_HDR_SANITIZE_RE = re.compile(
    r"URLEncoder\s*\.\s*encode|safeHttpHeader|StringEscapeUtils"
    r"|ESAPI\s*\.\s*encoder|encodeForHeader"
    r"|replaceAll\s*\([^)]*\\[rn]|replace\s*\(\s*['\"]\\[rn]" r"|_\w*encode\w*\s*\(",
    re.I)
_HDR_MEMBER_CALL_RE = re.compile(r"\b[A-Za-z_]\w*\s*\.\s*\w+\s*\([^()]*\)")


def _hdr_value_idents(expr: str) -> set[str]:
    """value 表达式里的**裸标识符**（先把 `x.y(...)` 方法调用整段删掉）。"""
    stripped = expr
    for _ in range(3):                     # 链式 `a.b().c()` 删三轮足够
        new = _HDR_MEMBER_CALL_RE.sub(" ", stripped)
        if new == stripped:
            break
        stripped = new
    return set(re.findall(r"\b([A-Za-z_]\w*)\b", stripped))


def _hdr_guarded(body: str, var: str) -> bool:
    """该变量在 sink 之前是否被**会中止的校验调用**挡过（M105）。

    waynboot 实测形态：
        if (!FileUtils.checkAllowDownload(fileName)) {
            throw new BusinessException("文件名称(...)非法，不允许下载。");
        }
        …
        response.setHeader("Content-Disposition", "attachment;fileName=" + …)

    判据（挂机制）：`if (<否定式校验调用>)` 且条件为真时中止（throw/return/
    revert 或花括号块）。只认"条件里有对**同一变量**的校验调用"，不认可空 if。
    """
    for m in _IF_RE.finditer(body):
        close = _sol_match_paren(body, m.end() - 1)
        if close < 0:
            continue
        cond = body[m.end():close]
        if not re.search(rf"\b{re.escape(var)}\b", cond):
            continue
        if not re.search(r"!\s*[\w.]+\s*\(|\bcheck\w*\s*\(", cond, re.I):
            continue
        tail = body[close + 1:]
        stripped = tail.lstrip()
        if stripped[:1] == "{":
            blk = _sol_block_body(stripped, 0)
            if blk and _sol_block_aborts(blk):
                return True
        elif re.match(r"\s*(?:throw|return|revert)\b", tail):
            return True
    return False


def header_injection_verdict(source: str) -> bool | None:
    """HTTP 响应头注入（M105，第 25 类）。"""
    if _looks_python(source):
        return None                        # Python 侧暂无确定性判据（不硬判）
    if _looks_solidity(source):
        return None
    body = entry_body(source)
    if not body:
        return None
    params = set(_bare_params(_entry_signature(source)))
    seen = False
    for m in _HDR_SINK_RE.finditer(body):
        args = _ssti_call_args(body, m.end() - 1)
        if len(args) < 2:
            continue
        seen = True
        value = args[1]
        idents = _hdr_value_idents(value)
        tainted = bool(_REQUEST_READ_RE.search(value)) or bool(params & idents)
        if not tainted:
            continue
        if _HDR_SANITIZE_RE.search(value):
            continue                       # 已编码/已剥 CR LF → 该处安全
        # 前置守卫：同变量被"会中止的校验调用"挡过 → 该处安全
        if any(_hdr_guarded(body, p) for p in (params & idents)):
            continue
        return True
    return False if seen else None


# ---------------- M123：批量赋值（CWE-915，第 26 类） ----------------
#
# 机制：把**整个**请求体一次性灌进模型，攻击者顺手带上 `is_admin` / `role`
# 就把自己提权了。
#
# 判据三件事实缺一不可：
#   ① 有"整包灌入"的 sink（`Model(**request.json)` / `copyProperties(map, x)`）；
#   ② 灌入的**源**是请求数据（不是服务端常量）；
#   ③ 目标侧**有**权限字段且**没有**白名单/ignoreProperties 挡着。
#
# ③ 的"目标侧"只能从切片里能看到的线索判断：模型类定义（`is_admin = ...`）、
# 变量名（`user` / `admin` / `account`）、或显式出现在实参里的字典键。
# 看不见就退 None —— 不能因为"没看到 is_admin"就判安全。
_MASS_PY_SINK_RE = re.compile(
    r"\b(?:[A-Z]\w*|self\s*\.\s*\w+)\s*\(\s*\*\*\s*"
    r"(?:request\s*\.\s*(?:json|form|data|values|get_json\s*\(\s*\))"
    r"|request\.json|data|payload|params|kwargs)\b")
_MASS_PY_UPDATE_RE = re.compile(
    r"\.\s*__dict__\s*\.\s*update\s*\(\s*"
    r"(?:request\s*\.\s*(?:json|form|data|values)|data|payload|params)\b"
    r"|\.\s*update\s*\(\s*request\s*\.\s*(?:json|form|data|values)")
_MASS_JAVA_SINK_RE = re.compile(
    r"\bBeanUtils\s*\.\s*copyProperties\s*\(\s*([^,]+),\s*([^)]+)\)")
_MASS_PRIV_FIELDS = (
    "is_admin", "isadmin", "is_superuser", "issuperuser", "is_staff",
    "isstaff", "role", "roles", "permission", "permissions", "balance",
    "wallet", "owner_id", "ownerid", "user_id", "userid", "tenant",
)
_MASS_WHITELIST_RE = re.compile(
    r"ignoreProperties\s*\(|ignore_properties|allow_?list|ALLOWED_?\w*"
    r"|whitelist|\bexclude\s*=|\bonly\s*=\s*\(|fields\s*=\s*\[")
_MASS_TARGET_HINT_RE = re.compile(
    r"\b(?:user|account|admin|member|profile|staff|role)\b", re.I)
# 类型名是驼峰（`UserEntity` / `AdminUser` / `AccountDTO`），末尾没有词边界 ——
# 用不带 `\b` 的形态单独判。
_MASS_TYPE_HINT_RE = re.compile(
    r"(?:user|account|admin|member|profile|staff|role)", re.I)


def _entry_region(source: str) -> str:
    """**入口自己的**代码区域（M122/M123：证据归属的统一口径）。

    切片是"入口 + 同文件辅助 + 跨文件/父合约证据"拼起来的，证据段用
    `// ---- xxx ----` 或 `// 来自 Xxx.java:46 [Hop 3]` 这类**注释行**分隔。
    而 `entry_body()` 会剥掉注释 —— 剥完注释，证据段的**代码**就混进 body 了。

    后果：别的方法里的 `Cipher.getInstance("DES/…")` / `BeanUtils.copyProperties`
    会被算到当前入口头上（eladmin 4 条 crypto、jeecg 2 条 mass_assignment
    实测都是这么来的）。

    所以凡是"这个动作是入口自己做的吗"这类判据，都必须先按标记切段，
    再看入口那一段。
    """
    return re.split(r"(?m)^[ \t]*//[ \t]*(?:----|来自)", source)[0]


def _mass_target_has_priv_fields(text: str) -> bool:
    """目标模型/实参里是否出现权限字段。"""
    low = text.lower()
    return any(f in low for f in _MASS_PRIV_FIELDS)


def mass_assignment_verdict(source: str) -> bool | None:
    """批量赋值（M123，第 26 类）。"""
    if _looks_solidity(source):
        return None
    body = entry_body(_entry_region(source))
    if not body:
        return None
    if _looks_python(source):
        m = _MASS_PY_SINK_RE.search(body) or _MASS_PY_UPDATE_RE.search(body)
        if not m:
            # 有"从请求数据构造模型"但被字段白名单过滤掉 →
            # `User(**{k: v for k, v in request.json.items() if k in ALLOWED})`
            # 这是**安全写法**，判 False 而不是"不归本类目"。
            if _MASS_WHITELIST_RE.search(body) and re.search(
                    r"\b[A-Z]\w*\s*\(\s*\*\*\s*\{|request\s*\.\s*"
                    r"(?:json|form|data|values)", body):
                return False
            return None
        if _MASS_WHITELIST_RE.search(body):
            return False                   # 显式白名单/字段过滤
        # ③ 目标侧证据：模型类定义（在切片后段的 model/class 里）或变量名
        region = source if len(source) > len(body) else body
        if _mass_target_has_priv_fields(region) \
                or _MASS_TARGET_HINT_RE.search(m.group(0)):
            return True
        return None                        # 看不到目标字段 → 缺证据
    # Java：BeanUtils.copyProperties(src, dst)
    for m in _MASS_JAVA_SINK_RE.finditer(body):
        src_arg, dst_arg = m.group(1), m.group(2)
        if _MASS_WHITELIST_RE.search(body):
            return False
        # 三参以上的重载本身就是**排除列表**：
        #   `BeanUtils.copyProperties(src, dst, "isAdmin", "role")`
        # 第三个实参起是要忽略的字段名 —— 这是 Spring 的确定性 API 语义。
        # 注意 `[^)]+` 会把 `u, "isAdmin", "role"` 整段吃进 dst_arg，
        # 所以按"捕获里有没有逗号"判断，而不是看闭括号之后。
        if "," in dst_arg or re.match(r'\s*,\s*"', body[m.end():]):
            return False
        # **方向**判定（M134 实测）：`copyProperties(实体, VO)` 是服务端 →
        # 展示层的正常拷贝，不是批量赋值。危险方向只有"请求数据 → 实体"。
        # jeecg 的 `copyProperties(sysUser, loginUser)` 是登录成功后把实体转
        # 会话对象，与权限绑定无关；只看"目标是用户类"会把它判成漏洞。
        src_name = src_arg.strip()
        danger_src = bool(
            re.search(rf"@RequestBody\s+[\w<>,\s\[\]]*\b{re.escape(src_name)}\b",
                      body)
            or re.search(rf"\bMap\s*<[^>]*>\s*{re.escape(src_name)}\b", body)
            or re.match(r"(?i)^(?:req|request|param|params|data|payload"
                        r"|form|body|map|m|dto|vo|input)$", src_name))
        if not danger_src:
            continue
        # 目标类型往往只以**声明**出现（`UserEntity u = new UserEntity();`），
        # 实体类体不在切片里 —— 从声明里取类型名判"是不是用户/权限实体"。
        dst_name = dst_arg.strip()
        tm = re.search(rf"\b([A-Z]\w*)\s+{re.escape(dst_name)}\b", body)
        dst_type = tm.group(1) if tm else ""
        if _mass_target_has_priv_fields(body) \
                or _MASS_TYPE_HINT_RE.search(dst_type):
            return True
    if _MASS_JAVA_SINK_RE.search(body):
        return None
    return None


# ---------------- M124：链上伪随机（SWC-120，第 27 类） ----------------
#
# 机制：`block.timestamp` / `blockhash` / `block.difficulty` 全是矿工可见、
# 部分可操纵的公开值，拿它决定"谁中奖 / 谁拿到稀有 NFT"就是可预测随机。
#
# 判据两头卡死：
#   ① 随机源必须是**区块变量**且结果参与**取模/比较/哈希**；
#   ② 结果必须流向**价值转移**（transfer/send/call{value:}/mint）或决定赢家；
#   ③ 时间戳**只做冷却期/截止期比较**（`require(block.timestamp >= x)`
#      而没参与结果计算）→ False；
#   ④ 有 VRF / commit-reveal → False。
_BAD_RAND_BLOCKVAR_RE = re.compile(
    r"\bblock\s*\.\s*(?:timestamp|difficulty|prevrandao|number|coinbase"
    r"|blockhash|gaslimit)\b|\bblockhash\s*\(|\bnow\b(?!\w)")
_BAD_RAND_COMBINE_RE = re.compile(
    r"keccak256\s*\(|sha256\s*\(|abi\s*\.\s*encodePacked\s*\(|%\s*\d+"
    r"|\bmod\s*\d+|\buint\s*\(\s*keccak256")
_BAD_RAND_VALUE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*send\s*\(|call\s*\{\s*value\s*:"
    r"|\b_mint\s*\(|\bsafeMint\s*\(|\bwinner\b|\blucky\b|\breward\b", re.I)
_BAD_RAND_OK_RE = re.compile(
    r"\bfulfillRandomWords\b|\brequestRandomWords\b|\bVRFConsumerBase"
    r"|\bcommit\s*[-_]?\s*reveal\b|\breveal\s*\(", re.I)
_BAD_RAND_COOLDOWN_RE = re.compile(
    r"\brequire\s*\(\s*block\s*\.\s*timestamp\s*[><]=?[^)]*\)"
    r"|\bif\s*\(\s*block\s*\.\s*timestamp\s*[><]=?[^)]*\)")


def bad_randomness_verdict(source: str) -> bool | None:
    """链上伪随机（M124，第 27 类，SWC-120）。"""
    if not _looks_solidity(source):
        return None
    body = entry_body(_entry_region(source))
    if not body:
        return None
    if _BAD_RAND_OK_RE.search(body):
        return False                       # VRF / commit-reveal
    if not _BAD_RAND_BLOCKVAR_RE.search(body):
        return None                        # 没用到区块变量
    combine = _BAD_RAND_COMBINE_RE.search(body)
    result_assign = re.search(
        r"\b(?:winner|win|prize|lucky|reward)\w*\s*=", body, re.I)
    cooldown = _BAD_RAND_COOLDOWN_RE.search(body)
    # 没有"组合成随机数"也没有"结果赋值"，只是拿时间戳做窗口比较 → 冷却期，安全。
    # 这一条必须在价值转移判断**之前**：`require(block.timestamp >= t)` 后面
    # 往往紧跟 `transfer`，先看 transfer 会把冷却期误判成伪随机。
    if not combine and not result_assign:
        if cooldown:
            return False
        return None
    if not _BAD_RAND_VALUE_RE.search(body):
        return None                        # 随机数没流向价值转移/赢家
    return True


def _entry_region(source: str) -> str:
    """入口段的**原始文本**：第一个证据段头之前的全部内容（M135 收口）。

    与 `entry_body()` 的分工是**时序**，不是措辞：

        _entry_region(source)  → 先按 `// ----` / `// 来自` 切段（此时注释还在）
        entry_body(region)     → 再在入口段内部剥注释 + 截方法体

    反过来做（先剥注释再切段）会把 `// ---- [Hop N] ----` 这个**边界**擦掉，
    于是 Hop 3 的辅助代码混进入口体 —— M119 的 eladmin 四条 crypto 误报
    就是这么来的。这个函数把那条修法固化成单一口径，避免每个类目各自
    手抄一遍 `re.split`（两处拼写一旦漂移，边界就又漏了）。
    """
    return re.split(r"(?m)^[ \t]*//[ \t]*(?:----|来自)", source)[0]


# ================= M139–M141：第 28～30 类规则 =================
#
# 三类的共同点：**危险来自"名字/路径/目标由数据决定"**，而不是某个固定 API。
# 因此判据都锚在"数据 → 汇聚点"的可核对事实上，而不是"文件里有没有这个词"。

# ---- 第 28 类：不安全反射（CWE-470）----
_PY_REFLECT_SINKS = (
    r"\bimportlib\s*\.\s*import_module\s*\(\s*([^,)]*)",
    r"\b__import__\s*\(\s*([^,)]*)",
    r"\bgetattr\s*\(\s*[^,]+,\s*([^,)]*)",
    r"\bglobals\s*\(\s*\)\s*\[\s*([^\]]+)\]",
)
_JAVA_REFLECT_SINKS = (
    r"\bClass\s*\.\s*forName\s*\(\s*([^,)]*)",
    r"\.\s*loadClass\s*\(\s*([^,)]*)",
    r"\.\s*get(?:Declared)?Method\s*\(\s*([^,)]*)",
    r"\.\s*get(?:Declared)?Field\s*\(\s*([^,)]*)",
)
_PY_REFLECT_RE = re.compile("|".join(f"(?:{p})" for p in _PY_REFLECT_SINKS))
_JAVA_REFLECT_RE = re.compile("|".join(f"(?:{p})" for p in _JAVA_REFLECT_SINKS))


def _reflect_sink_arg(m: re.Match) -> str:
    """从多分支合并的正则里取出**本次命中**的实参文本。"""
    for g in m.groups():
        if g is not None:
            return g.strip()
    return ""


# 外部请求来源（Python / Java 的同一语义）：反射参数常常不是**裸形参**，
# 而是先从请求里取出来赋给局部变量再传进去。只认形参会把整类漏掉。
_REQUEST_SRC_RE = re.compile(
    r"\brequest\s*\.\s*(?:args|form|values|json|data|files|get_json|GET|POST)"
    r"|\brequest\s*\.\s*getParameter\b|\brequest\s*\.\s*getHeader\b"
    r"|\bself\s*\.\s*request\s*\.\s*(?:args|form|json|GET|POST)"
    r"|\bget_json\s*\(\s*\)", re.I)


def _reflect_dynamic(arg: str, params: set[str], body: str) -> bool | None:
    """实参是否"由外部数据决定"：True / False(常量) / None(缺证据)。

    · 字符串字面量 → False（`Class.forName("com.mysql.cj.jdbc.Driver")`
      是**正确**写法，判 True 就是纯误报）；
    · 裸标识符：属入口形参 → True；否则看它最后一次赋值 —— 字面量 →
      False，请求取值（`request.args.get(...)` / `request.getParameter(...)`）
      → True，含形参 → True，其余退 None；
    · 表达式：含形参/请求取值 → True；纯字面量拼接 → False。
    """
    a = arg.strip()
    if not a:
        return None
    if re.fullmatch(r'"[^"]*"|\'[^\']*\'', a):
        return False
    if re.fullmatch(r"[A-Za-z_]\w*", a):
        if a in params:
            return True
        rhs = _last_assign_rhs(body, a)
        if rhs is not None:
            r = rhs.strip()
            if re.fullmatch(r'"[^"]*"|\'[^\']*\'', r):
                return False
            if _REQUEST_SRC_RE.search(r):
                return True
            if any(re.search(rf"\b{re.escape(p)}\b", r) for p in params):
                return True
            return None
        return None
    if any(re.search(rf"\b{re.escape(p)}\b", a) for p in params):
        return True
    if _REQUEST_SRC_RE.search(a):
        return True
    if re.fullmatch(r'"[^"]*"(?:\s*\+\s*"[^"]*")*', a):
        return False
    return None


def _reflect_whitelisted(prefix: str, var: str) -> bool:
    """调用点**之前**是否已有对该变量的白名单约束（M139）。

    只认三种可核对形态：① `X.contains(var)`；② `var in X` / `var not in X`；
    ③ `switch (var) { case "…": }`。字符过滤（replace/正则）不算 ——
    它能改内容但不限定**取值集合**。
    """
    if not var or not re.fullmatch(r"[A-Za-z_]\w*", var):
        return False
    v = re.escape(var)
    if re.search(rf"\b[A-Za-z_]\w*\s*\.\s*contains\s*\(\s*{v}\s*\)", prefix):
        return True
    if re.search(rf"\b{v}\s+(?:not\s+)?in\s+[A-Za-z_\[\({{'\"']", prefix):
        return True
    if re.search(rf"\bswitch\s*\(\s*{v}\s*\)\s*\{{[^}}]*\bcase\b", prefix, re.S):
        return True
    return False


def unsafe_reflection_verdict(source: str) -> bool | None:
    """不安全反射（CWE-470）：动态类名/模块名/方法名是否被白名单约束。

    语言无关的同一口径：
      · 没有反射汇聚点 → None（不归本类目管）；
      · 汇聚点实参是**字面量** → False（`Class.forName("…Driver")` 是标准写法）；
      · 实参来自入口形参且调用点前有白名单 → False；
      · 实参来自入口形参且无白名单 → True；
      · 实参来源判不出（成员变量/配置读取）→ None。

    **只看入口段**（`_entry_region` + `entry_body`）：Hop 证据段里别的方法
    的反射调用不算到当前入口头上 —— 与 M119 crypto 的证据归属同一条铁律。
    """
    region = _entry_region(source)
    body = entry_body(region)
    if not body:
        return None
    is_py = _looks_python(source)
    pattern = _PY_REFLECT_RE if is_py else _JAVA_REFLECT_RE
    if is_py:
        params = set(_py_func_params(source))
    else:
        params = set(_bare_params(_entry_signature(source) or source))
    hits = list(pattern.finditer(body))
    if not hits:
        return None
    saw_unknown = False
    for m in hits:
        arg = _reflect_sink_arg(m)
        if not arg:
            saw_unknown = True
            continue
        dyn = _reflect_dynamic(arg, params, body)
        if dyn is False:
            continue                       # 常量：明确安全
        if dyn is None:
            saw_unknown = True
            continue
        prefix = body[:m.start()]
        if _reflect_whitelisted(prefix, arg):
            continue
        return True
    return None if saw_unknown else False


# ---- 第 29 类：压缩包路径穿越（CWE-22）----
_ZIP_ENTRY_TYPE_RE = re.compile(
    r"\b(?:ZipEntry|JarEntry|TarArchiveEntry|ArchiveEntry)\b")
_ZIP_NAME_GET_RE = re.compile(r"\.\s*getName\s*\(\s*\)")
# M153：kkFileView 用 sevenzipjbinding，没有 ZipEntry.getName()，
# 条目名走 ISimpleInArchiveItem.getPath()。不认这两个类型/取值，
# 真实解压落盘代码会整片退 None（矩阵里 zip_slip 永远没有 Java 证据）。
_ZIP_SEVENZIP_TYPE_RE = re.compile(r"\b(?:ISimpleInArchiveItem|IInArchive|SevenZip)\b")
_ZIP_SEVENZIP_NAME_RE = re.compile(r"\.\s*getPath\s*\(\s*\)")
_JAVA_PATH_SINK_RE = re.compile(
    r"new\s+(?:java\.io\.)?File\s*\([^;]*\)"
    r"|Paths?\s*\.\s*(?:get|of)\s*\([^;]*\)"
    r"|new\s+(?:java\.io\.)?File(?:Output|Input)Stream\s*\([^;]*\)"
    r"|Files\s*\.\s*(?:copy|write|newOutputStream)\s*\([^;]*\)", re.S)
# 规范化前缀校验：`getCanonicalPath().startsWith(...)` / `normalize().startsWith(...)`
_ZIP_CANONICAL_GUARD_RE = re.compile(
    r"\.\s*(?:getCanonicalPath|getCanonicalFile|normalize|toRealPath)\s*\(\s*\)"
    r"[\s\S]{0,120}?\.\s*startsWith\s*\("
    r"|\.\s*toRealPath\s*\(\s*\)[\s\S]{0,120}?\.\s*startsWith\s*\(")
_PY_EXTRACT_RE = re.compile(
    r"\.\s*(?:extractall|extract)\s*\(\s*([^)]*)\)")
_PY_ZIP_FILTER_RE = re.compile(r"filter\s*=\s*['\"]data['\"]")
_PY_PATH_PREFIX_GUARD_RE = re.compile(
    r"os\s*\.\s*path\s*\.\s*(?:realpath|abspath)\s*\([^)]*\)[\s\S]{0,120}?"
    r"(?:startswith|commonpath|relative_to)"
    r"|Path\s*\([^)]*\)\s*\.\s*resolve\s*\(\s*\)[\s\S]{0,120}?"
    r"(?:startswith|relative_to|is_relative_to)")


def zip_slip_verdict(source: str) -> bool | None:
    """压缩包路径穿越（Zip Slip，CWE-22）。

    Java 侧：只有当 `ZipEntry/JarEntry/TarArchiveEntry` 的 `getName()` **真的
    流进**文件路径/输出流时才成立 —— 一个只解压到内存的 zip 读取器不该被报。
    Python 侧：`extractall/extract` 本身即落盘（PEP 706 的 `filter="data"`
    是官方给出的标准防护）。

    防护口径：`getCanonicalPath()/normalize()/toRealPath()` 后
    `startsWith(...)` 前缀校验，或 Python 的 `filter="data"` /
    `realpath(...).startswith(...)`。**只做 `..` 检查**不够（符号链接、
    编码变体都能绕过），但按本仓的保守口径，它也不构成"确定性"的反证 ——
    缺规范化前缀校验时仍判 True。
    """
    region = _entry_region(source)
    body = entry_body(region)
    if not body:
        return None
    if _looks_python(source):
        hits = list(_PY_EXTRACT_RE.finditer(body))
        if not hits:
            return None
        if _PY_ZIP_FILTER_RE.search(body):
            return False
        if _PY_PATH_PREFIX_GUARD_RE.search(source):
            return False
        return True
    seven = _ZIP_SEVENZIP_TYPE_RE.search(source)
    has_entry = bool(_ZIP_ENTRY_TYPE_RE.search(source) or seven)
    name_in_body = bool(_ZIP_NAME_GET_RE.search(body)
                        or (seven and _ZIP_SEVENZIP_NAME_RE.search(body)))
    if not has_entry:
        return None
    # M153：two-step 形态 —— 条目名在 helper 里取，入口只拿 helper 返回的
    # Path 落盘（kkFileView 的 unRar -> getFilePathInsideArchive）。
    # 判据要同时看入口与**切片里的 helper 实现体**，否则只能看到
    # "Path p = helper(item, dir)"，名字流与守卫都不在入口体内。
    if seven and not name_in_body:
        if not _ZIP_SEVENZIP_NAME_RE.search(source):
            return None
        helper_call = re.search(
            r"\b(?:Path|String|File)\s+\w+\s*=\s*\w+\s*\(\s*\w+\s*,", body)
        if not helper_call:
            return None
        if _ZIP_CANONICAL_GUARD_RE.search(source):
            return False
        if _JAVA_PATH_SINK_RE.search(body) or re.search(
                r"Files\s*\.\s*createDirectories", source):
            return True
        return None
    # helper 本身（名字 + resolve + 守卫）也是一个可判单元：它没有写出
    # 动作，但它的**返回值**就是落盘路径，缺守卫时调用方必然穿越。
    if seven and _ZIP_SEVENZIP_NAME_RE.search(body) \
            and re.search(r"\.\s*resolve\s*\(", body):
        if _ZIP_CANONICAL_GUARD_RE.search(source):
            return False
        if re.search(r"Files\s*\.\s*createDirectories|FileOutputStream", source):
            return True
        return None
    if not name_in_body:
        return None
    # 条目名 → 文件路径/输出流：直接内联，或经一个局部变量中转。
    names = set(re.findall(r"\b([A-Za-z_]\w*)\s*=\s*[^;]*?\.\s*getName\s*\(\s*\)",
                           body))
    flow = False
    for sm in _JAVA_PATH_SINK_RE.finditer(body):
        seg = sm.group(0)
        if _ZIP_NAME_GET_RE.search(seg):
            flow = True
            break
        if any(re.search(rf"\b{re.escape(n)}\b", seg) for n in names):
            flow = True
            break
    if not flow:
        return None
    if _ZIP_CANONICAL_GUARD_RE.search(body):
        return False
    return True


# ---- 第 30 类：不受信 delegatecall（SWC-112）----
_SOL_DELEGATECALL_RE = re.compile(
    r"(address\s*\([^)]*\)"                       # address(this) / address(x)
    r"|[A-Za-z_]\w*(?:\s*\[[^\]]*\])?(?:\s*\([^)]*\))?)"  # impl / impls[id] / _implementation()
    r"\s*\.\s*delegatecall")
# 自委托（Multicall 常见写法）：`address(this).delegatecall(...)`
_SOL_SELF_DELEGATE_RE = re.compile(
    r"\b(?:address\s*\(\s*this\s*\)|this)\s*\.\s*delegatecall")
# ERC-1967 实现槽读取：`_implementation()` / `getAddressSlot(...).value`
_SOL_IMPL_SLOT_RE = re.compile(
    r"\b_implementation\s*\(\s*\)|getAddressSlot\s*\(|"
    r"ERC1967Utils\s*\.\s*(?:getImplementation|IMPLEMENTATION_SLOT)")
# 身份**门控占位符**：`if (msg.sender == admin) { _; }`（Aave 的 ifAdmin）。
# 恒等比较出现在条件里，入口体只在相等分支执行 —— 与 require 同义。
_SOL_SENDER_EQ_GATE_RE = re.compile(
    r"\b(?:require|assert|if)\s*\(\s*msg\s*\.\s*sender\s*==")
# 一次性初始化守卫（M143）：`require(_implementation() == address(0))` /
# `initializer` / `reinitializer(n)` / `onlyInitializing`。这类函数的目标
# 地址由**部署时**指定，风险是部署竞态而不是部署后的权限提升 —— 与
# "不受信 delegatecall（部署后目标可控）"不是同一类，按类目边界排除。
_SOL_ONESHOT_INIT_RE = re.compile(
    r"require\s*\(\s*(?:_implementation|implementation|_getImplementation"
    r"|getImplementation)\s*\(\s*\)\s*==\s*address\s*\(\s*0\s*\)"
    r"|require\s*\(\s*address\s*\(\s*this\s*\)\s*\.\s*code\s*\.\s*length"
    r"\s*==\s*0\s*\)")
_SOL_INITIALIZER_MOD_RE = re.compile(
    r"\b(?:initializer|reinitializer|onlyInitializing)\b")


def _sol_unconditional_revert(body: str) -> bool:
    """函数**顶层的最后一条语句**是不是无条件 revert（M141）。

    synthetix 的 `simulateUpgradeTo` 是一次"演练"：它临时改写实现槽、
    delegatecall 到新实现，然后**无条件 revert** —— 整个交易回滚，
    任何被委托代码写的状态都不可能留下来（EVM 的原子性事实）。
    这种形态不是"目标不可信"，而是"根本没落地"。

    判据只看**顶层**（花括号深度 0）的语句：`if (...) { revert; }` 里的
    revert 不算（那是条件分支，函数还有正常出口）。语句按 `;` 切，
    整块 `{...}` 跳过；行注释先剥掉（`// solhint-disable-next-line`
    常紧贴在 `revert();` 上一行）。
    """
    clean = re.sub(r"//[^\n]*", "", body)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.S)
    depth = 0
    stmts: list[str] = []
    start = 0
    for i, ch in enumerate(clean):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                start = i + 1
        elif ch == ";" and depth == 0:
            stmt = clean[start:i].strip()
            if stmt:
                stmts.append(stmt)
            start = i + 1
    return bool(stmts) and bool(re.match(r"^revert\b", stmts[-1]))


def _sol_onlyproxy_guard(mod_block: str) -> bool:
    """`onlyProxy` 型守卫（OZ UUPS）：校验"当前经代理调用 + 实现槽非零"。

    实现体形态（OZ 5.x）：
        modifier onlyProxy() {
            _checkProxy();
            _;
        }
        function _checkProxy() internal view virtual {
            if (address(this) == __self) revert;      // 直调实现合约
            if (_getImplementation() != address(0)) ...
        }
    判据挂机制：modifier（或其调用的辅助函数）里同时出现
    `address(this) == __self` 与实现槽读取 —— 这是框架层的入口约束，
    与身份校验等价（直调实现合约时 msg.sender 是任意人，必须拒绝）。
    """
    if not mod_block:
        return False
    ev = mod_block
    has_self = bool(re.search(r"address\s*\(\s*this\s*\)\s*==\s*__self"
                              r"|__self\s*==\s*address\s*\(\s*this\s*\)"
                              r"|address\s*\(\s*this\s*\)\s*!=\s*__self", ev))
    has_slot = bool(re.search(r"_getImplementation\s*\(\s*\)"
                              r"|__self\s*\.\s*implementation", ev))
    return bool(has_self and has_slot)


def _sol_enclosing_function(text: str, pos: int) -> tuple[str, str]:
    """返回包住 `pos` 的那个函数的 (签名段, 配平函数体)。

    合成夹具/整合约文本里往往一次带好几个函数（`setImpl` + `run`），
    而 `_sol_param_names()` 只认**第一个** `function` —— 直接拿整段做
    "形参是否可控"的判断会张冠李戴（把另一个函数的形参算进来）。
    真实切片里只有入口函数，本函数对它是恒等变换。

    **`fallback` / `receive` / `constructor` 也必须算函数**（M143）：Solidity
    里这三个特殊入口**不写 `function` 关键字**，而代理合约的 `delegatecall`
    恰恰最常写在 `fallback()` 里。只认 `function` 的后果是：作用域定位失败，
    `_sol_signature` 回落到**文件里第一个普通函数**的签名 —— 如果那个函数是
    internal，整个 delegatecall 判定就被"内部不可达"提前判 False（把真问题
    洗成安全）。
    """
    decl = (r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)[^{;]*"
            r"|\b(?:fallback|receive|constructor)\s*\([^)]*\)[^{;]*")
    best: tuple[str, str] = ("", "")
    for m in re.finditer(decl, text):
        brace = text.find("{", m.end() - 1)
        if brace < 0 or brace > pos:
            continue
        body = _sol_block_body(text, brace)
        if not body:
            continue
        if brace + len(body) < pos:
            continue
        best = (text[m.start():brace], body)
    return best


def solidity_delegatecall_verdict(source: str) -> bool | None:
    """不受信 delegatecall（SWC-112）。

    **排除面（判 False）**：
      · `address(this).delegatecall(...)`（Multicall/自委托，目标是本合约）；
      · 目标来自 ERC-1967 实现槽（`_implementation()` / `getAddressSlot`）；
      · 函数受身份校验保护（`onlyOwner`/`auth`/`wards[msg.sender]` 等，
        实现体真的比对了身份）；
      · `onlyProxy` 型入口约束（OZ UUPS：拒绝直调实现合约）；
      · internal/private（外部不可达）；
      · 目标在 require 里与白名单/可信槽位做过比较。

    **成立（True）**：目标来自**入口形参**，或来自本函数里刚从形参写入的
    状态槽，且无上述任何保护。

    其余（目标来源判不出的成员变量）→ None：单函数切片里看不到它是否可被
    外部改写，"可能可写"不是"确定可写"。
    """
    if not _looks_solidity(source):
        return None
    func_src, mod_block, _inh = _split_sol_sections(source)
    if not re.search(r"\bdelegatecall\b", func_src):
        return None
    # 只分析**包住 delegatecall 的那个函数**
    first = _SOL_DELEGATECALL_RE.search(func_src)
    if first is None:
        # `delegatecall` 字面出现在注释/字符串/跨行拼接里，但没有可解析的
        # `目标.delegatecall` 形态 → 缺证据，不硬判。
        return None
    scope_sig, scope_body = _sol_enclosing_function(func_src, first.start())
    sig = scope_sig or _sol_signature(func_src)
    scope = (scope_sig + "{" + scope_body + "}") if scope_body else func_src
    if _sol_is_internal_only(sig):
        return False
    # M143：一次性初始化函数（`initializer` / `require(impl == address(0))`）
    # —— 目标地址由部署时给定，不属于"部署后目标可控"这一类。
    if (_SOL_INITIALIZER_MOD_RE.search(sig)
            or _SOL_ONESHOT_INIT_RE.search(scope)):
        return False
    # M141：演练型函数（顶层最后一句无条件 revert）—— 状态不可能落地。
    # 传的是**不含外层大括号**的函数体：`if (...) { revert; }` 里的 revert
    # 算在深度 1，不当成"无条件"。
    if _sol_unconditional_revert(scope_body or scope):
        return False
    targets = [m.group(1).strip() for m in _SOL_DELEGATECALL_RE.finditer(scope)]
    if not targets:
        return None
    # 自委托：目标就是 address(this)
    if all(re.fullmatch(r"(?:address\s*\(\s*this\s*\)|this)", t) for t in targets):
        return False
    if _SOL_SELF_DELEGATE_RE.search(scope):
        rest = [t for t in targets
                if not re.fullmatch(r"(?:address\s*\(\s*this\s*\)|this)", t)]
        if not rest:
            return False
        targets = rest
    # ERC-1967 实现槽
    if _SOL_IMPL_SLOT_RE.search(scope):
        targets = [t for t in targets if t not in {"_implementation()"}]
        if not targets:
            return False
    # 保护：身份校验 or onlyProxy
    protected = bool(_SOLIDITY_MSGSENDER_CHECK_RE.search(scope)
                     or _SOLIDITY_MSGSENDER_MEMBER_RE.search(scope)
                     or _sol_caller_map_auth(scope)
                     # 门控占位符形态：`if (msg.sender == admin) { _; }`
                     or _SOL_SENDER_EQ_GATE_RE.search(scope)
                     or _sol_identity_call_check(scope)
                     or _sol_predicate_authz_check(source)
                     or _sol_inverted_identity_guard(scope)
                     or _sol_negated_identity_call(scope)
                     or _sol_onlyproxy_guard(mod_block)
                     or _sol_indirect_identity_check(scope, mod_block, _inh))
    if not protected:
        # 只在**签名真的引用了**该 modifier 时才认它的实现体 —— 否则同文件里
        # 一个没被用上的 onlyOwner 会凭空给本函数发保护（负面锚点必须能翻转）。
        _VIS_KW = {"external", "public", "internal", "private", "view", "pure",
                   "payable", "constant", "returns", "virtual", "override"}
        tail = sig[sig.find(")") + 1:] if ")" in sig else ""
        used_mods = {w for w in re.findall(r"\b([A-Za-z_]\w*)\b", tail)
                     if w not in _VIS_KW}
        mod_src = mod_block + "\n" + source
        for mm in re.finditer(
                r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*[^{]*\{",
                mod_src):
            if used_mods and mm.group(1) not in used_mods:
                continue
            body = _sol_block_body(mod_src, mm.end() - 1)
            if not body:
                continue
            if (_SOLIDITY_MSGSENDER_CHECK_RE.search(body)
                    or _SOLIDITY_MSGSENDER_MEMBER_RE.search(body)
                    or _sol_caller_map_auth(body)
                    or _SOL_SENDER_EQ_GATE_RE.search(body)
                    or _sol_onlyproxy_guard(body)):
                protected = True
                break
            # `modifier onlyProxy() { _checkProxy(); _; }` —— 真正的
            # `address(this) == __self` + 实现槽校验在**下一跳**的辅助函数里。
            # 只看 modifier 体本身会漏掉整条 UUPS 入口约束（M143 实测）。
            for _callee in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body):
                if _callee in {"if", "require", "revert", "assert"}:
                    continue
                _cb = _sol_func_body_by_name(mod_src, _callee)
                if _cb and _sol_onlyproxy_guard(_cb):
                    protected = True
                    break
            if protected:
                break
    if protected:
        return False
    params = _sol_param_names(sig)
    # 目标在 require 里与白名单/可信槽位比较过 → 受约束
    for t in targets:
        base = re.sub(r"\s*\(.*$", "", t).strip()
        if not base:
            continue
        if re.search(rf"(?:require|assert)\s*\([^;]{{0,120}}?\b{re.escape(base)}\b"
                     rf"\s*==", scope):
            return False
    for t in targets:
        base = re.sub(r"\s*\(.*$", "", t).strip()
        if base in params:
            return True
        # 状态槽：本函数里刚从形参写入 → 目标可控
        if params and re.search(
                rf"\b{re.escape(base)}\s*=\s*[^;]*\b(?:"
                + "|".join(re.escape(p) for p in params) + r")\b", scope):
            return True
    return None



# ================= M157/M158：第 31、32 类规则 =================
#
# 两类都遵守同一条铁律：判据锚在"数据流到汇聚点"的可核对事实上，
# 而不是"文件里出现了某个词"。名字/注释都不算证据。

# ---- 第 31 类：不受限文件上传（CWE-434）----
_UPLOAD_JAVA_NAME_RE = re.compile(
    r"\bget(?:OriginalFilename|SubmittedFileName)\s*\(\s*\)")
_UPLOAD_JAVA_SINK_RE = re.compile(
    r"\.\s*transferTo\s*\(|new\s+File\s*\(|Paths\s*\.\s*get\s*\("
    r"|new\s+FileOutputStream\s*\(|Files\s*\.\s*(?:copy|write)\s*\(")
_UPLOAD_JAVA_PARAM_RE = re.compile(r"\bMultipartFile\b|\bPart\b")
_UPLOAD_PY_NAME_RE = re.compile(r"\.\s*filename\b")
_UPLOAD_PY_PARAM_RE = re.compile(
    r"\bUploadFile\b|\brequest\s*\.\s*files\b|\bFileStorage\b")
_UPLOAD_PY_SINK_RE = re.compile(
    r"\bopen\s*\(|\bshutil\s*\.\s*copyfileobj\s*\(|\.\s*save\s*\(")

# 白名单/固定后缀的"证据面"：必须同时出现**判定**与**中止**，
# 只写一个 ALLOWED 常量但从不拿它 if，不算防护。
_UPLOAD_WHITELIST_HINT_RE = re.compile(
    r"(?i)(?:allowed|permitted|valid)_?(?:ext|exts|extensions?|suffix|suffixes|filetypes?|types?)"
    r"|\bwhitelist\b|\.\s*endsWith\s*\(|\.\s*endswith\s*\("
    r"|\b(?:in|not\s+in)\s+\w*(?:ALLOWED|SAFE|PERMITTED|VALID)\w*"
    r"|\.\s*contains\s*\(\s*(?:ext|suffix|fileType)\s*\)")
_UPLOAD_JAVA_GUARD_RE = re.compile(
    # 条件里可能有两层括号（if (...) { ... } 与 contains(...)），
    # 只吃一个右括号会把 ")) {" 判成不匹配 —— 白名单明明写了却判 True。
    r"(?is)if\s*\([^)]{0,400}(?:allowed|safe|permitted|endsWith|contains|"
    r"ALLOWED|valid)[^)]{0,400}\)\s*\)?\s*\{[^}]{0,600}(?:return|throw|continue)")
_UPLOAD_PY_GUARD_RE = re.compile(
    r"(?is)if\s+[^:\n]{0,400}(?:not\s+in|endswith|allowed|safe|permitted)"
    r"[^:\n]{0,400}:\s*\n\s*(?:raise|return|continue|abort)")
# 服务端重命名 + **固定后缀**：UUID 后跟字面量 .png/.jpg 才算；
# UUID + 原始后缀（fileName.substring(...)）仍然可传 .jsp，不算。
_UPLOAD_GENERATED_RE = re.compile(
    r"(?i)\b(?:uuid|uuid4|randomUUID|nanoTime|snowflake)\b[^;\n]{0,160}"
    r"[\"']\.(?:png|jpe?g|gif|pdf|zip|txt|docx?|xlsx?)[\"']")


def _upload_has_guard(body: str, python: bool) -> bool:
    if not _UPLOAD_WHITELIST_HINT_RE.search(body):
        return False
    return bool((_UPLOAD_PY_GUARD_RE if python else _UPLOAD_JAVA_GUARD_RE)
                .search(body))


def unrestricted_upload_verdict(source: str) -> bool | None:
    """第 31 类（M157）：原始文件名直接落盘，且无后缀白名单/固定重命名。

    判 False 的两条机制（都可核对）：
      ① 白名单判定 + 中止分支（if/raise/return/throw）；
      ② 服务端生成 UUID + **固定后缀**（不是沿用原始后缀）。
    只有 MIME/Content-Type 校验不算 —— 客户端可控。
    """
    if _looks_solidity(source):
        return None
    body = entry_body(_entry_region(source))
    if not body:
        return None
    if _looks_python(source):
        if not (_UPLOAD_PY_PARAM_RE.search(source)
                or _UPLOAD_PY_PARAM_RE.search(body)):
            return None
        if not _UPLOAD_PY_NAME_RE.search(body):
            return None
        if not _UPLOAD_PY_SINK_RE.search(body):
            return None
        if _upload_has_guard(body, python=True):
            return False
        if _UPLOAD_GENERATED_RE.search(body):
            return False
        return True
    # Java / Kotlin
    if not (_UPLOAD_JAVA_PARAM_RE.search(source)
            or _UPLOAD_JAVA_PARAM_RE.search(body)):
        return None
    if not _UPLOAD_JAVA_NAME_RE.search(body):
        return None
    if not _UPLOAD_JAVA_SINK_RE.search(body):
        return None
    if _upload_has_guard(body, python=False):
        return False
    if _UPLOAD_GENERATED_RE.search(body):
        return False
    return True


# ---- 第 32 类：签名重放 / 缺失 nonce 消费（SWC-121 / CWE-347）----
_SOL_ECRECOVER_RE = re.compile(r"\becrecover\s*\(")
_SOL_ECRECOVER_ASSIGN_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(\w+)\s*=\s*ecrecover\s*\(")
_SOL_STATE_CHANGE_RE = re.compile(
    r"\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom|_mint|_burn"
    r"|selfdestruct|delegatecall|call\s*\{)\b"
    r"|\b\w+\s*\[[^\]]*\]\s*[+\-]?=(?!=)|\bdelete\s+\w+|\+\+|--")


def _sol_has_nonce_consumption(body: str) -> bool:
    """一次性 nonce / 签名哈希是否**先判后写**。"""
    guard = re.search(
        r"(?is)(?:require|if)\s*\([^)]{0,300}!\s*\w+\s*\[", body)
    write = re.search(
        r"(?is)\w+\s*\[[^\]]+\]\s*=\s*(?:true|block\.timestamp|block\.number"
        r"|\w+\s*\+\s*1)", body)
    bump = re.search(r"\w+\s*\[[^\]]+\]\s*\+\+", body)
    return bool((guard and write) or bump)


def signature_replay_verdict(source: str) -> bool | None:
    """第 32 类（M158）：状态变更路径上的原生 ecrecover 缺零地址校验/nonce。

    编译器强制的事实优先：view/pure 不写状态、internal/private 外部不可达，
    两者都判 False（验签辅助函数不构成本类漏洞）。
    安全判据要**同时**满足：恢复地址 != address(0)，且 nonce/哈希被消费。
    """
    if not _looks_solidity(source):
        return None
    func_src, _mod_block, _inh = _split_sol_sections(source)
    sig = _sol_signature(func_src)
    if _sol_is_readonly(sig) or _sol_is_internal_only(sig):
        return False
    if not _SOL_ECRECOVER_RE.search(func_src):
        return None
    # 验签结果没进入任何状态变更/价值转移 → 不是"签名重放"能造成损失的路径。
    # 但 "used[hash] = true" 本身就是状态变更，所以这条只在**没有**任何
    # 赋值/转移时才退 None（纯验签工具函数）。
    if not _SOL_STATE_CHANGE_RE.search(func_src):
        return None
    m = _SOL_ECRECOVER_ASSIGN_RE.search(func_src)
    zero_ok = False
    if m:
        var = re.escape(m.group(1))
        zero_ok = bool(re.search(
            rf"\b{var}\s*!=\s*address\s*\(\s*0\s*\)", func_src))
    nonce_ok = _sol_has_nonce_consumption(func_src)
    if zero_ok and nonce_ok:
        return False
    return True



# ================= M171/M172：第 33/34 类规则 =================

# ---- 第 33 类：NoSQL 注入（CWE-943）----
_MONGO_JAVA_PARSE_RE = re.compile(
    r"\b(?:BasicDBObject|Document)\s*\.\s*parse\s*\(\s*([^)]*)")
_MONGO_JAVA_WHERE_RE = re.compile(
    r"new\s+BasicDBObject\s*\(\s*[\"']\$where[\"']\s*,\s*([^)]*)")
_MONGO_PY_SINK_RE = re.compile(
    r"\.\s*(?:find|find_one|find_one_and_\w+|update_one|update_many"
    r"|delete_one|delete_many|aggregate|count_documents)\s*\(")
_MONGO_DOLLAR_GUARD_RE = re.compile(
    r"contains\s*\(\s*[\"']\$[\"']|startsWith\s*\(\s*[\"']\$"
    r"|startswith\s*\(\s*[\"']\$|[\"']\$[\"']\s+in\b"
    r"|startswith\(\s*[\"']\$[\"']\s*\)")
_MONGO_ABORT_RE = re.compile(r"\b(?:throw|raise|return|continue|break)\b")


def nosqli_verdict(source: str) -> bool | None:
    """第 33 类（M171）：外部字符串/字典直接进入 Mongo 查询。

    判 False 的机制：显式拒绝以 $ 开头的键并中止；或值被强类型化且
    键是服务端常量。只转义引号不拦操作符，不算防护。
    """
    body = entry_body(source)
    if not body:
        return None
    if _looks_python(source):
        if not _MONGO_PY_SINK_RE.search(body):
            return None
        # Python 的污点源是 request.get_json()/request.json，落到局部变量
        # 再进 find；只认"该变量确实由请求对象赋值"这一条可核对事实。
        src_var = re.search(
            r"(\w+)\s*=\s*request\s*\.\s*(?:json|get_json|args|form)", body)
        if src_var:
            if not re.search(rf"\.\s*(?:find|find_one|find_one_and_\w+|"
                             rf"update_one|update_many|delete_one|delete_many|"
                             rf"aggregate|count_documents)\s*\([^)]*\b"
                             rf"{re.escape(src_var.group(1))}\b", body):
                return None
        elif not re.search(r"\.\s*(?:find|find_one|find_one_and_\w+|update_one"
                           r"|update_many|delete_one|delete_many|aggregate"
                           r"|count_documents)\s*\(\s*request\s*\.", body):
            return None
        if _MONGO_DOLLAR_GUARD_RE.search(body) and _MONGO_ABORT_RE.search(body):
            return False
        if re.search(r"isinstance\s*\([^)]*,\s*(?:str|int)\s*\)", body):
            return False
        return True
    m = _MONGO_JAVA_PARSE_RE.search(body) or _MONGO_JAVA_WHERE_RE.search(body)
    if not m:
        return None
    arg = (m.group(1) or "").strip()
    if not arg or re.fullmatch(r"\"[^\"]*\"|'[^']*'", arg):
        return False                   # 常量查询串，没有注入面
    if _MONGO_DOLLAR_GUARD_RE.search(body) and _MONGO_ABORT_RE.search(body):
        return False
    return True


# ---- 第 34 类：日志注入（CWE-117）----
_LOG_CALL_RE = re.compile(
    r"\b(?:log|logger|LOG|LOGGER|logging)\s*\.\s*"
    r"(?:info|warn|warning|error|debug|trace)\s*\(([^;]{0,600})\)", re.I)
_LOG_SANITIZE_RE = re.compile(
    r"\.\s*replace\s*\(\s*[\"']\\r|\.\s*replace\s*\([^)]*\\n"
    r"|replaceAll\s*\(\s*[\"']\[?\\r|escapeJava|escapeJson|sanitizeLog"
    r"|stripCRLF|strip_crlf", re.I)


def _log_tainted(call: str, params: set[str]) -> bool:
    """日志实参里是否真的有外部形参（不是字符串字面量里的同名文字）。"""
    # 先保留 f-string 内容，再剥普通字符串字面量。
    keep: list[str] = []

    def _keep_f(m: re.Match) -> str:
        keep.append(m.group(0))
        return f"__F{len(keep) - 1}__"

    tmp = re.sub(r"\bf[\"'][^\"']*\{[^}]*\}[^\"']*[\"']", _keep_f, call)
    tmp = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", '""', tmp)
    for i, s in enumerate(keep):
        tmp = tmp.replace(f"__F{i}__", s)
    for p in params:
        if re.search(rf"\b{re.escape(p)}\b", tmp):
            return True
    return False


def log_injection_verdict(source: str) -> bool | None:
    """第 34 类（M172）：外部可控字符串直接拼进日志，未剥离 CR/LF。"""
    body = entry_body(source)
    if not body:
        return None
    params = (set(_py_func_params(source)) if _looks_python(source)
              else set(_bare_params(_entry_signature(source))))
    # 局部变量由请求对象赋值也算污点（Python 常见：msg = request.args.get）。
    params |= set(re.findall(r"(\w+)\s*=\s*request\s*\.", body))
    if not params:
        return None
    py = _looks_python(source)
    for m in _LOG_CALL_RE.finditer(body):
        call = m.group(0)
        # 只收"字符串拼接 / f-string / % 运算"的日志。SLF4J 的
        # logger.info("...{}", x) 与 Python 的 logging.info("...%s", x)
        # 是参数化日志（占位符由日志框架填充），不属本类目的拼接面；
        # 否则 kkFileView 这类正常参数化日志会整片假阳。
        if not py and "+" not in call:
            continue                    # 直传 getter 不是字符串拼接
        if not py and "{}" in call and "+" not in call:
            continue
        # String.format(常量, 参数) 是格式化，不是字符串拼接；本类目只收
        # 拼接形态（与 M172 规格一致）。
        if not py and "String.format(" in call:
            continue
        if py and re.search(r"[\"'][^\"']*%[sd]", call) and "," in call \
                and " % " not in call:
            continue
        if not _log_tainted(call, params):
            continue
        # 清洗可能写在日志语句**之前**的一行（msg = msg.replace(...)），
        # 只扫 call 本身会漏掉这种标准写法。
        if _LOG_SANITIZE_RE.search(body[:m.start()]):
            return False
        return True
    return None


def verdict(category: str, source: str) -> bool | None:
    """对配置型类目给出确定性结论：True(有漏洞) / False(安全) / None(证据不足)。"""
    cfg = parse_config_block(source)

    if category == "crypto":
        alg = extract_cipher_alg(source, cfg)
        if not alg:
            return None
        # M122：**证据归属**。切片会把 Hop 2/3 的辅助类贴进证据段
        # （`// 来自 EncryptUtils.java:46 [Hop 3]`）。如果入口体里根本没有
        # 加解密调用，那么 DES/Cipher 属于**别的方法**，算到当前入口头上就是
        # 假阳 —— eladmin 实测 `RoleController.getRoleLevel` / `UserController.
        # centerUser` 四条的 DES 全来自 Hop 3 的 `EncryptUtils.desEncrypt`。
        # 归属不了就退 None（"缺证据不下结论"），而不是判 True。
        #
        # 关键：`entry_body()` 会**剥掉注释**，而跨文件/Hop 证据段恰恰是用
        # `// 来自 Xxx.java:46 [Hop 3]` 这种注释行分隔的 —— 剥完注释，证据段
        # 的**代码**就混进 body 了（实测 `desEncrypt` 的 `Cipher.getInstance`
        # 仍在）。所以必须先对**原始 source** 按标记切段，再看入口那一段。
        _region = _entry_region(source)
        _body = entry_body(_region)
        # M153 实测：原来写裸 encrypt|decrypt 会把**形参名** encryption
        # 当成加解密调用（kkFileView onlinePreview 的 encryption 是查询参数），
        # 证据归属守卫被一个变量名绕过，AES/ECB 从 Hop 2 的 AESUtil 算到入口
        # 头上 —— 4 条 crypto 假阳。要求真的出现**调用**（后面跟括号）。
        if not re.search(r"Cipher\s*\.\s*getInstance|\.\s*(?:doFinal|update)\s*\("
                         r"|new\s+\w*Cipher"
                         r"|\b(?:encrypt|decrypt)(?:Data|String|Bytes|File|Url)?\s*\(",
                         _body, re.I):
            return None
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

    if category == "ssti":
        return ssti_verdict(source)

    if category in ("header_injection", "crlf"):
        return header_injection_verdict(source)

    if category == "mass_assignment":
        return mass_assignment_verdict(source)

    if category == "bad_randomness":
        return bad_randomness_verdict(source)

    if category == "xxe":
        return xxe_verdict(source)

    if category == "sqli":
        if _looks_python(source):
            return python_sqli_verdict(source)
        return sqli_verdict(source)

    if category in ("redir", "openredirect"):
        return redir_verdict(source)

    if category == "xss":
        if _looks_python(source):
            return python_xss_verdict(source)
        return xss_verdict(source)

    if category == "ssrf":
        return ssrf_verdict(source)

    if category == "hardcoded_secret":
        return hardcoded_secret_verdict(source)

    if category == "jwt_weakness":
        return jwt_weakness_verdict(source)

    if category == "cmdi":
        if _looks_python(source):
            return python_cmdi_verdict(source)
        return cmdi_verdict(source)

    if category == "pathtraver":
        return pathtraver_verdict(source)

    if category == "xpathi":
        return xpathi_verdict(source)

    if category == "authz":
        # M121：DRF 类视图切片带 `// View-Action:` 头 —— 走 Django/DRF 专门口径，
        # 不能扔给通用的 Java 风格判据（它看不见类级 permission_classes）。
        if "// View-Action:" in source or "// View-Action:" in source.replace(
                "\r", ""):
            return _drf_authz_verdict(source, entry_body(source),
                                      re.search(r"//\s*View-Action:\s*(\w+)",
                                                source).group(1))
        if _looks_python(source):
            return python_authz_verdict(source)
        return authz_verdict(source)

    if category == "reentrancy":
        if _looks_solidity(source):
            return solidity_reentrancy_verdict(source)
        return None

    if category in ("access_control", "broken_access"):
        if _looks_solidity(source):
            return solidity_access_verdict(source)
        return None

    if category == "unchecked_low_level_calls":
        if _looks_solidity(source):
            return solidity_unchecked_call_verdict(source)
        return None

    if category == "arithmetic":
        if _looks_solidity(source):
            return solidity_arithmetic_verdict(source)
        return None

    # M139–M141：第 28～30 类（跨语言：反射 / 压缩包穿越 / 不受信 delegatecall）
    if category == "unsafe_reflection":
        return unsafe_reflection_verdict(source)

    if category == "zip_slip":
        return zip_slip_verdict(source)

    if category == "delegatecall_untrusted":
        return solidity_delegatecall_verdict(source)

    # M157/M158：第 31、32 类
    if category == "unrestricted_upload":
        return unrestricted_upload_verdict(source)
    if category == "signature_replay":
        return signature_replay_verdict(source)
    if category == "nosqli":
        return nosqli_verdict(source)
    if category == "log_injection":
        return log_injection_verdict(source)

    return None
