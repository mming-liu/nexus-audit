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


def cors_verdict(source: str) -> bool | None:
    body = entry_body(source)
    if not ACAO_RE.search(body):
        return None                    # 入口体内没有 CORS 头，交给装配解析器

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
            continue                   # 固定字面量域名，不看请求，安全
        if _IDENT.match(val) and ORIGIN_READ_RE.search(body):
            echoes_origin = True       # 变量 = getHeader("Origin")，原样回显
        elif _IDENT.match(val):
            # 变量来源不明，但 body 里出现过读 Origin 头的动作
            echoes_origin = echoes_origin or bool(ORIGIN_READ_RE.search(body))

    if ORIGIN_READ_RE.search(body) and ORIGIN_CHECK_RE.search(body):
        return False                   # 读了 Origin，但先做了白名单校验
    return echoes_origin or None


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

    return None
