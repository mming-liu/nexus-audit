"""CVSS v3.1 Base Score 计算器（M83，零外部依赖）。

映射口径：按类目的**典型可利用路径**给基础向量，再由标准公式现算分值。
同一个类目在全局配置继承时可换用更贴近暴露面的向量（CORS）。
"""
from __future__ import annotations

import math

# 向量分量：AV/AC/PR/UI/S/C/I/A。不写 `CVSS:3.1/` 前缀，计算器统一补。
_VECTORS: dict[str, str] = {
    "sqli": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "pathtraver": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "weakrand": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "securecookie": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "trustbound": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "hash": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "crypto": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ldapi": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "xpathi": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "ssrf": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "xxe": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "spel": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserial": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "redir": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "cors": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "hardcoded_secret": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "jwt_weakness": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "authz": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "reentrancy": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "access_control": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "arithmetic": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
}
_DEFAULT = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
# 全局 CORS 配置：攻击者只需诱导受害者浏览器发请求，读取面高、写入面无。
_CORS_GLOBAL = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 规范：向上取到一位小数。"""
    return math.ceil(round(x, 6) * 10) / 10


def _severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def compute_cvss31(category: str, unit: str = "",
                   is_global_config: bool = False) -> dict:
    """返回 {score, vector, severity}；category 不在表内走默认向量。"""
    cat = (category or "").lower()
    vec = _VECTORS.get(cat, _DEFAULT)
    if cat == "cors" and is_global_config:
        vec = _CORS_GLOBAL
    p = {}
    for part in vec.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            p[k] = v
    changed = p.get("S") == "C"
    iss = 1.0 - ((1.0 - _CIA[p["C"]]) * (1.0 - _CIA[p["I"]])
                 * (1.0 - _CIA[p["A"]]))
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_C if changed else _PR_U)[p["PR"]]
    exploit = 8.22 * _AV[p["AV"]] * _AC[p["AC"]] * pr * _UI[p["UI"]]
    if impact <= 0:
        raw = 0.0
    elif changed:
        raw = min(1.08 * (impact + exploit), 10.0)
    else:
        raw = min(impact + exploit, 10.0)
    score = _roundup(raw)
    return {"score": score, "vector": f"CVSS:3.1/{vec}",
            "severity": _severity(score)}
