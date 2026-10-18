"""离线基线：纯 sink 关键词匹配（不调用任何 LLM）。

用途：作为 LLM 两步法的对照组。如果 LLM 的 BenchmarkScore 不比这个高，
说明引入模型没有产生实际增益，需要回头查切片与 prompt。

注意：这是刻意做"笨"的基线 —— 只看危险汇聚点是否存在，完全不做净化判断，
因此它的 TPR 会较高、FPR 会非常高（这是对照组该有的样子）。
"""
from __future__ import annotations

import re

# 每类漏洞的危险汇聚点正则
SINK_PATTERNS: dict[str, list[str]] = {
    "sqli": [r"\.execute(Query|Update)?\s*\(", r"createStatement\s*\("],
    "cmdi": [r"Runtime\.getRuntime\(\)\.exec\s*\(", r"new\s+ProcessBuilder\s*\("],
    "xss": [r"getWriter\(\)\s*\.\s*print(ln)?\s*\("],
    "pathtraver": [r"new\s+FileInputStream\s*\(", r"new\s+FileOutputStream\s*\(",
                   r"Files\.(read|write|newInputStream)"],
    "weakrand": [r"new\s+(java\.util\.)?Random\s*\(", r"Math\.random\s*\("],
    "securecookie": [r"new\s+(javax\.servlet\.http\.)?Cookie\s*\("],
    "trustbound": [r"\.setAttribute\s*\("],
    "hash": [r"MessageDigest\.getInstance\s*\("],
    "crypto": [r"Cipher\.getInstance\s*\("],
    "ldapi": [r"\.search\s*\("],
    "xpathi": [r"\.evaluate\s*\(", r"XPathExpression"],
}


def offline_predict(source: str, category: str) -> bool:
    """命中任一 sink 即判定为该类漏洞（无净化判断）。"""
    for pat in SINK_PATTERNS.get(category, []):
        if re.search(pat, source):
            return True
    return False
