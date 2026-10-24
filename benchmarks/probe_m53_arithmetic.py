"""M53 探针：smartbugs dataset/arithmetic（15 合约，官方 @vulnerable_at_lines）。

先跑只读探针 + 反查真值，确认判据形态再落码。要回答的问题：

  1. 每个被官方标注的函数，其"算术表达式"长什么样（状态写 / 局部写 /
     映射写；右操作数是不是外部形参）？
  2. **safe 负样本**（同文件里官方没标的函数）长什么样 —— 它们和 vul 的
     机制差别在哪？（这是 0 误报的关键）
  3. pragma 版本分布：0.4.x 全部无内置溢出检查；0.8.x 内置回滚。

用法：python benchmarks/probe_m53_arithmetic.py
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.slicer.web3_slither import SoliditySlicer   # noqa: E402

REPO = ROOT / "reference_repos" / "smartbugs-curated-main"

_ARITH_OPS = ("+=", "-=", "*=", "/=")
# 算术表达式右操作数里出现形参名
_ARITH_STMT_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*)\s*(\+=|-=|\*=|/=)\s*([^;]+);")
# 纯表达式（无赋值）：`uint res = count - input;` 的右值
_BINOP_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*)\s*([-+*])\s*([A-Za-z_]\w*)\s*;")
_FUNC_PARAMS_RE = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")


def params_of(src: str) -> set[str]:
    m = _FUNC_PARAMS_RE.search(src)
    if not m:
        return set()
    out = set()
    for p in m.group(2).split(","):
        p = p.strip()
        if not p:
            continue
        parts = p.split()
        out.add(parts[-1])
    return out


def main() -> int:
    meta = {Path(x["path"]).name: x
            for x in json.loads((REPO / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(REPO)
    units = slicer.extract_entry_units(REPO / "dataset" / "arithmetic")
    print(f"切出函数 {len(units)} 个\n")

    stats = Counter()
    for u in units:
        fn = Path(u.file_path).name
        entry = meta.get(fn)
        if not entry:
            continue
        vul_lines = {l for v in entry["vulnerabilities"]
                     if v["category"] == "arithmetic" for l in v["lines"]}
        if not vul_lines:
            continue
        truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
        src = u.source_code or ""
        body = re.sub(r"//[^\n]*", "", src)
        params = params_of(src)
        has_state = bool(re.search(r"\w+\s*(?:\[[^\]]*\])?\s*\+=|\w+\s*(?:\[[^\]]*\])?\s*-=|"
                                   r"\w+\s*(?:\[[^\]]*\])?\s*\*=", body))
        arith_ops = [m.group(2) for m in _ARITH_STMT_RE.finditer(body)]
        binops = [(m.group(1), m.group(2), m.group(3))
                  for m in _BINOP_RE.finditer(body)]
        # 右操作数含形参？
        rhs_param = any(any(p in m.group(3) for p in params)
                        for m in _ARITH_STMT_RE.finditer(body))
        binop_param = any(any(p == c for p in params)
                          for _a, _op, c in binops)
        # 前置校验：require/assert 紧邻上方提到同一个左值
        guarded = bool(re.search(r"require\s*\([^;]*\b\w+\b[^;]*\)\s*;"
                                 r"\s*\w+\s*(?:\[[^\]]*\])?\s*[-+*]=",
                                 body))
        safe_math = bool(re.search(r"\.\s*(?:add|sub|mul|div)\s*\(", body))
        tag = "VUL " if truth else "safe"
        stats[f"{tag}/状态写" if has_state else f"{tag}/局部"] += 1
        stats[f"{tag}/形参右值" if (rhs_param or binop_param) else f"{tag}/非形参"] += 1
        print(f"[{tag}] {fn}:{u.unit_name} L{u.start_line}-{u.end_line} "
              f"ops={arith_ops} binops={binops} "
              f"params={sorted(params)} "
              f"状态写={has_state} 形参右值={rhs_param or binop_param} "
              f"前置校验={guarded} SafeMath={safe_math}")
        if truth:
            print("       " + " / ".join(
                l.strip() for l in src.splitlines() if l.strip())[:150])

    print("\n统计：")
    for k, v in sorted(stats.items()):
        print(f"  {k:24} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
