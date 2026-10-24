"""M54：access_control 最后 4 条的**判反风险锚点** —— 委托形态早退。

拟新增早退：函数把 `from` 的转出**委托**给本切片看不见的实现
（`super.transferFrom(...)` 解析不到 / `X.transferFrom(...)` 外部合约），
按"缺证退 None"铁律不判 True。

**判反风险**：smartbugs access_control 真阳里若出现这种形态，
早退会把真阳判成 None（退回）—— 那是覆盖率损失而非判反，
但仍需先确认形态分布。
"""
from __future__ import annotations
import json, re, sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import _split_sol_sections

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "access_control")

SUPER_FROM = re.compile(r"\bsuper\s*\.\s*(?:transferFrom|_transfer|_safeTransfer)"
                         r"\s*\(\s*_?from\b")
EXT_FROM = re.compile(r"\b[A-Za-z_]\w*\s*\.\s*(?:transferFrom|_transfer|_safeTransfer)"
                       r"\s*\(\s*_?from\b")
LOCAL_FROM = re.compile(r"(?<![.\w])(?:_?transferFrom|_transfer|_safeTransfer)"
                         r"\s*\(\s*_?from\b")


def scan(units, label, truth_only):
    cnt = Counter()
    detail = []
    for u in units:
        entry = meta.get(Path(u.file_path).name)
        if entry:
            vul = {l for v in entry["vulnerabilities"]
                   if v["category"] == "access_control" for l in v["lines"]}
            truth = bool(vul) and any(u.start_line <= l <= u.end_line
                                      for l in vul)
        else:
            truth = False
        if truth_only and not truth:
            continue
        func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
        evid = func_src + "\n" + mod_ev + "\n" + func_ev
        # 有 from 形参？
        if not re.search(r"address\s+(?:payable\s+)?_?from\b", func_src):
            continue
        if SUPER_FROM.search(func_src):
            cnt["super"] += 1
            detail.append(("super", Path(u.file_path).name, u.unit_name,
                           bool(re.search(r"function\s+transferFrom\s*\(", evid))))
        elif EXT_FROM.search(func_src):
            cnt["ext"] += 1
            detail.append(("ext", Path(u.file_path).name, u.unit_name,
                           bool(re.search(r"function\s+transferFrom\s*\(", evid))))
        elif LOCAL_FROM.search(func_src):
            cnt["local"] += 1
            detail.append(("local", Path(u.file_path).name, u.unit_name,
                           bool(re.search(r"function\s+transferFrom\s*\(", evid))))
    print("[%s] %s" % (label, dict(cnt)))
    for d in detail[:20]:
        print("    %-6s %-30s %-24s 可见实现体=%s" % d)
    return cnt


print("=== smartbugs access_control 真阳单元 ===")
c_truth = scan(units, "真阳", True)
print()
print("=== smartbugs access_control 全部单元 ===")
c_all = scan(units, "全部", False)
print()
print("锚点结论：真阳里 super/ext 委托形态若为 0 ⇒ 新早退不损失真阳覆盖。")
print("真阳计数：", dict(c_truth))
