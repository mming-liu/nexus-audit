"""M54 特征探针：对比 smartbugs 真阳（arithmetic vul）与 Top200 误报的形态。

**为什么需要**：两个门禁方向相反（smartbugs 要判 True / Top200 判 True 即误报），
共用同一批规则。改规则前必须先看清"哪些形态是真阳、哪些形态是误报"，
否则修一边崩另一边。本探针把两边按**机制特征**并排列出：

    · 函数可见性（public/external vs internal/private/pure）
    · pragma 主版本（0.4~0.7 无检查 vs 0.8+ 内置回滚）
    · 算术落点（状态写 vs 纯局部）
    · 溢出证明形态（前置比较 / 后置回验 / SafeMath / 无）
    · 合约级聚合上限（totalSupply 类）

用法：python benchmarks/probe_m54_shapes.py [arithmetic]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402

SB_REPO = ROOT / "reference_repos" / "smartbugs-curated-main"
GP_REPO = ROOT / "reference_repos" / "GPTScan-Top200-dev"

# 合约级"聚合上限"标识：ERC20 总供应量 / 铸币上限 —— 有它，余额累加就不可能
# 溢出（余额总和被总供应量封顶）。这是**机制**（总量守恒）不是类目。
_AGG_RE = re.compile(r"\b_?total_?supply\b|\b_?totalSupply\b|\bsupply\b", re.I)


def _feat(src: str, whole_file: str) -> tuple:
    sig = ""
    m = re.search(r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)", src)
    if m:
        sig = m.group(0)
    vis = ("internal" if re.search(r"\binternal\b", sig) else
           "private" if re.search(r"\bprivate\b", sig) else
           "public" if re.search(r"\bpublic\b", sig) else
           "external" if re.search(r"\bexternal\b", sig) else "default")
    pure = bool(re.search(r"\b(?:pure|view|constant)\b", sig))
    pm = re.search(r"pragma:\s*solidity\s*([^;]+);", src)
    pv = pm.group(1).strip() if pm else "?"
    vm = re.search(r"(\d+)\.(\d+)", pv)
    major = int(vm.group(2)) if vm and int(vm.group(1)) == 0 else (
        int(vm.group(1)) if vm else None)
    body = re.sub(r"//[^\n]*", "", src)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    has_unchecked = bool(re.search(r"\bunchecked\s*\{", body))
    safemath = bool(re.search(r"\.\s*(?:add|sub|mul|div)\s*\(", body))
    # 状态写 vs 纯局部：映射下标写 / 标量写
    mapwrite = bool(re.search(r"\w\s*\[[^\]]*\]\s*[-+*/]?=", body))
    scalwrite = bool(re.search(r"(?<![\w.])([A-Za-z_]\w*)\s*[-+*/]?=(?!=)", body))
    agg = bool(_AGG_RE.search(whole_file))
    return (vis, "pure" if pure else "impure",
            f"0x{major}" if major is not None else "?", 
            "unchecked" if has_unchecked else "-",
            "safemath" if safemath else "-",
            "mapw" if mapwrite else "-",
            "scalw" if scalwrite else "-",
            "agg" if agg else "-")


def main() -> None:
    cat = sys.argv[1] if len(sys.argv) > 1 else "arithmetic"

    # ---- smartbugs 真阳 ----
    meta = {Path(x["path"]).name: x
            for x in json.loads((SB_REPO / "vulnerabilities.json")
                                .read_text(encoding="utf-8"))}
    slicer = SoliditySlicer(SB_REPO)
    sb_pos = []
    for u in slicer.extract_entry_units(SB_REPO / "dataset" / cat):
        entry = meta.get(Path(u.file_path).name)
        if not entry:
            continue
        vl = {l for v in entry["vulnerabilities"]
              if v["category"] == cat for l in v["lines"]}
        if not vl:
            continue
        truth = any(u.start_line <= l <= u.end_line for l in vl)
        if truth and rule_verdict(cat, u.source_code) is True:
            whole = Path(u.file_path).read_text(encoding="utf-8", errors="ignore")
            sb_pos.append((Path(u.file_path).name, u.unit_name,
                           _feat(u.source_code, whole)))

    # ---- Top200 误报 ----
    gp_units = SoliditySlicer(GP_REPO).extract_entry_units(GP_REPO)
    gp_neg = []
    file_cache: dict[str, str] = {}
    for u in gp_units:
        if rule_verdict(cat, u.source_code) is not True:
            continue
        p = str(u.file_path)
        if p not in file_cache:
            try:
                file_cache[p] = Path(p).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                file_cache[p] = ""
        gp_neg.append((Path(p).name, u.unit_name,
                       _feat(u.source_code, file_cache[p])))

    print(f"类目 {cat}：smartbugs 真阳 {len(sb_pos)} 条 / Top200 误报 {len(gp_neg)} 条")
    print("\n--- smartbugs 真阳 形态 ---")
    for f, n, ft in sb_pos:
        print(f"  {f[:34]:36} {n[:24]:26} {' '.join(ft)}")
    print("\n--- Top200 误报 形态（按特征聚类）---")
    cl = Counter(ft for _f, _n, ft in gp_neg)
    for ft, n in cl.most_common():
        print(f"  {n:>4}  {' '.join(ft)}")
    print("\n--- Top200 误报 形态（逐条）---")
    for f, n, ft in gp_neg:
        print(f"  {f[:34]:36} {n[:24]:26} {' '.join(ft)}")


if __name__ == "__main__":
    main()
