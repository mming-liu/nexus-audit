"""M54 误报模式聚类：Top200 纯负样本集上的 341 条误报，按机制归类。

用法：python benchmarks/probe_m54_fp.py [类目]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402

REPO = ROOT / "reference_repos" / "GPTScan-Top200-dev"
CATEGORIES = ["reentrancy", "access_control", "unchecked_low_level_calls",
              "arithmetic"]


def main() -> None:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cats = [only] if only else CATEGORIES
    slicer = SoliditySlicer(REPO)
    units = slicer.extract_entry_units(REPO)
    print(f"切片单元 {len(units)}")

    for cat in cats:
        fps = []
        for u in units:
            if rule_verdict(cat, u.source_code) is True:
                fps.append(u)
        print(f"\n{'=' * 70}\n{cat}: 误报 {len(fps)} 条\n{'=' * 70}")
        # 聚类：按函数名 + 关键形态
        by_fn = Counter(u.unit_name for u in fps)
        print("  按函数名 Top 15：")
        for fn, n in by_fn.most_common(15):
            print(f"    {fn:34} {n}")
        # 形态聚类
        shapes = Counter()
        for u in fps:
            src = u.source_code or ""
            body = re.sub(r"//[^\n]*", "", src)
            if cat == "arithmetic":
                pm = re.search(r"pragma:\s*solidity\s*([^;]+);", src)
                pv = pm.group(1) if pm else "?"
                has_safemath = bool(re.search(r"\.\s*(?:add|sub|mul|div)\s*\(", body))
                unguarded = "unchecked" in body
                shapes[(f"pragma={pv[:12]}", f"safemath={has_safemath}",
                        f"unchecked={unguarded}")] += 1
            elif cat == "access_control":
                pm = re.search(r"pragma:\s*solidity\s*([^;]+);", src)
                pv = pm.group(1) if pm else "?"
                has_own = bool(re.search(r"onlyOwner|_owner|owner\s*==", body))
                shapes[(f"pragma={pv[:12]}", f"owner词={has_own}")] += 1
            elif cat == "unchecked_low_level_calls":
                has_func = bool(re.search(r"functionCallWithValue|\.functionCall\b", body))
                has_addr = bool(re.search(r"Address\.|address\s*\(", body))
                shapes[(f"functionCall={has_func}", f"Address={has_addr}")] += 1
        print("  按形态：")
        for k, n in shapes.most_common(12):
            print(f"    {k} → {n}")

        # 打印 3 个完整样本
        for u in fps[:3]:
            print(f"\n  ---- 样本 {Path(u.file_path).name}:{u.unit_name} "
                  f"(L{u.start_line}-{u.end_line}) ----")
            print("\n".join("    " + x for x in (u.source_code or "").splitlines()[:70]))


if __name__ == "__main__":
    main()
