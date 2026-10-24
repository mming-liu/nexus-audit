"""M54 误报样本转储器：按类目导出全部误报单元的切片源码。

用法：python benchmarks/probe_m54_dump.py <category> [max]
输出到 benchmarks/results/m54_fp_<cat>.txt
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402

REPO = ROOT / "reference_repos" / "GPTScan-Top200-dev"


def main() -> None:
    cat = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    slicer = SoliditySlicer(REPO)
    units = slicer.extract_entry_units(REPO)
    fps = [u for u in units if rule_verdict(cat, u.source_code) is True]
    print(f"{cat}: 误报 {len(fps)}")

    by_fn = Counter(u.unit_name for u in fps)
    print("按函数名：")
    for fn, n in by_fn.most_common(40):
        print(f"  {fn:36} {n}")

    out = ROOT / "benchmarks" / "results" / f"m54_fp_{cat}.txt"
    lines = []
    for i, u in enumerate(fps):
        if limit and i >= limit:
            break
        lines.append("=" * 78)
        lines.append(f"[{i}] {Path(u.file_path).name}:{u.unit_name} "
                     f"L{u.start_line}-{u.end_line}  proj={u.file_path}")
        lines.append("=" * 78)
        lines.append(u.source_code or "")
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"转储 {min(limit or len(fps), len(fps))} 条 → {out}")


if __name__ == "__main__":
    main()
