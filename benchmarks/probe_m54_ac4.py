"""M54：access_control 剩余误报逐条 dump（按函数分组）。"""
from __future__ import annotations
import sys
from collections import defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import (
    verdict as rule_verdict, _split_sol_sections)
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))

want = set(sys.argv[1:]) if len(sys.argv) > 1 else None
out = []
by_fn = defaultdict(list)
for u in units:
    if rule_verdict("access_control", u.source_code) is not True:
        continue
    by_fn[u.unit_name].append(u)

for fn, us in sorted(by_fn.items()):
    if want and fn not in want:
        continue
    out.append("#" * 78)
    out.append("### %s  x%d" % (fn, len(us)))
    for u in us:
        out.append("-" * 70)
        out.append("FILE: %s" % Path(u.file_path).name)
        func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
        out.append("--- func_src ---")
        out.append(func_src[:1200])
        out.append("--- mod_ev ---")
        out.append((mod_ev or "(空)")[:800])
        out.append("--- func_ev ---")
        out.append((func_ev or "(空)")[:1200])
    out.append("")

Path(ROOT / "benchmarks" / "results" / "m54_ac_detail.txt").write_text(
    "\n".join(out), encoding="utf-8")
for fn, us in sorted(by_fn.items()):
    print("%-36s %d" % (fn, len(us)))
