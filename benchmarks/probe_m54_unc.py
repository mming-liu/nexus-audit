"""M54 unchecked 误报形态探针：把每条 Top200 误报的调用点上下文打出来。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import verdict as rule_verdict
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))
out = []
for u in units:
    rv = rule_verdict("unchecked_low_level_calls", u.source_code)
    if rv is not True:
        continue
    src = u.source_code
    # 找调用点所在行 + 前后文
    lines = src.splitlines()
    for i, ln in enumerate(lines):
        if re.search(r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(", ln):
            lo, hi = max(0, i - 3), min(len(lines), i + 4)
            out.append("### %s :: %s (line %d)" % (Path(u.file_path).name, u.unit_name, i + 1))
            out.extend("    " + l for l in lines[lo:hi])
            # 证据段
            for sep in ("// ---- 父合约函数证据", "// ---- 同文件辅助函数证据", "// ---- 父合约继承证据"):
                p = src.find(sep)
                if p >= 0:
                    seg = src[p:p + 900]
                    out.append("    [证据] " + seg.replace("\n", "\n    "))
            out.append("")
            break
Path(ROOT / "benchmarks" / "results" / "m54_unc_probe.txt").write_text("\n".join(out), encoding="utf-8")
print("units with FP:", sum(1 for u in units if rule_verdict("unchecked_low_level_calls", u.source_code) is True))
print("blocks:", len(out))
