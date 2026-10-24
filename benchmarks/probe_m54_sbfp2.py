"""M54：只 dump smartbugs unchecked 真值文件中"含 call/send 但 truth=False"的单元。"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import verdict as rule_verdict

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "unchecked_low_level_calls")
out = []
n = 0
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "unchecked_low_level_calls" for l in v["lines"]}
    if not vul:
        continue
    truth = any(u.start_line <= l <= u.end_line for l in vul)
    if truth:
        continue
    src = u.source_code
    if not re.search(r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(", src):
        continue
    n += 1
    out.append("### %s :: %s  lines=%d-%d  vul_lines=%s  rule=%s" % (
        Path(u.file_path).name, u.unit_name, u.start_line, u.end_line,
        sorted(vul), rule_verdict("unchecked_low_level_calls", src)))
    out.append(src)
    out.append("")
Path(ROOT / "benchmarks" / "results" / "m54_sb_unc_fp.txt").write_text(
    "\n".join(out), encoding="utf-8")
print("safe-with-call units:", n)
