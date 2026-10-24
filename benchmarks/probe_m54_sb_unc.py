"""M54：smartbugs unchecked 真值形态普查 —— 定"消费"口径的锚点。"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "unchecked_low_level_calls")
out = []
shapes = {}
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "unchecked_low_level_calls" for l in v["lines"]}
    if not vul:
        continue
    truth = any(u.start_line <= l <= u.end_line for l in vul)
    src = u.source_code
    for i, ln in enumerate(src.splitlines()):
        if re.search(r"\.\s*call\s*(?:\{|\.|\()|\.\s*send\s*\(", ln):
            shape = "裸调用"
            if re.search(r"\(\s*bool\s+\w+", ln) or re.search(r"=\s*\w+\.call", ln):
                shape = "赋值"
            if re.search(r"return\s*\(", ln):
                shape = "透传返回"
            if re.search(r"if\s*\(", ln):
                shape = "if条件"
            shapes.setdefault((truth, shape), []).append(
                "%s::%s | %s" % (Path(u.file_path).name, u.unit_name, ln.strip()[:110]))
            break
Path(ROOT / "benchmarks" / "results" / "m54_sb_unc_shapes.txt").write_text(
    "\n\n".join("### truth=%s shape=%s  (n=%d)\n" % (t, s, len(v))
                + "\n".join("    " + x for x in v)
                for (t, s), v in sorted(shapes.items())), encoding="utf-8")
for (t, s), v in sorted(shapes.items()):
    print("truth=%-5s shape=%-8s n=%d" % (t, s, len(v)))
