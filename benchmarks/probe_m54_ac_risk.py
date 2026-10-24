"""M54：access_control 判反风险锚点 —— smartbugs 真阳单元在四种形态上的样子。"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from core.agents.rule_detectors import (
    _split_sol_sections, _SOLIDITY_OWNERISH_RE, _SOL_ALLOWANCE_WRITE_RE)

SB = ROOT / "reference_repos" / "smartbugs-curated-main"
meta = {Path(x["path"]).name: x
        for x in json.loads((SB / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(SB)
units = slicer.extract_entry_units(SB / "dataset" / "access_control")
print("### smartbugs access_control 真阳单元里的 owner 写形态")
n = 0
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "access_control" for l in v["lines"]}
    if not vul:
        continue
    if not any(u.start_line <= l <= u.end_line for l in vul):
        continue
    func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
    for m in _SOLIDITY_OWNERISH_RE.finditer(func_src):
        head = func_src[:m.start()]
        toks = re.findall(r"[A-Za-z_]\w*", head)
        typ = toks[-1] if toks else ""
        s = max(0, m.start() - 70); e = min(len(func_src), m.end() + 30)
        print("  [%s] lefttok=%-12s | %s" % (u.unit_name, typ,
              func_src[s:e].replace("\n", " | ")))
        n += 1
        break
print("  合计", n)
print()
print("### smartbugs access_control 真阳单元里的 tx.origin 形态")
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul = {l for v in entry["vulnerabilities"]
           if v["category"] == "access_control" for l in v["lines"]}
    if not vul or not any(u.start_line <= l <= u.end_line for l in vul):
        continue
    func_src, _m, _f = _split_sol_sections(u.source_code)
    for mm in re.finditer(r"(?:require|if)\s*\([^;]{0,120}?\btx\s*\.\s*origin\s*==[^)]*\)",
                          func_src):
        print("  [%s] %s" % (u.unit_name, mm.group(0).replace("\n", " ")))
print()
print("### smartbugs access_control 全部单元里的 allowance 形态")
for u in units:
    func_src, _m, _f = _split_sol_sections(u.source_code)
    for mm in _SOL_ALLOWANCE_WRITE_RE.finditer(func_src + "\n" + _m):
        print("  [%s] %s" % (u.unit_name, mm.group(0)))
