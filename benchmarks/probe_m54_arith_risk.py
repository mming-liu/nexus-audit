"""M54 arithmetic 三处改动的判反锚点（只读）：
A) internal/private 真阳条数
B) 回卷校验形态（A + B >= A）真阳条数
C) 槽位加法（X[k] += param）真阳条数与明细
D) 关键字左值（now 等）真阳条数
"""
import re, sys, json
from pathlib import Path
sys.path.insert(0, ".")
from core.agents.rule_detectors import (
    solidity_arithmetic_verdict, _sol_pragma_major, _sol_param_names,
    _ARITH_OP_ASSIGN_RE, _split_sol_modifier_block,
)
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

REPO = Path("reference_repos/smartbugs-curated-main")
meta = {Path(x["path"]).name: x
        for x in json.loads((REPO / "vulnerabilities.json").read_text(encoding="utf-8"))}
slicer = SoliditySlicer(REPO)
CAT = "arithmetic"
units = slicer.extract_entry_units(REPO / "dataset" / CAT)

n_true = 0
for u in units:
    entry = meta.get(Path(u.file_path).name)
    if not entry:
        continue
    vul_lines = {l for v in entry["vulnerabilities"] if v["category"] == CAT
                 for l in v["lines"]}
    if not vul_lines or not any(u.start_line <= l <= u.end_line for l in vul_lines):
        continue
    src = u.source_code
    if solidity_arithmetic_verdict(src) is not True:
        continue
    n_true += 1
    func_src, _ = _split_sol_modifier_block(src)
    body = re.sub(r"//[^\n]*", "", func_src)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    vm = re.search(r"function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*([^{;]*)", func_src)
    vis = "default"
    if vm:
        for kw in ("public", "internal", "private", "external"):
            if re.search(rf"\b{kw}\b", vm.group(1)):
                vis = kw; break
    params = _sol_param_names(func_src)
    slot_add = [m.group(1).strip() for m in _ARITH_OP_ASSIGN_RE.finditer(body)
                if "+" in m.group(2) and "[" in m.group(1)
                and any(re.search(rf"\b{re.escape(p)}\b", m.group(3)) for p in params)]
    wrap = re.findall(r"[\w.\[\]]+\s*\+\s*[\w.\[\]]+\s*(?:>=|>)\s*[\w.\[\]]+", body)
    print(f"{Path(u.file_path).name}:{u.unit_name} vis={vis} slot_add={slot_add} wrap={wrap}")
print(f"真阳总数 {n_true}")
