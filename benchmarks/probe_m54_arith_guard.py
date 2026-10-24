"""看 19 条 other_opassign 误报的守卫形态（只读）。"""
import re, sys
sys.path.insert(0, ".")
from core.agents.rule_detectors import (
    solidity_arithmetic_verdict, _sol_pragma_major, _sol_param_names,
    _ARITH_OP_ASSIGN_RE, _ARITH_GUARD_RE, _split_sol_modifier_block,
)
from benchmarks.benchmark_gptscan import DEFAULT_TARGET
from benchmarks.slice_cache import cached_units
from core.slicer.web3_slither import SoliditySlicer

repo = DEFAULT_TARGET
slicer = SoliditySlicer(repo)
units = cached_units(repo, "gptscan-top200", lambda: slicer.extract_entry_units(repo))

n = 0
for u in units:
    src = u.source_code
    if solidity_arithmetic_verdict(src) is not True:
        continue
    func_src, _ = _split_sol_modifier_block(src)
    body = re.sub(r"//[^\n]*", "", func_src)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    major = _sol_pragma_major(src)
    params = _sol_param_names(func_src)
    vm = re.search(r"function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*([^{;]*)", func_src)
    vis = "default"
    if vm:
        for kw in ("public", "internal", "private", "external"):
            if re.search(rf"\b{kw}\b", vm.group(1)):
                vis = kw; break
    if vis in ("internal", "private"):
        continue
    uns = []
    for m in _ARITH_OP_ASSIGN_RE.finditer(body):
        lhs, op, rhs = m.group(1).strip(), m.group(2), m.group(3).strip()
        if not any(re.search(rf"\b{re.escape(p)}\b", rhs) for p in params):
            continue
        uns.append((lhs, op, rhs))
    if not uns:
        continue
    n += 1
    guards = [gm.group(0) for gm in _ARITH_GUARD_RE.finditer(body)]
    print(f"=== {u.file_path}:{u.unit_name} maj={major} vis={vis}")
    for lhs, op, rhs in uns[:2]:
        print(f"  EXPR: [{lhs}] {op} [{rhs}]")
    # 全部 require / if 行（找漏掉的守卫形态）
    for line in body.splitlines():
        l = line.strip()
        if re.search(r"\b(require|assert|if)\b", l) and re.search(r"[<>]|[-+*/]", l):
            print(f"  GUARD?: {l[:140]}")
print(f"\n共 {n} 条 external/default 误报")
