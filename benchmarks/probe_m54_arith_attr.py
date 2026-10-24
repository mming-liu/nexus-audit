"""M54 arithmetic 93 条误报的分支归因探针（只读）。"""
import re, sys, json
from collections import Counter
sys.path.insert(0, ".")
from core.agents.rule_detectors import (
    solidity_arithmetic_verdict, _sol_pragma_major, _sol_param_names,
    _ARITH_OP_ASSIGN_RE, _ARITH_BINOP_RE, _ARITH_CALLARG_RE,
    _ARITH_GUARD_RE, _SAFE_MATH_RE, _UNCHECKED_RE, _split_sol_modifier_block,
)
from benchmarks.benchmark_gptscan import DEFAULT_TARGET
from benchmarks.slice_cache import cached_units
from core.slicer.web3_slither import SoliditySlicer

repo = DEFAULT_TARGET
slicer = SoliditySlicer(repo)
units = cached_units(repo, "gptscan-top200",
                     lambda: slicer.extract_entry_units(repo))
print(f"units: {len(units)}")

attr = Counter()
samples = {}
for u in units:
    src = u.source_code
    v = solidity_arithmetic_verdict(src)
    if v is not True:
        continue
    func_src, mod = _split_sol_modifier_block(src)
    body = re.sub(r"//[^\n]*", "", func_src)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    major = _sol_pragma_major(src)
    params = _sol_param_names(func_src)
    vm = re.search(r"function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*([^{;]*)", func_src)
    vis = "default"
    if vm:
        mods = vm.group(1)
        for kw in ("public", "internal", "private", "external"):
            if re.search(rf"\b{kw}\b", mods):
                vis = kw; break
    # 逐表达式找未保护的
    reasons = []
    for m in _ARITH_OP_ASSIGN_RE.finditer(body):
        lhs, op, rhs = m.group(1).strip(), m.group(2), m.group(3).strip()
        if not any(re.search(rf"\b{re.escape(p)}\b", rhs) for p in params):
            continue
        reasons.append(("opassign", op, lhs, rhs))
    for m in _ARITH_BINOP_RE.finditer(body):
        reasons.append(("binop", m.group(2), m.group(1), m.group(3)))
    for m in _ARITH_CALLARG_RE.finditer(body):
        reasons.append(("callarg", m.group(2), "", m.group(1)))
    # 哪些表达式没被 guard 盖住
    guards = set()
    for gm in _ARITH_GUARD_RE.finditer(body):
        for g in gm.groups():
            if g: guards.add(g.strip())
    checked = set()
    for rm in re.finditer(r"(?:require|assert)\s*\(([^;()]*)\)", body):
        arg = rm.group(1)
        if re.search(r"[-+*/]|\|\||&&", arg):
            checked.update(re.findall(r"\b([A-Za-z_]\w*)\b", arg))
    safemath = bool(_SAFE_MATH_RE.search(body))
    unchecked = bool(_UNCHECKED_RE.search(body))
    unprotected = []
    for kind, op, lhs, rhs in reasons:
        base = lhs.split("[")[0].strip() if lhs else ""
        prot = base and (base in guards or lhs in guards)
        if not prot and base and not (kind == "opassign") and base in checked:
            prot = True
        if not prot and safemath and not lhs:
            prot = True
        if not prot:
            unprotected.append((kind, op, lhs, rhs))
    if not unprotected:
        attr["no-unprot-but-True"] += 1
        continue
    kind, op, lhs, rhs = unprotected[0]
    # 归因
    if vis in ("internal", "private"):
        key = f"vis_{vis}"
    elif unchecked:
        key = "unchecked_block"
    elif major == 8:
        key = "major8_no_unchecked_block"
    elif safemath:
        key = "safemath_partial"
    else:
        key = f"other_{kind}"
    attr[key] += 1
    samples.setdefault(key, (f"{u.file_path}:{u.unit_name}", vis, major, op, lhs, rhs))

for k, c in attr.most_common():
    print(f"{c:5d}  {k}")
print("\n--- 样本 ---")
for k, (uid, vis, major, op, lhs, rhs) in samples.items():
    print(f"{k}: {uid} vis={vis} maj={major} [{lhs}] {op} [{rhs}]")
