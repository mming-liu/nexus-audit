"""M54：调试 modifier 调用链身份检查（C 分支）为何没命中。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import (
    _split_sol_sections, _SOL_IDENTITY_FUNC_BODY_RE, _SOL_COMPARE_CALL_RE,
    _SOL_COMPARE_CALL_RE2, _sol_modifier_callees, _sol_func_body_by_name,
    _sol_indirect_identity_check)
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200",
                     lambda: SoliditySlicer(GP).extract_entry_units(GP))
n = 0
for u in units:
    if u.unit_name != "transferOwnership":
        continue
    if Path(u.file_path).name not in {"Ownable.sol", "Bora20v2.sol"}:
        continue
    func_src, mod_ev, func_ev = _split_sol_sections(u.source_code)
    own = func_src + "\n" + mod_ev
    evid = own + "\n" + func_ev
    idfns = {m.group(1) for m in _SOL_IDENTITY_FUNC_BODY_RE.finditer(evid)}
    callees = _sol_modifier_callees(mod_ev)
    print("=" * 70)
    print(Path(u.file_path).name, "| contract:",
          re.search(r"contract:\s*(\S+)", func_src).group(1))
    print("  identity_funcs =", idfns)
    print("  modifier callees =", callees)
    for f in callees:
        body = _sol_func_body_by_name(evid, f)
        print("  callee %-14s body found=%s" % (f, bool(body)))
        if body:
            for pat in (_SOL_COMPARE_CALL_RE, _SOL_COMPARE_CALL_RE2):
                for m in pat.finditer(body):
                    print("     %s -> group1=%r in_idfns=%s | %s"
                          % (pat.pattern[:24], m.group(1),
                             m.group(1) in idfns,
                             m.group(0)[:70].replace("\n", " ")))
    print("  indirect_identity_check =",
          _sol_indirect_identity_check(func_src, mod_ev, func_ev))
    n += 1
    if n >= 3:
        break
