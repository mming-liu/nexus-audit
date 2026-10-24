"""M54：验证 super.X 委托的父合约实现体是否进了证据段。"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import _split_sol_sections
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200",
                     lambda: SoliditySlicer(GP).extract_entry_units(GP))
targets = {"MANAToken.sol", "WBTC.sol", "chiliZ.sol", "FantomToken.sol"}
n = 0
for u in units:
    if Path(u.file_path).name not in targets:
        continue
    if u.unit_name != "transferFrom":
        continue
    _f, _m, func_ev = _split_sol_sections(u.source_code)
    print("=" * 70)
    print(Path(u.file_path).name, u.unit_name)
    print(func_ev[:900] or "(空)")
    n += 1
    if n >= 4:
        break
