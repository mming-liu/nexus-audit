"""M54：验证 access_control 四条根因的证据可得性（精确版）。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents.rule_detectors import _split_sol_sections
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))
targets = [("Bora20v2.sol", "zDestroy"), ("Bora20v2.sol", "zTransferByAdmin"),
           ("MANAToken.sol", "transferFrom"), ("MXToken.sol", "transferFrom"),
           ("BridgeToken.sol", "unwrap")]
for fn, uname in targets:
    for u in units:
        if Path(u.file_path).name != fn or u.unit_name != uname:
            continue
        src = u.source_code
        func_src, mod_ev, func_ev = _split_sol_sections(src)
        print("=" * 78)
        print("%s :: %s" % (fn, uname))
        print("--- mod_ev (本合约modifier段) ---")
        print(mod_ev[:600])
        print("--- func_ev 段头 ---")
        for m in re.finditer(r"// ---- [^\n]*", func_ev):
            print("   ", m.group(0))
        # 父合约继承证据段在 func_ev 里
        p = func_ev.find("// ---- 父合约继承证据 [")
        if p >= 0:
            print("--- 父合约继承证据段 ---")
            print(func_ev[p:p + 700])
        break
