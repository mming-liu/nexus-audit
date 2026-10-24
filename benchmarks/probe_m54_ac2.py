"""M54：验证 access_control 四条根因的证据可得性。"""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.slicer.web3_slither import SoliditySlicer
from benchmarks.slice_cache import cached_units

GP = ROOT / "reference_repos" / "GPTScan-Top200-dev"
units = cached_units(GP, "gptscan-top200", lambda: SoliditySlicer(GP).extract_entry_units(GP))
want = {"zDestroy", "zTransferByAdmin", "transferOwnership", "transferFrom"}
seen = 0
for u in units:
    if u.unit_name not in want:
        continue
    src = u.source_code
    if "Bora20v2" not in u.file_path and "MANAToken" not in u.file_path and "MXToken" not in u.file_path:
        continue
    seen += 1
    if seen > 6:
        break
    print("=" * 78)
    print("%s :: %s" % (Path(u.file_path).name, u.unit_name))
    for sep in ("// ---- 修饰符定义（本合约，供核验）----",
                "// ---- 父合约继承证据 [", "// ---- 父合约函数证据 [",
                "// ---- 同文件辅助函数证据 ["):
        p = src.find(sep)
        if p >= 0:
            print("  >> %s @ %d" % (sep, p))
    print("  --- full src (first 2200) ---")
    print(src[:2200])
