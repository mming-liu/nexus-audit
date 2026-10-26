"""transmissions11/solmate —— 第 42 仓（Solidity #14），M186。"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web3_slither import SoliditySlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "solmate" / "src"
CATS = ("access_control", "reentrancy", "unchecked_low_level_calls",
        "delegatecall_untrusted", "signature_replay",
        "unchecked_erc20_return", "oracle_stale_price")
_ANCHOR = '''pragma solidity ^0.8.0;
contract A { address owner;
  modifier requiresAuth() { require(msg.sender == owner, "x"); _; }
  function setOwner(address n) public requiresAuth { owner = n; } }'''

def main() -> int:
    ap = argparse.ArgumentParser(description="solmate 零误报基准（M186）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "solmate.json"))
    a = ap.parse_args()
    repo = Path(a.target)
    if not repo.exists():
        print(f"! 找不到 {repo}"); return 2
    units = [u for u in SoliditySlicer(repo).extract_entry_units(repo)
             if "/test/" not in u.file_path.replace("\\", "/")]
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    own = next((u for u in units if u.unit_name == "transferOwnership"), None)
    own_v = R.verdict("access_control", own.source_code) if own else None
    anchor = R.verdict("access_control", _ANCHOR)
    print(f"切片 {len(units)} / True {len(true_rows)} / Owned {own_v} / 锚点 {anchor}")
    bad = []
    if len(units) < 120: bad.append(f"切片 {len(units)} < 120")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if own_v is not False: bad.append(f"Owned.transferOwnership {own_v}")
    if anchor is not False: bad.append(f"requiresAuth 锚点失效 {anchor}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "true": len(true_rows),
                               "owned": own_v, "anchor": anchor,
                               "fp": len(true_rows), "pass": not bad},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 入口 / 0 True / Owned False）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
