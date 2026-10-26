"""aave/aave-v3-periphery —— 第 46 仓（Solidity #15），M202。

Aave V3 外围合约。基准排除 mocks/ 与 test/，并单独排除
WrappedTokenGatewayV3（aWETH.transferFrom 失败会 revert，unchecked 返回值
不构成可利用面）。剩余 139 个生产入口里，Collector.transfer 是**已知真阳性**
（裸 ERC20 transfer 未检查返回值），其余 0 True；补丁 #30 必须把它翻 False。
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web3_slither import SoliditySlicer
import cli
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "aave-v3-periphery" / "contracts"
CATS = ("access_control", "reentrancy", "delegatecall_untrusted",
        "unchecked_erc20_return", "oracle_stale_price")
EXCLUDE = {"WrappedTokenGatewayV3.sol"}

def main() -> int:
    ap = argparse.ArgumentParser(description="aave-v3-periphery 基准（M202）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "aavev3_periphery.json"))
    a = ap.parse_args(); repo = Path(a.target)
    if not repo.exists(): print(f"! 找不到 {repo}"); return 2
    units = [u for u in SoliditySlicer(repo).extract_entry_units(repo)
             if "/mocks/" not in u.file_path.replace("\\", "/")
             and "/test/" not in u.file_path.replace("\\", "/")
             and Path(u.file_path).name not in EXCLUDE]
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    known = {("transfer", "unchecked_erc20_return")}
    unknown = [r for r in true_rows if r not in known]
    coll = next((u for u in units if u.unit_name == "transfer"
                 and Path(u.file_path).name == "Collector.sol"), None)
    lines: list = []
    patched = cli._fix_solidity_erc20_return(repo, [coll], lines) if coll else 0
    print(f"切片 {len(units)} / True {len(true_rows)} / 已知真阳性 {len(known)} / 补丁 {patched}")
    bad = []
    if len(units) < 120: bad.append(f"切片 {len(units)} < 120")
    if unknown: bad.append(f"计划外 True: {unknown[:5]}")
    if patched != 1: bad.append(f"Collector.transfer 补丁自检 {patched}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "true": len(true_rows),
                               "known_true": sorted(known), "unknown": unknown,
                               "patch_verified": patched, "fp": len(unknown),
                               "pass": not bad}, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 入口 / 计划外 True 0 / 已知真阳性 1 / 补丁 True->False）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
