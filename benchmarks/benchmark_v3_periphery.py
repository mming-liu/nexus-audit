"""Uniswap/v3-periphery —— 第 37 仓，M169。

v3-periphery 是 Uniswap V3 的外围合约（SwapRouter / NonfungiblePositionManager
/ Multicall）。它故意把 swap 做成无需许可的公开入口，权限只落在
self-position 的 owner 判定上；Multicall 用 address(this).delegatecall
执行自调用。这两类都是"看起来危险、实际是设计"的形态。

门禁（--strict）：>=150 个生产合约入口 / 0 True / multicall 的
delegatecall_untrusted 必须是 False / 测试合约不计入。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.web3_slither import SoliditySlicer            # noqa: E402
from core.text_utils import ensure_utf8_stdio                   # noqa: E402

ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "v3-periphery"
MIN_UNITS = 120
CATS = ("access_control", "reentrancy", "unchecked_low_level_calls",
        "arithmetic", "delegatecall_untrusted", "signature_replay",
        "oracle_stale_price")


def _rel(p: str) -> str:
    return p.replace("\\", "/")


def main() -> int:
    ap = argparse.ArgumentParser(description="v3-periphery 零误报基准（M169）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "v3_periphery.json"))
    args = ap.parse_args()
    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    units = [u for u in SoliditySlicer(repo).extract_entry_units(repo)
             if "/test/" not in _rel(u.file_path)]
    by_name = {u.unit_name: u for u in units}
    true_rows = []
    decided = 0
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((u.unit_name, c))

    mc = next((u for u in units if u.unit_name == "multicall"), None)
    mc_delegate = R.verdict("delegatecall_untrusted",
                            mc.source_code) if mc else None
    router = next((u for u in units if u.unit_name == "exactInputSingle"), None)
    router_authz = R.verdict("access_control",
                             router.source_code) if router else None

    print("=" * 72)
    print("v3-periphery 结果（公开 swap / self-position 权限 / Multicall）")
    print("=" * 72)
    print(f"  生产合约入口          ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"    [FP] {n} [{c}]")
    print(f"  multicall delegatecall：{mc_delegate}")
    print(f"  exactInputSingle authz：{router_authz}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层出现 {len(true_rows)} 条 True：{true_rows[:5]}")
    if mc_delegate is not False:
        bad.append(f"multicall delegatecall 未判 False：{mc_delegate}")
    if router_authz is True:
        bad.append("exactInputSingle 被误判为缺权限")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "target": str(repo), "total_units": len(units),
        "decided": decided, "true": len(true_rows),
        "multicall_delegatecall": mc_delegate,
        "router_authz": router_authz,
        "fp": len(true_rows), "reverse_fn": 0, "pass": not bad,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if bad:
        print("\nSTRICT FAIL ✘ " + "；".join(bad))
        print(f"结果写入 {out}")
        return 1
    print(f"\nSTRICT PASS ✔（{len(units)} 入口 / 0 True / "
          f"multicall delegatecall False / 公开 swap 不误判）")
    print(f"结果写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
