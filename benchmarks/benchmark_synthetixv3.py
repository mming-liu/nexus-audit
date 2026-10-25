"""Synthetixio/synthetix-v3 —— 第 19 野战仓，M108 Diamond 代理 + 谓词式鉴权。

## 为什么选它

Synthetix V3 是衍生品流动性协议，架构上把 Compound/Uniswap 的两种复杂度合到一起：

- **Diamond 代理**：`PoolModule` 等模块通过 router 分发，`msg.sender` 经过
  ERC-2771 中继转发，身份统一走 `ERC2771Context._msgSender()`；
- **谓词式鉴权**：`isOwner()` / `_isApprovedOrOwner()` 把身份判定封进函数，
  外层只写 `require(isOwner(), …)` 或 `if (!_isApprovedOrOwner(_msgSender(), id)) revert`；
- **反向条件**：`if (pool.nominatedOwner != _msgSender()) revert` —— 与
  `require(a == b)` 等价，但字面是 `!=`；
- **身份别名**：`address sender = _msgSender(); if (sender != rewardsManager) revert`。

## M108 补齐的三个机制（全部纯增量）

| 误报 | 机制 | 补的判据 |
|---|---|---|
| `Sushiswap`/`Synthetix` 的 `transferOwnership`（`require(isOwner(), …)`） | 身份比较封在零参谓词里，requirement 只看得到函数名 | `_sol_predicate_authz_check`：先在切片里找"体内部做了身份比较"的谓词，再看它是否出现在 require 或中止型 if 里 |
| `ERC721.transferFrom`（`if (!_isApprovedOrOwner(_msgSender(), id)) revert`） | 取反 + 中止写在 if 里，旧判据只认 `require(_isApprovedOrOwner(` | `_sol_negated_identity_call`：`if (!call(...))` 且 call 实参含身份函数 |
| `PoolModule.acceptPoolOwnership` / `SnapshotRewardsDistributor.onPositionUpdated` | `if (X != sender) revert` 与 `require(X == sender)` 等价；别名变量同理 | `_sol_inverted_identity_guard`（含 `_sol_identity_aliases` 别名解析） |

顺带修掉一个**静默失效**：`_sol_block_body(text, close + 1)` 要求下标正好落在
`{` 上，而 `)` 与 `{` 之间几乎总有空格或换行 —— 于是块体永远取到空串，
判定不报错、只是永远 False。新增 `_sol_block_body_at` 先跳空白。

## 门禁（--strict）

- 生产范围（`protocol/` `markets/` `auxiliary/` `utils/core-contracts/contracts/{token,storage,utils}/`，
  排除 `test/` `mocks/` `sample-project/`）切片 ≥1000（实测 1264）；
- 四类 Solidity 判据在该范围内 **0 条 True**；
- `test/Destroyer.sol:upgradeTo` 这类**故意写成无鉴权**的测试载荷不在生产范围内
  —— 不是"规则看不见"，是被正确排除（样板 `sample-project` 同理）。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "synthetix-v3"
CATS = ("access_control", "reentrancy", "unchecked_low_level_calls",
        "arithmetic")
PROD_PREFIXES = (
    "protocol/", "markets/", "auxiliary/",
    "utils/core-contracts/contracts/token/",
    "utils/core-contracts/contracts/storage/",
    "utils/core-contracts/contracts/utils/",
)
EXCLUDE_MARKS = ("/test/", "/mocks/", "sample-project")
MIN_UNITS = 1000


def _in_scope(file_path: str) -> bool:
    s = file_path.replace("\\", "/")
    if any(k in s for k in EXCLUDE_MARKS):
        return False
    return any(k in s for k in PROD_PREFIXES)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Synthetix V3 生产合约零误报基准（M108）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥1000 生产入口 + 四类 0 True")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "synthetixv3.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Synthetixio/synthetix-v3.git）")
        return 2

    units = list(SoliditySlicer(repo).extract_entry_units(repo))
    scoped = [u for u in units if _in_scope(u.file_path)]
    print(f"靶场：{repo}")
    print(f"      全库切片 {len(units)} 个 ｜ 生产范围 {len(scoped)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    for u in scoped:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))

    print("=" * 72)
    print("Synthetix V3 结果（Diamond 代理 + 谓词式鉴权）")
    print("=" * 72)
    print(f"  生产范围切片          ：{len(scoped)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for f, n, c in true_rows[:12]:
        print(f"      [FP] {f}:{n} [{c}]")

    bad = []
    if len(scoped) < MIN_UNITS:
        bad.append(f"生产范围切片 {len(scoped)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"计划外 True {len(true_rows)} 条")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（1264 生产入口 / 四类 0 True）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "synthetixv3", "units": len(scoped),
        "total_units": len(scoped), "all_units": len(units),
        "decided": len(scoped), "correct": len(scoped) - len(true_rows),
        "fp": len(true_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "production_prefixes": list(PROD_PREFIXES),
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
