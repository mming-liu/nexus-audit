"""M54 诊断：父合约索引的跨项目覆盖 + `_msgSender` 找不到的原因。

用法：python benchmarks/probe_m54_idx.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.slicer.web3_slither import SoliditySlicer   # noqa: E402

REPO = ROOT / "reference_repos" / "GPTScan-Top200-dev"


def main() -> None:
    own = []
    for sol in REPO.rglob("*.sol"):
        try:
            t = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"\bcontract\s+(Ownable|Context)\s*([^{]*)\{", t):
            own.append((m.group(1), m.group(2).strip()[:60],
                        str(sol.relative_to(REPO))))
    print(f"全库 Ownable/Context 定义 {len(own)} 个")
    cnt: dict = {}
    for name, inh, _p in own:
        cnt[(name, inh)] = cnt.get((name, inh), 0) + 1
    for k, n in sorted(cnt.items(), key=lambda x: -x[1])[:20]:
        print(f"  {k[0]:10} is {k[1]!r:44} x {n}")

    slicer = SoliditySlicer(REPO)
    idx = slicer._build_parent_index(REPO)
    print(f"\n索引条目 {len(idx)} 个")
    for k in ("Ownable", "Context"):
        if k in idx:
            bases, mods, funcs = idx[k]
            print(f"  {k}: bases={bases} funcs={sorted(funcs)[:8]}")

    tgt = REPO / "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82_bsc" / "CakeToken.sol"
    t = tgt.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"\bcontract\s+(\w+)\s*([^{]*)\{", t):
        print(f"  CakeToken.sol: contract {m.group(1)} is{m.group(2).strip()}")


if __name__ == "__main__":
    main()
