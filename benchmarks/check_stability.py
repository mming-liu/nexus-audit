"""判定稳定性复测：同一份代码、同一个 prompt，连问 N 次看结果是否一致。

为什么需要这个脚本：
  真实项目评测里发现，两轮之间 66 条样本有 10 条判定翻转。这没法用"改进了"
  或"退化了"解释 —— 是判定器本身不稳定。`temperature=0` 只能降低采样随机性，
  不能消除：服务端批处理、KV cache、浮点累加顺序都会带来差异。

  单轮跑出的 TPR/FPR 如果不稳定，就没有任何意义。所以在相信任何分数之前，
  先测抖动率。

用法：
  python benchmarks/check_stability.py                 # 默认样本 ×3 次
  python benchmarks/check_stability.py --repeat 5      # 连问 5 次
  python benchmarks/check_stability.py --units XSS.safe,Cors.vuls1
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.benchmark_javaseccode import DEFAULT_TARGET, classify  # noqa: E402
from core.agents.router import OpenAICompatClient, TwoTierRouter       # noqa: E402
from core.agents.scenario_matcher import ScenarioMatcher               # noqa: E402
from core.slicer.java_servlet import JavaSlicer                        # noqa: E402

# 默认挑「历史轮次里判过便」和「判错过」的混合样本，抖动最容易在这里现形
DEFAULT_UNITS = [
    "Cors.vuls1", "Cors.vuls2", "Cors.getCsrfToken_01", "Cors.getCsrfToken_02",
    "Cors.seccode", "Cors.secCrossOrigin", "Cors.getCsrfToken_03",
    "XSS.store", "XSS.reflect", "XSS.show", "XSS.safe",
]


async def run(args):
    units = JavaSlicer(Path(args.target).resolve()).extract_entry_units()
    by = {u.unit_name: u for u in units}
    targets = args.units.split(",") if args.units else DEFAULT_UNITS
    targets = [t for t in targets if t in by]
    if not targets:
        print("没有匹配到样本，检查 --units")
        return

    from cli import load_dotenv
    load_dotenv(ROOT / ".env")

    matcher = ScenarioMatcher(
        router=TwoTierRouter(tier1=OpenAICompatClient(model=args.model, timeout=180)),
        max_concurrency=args.concurrency, code_language="java_web")

    print(f"稳定性复测：{len(targets)} 条 × {args.repeat} 次，模型 {args.model}\n")
    flaky = 0
    rows = []
    for name in targets:
        u = by[name]
        cat, truth, _src = classify(u)
        if not cat:
            continue
        votes = []
        for _ in range(args.repeat):
            hs = await matcher.audit_unit_for(u, [cat], "java_web")
            votes.append(any(h.property_missing for h in hs))
        flip = len(set(votes)) > 1
        flaky += flip
        rows.append((name, cat, truth, votes, flip))
        mark = "  <-- 抖动" if flip else ""
        print(f"{name:<26} cat={cat:<6} truth={str(truth):<6} votes={votes}{mark}",
              flush=True)

    print(f"\n抖动 {flaky}/{len(rows)} 条（{flaky / max(1, len(rows)):.1%}）")
    print("抖动率 > 5% 时，单轮 TPR/FPR 不具备可复现性，不应作为结论引用。")


def main():
    ap = argparse.ArgumentParser(description="判定稳定性复测")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--units", default="", help="逗号分隔的 unit 名，默认用内置清单")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    args = ap.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
