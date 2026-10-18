"""A/B 对照：单次采样 vs 多次投票，比的是「跑两遍结果会不会变」。

测法（这是关键）：
  抖动不是「同一批样本里有几条判错」，而是「同一批样本跑第二遍，结论变不变」。
  所以对每种采样策略各跑 2 轮完整评测，比较两轮之间有多少条判定翻转。

  之前误用「总体 TPR/FPR 高低」来判断投票有没有用，是错的 —— 投票改的是
  *一致性*，不是 *准确率*。一个稳定判错的引擎比一个随机猜对的引擎更有价值，
  因为前者的错误可以被规则修正，后者不能。

用法：
  python benchmarks/ab_votes.py --rounds 2 --votes 1      # 单次采样基线
  python benchmarks/ab_votes.py --rounds 2 --votes 3      # 三次投票
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "benchmarks" / "results"


def load(tag: str) -> dict[str, bool]:
    p = RESULTS / f"{tag}.jsonl"
    if not p.exists():
        return {}
    out = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("flagged") is not None:
            out[r["unit"]] = bool(r["flagged"])
    return out


def compare(tag_a: str, tag_b: str) -> None:
    a, b = load(tag_a), load(tag_b)
    common = sorted(set(a) & set(b))
    if not common:
        print(f"{tag_a} / {tag_b}: 没有可比样本")
        return
    flips = [u for u in common if a[u] != b[u]]
    print(f"\n{tag_a}  vs  {tag_b}")
    print(f"  可比样本 {len(common)}，判定翻转 {len(flips)} 条"
          f"（{len(flips) / len(common):.1%}）")
    for u in flips:
        print(f"    {u:<32}{a[u]} -> {b[u]}")


def main():
    ap = argparse.ArgumentParser(description="采样策略一致性对照")
    ap.add_argument("tags", nargs="+", help="要比较的 results 标签，两两比较")
    args = ap.parse_args()
    for i in range(0, len(args.tags) - 1):
        compare(args.tags[i], args.tags[i + 1])


if __name__ == "__main__":
    main()
