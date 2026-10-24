"""GPTScan-Top200 —— 第 22 个靶场，ICSE'24 GPTScan 官方数据集（纯负样本集）。

## 为什么需要这个靶场

前面 21 个靶场里，Solidity 的**正样本**（真漏洞）分母一直很薄：
smartbugs 三个类目加起来 24 条 vul，DeFiVulnLabs 9 条，nssc 7 条 ——
按记忆条 3（分母 <20 只记录不下结论），能下"召回率"结论的类目屈指可数。

但**误报**这一侧恰恰相反：真实生产合约的分布只有"已审计的大额项目"能提供。
本靶场就是为此而生。

## 数据集口径（ICSE'24 GPTScan 官方）

`GPTScan-Top200`：市值 top-200 的**已审计**智能合约项目。官方明确声明这些
项目"可合理假设不存在显著漏洞"（reasonably assume no significant
vulnerabilities）—— 于是它是一个**纯 safe 负样本集**：

  · 303 个项目 / 1020 个 .sol 文件；
  · 官方自带的 `top200_result.csv` 逐项目记录 GPTScan 自己的**误报数**
    （"False Positives" 列）—— 官方自己也把它当误报基准用。

**所以本靶场不产 TPR，只产 FPR。** 规则层对每个切片单元判 True，就意味着
"在一个已审计项目上误报了一次" —— 数字必须逐条归零才谈得上可用。

同仓库另有两个数据集 `GPTScan-Web3Bugs` / `GPTScan-DefiHacks`：官方**只提供
扫描报告 PDF，没有源码**（0 个 .sol）—— 没有源码就没有切片单元，无法作靶场，
故本靶场只取 Top200。

## 门禁（--strict）

**零误报**（FPR = 0）。这是纯负样本集唯一的指标：safe 分母 = 全部分母，
每一条 True 都是误报。判 False / 退 None 都不算误报。

注意方向：这里**判 True 是唯一失败模式**，判 False 无害（本来就是 safe），
退 None 也无害（交给模型）。所以本靶场与 smartbugs 的门禁语义相反 ——
smartbugs 是"vul 判 False 才致命"，这里是"safe 判 True 才致命"。

## 温缓存（M47 slice_cache）

1020 个 .sol 的父合约索引构建不便宜，用 `cached_units` 的 SHA-256 温缓存：
切片器源码指纹 ⊕ 靶场清单指纹 ⊕ bench 名。判定永远现算，缓存只省切片。

## 模型层

`--offline` 跳过（CI 门禁必须离线）。模型阶段只跑**规则退回批**，
口径与 smartbugs 一致：模型指标的分母是"规则查不出的那部分"。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402
from benchmarks.slice_cache import cached_units                     # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "GPTScan-Top200-dev"

# Top200 是纯负样本集，四个 Solidity 类目各自独立算 FPR。
CATEGORIES = ["reentrancy", "access_control", "unchecked_low_level_calls",
              "arithmetic"]


def _load_official_fp(repo: Path) -> dict[str, int]:
    """读官方自带的 `top200_result.csv`（逐项目误报数）。

    官方把它当误报基准用 —— 我们把它作为**对照口径**放进报告：
    "官方工具在这个项目上误报 N 次，我们误报 M 次"。
    """
    csv = repo / "top200_result.csv"
    if not csv.exists():
        return {}
    out: dict[str, int] = {}
    try:
        lines = csv.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for ln in lines[1:]:
        if not ln.strip():
            continue
        parts = ln.split(",")
        if len(parts) < 2:
            continue
        try:
            out[parts[0].strip()] = int(parts[1].strip())
        except ValueError:
            continue
    return out


def _project_of(file_path: str) -> str:
    """从文件路径取项目名（Top200 的顶层目录名 = 项目名）。"""
    p = Path(file_path)
    for part in p.parts:
        if part.startswith("0x") and "_" in part:
            return part
    return p.parent.name or p.stem


async def _model_stage(rows: list[dict], args) -> list[dict]:
    """把规则退回批交模型（与 smartbugs 同口径）。"""
    from cli import load_dotenv
    load_dotenv(ROOT / ".env")
    from core.agents.router import OpenAICompatClient, TwoTierRouter
    from core.agents.scenario_matcher import ScenarioMatcher

    router = TwoTierRouter(tier1=OpenAICompatClient(model=args.model))
    matcher = ScenarioMatcher(router=router, max_concurrency=args.concurrency,
                              code_language="solidity_web3")
    sem = asyncio.Semaphore(args.concurrency)

    async def one(r: dict) -> dict:
        async with sem:
            t0 = time.time()
            base = {"file": r["file"], "unit": r["unit"].unit_name,
                    "category": r["category"], "real_vuln": False,
                    "rule": r.get("rule")}
            try:
                hs = await matcher.audit_unit_for(r["unit"], [r["category"]],
                                                  "solidity_web3")
            except Exception as e:                      # 超时 / 熔断 / 连接
                return {**base, "flagged": None,
                        "detail": f"{type(e).__name__}: {e}"[:160],
                        "elapsed_s": round(time.time() - t0, 1)}
            if any("LLM 调用失败" in (h.reasoning_summary or "") for h in hs):
                return {**base, "flagged": None,
                        "detail": next(h.reasoning_summary for h in hs
                                       if "LLM 调用失败" in h.reasoning_summary)[:200],
                        "elapsed_s": round(time.time() - t0, 1)}
            h = hs[0] if hs else None
            return {**base, "flagged": bool(h.property_missing) if h else False,
                    "reason": (h.reasoning_summary if h else "场景未命中")[:160],
                    "elapsed_s": round(time.time() - t0, 1)}

    return list(await asyncio.gather(*(one(r) for r in rows)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="零误报门禁（CI 用）：safe 判 True 一条都不许有")
    ap.add_argument("--offline", action="store_true", help="只跑规则层")
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", "glm-5.3-flash"))
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0, help="模型阶段最多跑多少条")
    ap.add_argument("--no-cache", action="store_true", help="强制冷切片")
    ap.add_argument("--top", type=int, default=20,
                    help="报告里最多列多少条误报样本")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "gptscan.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到靶场 {repo}")
        sys.exit(2)

    official_fp = _load_official_fp(repo)

    print(f"靶场：{repo}")
    print("[1/2] 切片（温缓存）...")
    slicer = SoliditySlicer(repo)
    units = cached_units(repo, "gptscan-top200",
                         lambda: slicer.extract_entry_units(repo),
                         no_cache=args.no_cache)
    n_sol = sum(1 for _ in repo.rglob("*.sol"))
    projects = {_project_of(u.file_path) for u in units}
    print(f"      .sol {n_sol} 个 / 项目 {len(projects)} 个 / 切片单元 {len(units)} 个")
    print(f"      官方对照：top200_result.csv 记录 {len(official_fp)} 个项目的误报数")

    print("[2/2] 规则层判定...")
    t0 = time.monotonic()
    fp_rows: list[dict] = []
    decided = 0
    per_cat: dict[str, Counter] = {c: Counter() for c in CATEGORIES}
    fallback: list[dict] = []
    unit_fp: dict[str, list[str]] = defaultdict(list)
    for u in units:
        for cat in CATEGORIES:
            rv = rule_verdict(cat, u.source_code)
            if rv is None:
                per_cat[cat]["fallback"] += 1
                continue
            decided += 1
            per_cat[cat]["decided"] += 1
            if rv is True:
                per_cat[cat]["fp"] += 1
                fp_rows.append({"file": Path(u.file_path).name,
                                "unit": u.unit_name, "category": cat,
                                "project": _project_of(u.file_path)})
                unit_fp[Path(u.file_path).name].append(f"{cat}:{u.unit_name}")
            else:
                per_cat[cat]["correct"] += 1
            if rv is None:
                fallback.append({"unit": u, "category": cat, "rule": rv,
                                 "file": Path(u.file_path).name})
    dt = time.monotonic() - t0

    n_fp = len(fp_rows)
    print()
    print("=" * 72)
    print("GPTScan-Top200 结果（规则层，纯负样本集 → 只看误报）")
    print("=" * 72)
    for cat in CATEGORIES:
        c = per_cat[cat]
        n = c["decided"] + c["fallback"]
        fpr = c["fp"] / c["decided"] if c["decided"] else 0.0
        print(f"  {cat:26} 单元 {n:5}  判定 {c['decided']:5}  "
              f"误报 {c['fp']:4}  FPR={fpr * 100:.2f}%")
    print(f"  合计：切片 {len(units)} 个单元 × {len(CATEGORIES)} 类目 = "
          f"{len(units) * len(CATEGORIES)} 次判定，"
          f"规则定论 {decided} 次，误报 {n_fp} 次（{dt:.1f}s）")

    if fp_rows:
        by_cat = Counter(r["category"] for r in fp_rows)
        print(f"\n! 误报 {n_fp} 条（strict 门禁必须为 0），按类目：")
        for cat, n in by_cat.most_common():
            print(f"    {cat:26} {n}")
        print(f"  涉及项目 {len({r['project'] for r in fp_rows})} 个")
        print(f"\n  误报样本（前 {args.top} 条）：")
        for r in fp_rows[:args.top]:
            off = official_fp.get(r["project"])
            off_s = f"，官方同项目误报 {off} 次" if off is not None else ""
            print(f"    {r['project'][:44]:46} {r['file'][:40]:42} "
                  f"{r['category']}:{r['unit']}{off_s}")

    model_stats = None
    todo = fallback[:args.limit] if args.limit else fallback
    if args.offline or not todo:
        why = "offline" if args.offline else "无可送审样本"
        print(f"\n模型层：跳过（{why}）")
        model_stats = {"model": None, "skipped": why,
                       "n_fallback": len(fallback)}
    else:
        print(f"\n模型层：{args.model} 判定 {len(todo)} 条退回样本，"
              f"并发 {args.concurrency}）...", flush=True)
        model_rows = asyncio.run(_model_stage(todo, args))
        ok = [m for m in model_rows if m["flagged"] is not None]
        err = len(model_rows) - len(ok)
        mfp = sum(1 for m in ok if m["flagged"] and not m["real_vuln"])
        print(f"  有效 {len(ok)} / 调用失败 {err}；模型误报 {mfp} 条")
        if mfp:
            print("  模型误报样本：")
            for m in [x for x in ok if x["flagged"]][:args.top]:
                print(f"    {m['file'][:46]}:{m['unit']}  {m['category']}")
        model_stats = {"model": args.model, "n_sent": len(model_rows),
                       "n_valid": len(ok), "call_failed": err, "fp": mfp}

    out = {
        "target": str(repo),
        "dataset": "GPTScan-Top200",
        "total_sol": n_sol,
        "total_projects": len(projects),
        "total_units": len(units),
        "total_judgements": len(units) * len(CATEGORIES),
        "decided": decided,
        "correct": decided - n_fp,
        "fp": n_fp,
        "reverse_fn": 0,          # 纯负样本集没有 vul，不存在判反
        "fallback": len(fallback),
        "per_category": {c: dict(per_cat[c]) for c in CATEGORIES},
        "fp_rows": fp_rows[:200],
        "official_fp_reference": official_fp,
        "model": model_stats,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        if n_fp:
            print(f"\nSTRICT 门禁：未通过 ✘（误报 {n_fp} 条，纯负样本集必须为 0）")
            sys.exit(1)
        print("\nSTRICT 门禁：通过 ✔（零误报）")


if __name__ == "__main__":
    main()
