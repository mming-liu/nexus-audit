"""OWASP Benchmark 误报率跑分器。

用法：
  python benchmarks/benchmark_owasp.py --per-category 20 --concurrency 6 \
      --output benchmarks/results/owasp_scorecard.csv

口径（严格对齐 OWASP Benchmark 官方评分规则）：
  - 单个测试用例被引擎标记为存在该类漏洞 => 引擎认为"有漏洞"
  - TP = 真实有漏洞 且 引擎标记      FN = 真实有漏洞 但 引擎没标记（漏报）
  - FP = 真实安全   但 引擎标记      TN = 真实安全   且 引擎没标记
  - TPR（检出率） = TP / (TP + FN)
  - FPR（误报率） = FP / (FP + TN)
  - Score        = TPR - FPR       （官方 BenchmarkScore，0~1，越高越好）

设计要点：
  - 每个用例只喂「本类别的 Scenario/Property」两个问题，不让模型一次面对 11 个场景，
    否则单次 prompt 过长、判定注意力被稀释
  - 结果逐条落盘（jsonl），支持 --resume 断点续跑；免费模型慢，中断不丢进度
  - 只取 doPost（OWASP 的业务逻辑都在 doPost 里，doGet 仅转发），
    避免同一用例被算两次
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import vuln_categories as VC          # noqa: E402
from core.agents.router import OpenAICompatClient, TwoTierRouter  # noqa: E402
from core.agents.scenario_matcher import ScenarioMatcher          # noqa: E402
from core.models import base_unit_name                          # noqa: E402
from core.slicer.java_servlet import JavaSlicer                   # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "BenchmarkJava-master"

# --categories 解析结果（None 表示全部类目）
only_cats: list[str] | None = None


@dataclass
class Case:
    name: str
    category: str
    real_vuln: bool
    cwe: str


def load_expected(target: Path) -> dict[str, Case]:
    """读取 expectedresults-1.2.csv，返回 name -> Case。"""
    csv_path = target / "expectedresults-1.2.csv"
    cases: dict[str, Case] = {}
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.reader(line for line in f if not line.startswith("#")):
            if len(row) < 4:
                continue
            name, cat, is_vuln, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            cases[name] = Case(name=name, category=cat, real_vuln=(is_vuln == "true"), cwe=cwe)
    return cases


def sample_cases(cases: dict[str, Case], per_category: int | None,
                 seed: int = 42, only: list[str] | None = None) -> list[Case]:
    """按类目分层采样，保证真/假各占一半，最大程度暴露误报。"""
    if only:
        cases = {k: v for k, v in cases.items() if v.category in only}
    if per_category is None:
        return list(cases.values())

    by_cat: dict[str, list[Case]] = defaultdict(list)
    for c in cases.values():
        by_cat[c.category].append(c)

    rng = random.Random(seed)
    picked: list[Case] = []
    for cat in sorted(by_cat):
        pool = sorted(by_cat[cat], key=lambda x: x.name)
        vulns = [c for c in pool if c.real_vuln]
        safes = [c for c in pool if not c.real_vuln]
        half = max(1, per_category // 2)
        picked.extend(rng.sample(vulns, min(half, len(vulns))))
        picked.extend(rng.sample(safes, min(per_category - half, len(safes))))
    picked.sort(key=lambda c: c.name)
    return picked


async def run(args) -> None:
    target = Path(args.target).resolve()
    expected = load_expected(target)
    code_dir = target / "src/main/java/org/owasp/benchmark/testcode"

    print(f"[1/4] 切片 {code_dir.relative_to(target)} ...", flush=True)
    t0 = time.time()
    units = JavaSlicer(code_dir).extract_entry_units()
    # 只保留 doPost 入口（用例类名为 BenchmarkTestNNNNN）
    unit_by_case = {}
    for u in units:
        cls, meth = base_unit_name(u.unit_name).split(".", 1)
        if meth == "doPost" and cls in expected:
            unit_by_case[cls] = u
    print(f"      {len(units)} 个入口 -> {len(unit_by_case)} 个用例可审计（{time.time()-t0:.1f}s）",
          flush=True)

    picked = [c for c in sample_cases(expected, args.per_category, args.seed, only_cats)
              if c.name in unit_by_case and c.category in VC.CATEGORIES]
    print(f"[2/4] 采样 {len(picked)} 个用例（{len({c.category for c in picked})} 类）", flush=True)

    out_jsonl = Path(args.output).with_suffix(".jsonl")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    done: dict[str, dict] = {}
    if args.resume and out_jsonl.exists():
        for line in out_jsonl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                # 旧版本记录（无 llm_failed 字段）里混着静默失败样本，需重跑
                if "llm_failed" not in rec:
                    continue
                done[rec["case"]] = rec
        print(f"      断点续跑：可用 {len(done)} 条", flush=True)

    todo = [c for c in picked if c.name not in done]
    print(f"[3/4] 调用 LLM 判定 {len(todo)} 条（并发 {args.concurrency}）...", flush=True)

    if not args.offline and todo:
        from cli import load_dotenv
        load_dotenv(ROOT / ".env")

    router = None if args.offline else TwoTierRouter(
        tier1=OpenAICompatClient(model=args.model, timeout=args.timeout))
    matcher = ScenarioMatcher(router=router, max_concurrency=args.concurrency,
                              code_language="java_web",
                              scenario_votes=args.votes, property_votes=args.votes)

    if args.offline:
        # 离线基线：纯 sink 关键词匹配，用来对比 LLM 的增益
        from benchmarks.offline_baseline import offline_predict
        for c in todo:
            flagged = offline_predict(unit_by_case[c.name].source_code, c.category)
            rec = {"case": c.name, "category": c.category, "real_vuln": c.real_vuln,
                   "flagged": flagged, "detail": f"offline baseline: {c.category} sink matched",
                   "stage": "sink_hit" if flagged else "no_sink", "elapsed_s": 0}
            done[c.name] = rec
            with out_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        lock = asyncio.Lock()
        finished = 0

        async def _one(c: Case):
            nonlocal finished
            t = time.time()
            unit = unit_by_case[c.name]

            # 第一步：确定性规则能判的直接判（算法强弱是客观事实，不该问模型）
            rule_verdict = None
            if not args.no_rules:
                from core.agents.rule_detectors import verdict as rule_verdict_fn
                rule_verdict = rule_verdict_fn(c.category, unit.source_code)

            if rule_verdict is not None:
                flagged = rule_verdict
                stage = "rule_missing_property" if rule_verdict else "rule_protected"
                detail = f"rule:{c.category} deterministic verdict"
                err = ""
                hs = []
            else:
                try:
                    hs = await matcher.audit_unit_for(unit, [c.category], "java_web")
                except Exception as e:
                    hs = []
                    err = str(e)[:300]
                else:
                    err = ""
                flagged = any(h.property_missing for h in hs)
                # 调用失败必须显式标记：静默当成"无漏洞"会把限流伪装成低误报
                llm_failed = any("LLM 调用失败" in h.reasoning_summary for h in hs) or bool(err)
                if llm_failed:
                    stage = "error"
                    detail = err or next(h.reasoning_summary for h in hs
                                         if "LLM 调用失败" in h.reasoning_summary)
                elif not hs or not hs[0].scenario_hit:
                    stage = "no_sink"
                    detail = hs[0].reasoning_summary if hs else "sink not reachable"
                elif not flagged:
                    stage = "protected"
                    detail = hs[0].reasoning_summary
                else:
                    stage = "missing_property"
                    detail = hs[0].reasoning_summary

            rec = {"case": c.name, "category": c.category, "real_vuln": c.real_vuln,
                   "flagged": flagged,
                   "llm_failed": bool(err) or (
                       False if rule_verdict is not None else
                       any("LLM 调用失败" in h.reasoning_summary for h in hs)),
                   "by_rule": rule_verdict is not None,
                   "stage": stage, "detail": detail,
                   "elapsed_s": round(time.time() - t, 1)}
            async with lock:
                finished += 1
                with out_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if finished % 10 == 0 or finished == len(todo):
                    print(f"      进度 {finished}/{len(todo)}", flush=True)
            done[c.name] = rec

        await asyncio.gather(*(_one(c) for c in todo))

    # ---------- 统计 ----------
    print(f"[4/4] 计算 scorecard ...", flush=True)
    all_rows = list(done.values())
    err_rows = [r for r in all_rows if r.get("llm_failed")]
    rows = [r for r in all_rows if r["case"] in {c.name for c in picked} and not r.get("llm_failed")]
    if err_rows:
        from collections import Counter
        print(f"      ⚠ 剔除调用失败样本 {len(err_rows)} 条（不计入 TPR/FPR，"
              f"集中在：{dict(Counter(r['category'] for r in err_rows))}）", flush=True)
    score = scorecard(rows)

    csv_out = Path(args.output)
    csv_out.parent.mkdir(parents=True, exist_ok=True)
    with csv_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category", "tp", "fn", "fp", "tn", "tpr", "fpr", "score", "count"])
        for cat, s in sorted(score["by_category"].items()):
            w.writerow([cat, s["tp"], s["fn"], s["fp"], s["tn"],
                        f"{s['tpr']:.3f}", f"{s['fpr']:.3f}", f"{s['score']:.3f}", s["n"]])
        o = score["overall"]
        w.writerow(["OVERALL", o["tp"], o["fn"], o["fp"], o["tn"],
                    f"{o['tpr']:.3f}", f"{o['fpr']:.3f}", f"{o['score']:.3f}", o["n"]])

    print_report(score, out_jsonl)
    md = Path(args.output).with_suffix(".md")
    md.write_text(render_markdown(score, args), encoding="utf-8")
    print(f"\n完成：scorecard -> {csv_out}\n      明细 -> {out_jsonl}\n      报告 -> {md}")


def scorecard(rows: list[dict]) -> dict:
    """按 OWASP 口径计算 TPR / FPR / Score。"""
    def tally(rs):
        tp = sum(1 for r in rs if r["real_vuln"] and r["flagged"])
        fn = sum(1 for r in rs if r["real_vuln"] and not r["flagged"])
        fp = sum(1 for r in rs if not r["real_vuln"] and r["flagged"])
        tn = sum(1 for r in rs if not r["real_vuln"] and not r["flagged"])
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
                "tpr": tpr, "fpr": fpr, "score": tpr - fpr, "n": len(rs)}

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    return {"overall": tally(rows),
            "by_category": {k: tally(v) for k, v in by_cat.items()}}


def print_report(score: dict, jsonl: Path) -> None:
    o = score["overall"]
    print("\n" + "=" * 64)
    print(f"{'类目':<16}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}{'TPR':>8}{'FPR':>8}{'Score':>8}")
    print("-" * 64)
    for cat, s in sorted(score["by_category"].items(), key=lambda kv: -kv[1]["score"]):
        print(f"{cat:<16}{s['tp']:>4}{s['fn']:>4}{s['fp']:>4}{s['tn']:>4}"
              f"{s['tpr']:>8.2f}{s['fpr']:>8.2f}{s['score']:>8.2f}")
    print("-" * 64)
    print(f"{'OVERALL':<16}{o['tp']:>4}{o['fn']:>4}{o['fp']:>4}{o['tn']:>4}"
          f"{o['tpr']:>8.2f}{o['fpr']:>8.2f}{o['score']:>8.2f}")
    print("=" * 64)

    # 误差归因：哪一类错误最多
    from collections import Counter
    fp_rows = [r for r in _load(jsonl) if not r["real_vuln"] and r["flagged"]]
    fn_rows = [r for r in _load(jsonl) if r["real_vuln"] and not r["flagged"]]
    if fp_rows:
        print("\n误报集中在：" + ", ".join(f"{c}×{n}" for c, n in
                                       Counter(r["category"] for r in fp_rows).most_common()))
        print("  典型误报卡点：" + ", ".join(f"{c}×{n}" for c, n in
                                        Counter(r["stage"] for r in fp_rows).most_common()))
    if fn_rows:
        print("漏报集中在：" + ", ".join(f"{c}×{n}" for c, n in
                                      Counter(r["category"] for r in fn_rows).most_common()))
        print("  典型漏报卡点：" + ", ".join(f"{c}×{n}" for c, n in
                                        Counter(r["stage"] for r in fn_rows).most_common()))


def _load(jsonl: Path) -> list[dict]:
    if not jsonl.exists():
        return []
    return [json.loads(l) for l in jsonl.read_text(encoding="utf-8").splitlines() if l.strip()]


def render_markdown(score: dict, args) -> str:
    o = score["overall"]
    lines = [
        "# nexus-audit — OWASP Benchmark 跑分报告",
        "",
        f"- 模型：`{args.model if not args.offline else '离线基线（sink 关键词匹配）'}`",
        f"- 采样：每类 {args.per_category or '全量'} 条（真/假各半）",
        f"- 样本总数：{o['n']}",
        "",
        "## 总体指标",
        "",
        "| 指标 | 数值 | 说明 |",
        "|---|---|---|",
        f"| TPR 检出率 | {o['tpr']:.3f} | TP {o['tp']} / (TP {o['tp']} + FN {o['fn']}) |",
        f"| FPR 误报率 | {o['fpr']:.3f} | FP {o['fp']} / (FP {o['fp']} + TN {o['tn']}) |",
        f"| BenchmarkScore | {o['score']:.3f} | TPR − FPR |",
        "",
        "## 分类目明细",
        "",
        "| 类目 | 样本 | TP | FN | FP | TN | TPR | FPR | Score |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for cat, s in sorted(score["by_category"].items(), key=lambda kv: -kv[1]["score"]):
        lines.append(f"| {cat} | {s['n']} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} "
                     f"| {s['tpr']:.2f} | {s['fpr']:.2f} | {s['score']:.2f} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="OWASP Benchmark 误报率跑分")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--per-category", type=int, default=20,
                    help="每个类目采样条数（真/假各半）；0 表示全量")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--output", default=str(ROOT / "benchmarks/results/owasp_scorecard.csv"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--offline", action="store_true", help="离线基线，不调用 LLM")
    ap.add_argument("--resume", action="store_true", help="从已有 jsonl 断点续跑")
    ap.add_argument("--categories", default=None,
                    help="只跑指定类目，逗号分隔，如 weakrand,crypto")
    ap.add_argument("--votes", type=int, default=1,
                    help="每个问题问几次取多数。默认 1；3 票实测不降抖动，"
                         "要提召回用 5（代价 5 倍调用）。见 REAL_PROJECT_REPORT.md 第四节")
    ap.add_argument("--no-rules", action="store_true",
                    help="关闭确定性规则前置，全部交给 LLM（用于对比规则增益）")
    args = ap.parse_args()
    if args.per_category == 0:
        args.per_category = None
    global only_cats
    only_cats = [c.strip() for c in args.categories.split(",")] if args.categories else None
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
