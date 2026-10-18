"""迁移侧 A/B：规则退回的那批样本，模型到底误报多少？

## 为什么单独一个脚本

`benchmarks/benchmark_hellojavasec.py` 报的是"规则覆盖率 + 规则正确率 + 模型侧
TPR/FPR"，但它的分母随规则变化而变 —— 规则多覆盖一条，模型侧的样本集就少一条，
两轮之间的 FPR 不可直接比较。

本脚本固定**当前规则退回的那批样本**作为测试集，逐条打印"规则为什么退回"，
并支持两种 prompt 的对照：
  --old      用单引证 prompt（只要求 evidence_line）
  默认       用双引证 prompt（needs_taint 的 Yes 必须给 source_line + sink_line）

## 指标口径

- TPR = 真值为漏洞、模型也判漏洞 / 全部真值为漏洞
- FPR = 真值为安全、模型判漏洞 / 全部真值为安全
- 调用失败与"证据核验不过"的票**从分母剔除**，单独计数。
  把失败当"无漏洞"会让限流伪装成极低的误报率 —— 这是本项目踩过的坑。
- 端到端 = (规则判对 + 模型判对) / 全部有人工真值的样本。
  只看模型侧 FPR 会漏掉"规则覆盖不足"这一半问题。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core.agents.scenario_matcher as sm                          # noqa: E402
from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.java_servlet import JavaSlicer                     # noqa: E402

sys.path.insert(0, str(ROOT / "benchmarks"))
from benchmark_hellojavasec import classify, route_of               # noqa: E402
from ab_cite import OLD_TAINT, OLD_CONFIG                           # noqa: E402

DEFAULT_REPO = ROOT / "reference_repos" / "Hello-Java-Sec-master"


def collect(repo: Path):
    """返回 (全部有真值样本, 规则退回样本)。"""
    units = JavaSlicer(repo).extract_entry_units()
    rows, fallback = [], []
    for u in units:
        cat, truth, src = classify(u)
        if not cat or truth is None:
            continue
        rec = {"unit": u, "category": cat, "real_vuln": truth, "src": src}
        rows.append(rec)
        if rule_verdict(cat, u.source_code) is None:
            fallback.append(rec)
    return rows, fallback


async def judge(matcher, rec, old: bool):
    """对一条样本给出最终判定。返回 dict。"""
    u, key = rec["unit"], rec["category"]
    cat = sm.VC.get(key)
    t0 = time.time()
    stage = ""
    try:
        if old:
            # 旧机制：Step1 单引证（只要 Yes/No，不要求引用），Step2 用同一个
            # property 模板但不核验 —— 上一轮基线就是这么跑的。
            # 两组只差"Step1 是否强制 source_line + sink_line"这一个变量，
            # 否则无法判断 FPR/TPR 的变化到底来自双引证还是来自别的改动。
            tmpl = OLD_TAINT if cat.needs_taint else OLD_CONFIG
            from core.agents.router import extract_json
            raw = await matcher._ask(
                tmpl.format(lang="java", question=cat.sink_question, code=u.source_code))
            hit = str(extract_json(raw).get("hit", "")).strip().lower().startswith("y")
            if not hit:
                return {**rec, "flagged": False, "stage": "no_sink", "detail": "",
                        "elapsed_s": round(time.time() - t0, 1)}
            praw = await matcher._ask(
                sm.PROPERTY_PROMPT_TMPL.format(property=cat.property, lang="java",
                                               code=u.source_code))
            protected = str(extract_json(praw).get("protected", "")).strip() \
                .lower().startswith("y")
            flagged = not protected
            stage = "protected" if protected else "missing_property"
        else:
            hs = await matcher.audit_unit_for(u, [key], "java_web")
            # `audit_unit_for` 在 Step1 判 No 时**不 append**（返回空列表），
            # 而真正的调用失败会 append 一条 `LLM 调用失败` 的假设。
            # 所以"空列表"只能解释为"判无此漏洞"，绝不能算作调用失败 ——
            # 把判 No 当失败剔除，会把 FPR 和 TPR 一起算错（FPR 被低估、
            # TPR 被高估），而且错得完全不报错。这个坑踩过一次。
            if not hs:
                return {**rec, "flagged": False, "stage": "no_sink", "detail": "",
                        "elapsed_s": round(time.time() - t0, 1)}
            h = hs[0]
            if "LLM 调用失败" in (h.reasoning_summary or ""):
                return {**rec, "flagged": None, "stage": "error",
                        "detail": (h.reasoning_summary or "")[:150],
                        "elapsed_s": round(time.time() - t0, 1)}
            flagged = bool(h.property_missing)
            stage = ("no_sink" if not h.scenario_hit
                     else "missing_property" if flagged else "protected")
    except Exception as e:
        return {**rec, "flagged": None, "stage": "error",
                "detail": str(e)[:150], "elapsed_s": round(time.time() - t0, 1)}
    return {**rec, "flagged": flagged, "stage": stage, "detail": "",
            "elapsed_s": round(time.time() - t0, 1)}


def report(rows, fallback, model_rows, rule_decided, rule_correct, old: bool):
    ok = [m for m in model_rows if m["flagged"] is not None]
    tp = sum(1 for m in ok if m["flagged"] and m["real_vuln"])
    fn = sum(1 for m in ok if not m["flagged"] and m["real_vuln"])
    fp = sum(1 for m in ok if m["flagged"] and not m["real_vuln"])
    tn = sum(1 for m in ok if not m["flagged"] and not m["real_vuln"])
    err = len(model_rows) - len(ok)

    tag = "旧 prompt（单引证）" if old else "新 prompt（双引证）"
    print("\n" + "=" * 72)
    print(f"{tag}｜模型 {len(ok)} 条有效 / {err} 条调用失败（已剔除，不计为无漏洞）")
    print("=" * 72)
    print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    if tp + fn:
        print(f"  模型 TPR = {tp}/{tp + fn} = {tp / (tp + fn) * 100:.1f}%")
    if fp + tn:
        print(f"  模型 FPR = {fp}/{fp + tn} = {fp / (fp + tn) * 100:.1f}%")
    model_right = tp + tn
    total = len(rows)
    print(f"  规则：{rule_correct}/{rule_decided} 判定且正确"
          f"（覆盖 {rule_decided}/{total}）")
    print(f"  端到端：(规则 {rule_correct} + 模型 {model_right}) / {total} = "
          f"{(rule_correct + model_right) / total * 100:.1f}%")

    print("\n逐条：")
    for m in model_rows:
        if m["flagged"] is None:
            print(f"  --  {m['unit'].unit_name:32} {m['category']:11} "
                  f"真值={m['real_vuln']!s:5} 调用失败: {m['detail']}")
            continue
        mark = "OK " if m["flagged"] == m["real_vuln"] else "ERR"
        print(f"  {mark} {m['unit'].unit_name:32} {m['category']:11} "
              f"真值={m['real_vuln']!s:5} 模型={m['flagged']!s:5} {m['stage']}")
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "errors": err,
            "end_to_end": round((rule_correct + model_right) / total, 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_REPO))
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--old", action="store_true", help="用单引证 prompt 作对照")
    ap.add_argument("--cat", default="", help="只跑某个类目")
    ap.add_argument("--resume", default="",
                    help="复用该结果文件里已成功的条目，只补跑缺失/失败的（限流时很有用）")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "ab_transfer.json"))
    args = ap.parse_args()

    from cli import load_dotenv
    load_dotenv(ROOT / ".env")
    from core.agents.router import OpenAICompatClient, TwoTierRouter

    repo = Path(args.target)
    rows, fallback = collect(repo)
    if args.cat:
        fallback = [r for r in fallback if r["category"] == args.cat]

    rule_decided = [r for r in rows if rule_verdict(r["category"], r["unit"].source_code) is not None]
    rule_correct = sum(1 for r in rule_decided
                       if rule_verdict(r["category"], r["unit"].source_code) == r["real_vuln"])

    print(f"靶场 {repo.name}｜有真值 {len(rows)} 条｜规则退回 {len(fallback)} 条")
    print(f"退回样本真值分布：vuln {sum(1 for r in fallback if r['real_vuln'])} / "
          f"safe {sum(1 for r in fallback if not r['real_vuln'])}")

    router = TwoTierRouter(tier1=OpenAICompatClient(model=args.model, timeout=180))
    matcher = sm.ScenarioMatcher(router=router, max_concurrency=args.concurrency,
                                 code_language="java_web")
    sem = asyncio.Semaphore(args.concurrency)

    # 断点续跑：免费模型限流会把一整轮打残，逐轮重跑全部样本既慢又更易触发限流。
    done: dict[str, dict] = {}
    if args.resume and Path(args.resume).exists():
        prev = json.loads(Path(args.resume).read_text(encoding="utf-8"))
        for d in prev.get("detail", []):
            if d.get("flagged") is not None:
                done[d["unit"]] = d
    todo = [r for r in fallback if r["unit"].unit_name not in done]
    if done:
        print(f"续跑：复用 {len(done)} 条已成功结果，补跑 {len(todo)} 条")

    async def one(rec):
        async with sem:
            return await judge(matcher, rec, args.old)

    async def gather_all():
        return await asyncio.gather(*(one(r) for r in todo))

    fresh = asyncio.run(gather_all())
    by_name = {m["unit"].unit_name: m for m in fresh}
    by_name.update(done)                       # 复用项里带的是字符串名
    model_rows = []
    for r in fallback:
        n = r["unit"].unit_name
        if n in by_name:
            m = dict(by_name[n])
            if isinstance(m.get("unit"), str):
                m["unit"] = r["unit"]           # 还原成 CodeUnit，供 report 使用
                m["category"] = r["category"]
                m["real_vuln"] = r["real_vuln"]
            model_rows.append(m)
    summary = report(rows, fallback, model_rows, len(rule_decided),
                     rule_correct, args.old)

    out = {
        "target": str(repo), "model": args.model, "old_prompt": args.old,
        "with_truth": len(rows), "rule_decided": len(rule_decided),
        "rule_correct": rule_correct, "fallback": len(fallback),
        **summary,
        "detail": [{k: (v if k != "unit" else v.unit_name) for k, v in m.items()}
                   for m in model_rows],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")


if __name__ == "__main__":
    main()
