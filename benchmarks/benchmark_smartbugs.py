"""smartbugs-curated —— 第 8 个靶场，第一个**真实 Solidity** 基准。

## 为什么需要这个靶场

Solidity 规则（Module 6）此前只靠 [57] 合成夹具锁定。`smartbugs/smartbugs-curated`
是社区权威数据集：`dataset/reentrancy/`（31 个合约）与 `dataset/access_control/`
（18 个合约），官方 `vulnerabilities.json` 给出漏洞行号 —— 含漏洞行的函数为
vul，其余函数构成**真实 safe 分母**（合成夹具给不出负样本分布）。

## 真值来源

`vulnerabilities.json`：`{path, vulnerabilities: [{lines, category}]}`。
真值按行号映射到函数：函数 [start_line, end_line] 覆盖任一标注行 → vul，
同文件其余函数 → safe。映射脚本会打印全部三元组供抽查。

## DISPUTED（口径分歧，不计入指标）

`parity_wallet_bug_1.sol` 与 `parity_wallet_bug_2.sol` 的 `kill` 函数
**代码逐字相同**（`onlymanyowners` 多签保护 + `suicide(_to)`），官方真值
却一处不标、一处标注为漏洞 —— 同一函数不可能既是 safe 又是 vul。
不为分数改判据（记忆条 34），把两个 kill 都记入 DISPUTED 剔除计分；
规则对相同代码给出相同判定，这本身就是该有的性质。

## Module 13 修复记录（真实合约抓出的判据坑）

1. `_looks_solidity` 要求 pragma/contract 关键字 —— 函数级切片没有
   文件头，恒 False，全部静默退 None；
2. 老语法 `msg.sender.call.value(x)()`（0.4.x 主流）不在外部调用集合；
3. modifier 可以无参（`modifier onlyowner {`），带参正则漏掉整类；
4. modifier 保护必须看**实现体**里的 msg.sender 恒等检查；纯状态门
   （parity `only_uninitialized` 查 m_numOwners）不是身份检查，拿它
   判安全会把 initWallet 判反 —— 方向错误比退回恶劣；
5. 错名构造函数（Rubixi 的 `DynamicPyramid`）= 函数名 != 合约名却写
   owner 态 → True；同名才是构造函数，正常初始化不判。

## 门禁（--strict）

safe 负样本**零误报（FPR = 0）**，且判过方向的样本 FN = 0
（判据宁退 None 不判反）。退回 None 交模型，不阻塞门禁。

## 模型层（Module 17，`--model` / `--offline` / `--scope`）

规则只定论了 86/246（Module 18 补了只读预筛后），剩下 160 条退回 ——
这些正是模型该接手的部分，也是"Solidity 赛道的模型 TPR/FPR"此前完全空白的
原因（类目没注册，`audit_unit_for` 拿到 `VC.get("reentrancy") is None` 直接空转）。

口径四条：

1. **默认只跑退回批**（`--scope fallback`）。把规则已判对的样本混进来会稀释
   模型分数，看不出模型贡献；
2. **`--scope all` 是为分母服务的**。退回批里 vul 只有 4 / 11 条，都在 20 以下，
   按记忆条 3 根本不能下 TPR 结论；跑全体后分母是 30 / 18 与 113 / 85，
   才谈得上"模型召回率是多少"。报告会同时切出退回子集，两口径可对比；
3. **空 hypothesis ≠ 调用失败**。空列表是"场景未命中"这个合法结论（TN），
   `flagged=None` 才是网络/解析失败，单列剔除、绝不折算成"无漏洞"；
4. **分母不足只记录不下结论**（记忆条 3）。

模型层**不参与 `--strict` 退出码** —— 模型非确定性，拿它做门禁等于把
随机性写进 CI。离线门禁（run_all / pre-push）必须显式 `--offline`。

## Module 18：只读预筛（规则层，不是提示词）

`view` / `pure` / `constant` 是**编译器强制**的：不许写状态（constant/view）
甚至不许读（pure）。重入要在"外部调用之后写状态"才有窗口，越权要写状态
才有特权动作 —— 所以只读函数对这两类都是确定性 safe。放在规则层而不是
提示词里：提示词是建议，编译器是事实。

实测收益：退回批 197 → 160，规则覆盖率 49/246 → 86/246（35%），
86/86 全对、safe 零误报、零判反；模型 FPR 分母从 197 条里的 182 safe
收敛到 160 条里的 145 safe（仍 ≥20，结论强度不降）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "smartbugs-curated-main"

CATEGORIES = ["reentrancy", "access_control", "unchecked_low_level_calls"]

# 口径分歧剔除表：(文件名, 函数名)。同一函数在官方数据集里真值相反。
DISPUTED = {
    ("parity_wallet_bug_1.sol", "kill"),
    ("parity_wallet_bug_2.sol", "kill"),
}


async def _model_stage(rows: list[dict], args) -> list[dict]:
    """把样本交模型。跑哪一批由 `--scope` 决定：

    · `fallback`（默认）：只跑规则退回批。模型指标的分母是"规则查不出的
      那部分"，把规则已判对的样本混进来会稀释成规则分数。
    · `all`：跑全部登记样本。存在的理由是**分母**：退回批里
      reentrancy 只有 4 条 vul、access_control 11 条，都在 20 以下，
      按记忆条 3 根本不能下 TPR 结论。跑全体后分母是 30 / 18 与
      112 / 85，才谈得上"模型召回率是多少"。
      代价是这批里混了规则已经判对的样本，所以报告**分两块**打印：
      全体（分母充足）与其中的退回子集（与 fallback 口径可对比）。

    三件事必须分开：
      ① `flagged is None` = 调用失败（网络/超时/解析），**单列剔除**，绝不折算成
         "无漏洞" —— 否则一次断网会被记成一批漏报；
      ② 空 hypothesis 列表是"场景未命中"这个**合法结论**，不是失败。旧 harness
         （hellojavasec）把空的当失败，等于把 TN 全扔了，这里不复制那个坑；
      ③ 模型不给结论的门禁权：`--strict` 只锁规则层，模型侧只出指标。
    """
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
                    "category": r["category"], "real_vuln": r["real_vuln"],
                    # 记住规则层对这个样本的结论：报告要能切出"退回子集"
                    "rule": r.get("rule")}
            try:
                hs = await matcher.audit_unit_for(r["unit"], [r["category"]],
                                                  "solidity_web3")
            except Exception as e:                      # 超时 / 熔断 / 连接
                return {**base, "flagged": None, "detail": f"{type(e).__name__}: {e}"[:160],
                        "elapsed_s": round(time.time() - t0, 1)}
            if any("LLM 调用失败" in (h.reasoning_summary or "") for h in hs):
                # 带上原始异常：只写"调用失败"会让 call_failed 变成无法
                # 分类的黑箱（Module 19 之前 5 条全是这个状况）。
                return {**base, "flagged": None,
                        "detail": next(h.reasoning_summary for h in hs
                                       if "LLM 调用失败" in h.reasoning_summary)[:200],
                        "elapsed_s": round(time.time() - t0, 1)}
            h = hs[0] if hs else None
            return {**base, "flagged": bool(h.property_missing) if h else False,
                    "reason": (h.reasoning_summary if h else "场景未命中")[:160],
                    "elapsed_s": round(time.time() - t0, 1)}

    return list(await asyncio.gather(*(one(r) for r in rows)))


def _metrics(sub: list[dict]) -> dict:
    tp = sum(1 for m in sub if m["flagged"] and m["real_vuln"])
    fn = sum(1 for m in sub if not m["flagged"] and m["real_vuln"])
    fp = sum(1 for m in sub if m["flagged"] and not m["real_vuln"])
    tn = sum(1 for m in sub if not m["flagged"] and not m["real_vuln"])
    return {"n": len(sub), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "tpr": round(tp / (tp + fn), 3) if (tp + fn) else None,
            "fpr": round(fp / (fp + tn), 3) if (fp + tn) else None,
            "tpr_denom": tp + fn, "fpr_denom": fp + tn}


def _print_block(title: str, sub: list[dict]) -> dict:
    print(f"\n  {title}")
    per: dict[str, dict] = {}
    for cat in CATEGORIES:
        rows_c = [m for m in sub if m["category"] == cat]
        if not rows_c:
            continue
        mt = _metrics(rows_c)
        per[cat] = mt
        print(f"    {cat:15} 有效 {mt['n']:3}  TP={mt['tp']:<3} FN={mt['fn']:<3} "
              f"FP={mt['fp']:<3} TN={mt['tn']:<3}")
        tpr_s = "—" if mt["tpr"] is None else f"{mt['tpr'] * 100:.1f}%"
        fpr_s = "—" if mt["fpr"] is None else f"{mt['fpr'] * 100:.1f}%"
        n1 = "" if mt["tpr_denom"] >= 20 else "  ← 漏洞分母 <20，只记录不下结论"
        n2 = "" if mt["fpr_denom"] >= 20 else "  ← safe 分母 <20，只记录不下结论"
        print(f"                     TPR={tpr_s}（分母 {mt['tpr_denom']}）{n1}")
        print(f"                     FPR={fpr_s}（分母 {mt['fpr_denom']}）{n2}")
    return per


def _report_model(model_rows: list[dict], model_name: str, scope: str) -> dict:
    """按类目分别报 TPR / FPR，分母不足的**只记录不下结论**（记忆条 3）。"""
    ok = [m for m in model_rows if m["flagged"] is not None]
    err_rows = [m for m in model_rows if m["flagged"] is None]
    err = len(err_rows)
    print()
    print("=" * 72)
    print(f"模型层（scope={scope}，送审 {len(model_rows)} 条，有效 {len(ok)} / "
          f"调用失败 {err}）")
    print("=" * 72)
    if err:
        print(f"! 调用失败 {err} 条已剔除，不计为'无漏洞'（网络问题 ≠ 漏报）。"
              f"逐条原因：")
        for m in err_rows:
            print(f"    {m['file'][:46]}:{m['unit']}  {m['category']}  "
                  f"{str(m.get('detail', ''))[:110]}")

    per_all = _print_block("全体受测样本", ok)
    fb = [m for m in ok if m["rule"] is None]
    per_fb = {}
    if scope == "all" and fb:
        per_fb = _print_block(f"其中规则退回批（{len(fb)} 条，与 fallback 口径可对比）", fb)

    if ok:
        print("\n  模型误报（safe 判 True）样本：")
        fps = [m for m in ok if m["flagged"] and not m["real_vuln"]]
        for m in fps[:15]:
            print(f"    {m['file'][:46]}:{m['unit']}  {m['category']}"
                  f"  {m.get('reason', '')[:60]}")
        if not fps:
            print("    （无）")
        print("\n  模型漏报（vul 判 False）样本：")
        fns = [m for m in ok if not m["flagged"] and m["real_vuln"]]
        for m in fns[:15]:
            print(f"    {m['file'][:46]}:{m['unit']}  {m['category']}"
                  f"  {m.get('reason', '')[:60]}")
        if not fns:
            print("    （无）")
    out = {"model": model_name, "scope": scope, "n_sent": len(model_rows),
           "n_valid": len(ok), "call_failed": err, "per_category": per_all,
           # 失败样本连原因一起落盘：不写进 json 的话，下一轮只能看到
           # "5 条失败"这个数字，没法判断是超时、熔断还是解析问题。
           "call_failed_rows": [{k: m.get(k) for k in ("file", "unit", "category",
                                                       "detail")}
                                for m in err_rows]}
    if per_fb:
        out["fallback_subset"] = per_fb
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="safe 负样本零误报 + 零判反（CI 门禁）")
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组供抽查")
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", "glm-5.3-flash"),
                    help="模型阶段使用的模型名")
    ap.add_argument("--offline", action="store_true",
                    help="只跑规则层，不发任何模型请求（CI / pre-push 用）")
    ap.add_argument("--concurrency", type=int, default=6, help="模型阶段并发数")
    ap.add_argument("--scope", choices=["fallback", "all"], default="fallback",
                    help="fallback=只跑规则退回批（默认）；all=跑全部登记样本"
                         "（TPR 分母才够，报告会同时切出退回子集）")
    ap.add_argument("--limit", type=int, default=0,
                    help="模型阶段最多跑多少条退回样本（0=全部，冒烟用）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "smartbugs.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    meta_file = repo / "vulnerabilities.json"
    if not meta_file.exists():
        print(f"! 找不到 {meta_file}")
        sys.exit(2)
    meta = {Path(x["path"]).name: x
            for x in json.loads(meta_file.read_text(encoding="utf-8"))}

    rows, disputed_rows = [], []
    total = 0
    slicer = SoliditySlicer(repo)
    for cat in CATEGORIES:
        units = slicer.extract_entry_units(repo / "dataset" / cat)
        for u in units:
            entry = meta.get(Path(u.file_path).name)
            if not entry:
                continue
            vul_lines = {l for v in entry["vulnerabilities"]
                         if v["category"] == cat for l in v["lines"]}
            if not vul_lines:
                continue
            total += 1
            truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
            row = {"unit": u, "category": cat, "real_vuln": truth,
                   "file": Path(u.file_path).name}
            if (row["file"], u.unit_name) in DISPUTED:
                disputed_rows.append(row)
            else:
                rows.append(row)

    vul_n = sum(1 for r in rows if r["real_vuln"])
    print(f"靶场：{repo}")
    print(f"[1/2] 切出函数 {total} 个，登记 {len(rows)} 条"
          f"（vul {vul_n} / safe {len(rows) - vul_n}），"
          f"口径分歧剔除 {len(disputed_rows)} 条")
    if args.list:
        for r in disputed_rows:
            print(f"      [DISPUTED] {r['file']}:{r['unit'].unit_name}")

    print("[2/2] 规则层判定...")
    wrong, reverse_fn, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        r["rule"] = rv            # 留给模型层切"退回子集"（--scope all）
        if rv is None:
            fallback.append(r)
        elif rv is True and not r["real_vuln"]:
            wrong.append(r)                    # 误报
        elif rv is False and r["real_vuln"]:
            reverse_fn.append(r)               # 判反（比退回恶劣）
    judged = len(rows) - len(fallback)
    right = judged - len(wrong) - len(reverse_fn)
    safe_n = len(rows) - vul_n

    print()
    print("=" * 72)
    print("smartbugs-curated 结果（规则层，零改动）")
    print("=" * 72)
    for cat in CATEGORIES:
        sub = [r for r in rows if r["category"] == cat]
        sub_v = sum(1 for r in sub if r["real_vuln"])
        tp = sum(1 for r in sub if r not in fallback and r not in wrong
                 and r not in reverse_fn and r["real_vuln"] and
                 rule_verdict(cat, r["unit"].source_code) is True)
        print(f"  {cat:15} 登记 {len(sub):3}（vul {sub_v} / safe {len(sub) - sub_v}）")
    print(f"登记样本              ：{len(rows)}（safe 分母 {safe_n}）")
    print(f"规则确定性判定        ：{judged}/{len(rows)}（退回 {len(fallback)}）")
    print(f"判定正确              ：{right}/{judged}")
    if wrong:
        print("\n! 误报（safe 判 True）—— strict 门禁必须为 0：")
        for r in wrong:
            print(f"  {r['file']}:{r['unit'].unit_name}  {r['category']}")
    if reverse_fn:
        print("\n! 判反（vul 判 False）—— 比退回恶劣，必须为 0：")
        for r in reverse_fn:
            print(f"  {r['file']}:{r['unit'].unit_name}  {r['category']}")
    if disputed_rows:
        print(f"\n口径分歧剔除 {len(disputed_rows)} 条（不计入任何指标）：")
        for r in disputed_rows:
            print(f"  {r['file']}:{r['unit'].unit_name}  官方真值={r['real_vuln']}")

    # ---------------- 模型层 ----------------
    model_stats = None
    pool = rows if args.scope == "all" else fallback
    todo = pool[:args.limit] if args.limit else pool
    if args.offline or not todo:
        why = "offline" if args.offline else "无可送审样本"
        print(f"\n模型层：跳过（{why}）")
        model_stats = {"model": None, "skipped": why, "n_fallback": len(fallback)}
    else:
        print(f"\n模型层：{args.model} 判定 {len(todo)} 条样本（scope={args.scope}，"
              f"并发 {args.concurrency}）...", flush=True)
        model_rows = asyncio.run(_model_stage(todo, args))
        model_stats = _report_model(model_rows, args.model, args.scope)

    out = {
        "target": str(repo),
        "total_functions": total,
        "registered": len(rows),
        "safe_denominator": safe_n,
        "decided": judged,
        "correct": right,
        "fp": len(wrong),
        "reverse_fn": len(reverse_fn),
        "fallback": len(fallback),
        "disputed": [{"file": r["file"], "unit": r["unit"].unit_name}
                     for r in disputed_rows],
        "model": model_stats,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        if wrong or reverse_fn:
            print("\nSTRICT 门禁：未通过 ✘")
            sys.exit(1)
        print("\nSTRICT 门禁：通过 ✔（safe 零误报 / 零判反）")


if __name__ == "__main__":
    main()
