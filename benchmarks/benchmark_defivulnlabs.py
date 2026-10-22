"""DeFiVulnLabs —— 第 9 个靶场：**成对 vuln/fixed 真值** + Solidity 0.8.x。

## 为什么需要它

smartbugs-curated 的 `access_control` 只有 19 个漏洞合约，DISPUTED 剔除后
函数级漏洞分母 18 —— 卡在记忆条 3 的 20 条下限之下，模型 TPR 一直是
"只记录、不下结论"的数字。换靶场才能解，不是跑得不够。

DeFiVulnLabs（SunWeb3Sec）把每个漏洞写成「漏洞合约 + 修复合约」对，
且作者注释里**指名**了漏洞点与修法，真值可以逐行核对。它同时补上
smartbugs 缺的两块：Solidity 0.8.x 语法、成对真值。

## 真值口径（人工标定，每条 why 写明依据）

· 只收**作者注释里指名**的漏洞函数（"wrong visibility" / "missing
  owner check" / "Do not follow check-effect-interaction"）。不收
  "我觉得这里有问题"的样本 —— 那是自证，不是基准。
· 修复合约里的同名函数记 safe。**成对真值是本靶场的核心价值**：
  同一个函数名、同一个业务、只差一条校验，判据到底看的是机制还是
  名字，在这里无处可藏。
· 标定用**源码行号**，脚本按 (文件名, start_line) 精确匹配切片单元。
  对不上直接失败 —— 上游改文件后真值表静默失效比没有真值更危险。
· 只标函数级：文件里的 forge `ContractTest`（攻击演示）不进真值表，
  它证明的是"漏洞可被利用"，不是"哪个函数有洞"。

## 门禁（--strict）

1. safe 负样本**零误报**、判过方向的样本**零判反**（宁退 None 不判反）；
2. 真值表 9 条全部命中切片单元（防上游漂移）；
3. 规则层确定性判定 ≥ 3 条（低于这个数说明切片或词表退化了）。

模型层不参与退出码：模型非确定性，拿它当门禁等于把随机性写进 CI。
离线门禁（run_all / pre-push）必须显式 `--offline`。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.slicer.web3_slither import SoliditySlicer  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "DeFiVulnLabs-main"

CATEGORIES = ["reentrancy", "access_control"]

# (文件名, 函数起始行, 函数名, 类目, 是否漏洞, 标定依据)
TRUTH: list[tuple[str, int, str, str, bool, str]] = [
    # ---- access_control：越权 / 身份校验缺失 ----
    ("Visibility.sol", 53, "changeOwner", "access_control", True,
     "作者注释：wrong visibility of changeOwner function should be onlyOwner"
     "（public 写 owner，任何人可夺取合约）"),
    ("txorigin.sol", 65, "transfer", "access_control", True,
     "README：uses tx.origin 做认证 → 钓鱼绕过；作者注释"
     "check with msg.sender instead of tx.origin"),
    ("NFT-transfer.sol", 74, "transferFrom", "access_control", True,
     "VulnerableERC721 注释：custom transferFrom which missing NFT owner check"
     "（直接 _transfer，不校验调用者）"),
    ("NFT-transfer.sol", 92, "transferFrom", "access_control", False,
     "FixedERC721 同函数加 require(_isApprovedOrOwner(...)) —— 成对修复样本"),
    ("Flashloan-flaw.sol", 89, "executeOperation", "access_control", True,
     "SimpleBankBug 的闪贷回调无 initiator 校验（作者注释：Missing flash loan "
     "initiator check），任何人可直调把资金转走"),
    ("Flashloan-flaw.sol", 125, "executeOperation", "access_control", False,
     "FixedSimpleBank 加 require(_initiator == address(this)) —— 成对修复样本"),
    # ---- reentrancy：CEI 顺序 ----
    ("Reentrancy.sol", 37, "withdrawFunds", "reentrancy", True,
     "EtherStore：先 call 转账，后 -=(且用 if 包着) —— 违反 CEI，"
     "重入可重复取款"),
    ("Reentrancy.sol", 64, "withdrawFunds", "reentrancy", False,
     "EtherStoreRemediated：nonReentrant 锁 + 先扣减后转账 —— 成对修复样本"),
    ("ERC777-reentrancy.sol", 140, "claim", "reentrancy", True,
     "作者注释：_mints[account] += amount // Do not follow "
     "check-effect-interaction；token.transfer 触发 tokensReceived 回调可重入"),
]


def _resolve(units, args) -> tuple[list[dict], list[str]]:
    """真值表 → 切片单元。命中失败是**硬错误**，不静默跳过。"""
    index = {}
    for u in units:
        index.setdefault((Path(u.file_path).name, u.start_line), []).append(u)
    rows, missing = [], []
    for fname, line, func, cat, is_vul, why in TRUTH:
        cands = [u for u in index.get((fname, line), []) if u.unit_name == func]
        if not cands:
            missing.append(f"{fname}:{line} {func}（真值表与源码不同步）")
            continue
        u = cands[0]
        rows.append({"file": fname, "unit": u, "unit_name": func, "category": cat,
                     "real_vuln": is_vul, "why": why,
                     "line": f"{u.start_line}-{u.end_line}"})
    return rows, missing


def _rule_stage(rows: list[dict]) -> tuple[list, list, list]:
    wrong, reverse_fn, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        if rv is None:
            fallback.append(r)
        elif rv == r["real_vuln"]:
            pass
        else:
            (reverse_fn if rv is True else wrong).append(r)
    return wrong, reverse_fn, fallback


async def _model_stage(todo: list[dict], args) -> list[dict]:
    """规则退回的样本交模型。三条口径与 smartbugs 完全一致：

    ① `flagged is None` = 调用失败，单列剔除，绝不折算成"无漏洞"；
    ② 空 hypothesis 是"场景未命中"这个合法结论（TN），不是失败；
    ③ 模型层不进 --strict 退出码。
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
            base = {"file": r["file"], "unit": r["unit_name"],
                    "category": r["category"], "real_vuln": r["real_vuln"]}
            try:
                hs = await matcher.audit_unit_for(r["unit"], [r["category"]],
                                                  "solidity_web3")
            except Exception as e:
                return {**base, "flagged": None,
                        "detail": f"{type(e).__name__}: {e}"[:200],
                        "elapsed_s": round(time.time() - t0, 1)}
            if any("LLM 调用失败" in (h.reasoning_summary or "") for h in hs):
                # 把**原始异常**带进 detail：只写"调用失败"会让 call_failed
                # 变成无法分类的黑箱（Module 19 之前 5 条全是这个状况）。
                return {**base, "flagged": None,
                        "detail": next(h.reasoning_summary for h in hs
                                       if "LLM 调用失败" in h.reasoning_summary)[:200],
                        "elapsed_s": round(time.time() - t0, 1)}
            h = hs[0] if hs else None
            return {**base, "flagged": bool(h.property_missing) if h else False,
                    "reason": (h.reasoning_summary if h else "场景未命中")[:160],
                    "elapsed_s": round(time.time() - t0, 1)}

    return list(await asyncio.gather(*(one(r) for r in todo)))


def _report_model(model_rows: list[dict], n_fallback: int, model_name: str) -> dict:
    ok = [m for m in model_rows if m["flagged"] is not None]
    err = [m for m in model_rows if m["flagged"] is None]
    print()
    print("=" * 72)
    print(f"模型层（只跑规则退回的 {n_fallback} 条，有效 {len(ok)} / "
          f"调用失败 {len(err)}）")
    print("=" * 72)
    if err:
        print("! 调用失败样本（已剔除，不计为'无漏洞'，明细见 json.call_failed_rows）：")
        for m in err:
            print(f"    {m['file']}:{m['unit']}  {m.get('detail', '')[:80]}")
    per: dict[str, dict] = {}
    for cat in CATEGORIES:
        sub = [m for m in ok if m["category"] == cat]
        if not sub:
            continue
        tp = sum(1 for m in sub if m["flagged"] and m["real_vuln"])
        fn = sum(1 for m in sub if not m["flagged"] and m["real_vuln"])
        fp = sum(1 for m in sub if m["flagged"] and not m["real_vuln"])
        tn = sum(1 for m in sub if not m["flagged"] and not m["real_vuln"])
        per[cat] = {"n": len(sub), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
                    "tpr_denom": tp + fn, "fpr_denom": fp + tn,
                    "tpr": None if not (tp + fn) else round(tp / (tp + fn), 3),
                    "fpr": None if not (fp + tn) else round(fp / (fp + tn), 3)}
        print(f"\n  {cat}")
        print(f"    有效判定 {len(sub):3}  TP={tp:<3} FN={fn:<3} FP={fp:<3} TN={tn:<3}")
        t = "—" if per[cat]["tpr"] is None else f"{per[cat]['tpr'] * 100:.1f}%"
        f = "—" if per[cat]["fpr"] is None else f"{per[cat]['fpr'] * 100:.1f}%"
        print(f"    TPR = {t}（分母 {tp + fn}）  FPR = {f}（分母 {fp + tn}）")
        print("    ← 本靶场体量小（9 条真值），单靶场不足以支撑比率结论，"
              "须与 smartbugs 合并口径看")
    return {"model": model_name, "n_sent": len(model_rows), "n_valid": len(ok),
            "call_failed": len(err),
            "call_failed_rows": [{k: m[k] for k in ("file", "unit", "category", "detail")}
                                 for m in err],
            "per_category": per,
            "rows": [{k: m.get(k) for k in ("file", "unit", "category",
                                            "real_vuln", "flagged", "reason")}
                     for m in model_rows]}


def main() -> int:
    ap = argparse.ArgumentParser(description="DeFiVulnLabs 成对真值基准")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑规则层（CI 门禁）")
    ap.add_argument("--strict", action="store_true",
                    help="safe 零误报 + 零判反 + 真值表全命中（CI 门禁）")
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", ""), help="模型名")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--list", action="store_true", help="打印逐条判定")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "defivulnlabs.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}（安装：curl -sL -o x.zip "
              f"https://codeload.github.com/SunWeb3Sec/DeFiVulnLabs/zip/refs/heads/main）")
        return 2

    slicer = SoliditySlicer(repo)
    units = list(slicer.extract_entry_units(repo / "src" / "test"))
    rows, missing = _resolve(units, args)

    print("DeFiVulnLabs 结果（成对 vuln/fixed 真值 + 0.8.x）")
    print("=" * 72)
    print(f"切片单元 {len(units)}，真值表 {len(TRUTH)} 条，命中 {len(rows)} 条")
    if missing:
        print("! 真值表未命中（上游文件已变，先重新标定再跑）：")
        for m in missing:
            print("   ", m)

    print("\n[1/2] 规则层判定...")
    wrong, reverse_fn, fallback = _rule_stage(rows)
    judged = len(rows) - len(fallback)
    safe_n = sum(1 for r in rows if not r["real_vuln"])
    print(f"  确定性判定 {judged}/{len(rows)}（safe 分母 {safe_n}）")
    print(f"  判对 {judged - len(wrong) - len(reverse_fn)}"
          f"  误报 {len(wrong)}  判反 {len(reverse_fn)}  退回模型 {len(fallback)}")
    for r in wrong:
        print(f"    [误报] {r['file']}:{r['unit_name']} ({r['line']})")
    for r in reverse_fn:
        print(f"    [判反] {r['file']}:{r['unit_name']} ({r['line']})")
    if args.list:
        print("\n  逐条：")
        for r in rows:
            rv = rule_verdict(r["category"], r["unit"].source_code)
            tag = "—" if rv is None else ("True" if rv else "False")
            print(f"    {r['file']:24} {r['unit_name']:18} 真值="
                  f"{'vul' if r['real_vuln'] else 'safe':4} 规则={tag}")

    model_stats = None
    todo = fallback[:args.limit] if args.limit else fallback
    if args.offline or not todo:
        why = "offline" if args.offline else "无退回样本"
        print(f"\n模型层：跳过（{why}）")
        model_stats = {"model": None, "skipped": why, "n_fallback": len(fallback)}
    else:
        print(f"\n[2/2] 模型层：{args.model} 判定 {len(todo)} 条退回样本"
              f"（并发 {args.concurrency}）...", flush=True)
        model_rows = asyncio.run(_model_stage(todo, args))
        model_stats = _report_model(model_rows, len(todo), args.model)

    out = {
        "target": str(repo),
        "truth_entries": len(TRUTH),
        "resolved": len(rows),
        "missing": missing,
        "total_functions": len(units),
        "decided": judged,
        "correct": judged - len(wrong) - len(reverse_fn),
        "fp": len(wrong),
        "reverse_fn": len(reverse_fn),
        "fallback": len(fallback),
        "safe_denominator": safe_n,
        "model": model_stats,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        bad = []
        if missing:
            bad.append(f"真值表 {len(missing)} 条未命中")
        if wrong:
            bad.append(f"safe 误报 {len(wrong)} 条")
        if reverse_fn:
            bad.append(f"判反 {len(reverse_fn)} 条")
        if judged < 3:
            bad.append(f"确定性判定仅 {judged} 条（<3，切片或词表退化）")
        if bad:
            print("STRICT FAIL ✘ " + "；".join(bad))
            return 1
        print("STRICT PASS ✔ （零误报 / 零判反 / 真值表全命中）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
