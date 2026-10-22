"""not-so-smart-contracts（Trail of Bits）—— 第 10 个靶场：补 access_control 分母。

## 为什么需要它

smartbugs + DeFiVulnLabs 合并后 access_control 模型 TPR 分母恰好 20 ——
卡在"只记录不下结论"的线上，没有一点裕度（记忆条 3）。本靶场补上
Trail of Bits 官方漏洞集，README 逐条指名漏洞函数与案例（Rubixi、Parity
initWallet），真值可以逐行核对。

## 真值口径

· 只收**目录 README 指名**的漏洞函数（"onlyOwner modifier is defined
  but not used" / "uses DynamicPyramid instead of Rubixi as a
  constructor" / "see initWallet"）。不收"我觉得这里也有问题"。
· 修复合约/函数记 safe（`changeOwner_fixed` 与漏洞函数成对，同
  DeFiVulnLabs 的成对真值口径）。
· **honeypots 目录不收**：README 描述的是"陷阱设计"（对受害者不可
  利用），同一个函数既"有洞"又"不可利用"——口径自相矛盾，收进去
  就是在给真值表掺沙子。
· 标定按 (文件名, start_line) 精确匹配切片，对不上直接 fail
  （防上游漂移静默失效）。

## 数据源事实记录（先探针后动刀）

· 跨文件继承 modifier 在本数据源 **0 命中**（coin.sol / KOTH /
  incorrect_constructor 的父合约 modifier 全部同文件）——切片器的
  mod_spans 本就是文件级全局，天然覆盖；跨文件检索不做投机升级。
· `Reentrancy.sol withdrawBalance_fixed_2` 是 transfer() 2300 gas
  事实（本靶场探针抓出的真误报），Module 21 修复后收进真值表。

## 门禁（--strict）

1. safe 零误报、判过方向零判反（宁退 None 不判反）；
2. 真值表全命中；
3. 确定性判定 ≥ 3 条。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "not-so-smart-contracts-master"

CATEGORIES = ["reentrancy", "access_control"]

# (相对路径, 函数起始行, 函数名, 类目, 是否漏洞, 标定依据)
TRUTH: list[tuple[str, int, str, str, bool, str]] = [
    # ---- unprotected_function（README："onlyOwner modifier is defined but not used"）----
    ("unprotected_function/Unprotected.sol", 18, "changeOwner", "access_control", True,
     "README 指名：onlyOwner 修饰符定义了但没用上，任何人可夺 owner"),
    ("unprotected_function/Unprotected.sol", 24, "changeOwner_fixed", "access_control", False,
     "同一合约的修复对：挂上 onlyowner 修饰符 —— 成对真值"),
    ("unprotected_function/WalletLibrary_source_code/WalletLibrary.sol",
     217, "initWallet", "access_control", True,
     "README 指名 Parity 案例：For code, see initWallet（无 anyonlymanyowners 保护）"),
    # ---- wrong_constructor_name（README 指名两个案例）----
    ("wrong_constructor_name/Rubixi_source_code/Rubixi.sol", 16, "DynamicPyramid",
     "access_control", True,
     "README：uses DynamicPyramid instead of Rubixi as a constructor —— "
     "错名构造函数落在运行时字节码，任何人可改 owner"),
    ("wrong_constructor_name/incorrect_constructor.sol", 13, "IamMissing",
     "access_control", True,
     "README：An incorrectly named constructor（注释：Anyone can call）"),
    # ---- reentrancy（README 指名 withdraw 场景与修法）----
    ("reentrancy/Reentrancy.sol", 14, "withdrawBalance", "reentrancy", True,
     "README 攻击场景原型：call.value 外转后写 userBalance=0 —— 违反 CEI"),
    ("reentrancy/Reentrancy.sol", 23, "withdrawBalance_fixed", "reentrancy", False,
     "源码注释指名修复：state has to be changed before the call —— 成对真值"),
    ("reentrancy/Reentrancy.sol", 33, "withdrawBalance_fixed_2", "reentrancy", False,
     "源码注释指名：send() and transfer() are safe against reentrancy —— "
     "2300 gas 津贴，VM 层重入不可能（Module 21 规则早退，曾为真误报）"),
]


def _resolve(units) -> tuple[list[dict], list[str]]:
    index = {}
    for u in units:
        index.setdefault(
            (str(Path(u.file_path).relative_to(_base)) if _base else Path(u.file_path).name,
             u.start_line), []).append(u)
    rows, missing = [], []
    for rel, line, func, cat, is_vul, why in TRUTH:
        cands = [u for u in index.get((rel, line), [])
                 if u.unit_name == func]
        if not cands:
            # 兜底：按文件名匹配（防 rel 路径写法与平台差异）
            cands = [u for (f, l), us in index.items() if Path(f).name == Path(rel).name
                     and l == line for u in us if u.unit_name == func]
        if not cands:
            missing.append(f"{rel}:{line} {func}（真值表与源码不同步）")
            continue
        u = cands[0]
        rows.append({"file": rel, "unit": u, "unit_name": func, "category": cat,
                     "real_vuln": is_vul, "why": why,
                     "line": f"{u.start_line}-{u.end_line}"})
    return rows, missing


_base = ""


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
    """口径与 smartbugs / DeFiVulnLabs 完全一致：
    flagged=None = 调用失败单列剔除；空 hypothesis = 合法 TN；
    模型层不进 --strict 退出码。"""
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
        print("! 调用失败样本（已剔除，不计为'无漏洞'）：")
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
    return {"model": model_name, "n_sent": len(model_rows), "n_valid": len(ok),
            "call_failed": len(err),
            "call_failed_rows": [{k: m[k] for k in ("file", "unit", "category", "detail")}
                                 for m in err],
            "per_category": per,
            "rows": [{k: m.get(k) for k in ("file", "unit", "category",
                                            "real_vuln", "flagged", "reason")}
                     for m in model_rows]}


def main() -> int:
    global _base
    ap = argparse.ArgumentParser(description="not-so-smart-contracts 基准（README 指名真值）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑规则层（CI 门禁）")
    ap.add_argument("--strict", action="store_true",
                    help="safe 零误报 + 零判反 + 真值表全命中（CI 门禁）")
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", ""), help="模型名")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--list", action="store_true", help="打印逐条判定")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "nssc.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}（安装：curl -sL -o x.zip "
              f"https://codeload.github.com/crytic/not-so-smart-contracts/zip/refs/heads/master）")
        return 2
    _base = repo

    slicer = SoliditySlicer(repo)
    units = list(slicer.extract_entry_units(repo))
    rows, missing = _resolve(units)

    print("not-so-smart-contracts 结果（Trail of Bits 官方漏洞集）")
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
            print(f"    {r['file']:55} {r['unit_name']:20} 真值="
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
