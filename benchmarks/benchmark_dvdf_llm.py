"""DVDF 全量 LLM 实时基准（免费模型优先）。

对 damn-vulnerable-defi 全部挑战合约跑 GPTScan 式两步法：
  Tier-1（免费模型）四类场景判断 → Tier-2（deepseek-v4-pro）反方挑刺
金标准：每个挑战目录内置一个已植入漏洞。

用法：
  python benchmarks/benchmark_dvdf_llm.py [--limit 60] [--output report_dvdf_llm.md]
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli import load_dotenv
from core.agents.router import TwoTierRouter, extract_json
from core.agents.skeptic_reviewer import SkepticReviewer
from core.context.symbol_indexer import SymbolIndexer
from core.models import CodeUnit, Language, VulnHypothesis
from core.slicer.web3_slither import SoliditySlicer

WEB3_SCENARIOS = [
    ("reentrancy", "该函数是否存在外部调用（call/transfer/函数回调）发生在关键状态变量更新之前，或外部调用者可在回调中重入改变记账？"),
    ("unauthorized_withdraw", "该函数是否允许提取/转出资金或代币，但缺少 onlyOwner/onlyRole 等权限修饰符或显式的归属校验？"),
    ("price_manipulation", "该函数是否使用现货余额/价格（如 balanceOf 比值、getReserves）作为定价依据，且该价格可被单笔交易操纵？"),
    ("precision_loss", "金额公式中是否存在减法与乘法混排且未用括号保证优先级，或不安全的整除顺序导致精度损失？"),
]

SYSTEM = ("You are a defensive smart-contract auditor performing static data-flow "
          "reachability analysis. Answer strictly in the requested JSON format.")

PROMPT_TMPL = """Analyze this Solidity function for logic vulnerabilities.

Questions (answer each "Yes" or "No"):
{questions}

Output ONLY JSON like {{"reentrancy": "No", "unauthorized_withdraw": "No", "price_manipulation": "No", "precision_loss": "No"}}
For each "Yes", append an "evidence" object: {{"<type>": {{"answer": "Yes", "evidence": "one sentence"}}}}

Function `{fn}` (file: {file}):
```solidity
{code}
```"""


class Web3LLMMatcher:
    def __init__(self, router: TwoTierRouter, concurrency: int = 4):
        self.router = router
        self.sem = asyncio.Semaphore(concurrency)

    async def audit_unit(self, u: CodeUnit) -> list[VulnHypothesis]:
        questions = "\n".join(f'"{tid}": {q}' for tid, q in WEB3_SCENARIOS)
        prompt = PROMPT_TMPL.format(questions=questions, fn=u.unit_name,
                                    file=Path(u.file_path).name, code=u.source_code[:4000])
        async with self.sem:
            try:
                raw = await self.router.tier1.chat(
                    [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                    temperature=0.0)
            except Exception as e:
                print(f"    [skip] {u.unit_name}: {e}")
                return []
        try:
            verdicts = extract_json(raw)
        except ValueError:
            return []
        hyps = []
        for tid, _ in WEB3_SCENARIOS:
            entry = verdicts.get(tid)
            if isinstance(entry, dict):
                yes = entry.get("answer", "").lower() == "yes"
                evidence = entry.get("evidence", "")
            else:
                yes = str(entry).lower() == "yes"
                evidence = ""
            if yes:
                hyps.append(VulnHypothesis(
                    unit=u, vuln_type=tid, scenario_hit=True,
                    property_missing=evidence or "(模型未给出证据)",
                    reasoning_summary=f"Tier-1 LLM 判定 {tid}", confidence=0.5))
        return hyps

    async def audit_repo(self, units: list[CodeUnit]) -> list[VulnHypothesis]:
        results = await asyncio.gather(*[self.audit_unit(u) for u in units])
        return [h for sub in results for h in sub]


async def main(limit: int, out: Path):
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    from core.agents.model_selector import auto_select_and_print
    repo = Path(__file__).resolve().parents[1] / "reference_repos" / "damn-vulnerable-defi-master" / "src"

    units = SoliditySlicer().extract_entry_units(repo)
    # 只审影响资金的外部/public 函数，internal 工具函数噪音太大
    units = [u for u in units if "external" in u.decorators_or_modifiers or "public" in u.decorators_or_modifiers]
    units = units[:limit]
    print(f"切片：{len(units)} 个 external/public 函数（limit={limit}）")

    router = TwoTierRouter()
    tier1_model = auto_select_and_print(tier=1)
    router.tier1.model = tier1_model
    matcher = Web3LLMMatcher(router)
    hyps = await matcher.audit_repo(units)
    print(f"Tier-1 假设：{len(hyps)}")

    # Tier-2 反方挑刺（只对假设，付费模型量小）
    if hyps:
        tier2 = TwoTierRouter()
        skeptic = SkepticReviewer(router=tier2)
        kept = []
        for h in hyps:
            try:
                r = await skeptic.review(h)
                kept.append(r)
            except Exception as e:
                print(f"    [skeptic skip] {h.unit.unit_name}: {e}")
                kept.append(h)
        confirmed = [h for h in kept if not h.skeptic_rejected]
    else:
        confirmed = []

    # 报告
    lines = ["# DVDF 全量 LLM 实时审计报告", "",
             f"- 模型：Tier-1={tier1_model}（免费） / Tier-2=deepseek-v4-pro",
             f"- 审计函数：{len(units)}，Tier-1 假设：{len(hyps)}，Skeptic 确认：{len(confirmed)}", ""]
    for h in confirmed:
        lines += [f"## [{h.vuln_type.upper()}] {h.unit.unit_name}",
                  f"- 位置：`{h.unit.file_path}:{h.unit.start_line}`",
                  f"- 证据：{h.property_missing}",
                  f"- 复核：{h.reasoning_summary}", ""]
    if not confirmed:
        lines.append("（无确认发现）")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完成：{out}（确认 {len(confirmed)}）")
    # 已知植入漏洞对照提示
    print("提示：金标准包括 side-entrance/truster/abi-smuggling/puppet-v2 等挑战目录的植入漏洞")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=60)
    p.add_argument("--output", default="report_dvdf_llm.md")
    a = p.parse_args()
    asyncio.run(main(a.limit, Path(a.output)))
