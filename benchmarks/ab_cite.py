"""A/B：要求模型引用证据（Cite-Before-Verdict）对判定质量的影响。

测两件事：

1. **核验通过率** —— 有多少采样能通过"引用必须真实存在且非注释行"的核验。
   通过率低说明机制在误伤合规输出，那比不启用更糟（会把模型判成"什么都判不出来"）。
2. **判定准确率** —— 同一批样本，旧 prompt（只问 Yes/No）vs 新 prompt（须引用）。
   核验本身只影响"票是否作废"，但要求引用会改变模型的**观察行为**：
   它必须先定位到具体一行，于是不得不读完整个切片，而不是凭印象只看方法体。

为什么这个实验值得固化：2026-10-18 实测发现新 prompt 在两个模型上都
恰好 +12.5 个百分点，翻转全部集中在 CORS 那几条"防护在框架装配里、
方法体只有 return token;"的样本上。这不是"防编造"能解释的收益，
而是**强制模型读完证据**的收益。

用法：
    python benchmarks/ab_cite.py                        # 默认 longcat，24 条
    python benchmarks/ab_cite.py beam-free 40           # 换模型/换样本量
    python benchmarks/ab_cite.py --rate-only            # 只测核验通过率
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import core.agents.scenario_matcher as sm
from core.agents.router import OpenAICompatClient, TwoTierRouter, extract_json
from core.slicer.java_servlet import JavaSlicer
from benchmarks.benchmark_javaseccode import classify

DEFAULT_REPO = ROOT / "reference_repos" / "java-sec-code"
DEFAULT_MODEL = "longcat-2.5-preview-free"
# 只挑"模型真的要判"的类目：规则覆盖到的不该出现在这里，
# 否则 A/B 测的是规则而不是 prompt。
CATS = {"xss", "sqli", "cors", "spel", "cmdi", "pathtraver"}

# 旧版 prompt（改造前），保留用于对照。改动这里会让 A/B 失去意义。
OLD_TAINT = """You are performing static code analysis on {lang} code.
Decide whether the code below exhibits the described insecure condition.

Question:
{question}

Answer with JSON only: {{"hit": "Yes"}} or {{"hit": "No"}}.

Answer "Yes" only if BOTH hold: (1) the described dangerous operation or insecure
configuration actually exists in the executable statements, and
(2) a value that originates from outside the function (request parameter, cookie,
header) flows into it. If the operation only receives constant/literal values, answer "No".

Code:
```{lang}
{code}
```"""

OLD_CONFIG = """You are performing static code analysis on {lang} code.
Decide whether the code below exhibits the described insecure condition.

Question:
{question}

Answer with JSON only: {{"hit": "Yes"}} or {{"hit": "No"}}.

This is a configuration-strength check: it does NOT require external input to reach the
call. Answer "Yes" if the insecure API or weak algorithm/configuration described above
is actually used in the executable statements. Commented-out code and doc comments
do not count.

Code:
```{lang}
{code}
```"""


def load_rows(limit: int):
    units = JavaSlicer(DEFAULT_REPO).extract_entry_units()
    units = [u for u in units if not u.unit_name.endswith(".doGet")]
    rows = []
    for u in units:
        cat, truth, _ = classify(u)
        if cat and truth is not None and cat in CATS:
            rows.append((u, cat, truth))
    return rows[:limit]


async def ask(unit, key: str, model: str, use_cite: bool):
    """返回 (是否通过核验, 判定 or None, 引用行)。None 判定 = 调用失败或核验不过。"""
    cat = sm.VC.get(key)
    if use_cite:
        tmpl = sm.SCENARIO_PROMPT_TMPL if cat.needs_taint else sm.CONFIG_SCENARIO_PROMPT_TMPL
    else:
        tmpl = OLD_TAINT if cat.needs_taint else OLD_CONFIG
    matcher = sm.ScenarioMatcher(router=TwoTierRouter(tier1=OpenAICompatClient(model=model)))
    prompt = tmpl.format(lang="java", question=cat.sink_question, code=unit.source_code)
    try:
        data = extract_json(await matcher._ask(prompt))
    except Exception:
        return False, None, ""
    verdict = str(data.get("hit", "")).strip().lower().startswith("y")
    if not use_cite:
        return True, verdict, ""
    evidence = str(data.get("evidence_line", ""))
    ok, _why = sm.verify_evidence(unit.source_code, evidence)
    return ok, (verdict if ok else None), evidence


async def run(model: str, limit: int, rate_only: bool):
    rows = load_rows(limit)
    if not rows:
        print("没有可判定样本，检查 reference_repos/java-sec-code 是否存在")
        return
    print(f"模型 {model}｜样本 {len(rows)} 条｜"
          f"{'只测核验通过率' if rate_only else 'A/B 对照'}", flush=True)

    sem = asyncio.Semaphore(4)

    async def w(u, c, cite):
        async with sem:
            return await ask(u, c, model, cite)

    if rate_only:
        res = await asyncio.gather(*(w(u, c, True) for u, c, _ in rows))
        passed = sum(1 for ok, v, _ in res if ok)
        print(f"\n核验通过 {passed}/{len(rows)}（{passed/len(rows)*100:.1f}%）")
        for (u, c, _), (ok, v, ev) in zip(rows, res):
            if not ok:
                print(f"  被作废：{u.unit_name:26} 引用={ev[:60]!r}")
        return

    old_res = await asyncio.gather(*(w(u, c, False) for u, c, _ in rows))
    new_res = await asyncio.gather(*(w(u, c, True) for u, c, _ in rows))

    def score(res):
        ok = n = 0
        for (_u, _c, truth), (_p, v, _e) in zip(rows, res):
            if v is None:
                continue
            n += 1
            ok += (v == truth)
        return ok, n

    o_ok, o_n = score(old_res)
    n_ok, n_n = score(new_res)
    print("\n" + "=" * 60)
    print(f"旧 prompt（只问 Yes/No）  ：{o_ok}/{o_n}  ({o_ok/max(o_n,1)*100:.1f}%)")
    print(f"新 prompt（须引用证据）   ：{n_ok}/{n_n}  ({n_ok/max(n_n,1)*100:.1f}%)")
    print("=" * 60)

    flips = []
    for (u, c, truth), (_p1, a, _e1), (_p2, b, _e2) in zip(rows, old_res, new_res):
        if a is None or b is None or a == b:
            continue
        flips.append((u.unit_name, truth, a, b))
    if flips:
        print("\n翻转明细：")
        for name, truth, a, b in flips:
            tag = "新对" if b == truth else ("新错" if a == truth else "都错")
            print(f"  {name:26} 真值={truth!s:5} 旧={a!s:5} 新={b!s:5}  {tag}")
    print(f"\n核验通过率：{sum(1 for ok,_,_ in new_res if ok)}/{len(rows)}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rate_only = "--rate-only" in sys.argv
    model = args[0] if args else DEFAULT_MODEL
    limit = int(args[1]) if len(args) > 1 else 24
    asyncio.run(run(model, limit, rate_only))


if __name__ == "__main__":
    main()
