"""GPTScan 式两步法推理（第2周实现，第5周扩展为多语言 / 多类目）。

复刻 GPTScan 的 query_template 设计（prompt_multiple_choice_scenarios /
prompt_single_yes_no_question），把"找漏洞"拆成客观判断题：

  Step 1 — Scenario（Yes/No）: 代码中是否存在该类漏洞对应的危险汇聚点，且入参可达？
  Step 2 — Property（Yes/No）: 汇聚点之前是否已经做了对应防护？

输出 VulnHypothesis 列表（仅保留 property 缺失的）。
合规：全部使用防御合规视角措辞。LLM 可注入（LLMClient 协议），支持 mock 测试。

第5周变更：
  - 由固定 3 个 Web 场景改为按 `core.agents.vuln_categories` 注册表驱动，
    支持 OWASP Benchmark 的 11 个真实类别（sqli/cmdi/xss/...）
  - 新增 code_language 参数，Java 切片渲染为 java 代码块
  - audit_many() 并发初筛（受 max_concurrency 约束），支撑 2700+ 用例跑分
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Callable, Sequence

from core.agents import vuln_categories as VC
from core.agents.router import TwoTierRouter, extract_json
from core.models import CodeUnit, VulnHypothesis

SYSTEM_MESSAGE = (
    "You are a defensive code auditor performing static data-flow reachability "
    "analysis. Answer strictly in the output format requested; no explanations "
    "beyond the format."
)

# 兼容旧接口：默认 Web 赛道场景（IDOR / 越权 / RCE）
WEB_SCENARIOS = [
    {
        "id": "idor",
        "question": ("该函数是否接收客户端可控的资源主键（如 order_id、account_id、user_id），"
                     "并执行数据库读取、修改或删除操作？"),
        "property": ("在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段"
                     "（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？"),
    },
    {
        "id": "authz_bypass",
        "question": ("该函数是否执行敏感管理操作（如修改角色、删除用户、导出数据），"
                     "但其路由未声明权限装饰器？"),
        "property": ("该函数是否被全局鉴权中间件或权限装饰器（如 @login_required、"
                     "@admin_required、Depends(get_admin)）保护？"),
    },
    {
        "id": "rce",
        "question": ("该函数是否将客户端可控输入传入执行类函数"
                     "（如 eval、exec、system、subprocess、pickle.loads）？"),
        "property": ("传入执行类函数的输入在到达前，是否经过白名单校验或参数化处理？"),
    },
]

SCENARIO_PROMPT_TMPL = """You are performing static code analysis on {lang} code.
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

# 配置型缺陷（weakrand / hash / crypto / securecookie）：
# 缺陷在 API/算法选择本身，与外部输入是否可达无关，不能套用污点可达的判据。
CONFIG_SCENARIO_PROMPT_TMPL = """You are performing static code analysis on {lang} code.
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

PROPERTY_PROMPT_TMPL = """You are auditing whether one specific protective property is PRESENT in the code below.

Property:
{property}

Answer with JSON only: {{"protected": "Yes"}} or {{"protected": "No"}}.
Judge ONLY on executable statements that actually run on the audited path.
Comments, string literals, log/error messages, and example URLs in comments are NOT
evidence — they frequently describe the unsafe alternative that this code avoided.
If the protective measure is not present in the executed statements, answer "No".

Code:
```{lang}
{code}
```"""

# 旧版模板（保留给 Python Web 赛道与既有测试）
SCENARIO_PROMPT_TMPL_V1 = """Given the following code, answer the questions below and organize the result in a JSON format like {{"idor": "Yes" or "No", "authz_bypass": "Yes" or "No", "rce": "Yes" or "No"}}.

{questions}

Code:
```python
{code}
```"""

PROPERTY_PROMPT_TMPL_V1 = """Does the following code satisfy this property (answer the property being PRESENT)?
"{property}"
Answer ONLY "Yes" or "No".

Code:
```python
{code}
```"""

LANG_TAG = {"python_web": "python", "java_web": "java", "solidity_web3": "solidity"}


def _is_yes(text: str, field: str) -> bool:
    """从模型输出里判定 Yes/No，兼容 JSON 与裸文本。"""
    try:
        data = extract_json(text)
        if isinstance(data, dict) and field in data:
            return str(data[field]).strip().lower().startswith("y")
    except Exception:
        pass
    low = text.lower()
    if "no" in low and "yes" not in low:
        return False
    return "yes" in low


class ScenarioMatcher:
    """两步法初筛器（运行在 Tier-1 模型上）。

    `scenario_votes` / `property_votes` 控制每个问题问几次取多数（默认 1）。

    为什么默认 1 而不是 3：曾经假设「多次采样取多数能降抖动」，实测证伪了。
    同一份代码、同一个 prompt、temperature=0 连问三次，12 条样本里 5 条不一致
    （抖动率 41.7%）。但把投票接进完整评测做 A/B（每种策略各跑 2 轮 66 样本）后：

      votes=1：两轮翻转 9/66（13.6%）
      votes=3：两轮翻转 9/66（13.6%）  ← 抖动一点没降，成本 ×3

    原因是抖动是 *采样级* 的：3 次里有 2 次错，多数票就稳定地错，投票只把
    噪声从「每轮不同」变成「每轮同一个错误」。所以投票不能当降抖动手段，
    默认关掉；`votes` 字段仅作为审计线索保留（1:2 分歧说明模型在该样本上犹豫，
    confidence 也据此从 0.7 降到 0.45）。真正的确定性只能来自规则与代码事实。
    """

    def __init__(self, router: TwoTierRouter | None = None,
                 llm: Callable[[list[dict]], str] | None = None,
                 code_language: str = "java_web",
                 max_concurrency: int = 6,
                 scenario_votes: int = 1, property_votes: int = 1):
        self.router = router
        self._llm = llm
        self.code_language = code_language
        self.max_concurrency = max_concurrency
        self.scenario_votes = max(1, scenario_votes)
        self.property_votes = max(1, property_votes)

    async def _ask(self, prompt: str) -> str:
        messages = [{"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt}]
        if self._llm is not None:
            # llm 既可能是同步函数（mock / 本地模型），也可能是 async（网关客户端）
            r = self._llm(messages)
            return await r if inspect.isawaitable(r) else r
        if self.router is None:
            raise RuntimeError("需要注入 router 或 llm")
        return await self.router.screen(messages)

    async def _vote(self, prompt: str, field: str, n: int) -> tuple[bool, tuple[bool, ...]]:
        """问 n 次，多数票为结论。

        并发发出而不是串行：n=3 时串行等于把延迟乘 3，并发只多占一点配额。
        奇数票才不会平局；偶数票平局时按「不判定通过」处理（保守，避免误报）。
        """
        if n <= 1:
            return _is_yes(await self._ask(prompt), field), ()
        results = await asyncio.gather(
            *(self._ask(prompt) for _ in range(n)), return_exceptions=True)
        votes: list[bool] = []
        for r in results:
            if isinstance(r, Exception):
                continue
            votes.append(_is_yes(r, field))
        if not votes:
            raise RuntimeError("多次采样全部失败")
        yes = sum(votes)
        return yes * 2 > len(votes), tuple(votes)

    # ---------- 新接口：按类目做两步法 ----------

    async def audit_unit_for(self, unit: CodeUnit, category_keys: Sequence[str],
                             language: str | None = None) -> list[VulnHypothesis]:
        """对单个 unit 按给定类目列表逐一执行 Scenario + Property。"""
        lang = LANG_TAG.get(language or self.code_language, "java")
        out: list[VulnHypothesis] = []
        for key in category_keys:
            cat = VC.get(key)
            if cat is None:
                continue
            # Step 1: Scenario（配置型缺陷走不要求污点可达的模板）
            tmpl = SCENARIO_PROMPT_TMPL if cat.needs_taint else CONFIG_SCENARIO_PROMPT_TMPL
            try:
                hit, s_votes = await self._vote(
                    tmpl.format(lang=lang, question=cat.sink_question,
                                code=unit.source_code),
                    "hit", self.scenario_votes)
            except Exception as e:
                out.append(VulnHypothesis(unit=unit, vuln_type=key, scenario_hit=False,
                                          property_missing="",
                                          reasoning_summary=f"LLM 调用失败：{e}"))
                continue
            if not hit:
                continue
            # Step 2: Property
            try:
                protected, p_votes = await self._vote(
                    PROPERTY_PROMPT_TMPL.format(
                        property=cat.property, lang=lang, code=unit.source_code),
                    "protected", self.property_votes)
            except Exception as e:
                out.append(VulnHypothesis(unit=unit, vuln_type=key, scenario_hit=True,
                                          property_missing="",
                                          reasoning_summary=f"LLM 调用失败：{e}"))
                continue
            all_votes = s_votes + p_votes
            unanimous = bool(all_votes) and len(set(all_votes)) == 1
            # 有一轮说"不安全"才判漏洞，但票数越悬殊置信度越低：
            # 3:0 给 0.7，2:1 给 0.45 —— 后者应当优先送人工复核而不是直接采信。
            if protected:
                conf = 0.3 if unanimous else 0.2
            else:
                miss = sum(1 for v in p_votes if not v)
                conf = 0.7 if miss == len(p_votes) else 0.45
            out.append(VulnHypothesis(
                unit=unit, vuln_type=key, scenario_hit=True,
                property_missing="" if protected else cat.property,
                reasoning_summary=(f"Scenario={key}=HIT, PropertyCheck="
                                   f"{'PRESENT' if protected else 'MISSING'}"
                                   f"{'' if unanimous else '（采样不一致）'}"),
                confidence=conf,
                votes=all_votes,
            ))
        return out

    async def audit_many(self, jobs: Sequence[tuple[CodeUnit, Sequence[str]]],
                         language: str | None = None) -> list[list[VulnHypothesis]]:
        """并发初筛：jobs 为 (unit, category_keys) 列表，返回与 jobs 对齐的结果。"""
        sem = asyncio.Semaphore(max(1, self.max_concurrency))

        async def _one(unit, keys):
            async with sem:
                return await self.audit_unit_for(unit, keys, language)

        return list(await asyncio.gather(*(_one(u, k) for u, k in jobs)))

    # ---------- 旧接口（Python Web 赛道，保持向后兼容） ----------

    async def audit_unit(self, unit: CodeUnit) -> list[VulnHypothesis]:
        """对单个 CodeUnit 执行旧版场景两步法。"""
        questions = "\n".join(f'"{s["id"]}": Does the code hit this scenario? "{s["question"]}"'
                              for s in WEB_SCENARIOS)
        s1 = await self._ask(SCENARIO_PROMPT_TMPL_V1.format(questions=questions,
                                                            code=unit.source_code))
        verdicts = extract_json(s1)

        hypotheses: list[VulnHypothesis] = []
        for scenario in WEB_SCENARIOS:
            if str(verdicts.get(scenario["id"], "No")).lower() != "yes":
                continue
            p = await self._ask(PROPERTY_PROMPT_TMPL_V1.format(property=scenario["property"],
                                                               code=unit.source_code))
            missing = "no" in p.lower()
            hypotheses.append(VulnHypothesis(
                unit=unit, vuln_type=scenario["id"], scenario_hit=True,
                property_missing=(scenario["property"] if missing else ""),
                reasoning_summary=f"Scenario={scenario['id']}, PropertyCheck={'MISSING' if missing else 'present'}",
                confidence=0.6 if missing else 0.1,
            ))
        return hypotheses

    async def audit_repo(self, units: list[CodeUnit]) -> list[VulnHypothesis]:
        """旧漏斗：全部 unit 走 Tier-1，仅 property_missing 的进入 Tier-2 队列。"""
        all_h: list[VulnHypothesis] = []
        for unit in units:
            all_h.extend(await self.audit_unit(unit))
        return [h for h in all_h if h.property_missing]
