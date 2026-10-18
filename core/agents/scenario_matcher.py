"""GPTScan 式两步法推理（第2周实现）：Scenario 场景匹配 + Property 属性核对。

复刻 GPTScan 的 query_template 设计（prompt_multiple_choice_scenarios /
prompt_single_yes_no_question），把"找漏洞"拆成客观判断题：

  Step 1 — Scenario（JSON 多选）: 该函数是否命中某类漏洞触发场景？
  Step 2 — Property（Yes/No）  : 命中场景下，关键校验属性是否缺失？

输出 VulnHypothesis 列表。合规：全部使用防御合规视角措辞。
LLM 可注入（LLMClient 协议），支持 mock 测试。
"""
from __future__ import annotations

from typing import Callable

from core.agents.router import TwoTierRouter, extract_json
from core.models import CodeUnit, VulnHypothesis

SYSTEM_MESSAGE = (
    "You are a defensive code auditor performing static data-flow reachability "
    "analysis. Answer strictly in the output format requested; no explanations "
    "beyond the format."
)

# 场景定义（Web 赛道：IDOR 优先；Web3 赛道后续在第2周后半段扩展）
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

SCENARIO_PROMPT_TMPL = """Given the following code, answer the questions below and organize the result in a JSON format like {{"idor": "Yes" or "No", "authz_bypass": "Yes" or "No", "rce": "Yes" or "No"}}.

{questions}

Code:
```python
{code}
```"""

PROPERTY_PROMPT_TMPL = """Does the following code satisfy this property (answer the property being PRESENT)?
"{property}"
Answer ONLY "Yes" or "No".

Code:
```python
{code}
```"""


class ScenarioMatcher:
    """两步法初筛器（运行在 Tier-1 模型上）。"""

    def __init__(self, router: TwoTierRouter | None = None,
                 llm: Callable[[list[dict]], str] | None = None):
        self.router = router
        # llm: 兜底注入点（mock/离线测试），接收 messages 返回文本
        self._llm = llm

    async def _ask(self, prompt: str) -> str:
        messages = [{"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt}]
        if self._llm is not None:
            return self._llm(messages)
        if self.router is None:
            raise RuntimeError("需要注入 router 或 llm")
        return await self.router.screen(messages)

    async def audit_unit(self, unit: CodeUnit) -> list[VulnHypothesis]:
        """对单个 CodeUnit 执行两步法，返回漏洞假设列表。"""
        # ---- Step 1: Scenario（JSON 多选）----
        questions = "\n".join(f'"{s["id"]}": Does the code hit this scenario? "{s["question"]}"'
                              for s in WEB_SCENARIOS)
        s1 = await self._ask(SCENARIO_PROMPT_TMPL.format(questions=questions, code=unit.source_code))
        verdicts = extract_json(s1)

        hypotheses: list[VulnHypothesis] = []
        # ---- Step 2: Property（仅对命中的场景）----
        for scenario in WEB_SCENARIOS:
            if str(verdicts.get(scenario["id"], "No")).lower() != "yes":
                continue
            p = await self._ask(PROPERTY_PROMPT_TMPL.format(property=scenario["property"],
                                                            code=unit.source_code))
            missing = "no" in p.lower()          # 属性缺失 => 假设成立
            hypotheses.append(VulnHypothesis(
                unit=unit,
                vuln_type=scenario["id"],
                scenario_hit=True,
                property_missing=(scenario["property"] if missing else ""),
                reasoning_summary=f"Scenario={scenario['id']}, PropertyCheck={'MISSING' if missing else 'present'}",
                confidence=0.6 if missing else 0.1,
            ))
        return hypotheses

    async def audit_repo(self, units: list[CodeUnit]) -> list[VulnHypothesis]:
        """漏斗主体：全部 unit 走 Tier-1，仅 property_missing 的进入 Tier-2 队列。"""
        all_h: list[VulnHypothesis] = []
        for unit in units:
            all_h.extend(await self.audit_unit(unit))
        return [h for h in all_h if h.property_missing]   # 传给 Skeptic / Tier-2
