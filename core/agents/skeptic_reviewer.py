"""反方挑刺 Agent（Skeptic Agent，第2周实现）。

运行在 Tier-2 推理模型上，专项排查可推翻初筛结论的因素：
全局网关鉴权、框架级注解、前置状态锁等。无法被推翻的假设才进入沙箱验证。
"""
from __future__ import annotations

from typing import Callable

from core.agents.router import TwoTierRouter
from core.models import VulnHypothesis

SKEPTIC_PROMPT_TMPL = """请作为反方质检员，审查以下静态分析结论是否为误报。

结论：代码可能存在 {vuln_type}（属性缺失：{property_missing}）

待审代码：
```python
{code}
```

请逐项排查以下可推翻结论的因素：
1. 全局网关/中间件级鉴权是否已覆盖该路由
2. 框架级注解或装饰器是否隐式执行了权限校验
3. 数据层默认过滤（如 ORM scope、父类基类校验）是否已限制资源归属
4. 前置状态锁或事务隔离是否使场景不可达

输出 JSON：{{"rejected": true/false, "reason": "..."}}
rejected=true 表示这是误报，应剔除。"""


class SkepticReviewer:
    def __init__(self, router: TwoTierRouter | None = None,
                 llm: Callable[[str], str] | None = None):
        self.router = router
        self._llm = llm

    async def review(self, h: VulnHypothesis) -> VulnHypothesis:
        prompt = SKEPTIC_PROMPT_TMPL.format(
            vuln_type=h.vuln_type, property_missing=h.property_missing or "(未记录)",
            code=h.unit.source_code)
        if self._llm is not None:
            raw = self._llm(prompt)
        else:
            if self.router is None:
                raise RuntimeError("需要注入 router 或 llm")
            raw = await self.router.deep_review(
                [{"role": "system", "content": "You are a strict code reviewer."},
                 {"role": "user", "content": prompt}])
        from core.agents.router import extract_json
        verdict = extract_json(raw)
        h.skeptic_rejected = bool(verdict.get("rejected"))
        h.reasoning_summary = f"{h.reasoning_summary} | skeptic: {verdict.get('reason', '')}"
        return h

    async def filter_false_positives(self, hyps: list[VulnHypothesis]) -> list[VulnHypothesis]:
        reviewed = [await self.review(h) for h in hyps]
        return [h for h in reviewed if not h.skeptic_rejected]
