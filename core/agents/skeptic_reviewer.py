"""反方挑刺 Agent（Skeptic Agent，第2周实现）。

运行在 Tier-2 推理模型上，专项排查可推翻初筛结论的因素：
全局网关鉴权、框架级注解、前置状态锁等。无法被推翻的假设才进入沙箱验证。
"""
from __future__ import annotations

from typing import Callable

from core.agents.router import TwoTierRouter
from core.models import Language, VulnHypothesis

# 提示词不能把语言写死成 python。
# 早期版本在 ``` 后面硬编码 `python`，Java 赛道接进来后，反方质检员会拿到一段
# Java 代码却被告知这是 Python —— 它就会按 Python 的语义去挑刺（例如找
# decorator 而非注解），挑出的"误报理由"和代码对不上。语言必须由 CodeUnit 决定。
_LANG_FENCE = {
    Language.PYTHON_WEB: "python",
    Language.JAVA_WEB: "java",
    Language.SOLIDITY_WEB3: "solidity",
}

# 各语言"可能推翻结论"的机制不同，逐项排查清单也得跟着换。
# 共用一份 Python 版清单，在 Java 上会指向不存在的概念（ORM scope、
# 中间件），质检员于是照抄清单里没命中任何一条的项、给出空洞的"不推翻"。
_SKEPTIC_CHECKLIST = {
    Language.PYTHON_WEB: """1. 全局网关/中间件级鉴权是否已覆盖该路由
2. 框架级注解或装饰器是否隐式执行了权限校验
3. 数据层默认过滤（如 ORM scope、父类基类校验）是否已限制资源归属
4. 前置状态锁或事务隔离是否使场景不可达""",
    Language.JAVA_WEB: """1. Filter / Interceptor / Spring Security 配置是否已覆盖该路由（注意：方法体里看不到装配）
2. 类或方法上的注解（@PreAuthorize / @Secured / @CrossOrigin / @Valid）是否隐式生效
3. 是否已有白名单校验（allowedOrigins、正则 match、枚举映射）真正收窄了输入
4. 该 sink 是否其实不可达（代码路径前面 return、被注释、路由注解冲突）""",
    Language.SOLIDITY_WEB3: """1. 是否已有 nonReentrant 等重入锁，或调用后不依赖状态一致性
2. 调用前余额/份额快照是否已做，使余额差校验无法被绕过
3. 精度/优先级写法是否真的会导致损失（可能只是写法不同，求值结果相同）
4. 攻击者是否真的能在同一次交易内操纵相关状态""",
}

SKEPTIC_PROMPT_TMPL = """请作为反方质检员，审查以下静态分析结论是否为误报。

结论：代码可能存在 {vuln_type}（属性缺失：{property_missing}）

待审代码：
```{lang}
{code}
```

请逐项排查以下可推翻结论的因素：
{checklist}

输出 JSON：{{"rejected": true/false, "reason": "..."}}
rejected=true 表示这是误报，应剔除。"""

# 兼容旧代码里直接 .format(vuln_type=..., property_missing=..., code=...) 的调用
class _CompatPrompt(str):
    def format(self, *a, **kw):  # type: ignore[override]
        kw.setdefault("lang", "python")
        kw.setdefault("checklist", _SKEPTIC_CHECKLIST[Language.PYTHON_WEB])
        return super().format(*a, **kw)


SKEPTIC_PROMPT_TMPL = _CompatPrompt(SKEPTIC_PROMPT_TMPL)


class SkepticReviewer:
    def __init__(self, router: TwoTierRouter | None = None,
                 llm: Callable[[str], str] | None = None):
        self.router = router
        self._llm = llm
        # 审计用：保留最近一次模型的原始输出（triages/报告要能回放）。
        self.last_raw = ""
        self.last_prompt = ""
        self.last_verdict: dict = {}

    async def review(self, h: VulnHypothesis) -> VulnHypothesis:
        lang = h.unit.language
        # 必须用 source_code，**不能用 own_body**。
        #
        # 这里踩过一次坑：P0-2 修好"兄弟路由被当辅助方法拼进切片"之后，
        # 我以为 source_code 还是脏的，于是让质检员改读 own_body。结果
        # own_body 只剩入口方法自己那几行：
        #     @RequestMapping("/safe")
        #     public static String safe(String xss) { return encode(xss); }
        # 而 `encode` 的实际方法体（StringUtils.replace 逐字符转义）只在
        # source_code 的「同文件辅助方法」段里。质检员看不见它，就只能对着
        # `return encode(xss)` 猜"encode 大概做了编码吧"——这正是它该推翻
        # 的那类误报，反而被放过去了。
        #
        # 边界应当这样切：
        #   own_body    → 只给 taint_chain（判"本方法自己写了什么介质"）
        #                 和 rule_detectors 的入口体截取用
        #   source_code → 给所有"读代码做判断"的推理型 agent（ScenarioMatcher
        #                 和 Skeptic）。P0-2 之后它已排除兄弟路由方法，
        #                 剩下的辅助方法体 / 跨文件实现 / 框架装配都是必需证据。
        code = h.unit.source_code or h.unit.own_body
        prompt = SKEPTIC_PROMPT_TMPL.format(
            vuln_type=h.vuln_type, property_missing=h.property_missing or "(未记录)",
            code=code,
            lang=_LANG_FENCE.get(lang, "text"),
            checklist=_SKEPTIC_CHECKLIST.get(lang, _SKEPTIC_CHECKLIST[Language.PYTHON_WEB]))
        self.last_prompt = prompt
        if self._llm is not None:
            raw = self._llm(prompt)
        else:
            if self.router is None:
                raise RuntimeError("需要注入 router 或 llm")
            raw = await self.router.deep_review(
                [{"role": "system", "content": "You are a strict code reviewer."},
                 {"role": "user", "content": prompt}])
        self.last_raw = raw
        from core.agents.router import extract_json
        verdict = extract_json(raw)
        self.last_verdict = verdict if isinstance(verdict, dict) else {}
        h.skeptic_rejected = bool(verdict.get("rejected"))
        h.reasoning_summary = f"{h.reasoning_summary} | skeptic: {verdict.get('reason', '')}"
        return h

    async def filter_false_positives(self, hyps: list[VulnHypothesis]) -> list[VulnHypothesis]:
        reviewed = [await self.review(h) for h in hyps]
        return [h for h in reviewed if not h.skeptic_rejected]
