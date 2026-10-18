"""第2周验收冒烟测试：两步法初筛 + 反方挑刺（mock LLM，全离线）。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agents.scenario_matcher import ScenarioMatcher
from core.agents.skeptic_reviewer import SkepticReviewer
from core.agents.router import extract_json
from core.models import CodeUnit, Language

REPO = Path(__file__).resolve().parents[0] / "fixtures" / "demo_flask"


def make_unit(name: str, source: str) -> CodeUnit:
    return CodeUnit(file_path="app.py", language=Language.PYTHON_WEB, unit_name=name,
                    start_line=1, end_line=10, decorators_or_modifiers=["@app.route"],
                    called_symbols=[], source_code=source)


# 用例1：delete_order 无归属校验 => IDOR 场景命中且属性缺失
vuln_unit = make_unit("delete_order", """
def delete_order(order_id):
    svc.delete_item(order_id)
    return jsonify({"ok": True})
""".strip())

# 用例2：显式归属校验 => 场景命中但属性存在，应被过滤
safe_unit = make_unit("get_order", """
def get_order(order_id):
    if order.owner_id != current_user.id:
        abort(403)
    return svc.get_item(order_id)
""".strip())


def mock_screener(messages):
    prompt = messages[-1]["content"]
    if '"idor": "Yes" or "No"' in prompt or "JSON format" in prompt:
        return '{"idor": "Yes", "authz_bypass": "No", "rce": "No"}'
    if 'Answer ONLY "Yes" or "No"' in prompt:
        return "Yes" if "owner_id != current_user.id" in prompt else "No"
    raise AssertionError(f"未预期的提问: {prompt[:80]}")


async def main():
    # --- Step 0: JSON 提取器稳健性 ---
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('噪声 {"a": {"b": [1,2]}} 噪声') == {"a": {"b": [1, 2]}}

    # --- 两步法 ---
    matcher = ScenarioMatcher(llm=mock_screener)
    hs_vuln = await matcher.audit_unit(vuln_unit)
    hs_safe = await matcher.audit_unit(safe_unit)

    idor = [h for h in hs_vuln if h.vuln_type == "idor" and h.property_missing]
    assert idor, "无归属校验的 delete 必须产出 IDOR 假设"
    print(f"vuln_unit 假设: {[h.vuln_type for h in hs_vuln if h.property_missing]}")

    safe_idor = [h for h in hs_safe if h.vuln_type == "idor"]
    assert safe_idor and not safe_idor[0].property_missing, "有归属校验的不应成立假设"
    print(f"safe_unit: 属性存在，已过滤 ✔")

    # --- 漏斗过滤 ---
    funnel = await matcher.audit_repo([vuln_unit, safe_unit])
    assert [h.unit.unit_name for h in funnel] == ["delete_order"], "漏斗应只放行 delete_order"

    # --- 反方挑刺 ---
    skeptic = SkepticReviewer(llm=lambda p: '{"rejected": true, "reason": "全局 before_request 已校验归属"}')
    kept = await skeptic.filter_false_positives(funnel)
    assert not kept, "被 Skeptic 推翻的假设应被剔除"
    print(f"Skeptic 推翻 {len(funnel)} 个假设，剩余 0 ✔")

    skeptic2 = SkepticReviewer(llm=lambda p: '{"rejected": false, "reason": "未发现全局鉴权"}')
    kept2 = await skeptic2.filter_false_positives(funnel)
    assert len(kept2) == 1 and not kept2[0].skeptic_rejected
    print(f"Skeptic 无法推翻时，假设保留并进入沙箱验证队列 ✔")

    print("\nWEEK2 SMOKE TEST PASS ✔")


asyncio.run(main())
