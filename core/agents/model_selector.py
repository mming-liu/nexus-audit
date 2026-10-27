"""OpenCode Go 套餐模型选择器 + 额度监控。

策略（用户要求）：
  1. 免费模型优先：探测 FREE_CANDIDATES（beam-free 置顶；longcat 已 HTTP 410 兜底），
     第一个可用的直接用
  2. 免费模型全不可用时按 PAID_FALLBACK 链依次降级（glm-5.3-flash → deepseek-v4.1-flash），
     但 **Tier-1 的付费穿透默认关闭**：仅当 LLM_ALLOW_PAID_FALLBACK=1 时才允许。
     大仓扫描遇到 429/抖动时默认停在待复核队列，绝不静默烧付费额度。
  3. 额度监控：GET /zen/go/v1/usage 返回 rolling/weekly/monthly 三窗口百分比，
     401 = key 失效（对齐上午的静默下线故障教训），>=80% 告警
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    httpx = None

BASE_URL = os.getenv("LLM_BASE_URL", "https://opencode.ai/zen/go/v1").rstrip("/")

# 免费候选（按优先级）；付费降级链
# longcat 已 HTTP 410（下线）；beam-free 实测可用，置顶。
FREE_CANDIDATES = ["beam-free", "longcat-2.5-preview-free"]
TIER1_PAID_FALLBACK = ["glm-5.3-flash", "deepseek-v4.1-flash"]
# 用户指定：Tier-2 用 OpenCode Go 付费 flash；先 glm-5.3-flash，缺货再 deepseek flash。
TIER2_PAID_FALLBACK = ["glm-5.3-flash", "deepseek-v4.1-flash"]

PROBE_MESSAGES = [{"role": "user", "content": "reply with exactly: ok"}]


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {os.getenv('LLM_API_KEY', '')}",
        "Content-Type": "application/json",
        "x-opencode-session": os.getenv("LLM_SESSION_ID", "nexus-audit-fixed-session"),
        "User-Agent": os.getenv("LLM_USER_AGENT", "nexus-audit/1.0"),
    }


def probe_model(model: str, timeout: float = 60.0, attempts: int = 3) -> bool:
    """小请求探测模型是否真实可用（协议兼容 + 上游在线）。

    必须重试，且要区分「确定性失败」和「瞬时失败」：

    - 401/403：key 或权限问题，重试一万次也一样，立即判否
    - 404：模型名不存在，同上
    - 5xx / 429 / 连接错误 / 超时：**瞬时**，重试可能就通了

    为什么单独强调这一点：曾经因为一次 `502 upstream connect failed`
    就断定"免费模型全不可用"，实际上几分钟后全部正常。上游 5xx 和连接被拒
    在这类聚合网关上非常常见，一次探测就下结论会让整个引擎平白降级到付费
    模型，或者直接抛"无可用模型"——故障率被放大成可用性问题。
    """
    if httpx is None:
        return False
    last = ""
    for i in range(max(1, attempts)):
        try:
            with httpx.Client(timeout=timeout) as client:
                r = client.post(f"{BASE_URL}/chat/completions", headers=_headers(),
                                json={"model": model, "messages": PROBE_MESSAGES,
                                      "max_tokens": 2000})
                if r.status_code == 200:
                    return bool(r.json().get("choices"))
                if r.status_code in (400, 401, 403, 404, 410):
                    # 确定性失败，重试没有意义。
                    # 400 也归这一类：探测用的请求体是固定的、对其他模型都返回 200，
                    # 所以 400 只可能是模型名/参数不被接受。实测不存在的模型名
                    # 返回的是 400 而不是 404，不归进来会白等 3 轮退避（22 秒）。
                    return False
                last = f"HTTP {r.status_code}"
        except Exception as e:                      # 连接错误/超时/JSON 错乱
            last = str(e)[:120]
        if i + 1 < attempts:
            time.sleep(min(8.0, 1.5 * (2 ** i)))
    if last:
        print(f"      [探测] {model} 连续 {attempts} 次不可用（末次：{last}）")
    return False


class PaidFallbackBlocked(RuntimeError):
    """Tier-1 免费候选全灭，且未显式允许付费降级。

    计费边界：Tier-1 是高吞吐初筛层，跑上千入口的大仓时一次 429 或
    上游抖动就静默切到付费池，会把账单放大到不可控。默认必须停在
    待复核队列；只有 LLM_ALLOW_PAID_FALLBACK=1 才允许付费兜底。
    """


def paid_fallback_allowed() -> bool:
    """Tier-1 是否允许在免费候选全灭后穿透到付费池（默认否）。"""
    return os.getenv("LLM_ALLOW_PAID_FALLBACK", "0").strip().lower() in {
        "1", "true", "yes", "on"}


def pick_model(tier: int = 1, force_paid: bool = False) -> str:
    """免费优先选型；force_paid=True 跳过免费直接走付费链。

    Tier-1 的付费穿透受 LLM_ALLOW_PAID_FALLBACK 门控（默认关闭）：
    免费候选全部不可用时抛 PaidFallbackBlocked，调用方据此保留待复核
    队列，而不是静默消耗付费额度。Tier-2 本身就是付费复核层，不受此门控。
    """
    if not force_paid:
        for m in FREE_CANDIDATES:
            if probe_model(m):
                return m
        if tier == 1 and not paid_fallback_allowed():
            raise PaidFallbackBlocked(
                "Tier-1 免费候选全部不可用；LLM_ALLOW_PAID_FALLBACK 未开启，"
                "拒绝静默降级到付费模型（根因保留在待复核队列）")
    chain = TIER1_PAID_FALLBACK if tier == 1 else TIER2_PAID_FALLBACK
    for m in chain:
        if probe_model(m):
            return m
    raise RuntimeError("无可用模型：免费与付费降级链全部探测失败")


def check_quota(api_key: str | None = None) -> dict:
    """额度检查：返回三窗口状态；401 抛 PermissionError（key 失效信号）。"""
    key = api_key or os.getenv("LLM_API_KEY", "")
    if httpx is None:
        raise RuntimeError("httpx 未安装")
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{BASE_URL}/usage", headers=_headers())
    if r.status_code == 401:
        raise PermissionError("OpenCode key 已失效（401）——可能又被静默下线，立即检查！")
    r.raise_for_status()
    usage = r.json()["usage"]
    result = {"checked_at": datetime.now(timezone.utc).isoformat(), "key_status": "ok"}
    for window in ("rolling", "weekly", "monthly"):
        w = usage.get(window, {})
        pct = w.get("percent", 0)
        result[window] = {"percent": pct, "status": w.get("status"),
                          "resets_at": w.get("resetsAt"),
                          "alert": pct >= 80}
    return result


def auto_select_and_print(tier: int = 1) -> str:
    """CLI 辅助：打印选型过程并返回选中模型。

    Tier-1 免费全灭时**不自动付费**：除非 LLM_ALLOW_PAID_FALLBACK=1，
    否则抛 PaidFallbackBlocked，让上层把样本留在待复核队列。显式
    LLM_DISABLE_FREE=1 也一样受门控 —— 关闭免费通道不等于允许产生账单。
    """
    if not force_free_disabled():
        for m in FREE_CANDIDATES:
            print(f"      探测免费模型 {m} ...", flush=True)
            if probe_model(m):
                print(f"      [OK] 使用免费模型：{m}")
                return m
        if tier == 1 and not paid_fallback_allowed():
            msg = ("      免费模型不可用；LLM_ALLOW_PAID_FALLBACK=0，"
                   "保持待复核队列（不静默降级付费）")
            print(msg, flush=True)
            raise PaidFallbackBlocked(msg)
        print("      免费模型不可用，降级付费链 ...")
    elif tier == 1 and not paid_fallback_allowed():
        msg = ("      免费模型已禁用（LLM_DISABLE_FREE=1）；"
               "LLM_ALLOW_PAID_FALLBACK=0，拒绝付费降级")
        print(msg, flush=True)
        raise PaidFallbackBlocked(msg)
    chosen = pick_model(tier, force_paid=True)
    print(f"      [OK] 使用付费模型：{chosen}")
    return chosen


def force_free_disabled() -> bool:
    return os.getenv("LLM_DISABLE_FREE", "").lower() in {"1", "true"}
