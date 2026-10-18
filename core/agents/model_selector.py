"""OpenCode Go 套餐模型选择器 + 额度监控。

策略（用户要求）：
  1. 免费模型优先：探测 FREE_CANDIDATES（longcat-2.5-preview-free / beam-free），
     第一个可用的直接用
  2. 免费模型全不可用时按 PAID_FALLBACK 链依次降级（glm-5.3-flash → deepseek-v4.1-flash）
  3. 额度监控：GET /zen/go/v1/usage 返回 rolling/weekly/monthly 三窗口百分比，
     401 = key 失效（对齐上午的静默下线故障教训），>=80% 告警
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    httpx = None

BASE_URL = os.getenv("LLM_BASE_URL", "https://opencode.ai/zen/go/v1").rstrip("/")

# 免费候选（按优先级）；付费降级链
FREE_CANDIDATES = ["longcat-2.5-preview-free", "beam-free"]
TIER1_PAID_FALLBACK = ["glm-5.3-flash", "deepseek-v4.1-flash"]
TIER2_PAID_FALLBACK = ["deepseek-v4-pro", "glm-5.3"]

PROBE_MESSAGES = [{"role": "user", "content": "reply with exactly: ok"}]


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {os.getenv('LLM_API_KEY', '')}",
        "Content-Type": "application/json",
        "x-opencode-session": os.getenv("LLM_SESSION_ID", "nexus-audit-fixed-session"),
        "User-Agent": os.getenv("LLM_USER_AGENT", "nexus-audit/1.0"),
    }


def probe_model(model: str, timeout: float = 60.0) -> bool:
    """小请求探测模型是否真实可用（协议兼容 + 上游在线）。"""
    if httpx is None:
        return False
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(f"{BASE_URL}/chat/completions", headers=_headers(),
                            json={"model": model, "messages": PROBE_MESSAGES, "max_tokens": 2000})
            if r.status_code != 200:
                return False
            data = r.json()
            return bool(data.get("choices"))
    except Exception:
        return False


def pick_model(tier: int = 1, force_paid: bool = False) -> str:
    """免费优先选型；force_paid=True 跳过免费直接走付费链。"""
    if not force_paid:
        for m in FREE_CANDIDATES:
            if probe_model(m):
                return m
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
    """CLI 辅助：打印选型过程并返回选中模型。"""
    if not force_free_disabled():
        for m in FREE_CANDIDATES:
            print(f"      探测免费模型 {m} ...", flush=True)
            if probe_model(m):
                print(f"      ✔ 使用免费模型：{m}")
                return m
        print("      免费模型不可用，降级付费链 ...")
    chosen = pick_model(tier, force_paid=True)
    print(f"      ✔ 使用付费模型：{chosen}")
    return chosen


def force_free_disabled() -> bool:
    return os.getenv("LLM_DISABLE_FREE", "").lower() in {"1", "true"}
