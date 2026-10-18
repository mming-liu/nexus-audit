"""OpenCode Go 套餐余额/额度监控（对齐 2026-10-18 静默下线故障教训）。

用法：
  python benchmarks/check_quota.py            # 打印额度，异常时退出码 1（可直接接告警）
  python benchmarks/check_quota.py --probe    # 顺带探测免费模型可用性

退出码：0 正常；1 key 失效(401)或请求失败；2 某窗口用量 >=80%
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli import load_dotenv
from core.agents.model_selector import check_quota, probe_model, FREE_CANDIDATES


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    try:
        result = check_quota()
    except PermissionError as e:
        print(f"[ALERT] {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] 额度查询失败：{e}")
        return 1

    print(f"检查时间: {result['checked_at']}")
    alerts = 0
    for w in ("rolling", "weekly", "monthly"):
        info = result[w]
        mark = "⚠️ ALERT" if info["alert"] else "ok"
        print(f"  {w:8s}: {info['percent']:3d}%  [{mark}]  resets: {info['resets_at']}")
        if info["alert"]:
            alerts += 1

    if "--probe" in sys.argv:
        for m in FREE_CANDIDATES:
            ok = probe_model(m, timeout=40)
            print(f"  probe {m}: {'✔ 可用' if ok else '✘ 不可用'}")

    if alerts:
        print(f"[ALERT] {alerts} 个窗口用量 >=80%，请关注")
        return 2
    print("[OK] key 有效，额度正常")
    return 0


if __name__ == "__main__":
    sys.exit(main())
