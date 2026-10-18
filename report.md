# nexus-audit 扫描报告

- 目标仓库：`C:\Users\ee54\WorkBuddy\2026-10-18-12-37-58\nexus-audit\benchmarks\fixtures\demo_flask`
- 初筛漏洞假设：2
- 沙箱验证确认：2

## [IDOR] get_order
- 位置：`C:\Users\ee54\WorkBuddy\2026-10-18-12-37-58\nexus-audit\benchmarks\fixtures\demo_flask\app.py:10`
- 状态：✔ 已复现（高危）
- 缺失校验：资源归属人与会话身份未比对
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_y2fuy24b\test_poc.py`
- 自愈轮数：0

## [IDOR] delete_order
- 位置：`C:\Users\ee54\WorkBuddy\2026-10-18-12-37-58\nexus-audit\benchmarks\fixtures\demo_flask\app.py:15`
- 状态：✔ 已复现（高危）
- 缺失校验：资源归属人与会话身份未比对
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_wzko_kls\test_poc.py`
- 自愈轮数：0
