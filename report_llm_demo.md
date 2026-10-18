# nexus-audit 扫描报告

- 目标仓库：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask`
- 初筛漏洞假设：2
- 沙箱验证确认：2

## [IDOR] get_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:10`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码仅展示 get_order 函数，调用 svc.get_item(order_id) 时未对资源归属人字段与当前会话身份做显式比对；同时未提供任何装饰器、中间件、数据层默认过滤或前置校验等证据，四个可推翻因素均无法确认存在，因此不应将该 IDOR 风险结论视为误报剔除。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_dzf5i1mk\test_poc.py`
- 自愈轮数：0

## [IDOR] delete_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:15`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码仅以 order_id 调用 svc.delete_item，未显式比对资源归属人字段与当前登录身份；且未提供中间件、装饰器、数据层默认过滤等任何覆盖证据，事务/状态锁也不能消除水平越权风险。因此该 IDOR 结论不应视为误报。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_tiker9fo\test_poc.py`
- 自愈轮数：0
