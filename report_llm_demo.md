# nexus-audit 扫描报告

- 目标仓库：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask`
- 初筛漏洞假设：2
- 沙箱验证确认：2

## [IDOR] get_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:10`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码仅通过 order_id 调用 svc.get_item(order_id)，未显式比对资源归属字段与当前登录身份；同时未提供全局中间件、装饰器或数据层默认过滤等可证明权限已覆盖的信息，因此无法推翻该 IDOR 风险结论。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_jn7gne6j\test_poc.py`
- 自愈轮数：0

## [IDOR] delete_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:15`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码中 delete_order 直接以 order_id 调用 svc.delete_item(order_id)，未见任何将资源归属字段（如 user_id/owner_id）与当前登录用户身份进行显式比对的逻辑；同时未展示全局网关/中间件级鉴权、框架注解/装饰器、ORM scope 或事务隔离等可覆盖该风险的机制，因此无法推翻 IDOR 风险提示，不属于误报。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_quc71581\test_poc.py`
- 自愈轮数：0
