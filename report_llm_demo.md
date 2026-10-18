# nexus-audit 扫描报告

- 目标仓库：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask`
- 初筛漏洞假设：2
- 沙箱验证确认：2

## [IDOR] get_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:10`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码仅通过 order_id 调用 svc.get_item(order_id)，未显式比对资源归属人字段与当前登录会话身份；同时未提供任何全局中间件、装饰器、ORM scope 或事务隔离等已覆盖归属校验的证据，因此该 IDOR 风险结论不能认定为误报。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_0a0nsuua\test_poc.py`
- 自愈轮数：0

## [IDOR] delete_order
- 位置：`C:\myFloders\git\nexus-audit\benchmarks\fixtures\demo_flask\app.py:15`
- 状态：✔ 已复现（高危）
- 缺失校验：在执行数据库查询条件或前置校验中，是否显式比对了该资源的归属人字段（如 user_id、owner_id）与当前登录会话身份（如 current_user.id）？
- 分析：Scenario=idor, PropertyCheck=MISSING | skeptic: 待审代码中 delete_order(order_id) 仅调用 svc.delete_item(order_id)，未显式比对资源归属人字段与当前登录身份，存在 IDOR 风险。逐项排查：1) 未提供全局网关/中间件级对象级鉴权证据；2) 无框架注解或装饰器执行权限校验；3) svc.delete_item 内部是否按当前用户过滤不可见，不能作为推翻依据；4) 无前置状态锁或事务隔离说明。因此该结论不是误报。
- 沙箱摘要：E       AssertionError: 越权访问未被拒绝：IDOR 复现成功（漏洞真实存在）
- PoC 脚本：`C:\Users\ee54\AppData\Local\Temp\nexus_poc_utd8_1jw\test_poc.py`
- 自愈轮数：0
