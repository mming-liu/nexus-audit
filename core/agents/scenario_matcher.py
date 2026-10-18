"""GPTScan 式两步法（Scenario 场景匹配 + Property 属性核对）。

Step 1 — Scenario：该函数是否接收客户端可控的资源主键（order_id / account_id）
         并执行数据库读取、修改或删除操作？
Step 2 — Property：查询条件或前置校验中，是否显式比对资源归属人字段
         （user_id / owner_id）与当前会话身份（current_user.id）？
TODO(第2周)：实现两步问答与静态变量关系校验。
"""
