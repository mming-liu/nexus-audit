# 第三波收官报告 —— M199 → M214（46 仓 / 63 门禁）

> doctor 十段 PASS、run_all 63 PASS、smoke [1]-[230] 1,247 项、
> clusters 204 根因 → 123 簇（14 个多仓共现，计数守恒）。

## 一、数字

| 项 | 数值 |
|---|---|
| 真实野仓 | 46（Java 19 + Python 12 + Solidity 15） |
| 入口/合约单元 | 15,576 |
| 路由级 P0 | 4,994 |
| 独立根因 | 204 |
| GHSA 草稿 | 204（46 仓，INDEX 零断链） |
| 跨仓簇 | 123 / 多仓共现 14 |
| 规则 / 补丁器 | 38 / 33 |
| run_all | 63 PASS |
| 冒烟 | [1]-[230] / 1,247 断言 |

## 二、第三波四仓

| 仓 | 基准 | 关键机制 |
|---|---|---|
| django-oauth-toolkit | 18 入口 / 0 True | token/revoke 端点身份由 client credentials/refresh token 建立，authz 退 None；@csrf_exempt 写视图锚点 True |
| flask-admin | 15 入口 / 0 True | 后台管理路由 authz/csrf/regex 0 True；csrf 锚点 True |
| Sentinel | sentinel-dashboard 56 入口 / 0 True | 权限注解/登录过滤器识别；反向锚点 True |
| aave-v3-periphery | 139 生产入口 / 计划外 True 0 / 已知真阳性 1 | 排除 mocks/test 与 WrappedTokenGateway（aToken revert 语义）；Collector.transfer 裸 ERC20 transfer 已知真阳性，补丁 #30 翻 False |

## 三、两条新规则

- csrf_disabled（CWE-352，补丁 #32）：Spring .csrf().disable() 仅在有状态会话判 True，STATELESS/JWT 判 False；Django @csrf_exempt 写视图判 True，补丁移除注解后 False。
- regex_dos（CWE-1333，补丁 #33）：Pattern.compile(参数)/re.compile(参数) 未 quote/escape 判 True；常量正则、Pattern.quote、re.escape 判 False；补丁重切后 True→False。

## 四、诚实边界

1. aave-v3-periphery 的 Collector.transfer 是**已知真阳性**（SWC-104），不是误报；基准把"计划外 True"锁 0，并验证补丁。WrappedTokenGatewayV3 的 aWETH.transferFrom 因 aToken 失败即 revert 被排除。
2. Sentinel 只扫 sentinel-dashboard 模块，不是整个 Sentinel 仓。
3. csrf_disabled 的 Java 入口是 SecurityConfig 配置语句（不是 controller 路由）；基准用配置单元 + 补丁文件级自检，扫描器对路由级配置的覆盖仍有限。
4. 204 根因里 django-oauth 0、flask-admin 0、Sentinel 0、aave 1；逐仓数字以 wild_hunt.json 为准。

## 五、下一步

第四波 M215-M232：halo / sanic / litestar / starlette 四仓（50 仓大满贯）+
第 39/40 类 jndi_injection / arbitrary_file_delete + 补丁 #34/#35，
目标 50 仓 / 40 类 / 35 补丁器 / 67 门禁。
