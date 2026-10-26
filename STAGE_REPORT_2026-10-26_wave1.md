# 第一波收官报告 —— M167 → M182（38 仓 / 55 门禁）

> 门禁：doctor 十段 PASS、run_all 55 PASS / 0 FAIL、smoke [1]-[210] 1,192 项、
> clusters 143 根因 → 76 簇（13 个多仓共现，计数守恒）。

## 一、数字

| 项 | 数值 |
|---|---|
| 真实野仓 | 38（Java 17 + Python 9 + Solidity 12） |
| 入口/合约单元 | 11,853 |
| 路由级 P0 | 1,663 |
| 独立根因 | 143 |
| GHSA 草稿 | 143（38 仓，INDEX 零断链） |
| 跨仓簇 | 76 / 多仓共现 13 |
| 规则 / 补丁器 | 34 / 29 |
| run_all | 55 PASS |
| 冒烟 | [1]-[210] / 1,192 断言 |

## 二、第一波四仓

| 仓 | 基准 | 关键机制 |
|---|---|---|
| spring-boot-demo | 19 个安全模块入口 / 7 类目 0 True | SecurityConfig 的 anyRequest().authenticated() + access("@rbacAuthorityService.hasPermission") → [global-authz] 覆盖 19/19，authz 退 None；反向锚点 True |
| xxl-job | 36 入口 / authz+deserial 0 True | @XxlSso(role) 管理员门 False；@XxlSso(login=false) 匿名门 None；validJobGroupPermission 资源组校验；MyBatis .load 不再误判反序列化 |
| flask-realworld | 26 入口 / 0 True / 8 条 authz False | current_user.profile.id 归属查询、current_user.profile 构造实参、favourite/unfavourite(profile) |
| v3-periphery | 136 生产入口 / 0 True | 排除 contracts/test；Multicall 的 address(this).delegatecall False；公开 swap 不误判 |

## 三、两类新规则

- nosqli（CWE-943，补丁 #28）：Java BasicDBObject/Document.parse、Python pymongo find(request_json)；拒绝 $ 操作符键后 False。
- log_injection（CWE-117，补丁 #29）：只收字符串拼接 / f-string / % 运算；SLF4J 参数化日志、String.format、直接 getter 不计入。

## 四、诚实边界

1. spring-boot-demo 的基准范围是 5 个安全语义模块（19 入口），不是整仓 55+ 模块。
   整仓仍有 85 条路由级 P0（cors 74 条是同一个全局 CORS 配置被每条路由继承，
   ssrf 7、upload 2、log 2 等是 demo 故意演示的不安全写法）。这些进入
   wild_hunt 根因与披露草稿，但不进 benchmark 的"0 True"声明。
2. xxl-job 的 xss 4 条（管理端模板渲染面）未纳入基准，benchmark 只锁 authz+deserial。
3. 143 根因比上一轮 119 多 24：spring 12、xxl 5、jeecg 新增 log_injection 13，
   减去 jeecg deserial 假阳 4、apollo 等修正 2。逐仓数字以 wild_hunt.json 为准。

## 五、下一步

第二波 M183-M198：morpho-blue / flask-jwt-extended / ruoyi-vue-pro / solmate
四仓 + 第 35/36 类 unchecked_erc20_return / oracle_stale_price + 补丁 #30/#31。
