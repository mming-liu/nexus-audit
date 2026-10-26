# 第二波收官报告 —— M183 → M198（42 仓 / 59 门禁）

> doctor 十段 PASS、run_all 59 PASS / 0 FAIL、smoke [1]-[220] 1,220 项、
> clusters 191 根因 → 115 簇（13 个多仓共现，计数守恒）。

## 一、数字

| 项 | 数值 |
|---|---|
| 真实野仓 | 42（Java 18 + Python 10 + Solidity 14） |
| 入口/合约单元 | 15,339 |
| 路由级 P0 | 4,981 |
| 独立根因 | 191 |
| GHSA 草稿 | 191（42 仓，INDEX 零断链） |
| 跨仓簇 | 115 / 多仓共现 13 |
| 规则 / 补丁器 | 36 / 31 |
| run_all | 59 PASS |
| 冒烟 | [1]-[220] / 1,220 断言 |

## 二、第二波四仓

| 仓 | 基准 | 关键机制 |
|---|---|---|
| morpho-blue | 80 入口 / 0 True | 排除 test；极简借贷核心无越权/重入/返回值误报；反向锚点 True |
| flask-jwt-extended | 3 条合成路由全 False | 库仓无路由；验证 jwt_required / fresh_jwt_required 装饰器语义与 verify_jwt_in_request 证据 |
| ruoyi-vue-pro | system+infra 302 入口 / 0 True | @PreAuthorize("@ss.hasPermission") False；@PermitAll None；getLoginUserId() 自助链 False；反向锚点 True |
| solmate | 144 入口 / 0 True | requiresAuth 修饰符实现体识别；Owned.transferOwnership False；SafeTransferLib 不误判 |

## 三、两条 DeFi 规则

- unchecked_erc20_return（CWE-252 / SWC-104，补丁 #30）：裸 transfer(to,amount) / transferFrom(from,to,amount) 未 require；原生 ETH 单参 transfer、safeTransfer、require 包裹均 False。
- oracle_stale_price（CWE-345，补丁 #31）：latestRoundData 未同时校验 price>0 与 updatedAt 新鲜度；补丁注入两个 require 后 True→False。

## 四、诚实边界

1. ruoyi-vue-pro 整仓 3,271 入口，基准只锁 system + infra 302 入口；
   其余模块仍有 35 条 authz True（pay/mes/oa 等），已作为真实候选进入 wild_hunt。
2. flask-jwt-extended 是库仓，0 个 Flask 路由；基准用真实装饰器 + 合成路由，
   并核对库源码 verify_jwt_in_request。examples/ 里的 JWT_SECRET_KEY 是教学
   占位，已从文件级密钥普查中排除（examples/docs 不入生产凭证面）。
3. morpho/solmate 基准排除 contracts/test；测试合约的裸 setOwner 会污染生产面。
4. 191 根因包含 ruoyi 46、spring 12、flask-jwt 0、morpho 0、solmate 2 等；
   逐仓数字以 wild_hunt.json 为准。

## 五、下一步

第三波 M199-M214：django-oauth-toolkit / flask-admin / Sentinel /
aave-v3-periphery 四仓 + 第 37/38 类 csrf_disabled / regex_dos + 补丁 #32/#33。
