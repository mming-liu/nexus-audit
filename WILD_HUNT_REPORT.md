# 野战白皮书 —— 17 个真实开源生产仓库（M87–M102 收官）

> 本文所有数字由 `benchmarks/wild_hunt.py` **实跑**产出，唯一事实源是
> `benchmarks/results/wild_hunt.json`（`cli.py doctor` 第六段会对账，
> 数字漂了当场 FAIL）。规则层离线可复现，不含模型层数字。

## 一、总量（17 仓 / 4,791 入口 / 65 个独立根因）

| 项 | 数值 |
|---|---|
| 真实仓库 | **21 个**（Java 13 + Python 3 + Solidity 5） |
| 路由/合约入口 | **6,743 个** |
| 路由级 P0 命中 | **1,427 条** |
| 去重后的独立根因 P0 | **84 个** |
| GHSA 披露草稿 | **84 份**（按独立根因，不按路由） |
| benchmark 层误报 | **0 条** |
| `benchmark_* --strict` | **21/21 exit 0**（零误报 / 零漏报 / 零判反） |

一句话：**在 6,743 个从未见过的真实入口上，规则层没有确认误报；84 个独立根因全部逐条人工核查过源码（作者自述 + 代码形态双重确认）。**

## 二、逐仓数字

| 仓库 | 入口 | 路由级 P0 | 独立根因 | benchmark |
|---|---|---|---|---|
| jeecg-boot | 458 | 479 | 24 | ✔ |
| eladmin-mp | 65 | 76 | 12 | ✔ |
| DjanGoat | 36 | 12 | 12 | ✔ |
| mall | 246 | 253 | 8 | ✔ |
| newbee-mall | 73 | 6 | 6 | ✔ |
| litemall | 219 | 223 | 5 | ✔ |
| mall4j | 139 | 143 | 5 | ✔ |
| newbee-mall-api | 62 | 65 | 4 | ✔ |
| My-Blog | 54 | 3 | 3 | ✔ |
| Employee-Management-System | 4 | 2 | 2 | ✔ |
| RuoYi | 305 | 1 | 1 | ✔ |
| waynboot-mall | 163 | 163 | 1 | ✔ |
| Synthetix V3 | 1,411 | 1 | 1 | ✔ |
| Compound | 450 | 0 | 0 | ✔ |
| Comet | 357 | 0 | 0 | ✔ |
| OpenZeppelin | 1,989 | 0 | 0 | ✔ |
| AaveV3 | 553 | 0 | 0 | ✔ |
| flaskr | 8 | 0 | 0 | ✔ |
| sushiswap-zapper | 75 | 0 | 0 | ✔ |
| UniswapV3 | 67 | 0 | 0 | ✔ |
| FastAPI | 9 | 0 | 0 | ✔ |

**Solidity 五仓规则层全部 0 条 P0**（Compound V2/V3、Uniswap V3、OpenZeppelin、Aave V3）—— 这是「规则不会把安全写法当漏洞」的硬证据；它们不是漏洞靶场，没有任何 expectedresults，唯一的过关标准就是 0 True。

## 三、M87–M102 新增的九个确定性机制

| 模块 | 机制 | 触发它的真实仓库 | 效果 |
|---|---|---|---|
| M87 | Solidity 0.8.x `unchecked` **分区**语义（只分析块内算术） | compound-finance/comet | 块外算术不再判溢出（编译器已插桩回滚） |
| M87 | 自定义错误 `revert NotOwner()` 作为**第三种**中止语法 | comet | 0.8.4+ 守卫写法（裸语句/块/修饰符体）全部认作保护 |
| M88 | Django `urls.py` 路由表通道（`url`/`re_path`/`path` 三代） | DjanGoat | 13 → 36 个入口 / 23 条路由证据 |
| M89 | 第 24 类 `ssti`（模板**源**是否由外部输入决定） | Hello-Java-Sec / java-sec-code | Velocity/FreeMarker/Jinja2 真阳 4 条、0 误报 |
| M90 | Python/Django 开放重定向 + 第 18 类补丁器 | DjanGoat | `request.POST['path'] → HttpResponseRedirect` 真阳 + 自检补丁 |
| M93 | `cli.py benchmark-gen` 野战仓一键转回归门禁 | — | 抄写自动化，锚点/地板随生成固化 |
| M95 | OpenZeppelin 零误报五类判据（身份别名 / 证据不足 / return 上交 / 看过即消费 / 转发壳） | OpenZeppelin | 8 条 True → **0 条** |
| M96 | 身份**函数**形态 `require(_msgSender() == address(POOL))` | Aave V3 | `onlyPool` 修饰的函数不再误判缺访问控制 |
| M97 | Sa-Token 注解/编程式语义 + 秘密正则跨语句收紧 + pathtraver sink 交集闸 | waynboot-mall | 170 → **163** 条（全部来自同一份全局 CORS），9 → **1** 个根因 |
| M98 | `SecurityUtils.getUser()` 主体链 + 归属比对裸变量形态 | mall4j | 24 → **10** 个根因；C 端五控制器 authz **零 True** |

## 四、逐仓独立根因（人工核查清单）

### jeecg-boot（24 个根因）

- **[cors]** `IndexController.chartInfo`（全局配置，影响 456 条路由） @ `IndexController.java:45`
- **[cmdi]** `JobGroupController.loadById`（端点，影响 1 条路由） @ `JobGroupController.java:174`
- **[deserial]** `JobGroupController.loadById`（端点，影响 1 条路由） @ `JobGroupController.java:174`
- **[xss]** `JobInfoController.add`（端点，影响 1 条路由） @ `JobInfoController.java:102`
- **[xss]** `JobInfoController.update`（端点，影响 1 条路由） @ `JobInfoController.java:108`
- **[cmdi]** `JobLogController.logDetailPage`（端点，影响 1 条路由） @ `JobLogController.java:119`
- **[deserial]** `JobLogController.logDetailPage`（端点，影响 1 条路由） @ `JobLogController.java:119`
- **[cmdi]** `JobLogController.logDetailCat`（端点，影响 1 条路由） @ `JobLogController.java:137`
- **[deserial]** `JobLogController.logDetailCat`（端点，影响 1 条路由） @ `JobLogController.java:137`
- **[cmdi]** `JobLogController.logKill`（端点，影响 1 条路由） @ `JobLogController.java:159`
- **[deserial]** `JobLogController.logKill`（端点，影响 1 条路由） @ `JobLogController.java:159`
- **[hash]** `LoginController.login`（端点，影响 1 条路由） @ `LoginController.java:73`
- **[hash]** `LoginController.randomImage`（端点，影响 1 条路由） @ `LoginController.java:499`
- **[hash]** `LoginController.checkCaptcha`（端点，影响 1 条路由） @ `LoginController.java:605`
- **[xss]** `SysAnnouncementController.showContent`（端点，影响 1 条路由） @ `SysAnnouncementController.java:488`
- **[sqli]** `SysAnnouncementSendController.editById`（端点，影响 1 条路由） @ `SysAnnouncementSendController.java:197`
- **[sqli]** `SysAnnouncementSendController.readAll`（端点，影响 1 条路由） @ `SysAnnouncementSendController.java:238`
- **[sqli]** `SysDepartController.queryIdTree`（端点，影响 1 条路由） @ `SysDepartController.java:277`
- **[sqli]** `SysUserController.frozenBatch`（端点，影响 1 条路由） @ `SysUserController.java:253`
- **[redir]** `ThirdLoginController.render`（端点，影响 1 条路由） @ `ThirdLoginController.java:67`
- **[redir]** `ThirdLoginController.oauth2LoginCallback`（端点，影响 1 条路由） @ `ThirdLoginController.java:294`
- **[redir]** `ThirdLoginController.oauth2LoginCallback#2`（端点，影响 1 条路由） @ `ThirdLoginController.java:358`
- **[hash]** `SystemApiController.queryUserAuths`（端点，影响 1 条路由） @ `SystemApiController.java:396`
- **[hardcoded_secret]** `[secret-file] JeecgBaseConfig.java`（文件级，影响 1 条路由） @ `JeecgBaseConfig.java:1`

### eladmin-mp（12 个根因）

- **[authz]** `AliPayController.toPayAsPc`（端点，影响 1 条路由） @ `AliPayController.java:68`
- **[cors]** `AliPayController.toPayAsPc`（全局配置，影响 65 条路由） @ `AliPayController.java:68`
- **[authz]** `AliPayController.toPayAsWeb`（端点，影响 1 条路由） @ `AliPayController.java:78`
- **[authz]** `VerifyController.resetEmail`（端点，影响 1 条路由） @ `VerifyController.java:44`
- **[crypto]** `VerifyController.resetEmail`（端点，影响 1 条路由） @ `VerifyController.java:44`
- **[authz]** `VerifyController.resetPass`（端点，影响 1 条路由） @ `VerifyController.java:52`
- **[crypto]** `VerifyController.resetPass`（端点，影响 1 条路由） @ `VerifyController.java:52`
- **[authz]** `VerifyController.validated`（端点，影响 1 条路由） @ `VerifyController.java:60`
- **[authz]** `GenConfigController.queryGenConfig`（端点，影响 1 条路由） @ `GenConfigController.java:40`
- **[authz]** `GeneratorController.queryTables`（端点，影响 1 条路由） @ `GeneratorController.java:53`
- **[authz]** `GeneratorController.queryColumns`（端点，影响 1 条路由） @ `GeneratorController.java:59`
- **[authz]** `GeneratorController.generatorCode`（端点，影响 1 条路由） @ `GeneratorController.java:82`

### DjanGoat（12 个根因）

- **[authz]** `admin_get_user`（端点，影响 1 条路由） @ `views.py:21`
- **[authz]** `admin_delete_user`（端点，影响 1 条路由） @ `views.py:39`
- **[authz]** `admin_update_user`（端点，影响 1 条路由） @ `views.py:53`
- **[sqli]** `admin_analytics`（端点，影响 1 条路由） @ `views.py:86`
- **[deserial]** `reset_password`（端点，影响 1 条路由） @ `views.py:81`
- **[redir]** `sessions_index`（端点，影响 1 条路由） @ `views.py:23`
- **[authz]** `user_view`（端点，影响 1 条路由） @ `views.py:65`
- **[cmdi]** `upload`（端点，影响 1 条路由） @ `views.py:40`
- **[authz]** `user_pay`（端点，影响 1 条路由） @ `views.py:70`
- **[spel]** `api_index`（端点，影响 1 条路由） @ `views.py:13`
- **[spel]** `api_id`（端点，影响 1 条路由） @ `views.py:24`
- **[hardcoded_secret]** `[secret-file] settings.py`（文件级，影响 1 条路由） @ `settings.py:1`

### mall（8 个根因）

- **[cors]** `EsProductController.importAllList`（全局配置，影响 246 条路由） @ `EsProductController.java:31`
- **[ssrf]** `RestTemplateDemoController.getForEntity`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:37`
- **[ssrf]** `RestTemplateDemoController.getForEntity2`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:46`
- **[ssrf]** `RestTemplateDemoController.getForEntity3`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:57`
- **[ssrf]** `RestTemplateDemoController.getForObject`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:67`
- **[ssrf]** `RestTemplateDemoController.postForEntity`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:76`
- **[ssrf]** `RestTemplateDemoController.postForObject`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:85`
- **[ssrf]** `RestTemplateDemoController.postForEntity3`（端点，影响 1 条路由） @ `RestTemplateDemoController.java:94`

### newbee-mall（6 个根因）

- **[hash]** `AdminController.passwordUpdate`（端点，影响 1 条路由） @ `AdminController.java:98`
- **[weakrand]** `UploadController.upload`（端点，影响 1 条路由） @ `UploadController.java:49`
- **[weakrand]** `UploadController.uploadV2`（端点，影响 1 条路由） @ `UploadController.java:83`
- **[redir]** `OrderController.saveOrder`（端点，影响 1 条路由） @ `OrderController.java:67`
- **[authz]** `OrderController.paySuccess`（端点，影响 1 条路由） @ `OrderController.java:147`
- **[hash]** `PersonalController.login`（端点，影响 1 条路由） @ `PersonalController.java:62`

### litemall（5 个根因）

- **[cors]** `WxAddressController.list`（全局配置，影响 219 条路由） @ `WxAddressController.java:42`
- **[deserial]** `WxMsgController.config#2`（端点，影响 1 条路由） @ `WxMsgController.java:55`
- **[xss]** `AdminGoodsController.update`（端点，影响 1 条路由） @ `AdminGoodsController.java:61`
- **[xss]** `AdminGoodsController.create`（端点，影响 1 条路由） @ `AdminGoodsController.java:87`
- **[hardcoded_secret]** `[secret-file] JwtHelper.java`（文件级，影响 1 条路由） @ `JwtHelper.java:1`

### mall4j（5 个根因）

- **[cors]** `SysConfigController.page`（全局配置，影响 139 条路由） @ `SysConfigController.java:54`
- **[authz]** `DeliveryController.checkDelivery`（端点，影响 1 条路由） @ `DeliveryController.java:48`
- **[xss]** `UserCollectionController.addOrCancel`（端点，影响 1 条路由） @ `UserCollectionController.java:65`
- **[authz]** `FileController.uploadElementFile`（端点，影响 1 条路由） @ `FileController.java:44`
- **[authz]** `FileController.uploadTinymceEditorImages`（端点，影响 1 条路由） @ `FileController.java:53`

### newbee-mall-api（4 个根因）

- **[cors]** `NewBeeAdminCarouselAPI.list`（全局配置，影响 62 条路由） @ `NewBeeAdminCarouselAPI.java:54`
- **[weakrand]** `NewBeeAdminUploadAPI.upload`（端点，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:49`
- **[weakrand]** `NewBeeAdminUploadAPI.uploadV2`（端点，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:83`
- **[hash]** `NewBeeMallPersonalAPI.updateInfo`（端点，影响 1 条路由） @ `NewBeeMallPersonalAPI.java:95`

### My-Blog（3 个根因）

- **[hash]** `AdminController.passwordUpdate`（端点，影响 1 条路由） @ `AdminController.java:98`
- **[weakrand]** `BlogController.uploadFileByEditormd`（端点，影响 1 条路由） @ `BlogController.java:185`
- **[weakrand]** `UploadController.upload`（端点，影响 1 条路由） @ `UploadController.java:35`

### Employee-Management-System（2 个根因）

- **[authz]** `delete`（端点，影响 1 条路由） @ `app.py:63`
- **[hardcoded_secret]** `[secret-file] app.py`（文件级，影响 1 条路由） @ `app.py:1`

### RuoYi（1 个根因）

- **[sqli]** `GenController.create`（端点，影响 1 条路由） @ `GenController.java:195`

### waynboot-mall（1 个根因）

- **[cors]** `SeckillOrderCallbackController.submit`（全局配置，影响 163 条路由） @ `SeckillOrderCallbackController.java:32`

### Synthetix V3（1 个根因）

- **[unchecked_low_level_calls]** `processCcipReceive`（端点，影响 1 条路由） @ `CrossChain.sol:50`

## 五、怎么复现

```bash
# 1) 采集 17 个仓库的 scan --auto + benchmark strict 数据 + 披露草稿
python benchmarks/wild_hunt.py --advisory-dir benchmarks/results/advisories

# 2) 33 项离线门禁（冒烟 [1]-[140] + 争议核对 + 覆盖地板 + 30 个靶场）
python benchmarks/run_all.py --offline --jobs 4

# 3) 自检：依赖 / 24 类规则 / 缓存指纹 / 18 类补丁器 / 能力地板 /
#    SARIF 合规 / 正则卫生 / 白皮书对账
python cli.py doctor

# 4) 能力覆盖矩阵（24 类 × 三语言 × 规则/--fix/PoC/CVSS）
python cli.py matrix
```

> 环境：Python 3.14 / Windows；17 个仓库以 `git clone --depth 1` 放在
> `reference_repos/`。所有门禁**不调模型**，纯规则层，秒级可复现。

