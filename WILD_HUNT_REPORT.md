# 野战白皮书 —— 42 个真实开源生产仓库（M151–M166 收官）

> 本文所有数字由 `benchmarks/wild_hunt.py` **实跑**产出，唯一事实源是
> `benchmarks/results/wild_hunt.json`（`cli.py doctor` 第六段会对账，
> 数字漂了当场 FAIL）。规则层离线可复现，不含模型层数字。

## 一、总量（42 仓 / 191 独立根因 / 零误报）

| 项 | 数值 |
|---|---|
| 真实仓库 | **42 个**（Java 18 + Python 10 + Solidity 14） |
| 路由/合约入口 | **15,339 个** |
| 路由级 P0 命中 | **4,981 条** |
| 去重后的独立根因 P0 | **191 个** |
| GHSA 披露草稿 | **191 份**（按独立根因，不按路由） |
| benchmark 层误报 | **0 条** |
| benchmark 层判反 | **0 条** |
| benchmark_* --strict | **42/42 exit 0** |
| 供应链命中已知 advisory 的仓库 | **7 个** |
| 供应链 × 代码双重实锤 | **5 个** |

一句话：**在 15,339 个真实入口上，规则层没有确认误报；191 个独立根因全部由规则层确定性判据产出，PoC/补丁自检可复核。**

## 二、逐仓数字

| 仓库 | 语言 | 入口 | 路由级 P0 | 独立根因 | benchmark | 组件 CVE |
|---|---|---|---|---|---|---|
| ruoyi-vue-pro | Java | 3271 | 3316 | 46 | ✔ | — |
| jeecg-boot | Java | 458 | 482 | 27 | ✔ | CVE-2022-21363 |
| DjanGoat | Python | 36 | 12 | 12 | ✔ | CVE-2013-7459、CVE-2017-12794、CVE-2018-14574 |
| eladmin-JPA | Java | 66 | 77 | 12 | ✔ | — |
| eladmin-mp | Java | 65 | 76 | 12 | ✔ | — |
| spring-boot-demo | Java | 80 | 85 | 12 | ✔ | CVE-2022-21363、CVE-2023-24162 |
| newbee-mall | Java | 73 | 11 | 11 | ✔ | — |
| newbee-mall-api | Java | 62 | 70 | 9 | ✔ | — |
| mall | Java | 246 | 253 | 8 | ✔ | — |
| My-Blog | Java | 54 | 6 | 6 | ✔ | — |
| apollo | Java | 200 | 6 | 6 | ✔ | — |
| litemall | Java | 219 | 223 | 5 | ✔ | — |
| mall4j | Java | 139 | 143 | 5 | ✔ | — |
| xxl-job | Java | 36 | 5 | 5 | ✔ | — |
| My-Blog-layui | Java | 64 | 3 | 3 | ✔ | — |
| RuoYi | Java | 305 | 3 | 3 | ✔ | — |
| Employee-Management-System | Python | 4 | 2 | 2 | ✔ | — |
| django-realworld | Python | 11 | 2 | 2 | ✔ | CVE-2017-12794、CVE-2018-14574、CVE-2020-25626、CVE-2022-29217 |
| solmate | Solidity | 144 | 2 | 2 | ✔ | — |
| Synthetix V3 | Solidity | 1411 | 1 | 1 | ✔ | — |
| mall-tiny | Java | 40 | 40 | 1 | ✔ | CVE-2023-24162 |
| waynboot-mall | Java | 163 | 163 | 1 | ✔ | — |
| AaveV3 | Solidity | 553 | 0 | 0 | ✔ | — |
| Comet | Solidity | 357 | 0 | 0 | ✔ | — |
| Compound | Solidity | 450 | 0 | 0 | ✔ | — |
| FastAPI | Python | 9 | 0 | 0 | ✔ | — |
| MakerDAO dss | Solidity | 234 | 0 | 0 | ✔ | — |
| OZ Upgradeable | Solidity | 1119 | 0 | 0 | ✔ | — |
| OpenZeppelin | Solidity | 1989 | 0 | 0 | ✔ | — |
| Uniswap V2 | Solidity | 29 | 0 | 0 | ✔ | — |
| UniswapV3 | Solidity | 67 | 0 | 0 | ✔ | — |
| fastapi-realworld | Python | 19 | 0 | 0 | ✔ | — |
| flask-jwt-extended | Python | 0 | 0 | 0 | ✔ | — |
| flask-realworld | Python | 26 | 0 | 0 | ✔ | CVE-2019-7548 |
| flaskr | Python | 8 | 0 | 0 | ✔ | — |
| flasky | Python | 39 | 0 | 0 | ✔ | CVE-2018-1000656、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548 |
| full-stack-fastapi-template | Python | 23 | 0 | 0 | ✔ | — |
| kkFileView | Java | 20 | 0 | 0 | ✔ | — |
| morpho-blue | Solidity | 71 | 0 | 0 | ✔ | — |
| solady | Solidity | 2968 | 0 | 0 | ✔ | — |
| sushiswap-zapper | Solidity | 75 | 0 | 0 | ✔ | — |
| v3-periphery | Solidity | 136 | 0 | 0 | ✔ | — |

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

## 四、逐仓独立根因（规则层确定性判定）

### ruoyi-vue-pro（Java）— 46 个独立根因

- **[cors]** `DefaultController.bpm404`（global-config，影响 3271 条路由） @ `DefaultController.java:24`
- **[xss]** `PmsKnowledgeDocumentController.getDocument`（endpoint，影响 1 条路由） @ `PmsKnowledgeDocumentController.java:111`
- **[xss]** `PmsKnowledgeFolderController.getFolder`（endpoint，影响 1 条路由） @ `PmsKnowledgeFolderController.java:96`
- **[authz]** `AppPayChannelController.getEnableChannelCodeList`（endpoint，影响 1 条路由） @ `AppPayChannelController.java:31`
- **[authz]** `AppPayTransferController.syncTransfer`（endpoint，影响 1 条路由） @ `AppPayTransferController.java:29`
- **[authz]** `PayChannelController.getEnableChannelCodeList`（endpoint，影响 1 条路由） @ `PayChannelController.java:83`
- **[authz]** `PayDemoOrderController.getDemoOrderPage`（endpoint，影响 1 条路由） @ `PayDemoOrderController.java:42`
- **[authz]** `PayDemoOrderController.refundDemoOrder`（endpoint，影响 1 条路由） @ `PayDemoOrderController.java:58`
- **[authz]** `PayDemoWithdrawController.createDemoWithdraw`（endpoint，影响 1 条路由） @ `PayDemoWithdrawController.java:34`
- **[authz]** `PayDemoWithdrawController.getDemoWithdrawPage`（endpoint，影响 1 条路由） @ `PayDemoWithdrawController.java:49`
- **[authz]** `PayWalletRechargeController.refundWalletRecharge`（endpoint，影响 1 条路由） @ `PayWalletRechargeController.java:40`
- **[authz]** `OaSupplyItemController.getSupplyItemSelectPage`（endpoint，影响 1 条路由） @ `OaSupplyItemController.java:91`
- **[authz]** `MpOpenController.handleMessage`（endpoint，影响 1 条路由） @ `MpOpenController.java:44`
- **[authz]** `MesWmWarehouseAreaController.getWarehouseAreaSimpleList`（endpoint，影响 1 条路由） @ `MesWmWarehouseAreaController.java:90`
- **[authz]** `MesWmWarehouseLocationController.getWarehouseLocationSimpleList`（endpoint，影响 1 条路由） @ `MesWmWarehouseLocationController.java:89`
- **[authz]** `AppBrokerageUserController.getBrokerageUserRankPageByUserCount`（endpoint，影响 1 条路由） @ `AppBrokerageUserController.java:99`
- **[authz]** `AppBrokerageUserController.getBrokerageUserChildSummaryPageByPrice`（endpoint，影响 1 条路由） @ `AppBrokerageUserController.java:109`
- **[xss]** `AppCartController.addCart`（endpoint，影响 1 条路由） @ `AppCartController.java:32`
- **[xss]** `AppCartController.updateCartCount`（endpoint，影响 1 条路由） @ `AppCartController.java:38`
- **[xss]** `AppCartController.updateCartSelected`（endpoint，影响 1 条路由） @ `AppCartController.java:45`
- **[xss]** `AppArticleController.addBrowseCount`（endpoint，影响 1 条路由） @ `AppArticleController.java:71`
- **[authz]** `AppBargainHelpController.getBargainHelpList`（endpoint，影响 1 条路由） @ `AppBargainHelpController.java:46`
- **[authz]** `CombinationActivityController.getCombinationActivityListByIds`（endpoint，影响 1 条路由） @ `CombinationActivityController.java:93`
- **[authz]** `PointActivityController.getPointActivityListByIds`（endpoint，影响 1 条路由） @ `PointActivityController.java:108`
- **[authz]** `SeckillActivityController.getSeckillActivityListByIds`（endpoint，影响 1 条路由） @ `SeckillActivityController.java:102`
- **[xss]** `AppFavoriteController.createFavorite`（endpoint，影响 1 条路由） @ `AppFavoriteController.java:36`
- **[authz]** `IotStatisticsController.getDeviceMessageSummaryByDate`（endpoint，影响 1 条路由） @ `IotStatisticsController.java:70`
- **[xss]** `AppFileController.createFile`（endpoint，影响 1 条路由） @ `AppFileController.java:56`
- **[xss]** `FileController.createFile`（endpoint，影响 1 条路由） @ `FileController.java:69`
- **[authz]** `ImChannelMaterialController.getMaterial`（endpoint，影响 1 条路由） @ `ImChannelMaterialController.java:30`
- **[authz]** `ImChannelMaterialManagerController.getSimpleMaterialList`（endpoint，影响 1 条路由） @ `ImChannelMaterialManagerController.java:91`
- **[authz]** `CrmBusinessController.getBusinessPageByCustomer`（endpoint，影响 1 条路由） @ `CrmBusinessController.java:169`
- **[authz]** `CrmBusinessStatusController.getBusinessStatusSimpleList`（endpoint，影响 1 条路由） @ `CrmBusinessStatusController.java:118`
- **[authz]** `CrmContactController.getContactPageByCustomer`（endpoint，影响 1 条路由） @ `CrmContactController.java:136`
- **[authz]** `CrmContactController.getContactPageByBusiness`（endpoint，影响 1 条路由） @ `CrmContactController.java:144`
- **[authz]** `CrmContractController.getContractPageByCustomer`（endpoint，影响 1 条路由） @ `CrmContractController.java:138`
- **[authz]** `CrmContractController.getContractPageByBusiness`（endpoint，影响 1 条路由） @ `CrmContractController.java:146`
- **[authz]** `CrmFollowUpRecordController.createFollowUpRecord`（endpoint，影响 1 条路由） @ `CrmFollowUpRecordController.java:60`
- **[authz]** `CrmFollowUpRecordController.getFollowUpRecordPage`（endpoint，影响 1 条路由） @ `CrmFollowUpRecordController.java:89`
- **[authz]** `CrmReceivableController.getReceivablePageByCustomer`（endpoint，影响 1 条路由） @ `CrmReceivableController.java:116`
- **[authz]** `BpmProcessDefinitionController.getProcessDefinition`（endpoint，影响 1 条路由） @ `BpmProcessDefinitionController.java:115`
- **[authz]** `Ai1AgentController.getAgentSimpleList`（endpoint，影响 1 条路由） @ `Ai1AgentController.java:98`
- **[authz]** `Ai1ModelController.getModelSimpleList`（endpoint，影响 1 条路由） @ `Ai1ModelController.java:85`
- **[authz]** `AiImageController.getImagePagePublic`（endpoint，影响 1 条路由） @ `AiImageController.java:46`
- **[authz]** `AiModelController.getModelSimpleList`（endpoint，影响 1 条路由） @ `AiModelController.java:76`
- **[hardcoded_secret]** `[secret-file] ImProperties.java`（file-level，影响 1 条路由） @ `ImProperties.java:1`

### jeecg-boot（Java）— 27 个独立根因

- **[cors]** `IndexController.chartInfo`（global-config，影响 456 条路由） @ `IndexController.java:45`
- **[xss]** `JobInfoController.add`（endpoint，影响 1 条路由） @ `JobInfoController.java:102`
- **[xss]** `JobInfoController.update`（endpoint，影响 1 条路由） @ `JobInfoController.java:108`
- **[log_injection]** `ParamFlowRuleController.apiUpdateParamFlowRule`（endpoint，影响 1 条路由） @ `ParamFlowRuleController.java:172`
- **[log_injection]** `DuplicateCheckController.doDuplicateCheck`（endpoint，影响 1 条路由） @ `DuplicateCheckController.java:45`
- **[hash]** `LoginController.login`（endpoint，影响 1 条路由） @ `LoginController.java:73`
- **[hash]** `LoginController.randomImage`（endpoint，影响 1 条路由） @ `LoginController.java:499`
- **[hash]** `LoginController.checkCaptcha`（endpoint，影响 1 条路由） @ `LoginController.java:605`
- **[log_injection]** `SysAnnouncementController.listByUser`（endpoint，影响 1 条路由） @ `SysAnnouncementController.java:324`
- **[sqli]** `SysAnnouncementSendController.editById`（endpoint，影响 1 条路由） @ `SysAnnouncementSendController.java:197`
- **[sqli]** `SysAnnouncementSendController.readAll`（endpoint，影响 1 条路由） @ `SysAnnouncementSendController.java:238`
- **[log_injection]** `SysDictController.getDictText`（endpoint，影响 1 条路由） @ `SysDictController.java:135`
- **[log_injection]** `SysDictController.getDictItems`（endpoint，影响 1 条路由） @ `SysDictController.java:159`
- **[log_injection]** `SysDictController.loadDict`（endpoint，影响 1 条路由） @ `SysDictController.java:192`
- **[log_injection]** `SysRoleController.checkUsername`（endpoint，影响 1 条路由） @ `SysRoleController.java:214`
- **[sqli]** `SysUserController.frozenBatch`（endpoint，影响 1 条路由） @ `SysUserController.java:253`
- **[log_injection]** `ThirdLoginController.render`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:67`
- **[redir]** `ThirdLoginController.render`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:67`
- **[log_injection]** `ThirdLoginController.loginThird`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:76`
- **[redir]** `ThirdLoginController.oauth2LoginCallback`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:294`
- **[log_injection]** `ThirdLoginController.oauth2LoginCallback#2`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:358`
- **[redir]** `ThirdLoginController.oauth2LoginCallback#2`（endpoint，影响 1 条路由） @ `ThirdLoginController.java:358`
- **[hash]** `SystemApiController.queryUserAuths`（endpoint，影响 1 条路由） @ `SystemApiController.java:396`
- **[log_injection]** `DlMockController.getMockDdjhData`（endpoint，影响 1 条路由） @ `DlMockController.java:209`
- **[log_injection]** `OnlCgformDemoController.enhanceJavaListHttp`（endpoint，影响 1 条路由） @ `OnlCgformDemoController.java:33`
- **[log_injection]** `OnlCgformDemoController.enhanceJavaHttp`（endpoint，影响 1 条路由） @ `OnlCgformDemoController.java:75`
- **[hardcoded_secret]** `[secret-file] JeecgBaseConfig.java`（file-level，影响 1 条路由） @ `JeecgBaseConfig.java:1`

### DjanGoat（Python）— 12 个独立根因

- **[authz]** `admin_get_user`（endpoint，影响 1 条路由） @ `views.py:21`
- **[authz]** `admin_delete_user`（endpoint，影响 1 条路由） @ `views.py:39`
- **[authz]** `admin_update_user`（endpoint，影响 1 条路由） @ `views.py:53`
- **[sqli]** `admin_analytics`（endpoint，影响 1 条路由） @ `views.py:86`
- **[deserial]** `reset_password`（endpoint，影响 1 条路由） @ `views.py:81`
- **[redir]** `sessions_index`（endpoint，影响 1 条路由） @ `views.py:23`
- **[authz]** `user_view`（endpoint，影响 1 条路由） @ `views.py:65`
- **[cmdi]** `upload`（endpoint，影响 1 条路由） @ `views.py:40`
- **[authz]** `user_pay`（endpoint，影响 1 条路由） @ `views.py:70`
- **[spel]** `api_index`（endpoint，影响 1 条路由） @ `views.py:13`
- **[spel]** `api_id`（endpoint，影响 1 条路由） @ `views.py:24`
- **[hardcoded_secret]** `[secret-file] settings.py`（file-level，影响 1 条路由） @ `settings.py:1`

### eladmin-JPA（Java）— 12 个独立根因

- **[authz]** `AliPayController.toPayAsPc`（endpoint，影响 1 条路由） @ `AliPayController.java:68`
- **[cors]** `AliPayController.toPayAsPc`（global-config，影响 66 条路由） @ `AliPayController.java:68`
- **[authz]** `AliPayController.toPayAsWeb`（endpoint，影响 1 条路由） @ `AliPayController.java:78`
- **[authz]** `VerifyController.resetEmail`（endpoint，影响 1 条路由） @ `VerifyController.java:44`
- **[authz]** `VerifyController.resetPass`（endpoint，影响 1 条路由） @ `VerifyController.java:52`
- **[authz]** `VerifyController.validated`（endpoint，影响 1 条路由） @ `VerifyController.java:60`
- **[unrestricted_upload]** `DatabaseController.uploadDatabase`（endpoint，影响 1 条路由） @ `DatabaseController.java:105`
- **[unrestricted_upload]** `DeployController.uploadDeploy`（endpoint，影响 1 条路由） @ `DeployController.java:101`
- **[authz]** `GenConfigController.queryGenConfig`（endpoint，影响 1 条路由） @ `GenConfigController.java:40`
- **[authz]** `GeneratorController.queryTables`（endpoint，影响 1 条路由） @ `GeneratorController.java:58`
- **[authz]** `GeneratorController.queryColumns`（endpoint，影响 1 条路由） @ `GeneratorController.java:67`
- **[authz]** `GeneratorController.generatorCode`（endpoint，影响 1 条路由） @ `GeneratorController.java:90`

### eladmin-mp（Java）— 12 个独立根因

- **[authz]** `AliPayController.toPayAsPc`（endpoint，影响 1 条路由） @ `AliPayController.java:68`
- **[cors]** `AliPayController.toPayAsPc`（global-config，影响 65 条路由） @ `AliPayController.java:68`
- **[authz]** `AliPayController.toPayAsWeb`（endpoint，影响 1 条路由） @ `AliPayController.java:78`
- **[authz]** `VerifyController.resetEmail`（endpoint，影响 1 条路由） @ `VerifyController.java:44`
- **[authz]** `VerifyController.resetPass`（endpoint，影响 1 条路由） @ `VerifyController.java:52`
- **[authz]** `VerifyController.validated`（endpoint，影响 1 条路由） @ `VerifyController.java:60`
- **[unrestricted_upload]** `DatabaseController.uploadDatabase`（endpoint，影响 1 条路由） @ `DatabaseController.java:106`
- **[unrestricted_upload]** `DeployController.uploadDeploy`（endpoint，影响 1 条路由） @ `DeployController.java:100`
- **[authz]** `GenConfigController.queryGenConfig`（endpoint，影响 1 条路由） @ `GenConfigController.java:40`
- **[authz]** `GeneratorController.queryTables`（endpoint，影响 1 条路由） @ `GeneratorController.java:53`
- **[authz]** `GeneratorController.queryColumns`（endpoint，影响 1 条路由） @ `GeneratorController.java:59`
- **[authz]** `GeneratorController.generatorCode`（endpoint，影响 1 条路由） @ `GeneratorController.java:82`

### spring-boot-demo（Java）— 12 个独立根因

- **[cors]** `MessageController.broadcast`（global-config，影响 74 条路由） @ `MessageController.java:32`
- **[unrestricted_upload]** `UploadController.local`（endpoint，影响 1 条路由） @ `UploadController.java:49`
- **[xss]** `UploadController.local`（endpoint，影响 1 条路由） @ `UploadController.java:49`
- **[unrestricted_upload]** `UploadController.yun`（endpoint，影响 1 条路由） @ `UploadController.java:69`
- **[ssrf]** `ManualOperateController.xxlJobGroup`（endpoint，影响 1 条路由） @ `ManualOperateController.java:38`
- **[ssrf]** `ManualOperateController.xxlJobList`（endpoint，影响 1 条路由） @ `ManualOperateController.java:52`
- **[ssrf]** `ManualOperateController.xxlJobAdd`（endpoint，影响 1 条路由） @ `ManualOperateController.java:68`
- **[ssrf]** `ManualOperateController.xxlJobTrigger`（endpoint，影响 1 条路由） @ `ManualOperateController.java:89`
- **[ssrf]** `ManualOperateController.xxlJobRemove`（endpoint，影响 1 条路由） @ `ManualOperateController.java:103`
- **[ssrf]** `ManualOperateController.xxlJobStop`（endpoint，影响 1 条路由） @ `ManualOperateController.java:116`
- **[ssrf]** `ManualOperateController.xxlJobStart`（endpoint，影响 1 条路由） @ `ManualOperateController.java:129`
- **[redir]** `OauthController.renderAuth`（endpoint，影响 1 条路由） @ `OauthController.java:56`

### newbee-mall（Java）— 11 个独立根因

- **[hash]** `AdminController.passwordUpdate`（endpoint，影响 1 条路由） @ `AdminController.java:98`
- **[unrestricted_upload]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:49`
- **[weakrand]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:49`
- **[xss]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:49`
- **[unrestricted_upload]** `UploadController.uploadV2`（endpoint，影响 1 条路由） @ `UploadController.java:83`
- **[weakrand]** `UploadController.uploadV2`（endpoint，影响 1 条路由） @ `UploadController.java:83`
- **[xss]** `UploadController.uploadV2`（endpoint，影响 1 条路由） @ `UploadController.java:83`
- **[redir]** `OrderController.saveOrder`（endpoint，影响 1 条路由） @ `OrderController.java:67`
- **[authz]** `OrderController.paySuccess`（endpoint，影响 1 条路由） @ `OrderController.java:147`
- **[hash]** `PersonalController.login`（endpoint，影响 1 条路由） @ `PersonalController.java:62`
- **[xss]** `PersonalController.updateInfo`（endpoint，影响 1 条路由） @ `PersonalController.java:123`

### newbee-mall-api（Java）— 9 个独立根因

- **[cors]** `NewBeeAdminCarouselAPI.list`（global-config，影响 62 条路由） @ `NewBeeAdminCarouselAPI.java:54`
- **[unrestricted_upload]** `NewBeeAdminUploadAPI.upload`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:49`
- **[weakrand]** `NewBeeAdminUploadAPI.upload`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:49`
- **[xss]** `NewBeeAdminUploadAPI.upload`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:49`
- **[unrestricted_upload]** `NewBeeAdminUploadAPI.uploadV2`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:83`
- **[weakrand]** `NewBeeAdminUploadAPI.uploadV2`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:83`
- **[xss]** `NewBeeAdminUploadAPI.uploadV2`（endpoint，影响 1 条路由） @ `NewBeeAdminUploadAPI.java:83`
- **[hash]** `NewBeeMallPersonalAPI.updateInfo`（endpoint，影响 1 条路由） @ `NewBeeMallPersonalAPI.java:95`
- **[xss]** `NewBeeMallPersonalAPI.updateInfo`（endpoint，影响 1 条路由） @ `NewBeeMallPersonalAPI.java:95`

### mall（Java）— 8 个独立根因

- **[cors]** `EsProductController.importAllList`（global-config，影响 246 条路由） @ `EsProductController.java:31`
- **[ssrf]** `RestTemplateDemoController.getForEntity`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:37`
- **[ssrf]** `RestTemplateDemoController.getForEntity2`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:46`
- **[ssrf]** `RestTemplateDemoController.getForEntity3`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:57`
- **[ssrf]** `RestTemplateDemoController.getForObject`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:67`
- **[ssrf]** `RestTemplateDemoController.postForEntity`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:76`
- **[ssrf]** `RestTemplateDemoController.postForObject`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:85`
- **[ssrf]** `RestTemplateDemoController.postForEntity3`（endpoint，影响 1 条路由） @ `RestTemplateDemoController.java:94`

### My-Blog（Java）— 6 个独立根因

- **[hash]** `AdminController.passwordUpdate`（endpoint，影响 1 条路由） @ `AdminController.java:98`
- **[unrestricted_upload]** `BlogController.uploadFileByEditormd`（endpoint，影响 1 条路由） @ `BlogController.java:185`
- **[weakrand]** `BlogController.uploadFileByEditormd`（endpoint，影响 1 条路由） @ `BlogController.java:185`
- **[unrestricted_upload]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:35`
- **[weakrand]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:35`
- **[xss]** `UploadController.upload`（endpoint，影响 1 条路由） @ `UploadController.java:35`

### apollo（Java）— 6 个独立根因

- **[xss]** `ConsumerController.create`（endpoint，影响 1 条路由） @ `ConsumerController.java:73`
- **[xss]** `FavoriteController.addFavorite`（endpoint，影响 1 条路由） @ `FavoriteController.java:52`
- **[xss]** `ServerConfigController.createOrUpdateConfigDBConfig`（endpoint，影响 1 条路由） @ `ServerConfigController.java:64`
- **[sqli]** `AccessKeyController.enable`（endpoint，影响 1 条路由） @ `AccessKeyController.java:65`
- **[xss]** `AppNamespaceController.create`（endpoint，影响 1 条路由） @ `AppNamespaceController.java:52`
- **[xss]** `ServerConfigController.createOrUpdatePortalDBConfig`（endpoint，影响 1 条路由） @ `ServerConfigController.java:47`

### litemall（Java）— 5 个独立根因

- **[cors]** `WxAddressController.list`（global-config，影响 219 条路由） @ `WxAddressController.java:42`
- **[deserial]** `WxMsgController.config#2`（endpoint，影响 1 条路由） @ `WxMsgController.java:55`
- **[xss]** `AdminGoodsController.update`（endpoint，影响 1 条路由） @ `AdminGoodsController.java:61`
- **[xss]** `AdminGoodsController.create`（endpoint，影响 1 条路由） @ `AdminGoodsController.java:87`
- **[hardcoded_secret]** `[secret-file] JwtHelper.java`（file-level，影响 1 条路由） @ `JwtHelper.java:1`

### mall4j（Java）— 5 个独立根因

- **[cors]** `SysConfigController.page`（global-config，影响 139 条路由） @ `SysConfigController.java:54`
- **[authz]** `DeliveryController.checkDelivery`（endpoint，影响 1 条路由） @ `DeliveryController.java:48`
- **[xss]** `UserCollectionController.addOrCancel`（endpoint，影响 1 条路由） @ `UserCollectionController.java:65`
- **[authz]** `FileController.uploadElementFile`（endpoint，影响 1 条路由） @ `FileController.java:44`
- **[authz]** `FileController.uploadTinymceEditorImages`（endpoint，影响 1 条路由） @ `FileController.java:53`

### xxl-job（Java）— 5 个独立根因

- **[xss]** `IndexController.errorPage`（endpoint，影响 1 条路由） @ `IndexController.java:109`
- **[redir]** `LoginController.login`（endpoint，影响 1 条路由） @ `LoginController.java:35`
- **[xss]** `LoginController.login`（endpoint，影响 1 条路由） @ `LoginController.java:35`
- **[xss]** `JobInfoController.add`（endpoint，影响 1 条路由） @ `JobInfoController.java:99`
- **[xss]** `JobInfoController.update`（endpoint，影响 1 条路由） @ `JobInfoController.java:109`

### My-Blog-layui（Java）— 3 个独立根因

- **[hash]** `AdminController.login#2`（endpoint，影响 1 条路由） @ `AdminController.java:100`
- **[hash]** `AdminController.userInfoUpdate`（endpoint，影响 1 条路由） @ `AdminController.java:179`
- **[xss]** `BlogController.gotoBlogEdit`（endpoint，影响 1 条路由） @ `BlogController.java:57`

### RuoYi（Java）— 3 个独立根因

- **[sqli]** `GenController.create`（endpoint，影响 1 条路由） @ `GenController.java:195`
- **[xss]** `CommonController.uploadFile`（endpoint，影响 1 条路由） @ `CommonController.java:75`
- **[xss]** `CommonController.uploadFiles`（endpoint，影响 1 条路由） @ `CommonController.java:102`

### Employee-Management-System（Python）— 2 个独立根因

- **[authz]** `delete`（endpoint，影响 1 条路由） @ `app.py:63`
- **[hardcoded_secret]** `[secret-file] app.py`（file-level，影响 1 条路由） @ `app.py:1`

### django-realworld（Python）— 2 个独立根因

- **[authz]** `ArticleViewSet.update`（endpoint，影响 1 条路由） @ `views.py:87`
- **[hardcoded_secret]** `[secret-file] settings.py`（file-level，影响 1 条路由） @ `settings.py:1`

### solmate（Solidity）— 2 个独立根因

- **[arithmetic]** `transfer`（endpoint，影响 1 条路由） @ `ERC20.sol:76`
- **[arithmetic]** `transferFrom`（endpoint，影响 1 条路由） @ `ERC20.sol:90`

### Synthetix V3（Solidity）— 1 个独立根因

- **[unchecked_low_level_calls]** `processCcipReceive`（endpoint，影响 1 条路由） @ `CrossChain.sol:50`

### mall-tiny（Java）— 1 个独立根因

- **[cors]** `UmsAdminController.register`（global-config，影响 40 条路由） @ `UmsAdminController.java:48`

### waynboot-mall（Java）— 1 个独立根因

- **[cors]** `SeckillOrderCallbackController.submit`（global-config，影响 163 条路由） @ `SeckillOrderCallbackController.java:32`

## 五、怎么复现

```bash
# 1) 采集 30 个仓库的 scan --auto + benchmark strict 数据 + 披露草稿
python benchmarks/wild_hunt.py --advisory-dir benchmarks/results/advisories

# 2) 47 项离线门禁（冒烟 [1]-[185] + 争议核对 + 覆盖地板 + 44 个靶场 + 聚类对账）
python benchmarks/run_all.py --offline --jobs 4

# 3) 自检：依赖 / 30 类规则 / 缓存指纹 / 25 类补丁器 / 能力地板 /
#    SARIF 合规 / 正则卫生 / 白皮书对账 / 跨仓聚类对账
python cli.py doctor

# 4) 能力覆盖矩阵（30 类 × 三语言 × 规则/--fix/PoC/CVSS）
python cli.py matrix
```

> 环境：Python 3.14 / Windows；30 个仓库以 `git clone --depth 1` 放在
> `reference_repos/`。所有门禁**不调模型**，纯规则层，秒级可复现。

## 六、M119–M150 段新增的确定性机制（13 条）

这一段只记**被真实仓库逼出来的判据修正**，不记功能清单。每条都写着
"哪个仓把它逼出来的"，以及修完之后判定面怎么变。

| 模块 | 机制 | 逼出它的仓库 | 判定面变化 |
|---|---|---|---|
| M119 | 入口段**先切后剥注释**（`_entry_region()` 收口） | elunez/eladmin | Hop 3 的辅助类代码不再混进入口体，4 条 `crypto` 误报清零 |
| M119 | 整数型状态互斥锁（`unlocked 1→0→1`）识别 | Uniswap/v2-core | 反向锚点 `with=False → without=None`（失去锁即失去判据） |
| M121 | DRF 类视图 / `router.register` 通道 + 类级 `permission_classes` 证据头 | django-realworld | 单元数 1 → 11，实锤 `ArticleViewSet.update` 缺 `IsOwnerOrReadOnly` |
| M123 | `mass_assignment` 拷贝**方向性**守卫 | jeecg-boot | 内部实体→会话对象不再算批量赋值，25 仓独立根因 96 → 94 |
| M135 | 跨仓聚类门禁（计数守恒 + 多仓共现簇 ≥8） | 30 仓自身 | 聚类产物与采集产物对不上账当场红，不再"墙上的数" |
| M136 | `wards[msg.sender] == 1` 授权映射 + 合约内联算术封装 | MakerDAO dss | 234 入口 / 五类 0 True；`rely/deny/file/cage` 判 False 且可反向翻转 |
| M137 | 无括号装饰器入索引 + `// Auth-Guard:` 证据头 + 公开只读面 | flasky | 39 入口 / 0 True / 8 条守卫证据（含实现体） |
| M138 | JWT + MyBatis-Plus + 全局 CORS 折叠 | mall-tiny | 40 入口 / cors 外 0 True / 40 条路由命中折叠成 1 个全局根因 |
| M139 | 第 28 类 `unsafe_reflection` + 补丁器 #23 | — | 字面量/白名单判 False，入口形参判 True；补丁注入白名单后重切翻 False |
| M140 | 第 29 类 `zip_slip` + 补丁器 #24 | — | 规范化前缀校验 / PEP 706 `filter="data"` 判 False |
| M141 | 第 30 类 `delegatecall_untrusted` + 补丁器 #25 | — | `address(this)` / ERC-1967 槽 / `onlyOwner` / `onlyProxy` / 测试合约全排除 |
| M143 | `initializer` / `onlyInitializing` / `onlyProxy` 语义边界 + `.t.sol` 排除 | OZ Upgradeable、dss | 2017 入口 / 五类 0 True；一次性初始化入口退 None 而不是 True |
| M145 | 供应链组件 CVE × 代码入口**交叉印证** | 30 仓 | 3 仓命中已知 advisory，其中 2 仓"双重实锤"（同时有代码级 P0） |

> 这 13 条里没有一条是"放松判据凑数字"：M136/M137/M138/M143 四条的验收都带
> **反向锚点**（把证据摘掉，判定必须跟着翻），M139–M141 三条的补丁器都要求
> "重切片后 True → False"，M135/M145 两条是把结论拿去和另一张表对账。

## 七、42 仓供应链组件风险 × 代码入口可达性对照

这一节回答一个单看任一表都答不出的问题：**哪些仓既用了已知有漏洞的组件版本，又真有一条代码级 P0？**

- 组件版本来自构建清单（Maven `pom.xml` + Python `requirements*.txt`/`requirements/*.txt`）。**不解析 `package.json`**：这 30 个仓里的 JS 依赖基本是 hardhat / editormd 这类构建期工具，不在运行时链路上。
- CVE 对照表是**人工维护的保守清单**（每条都带修复版本与编号），未收录的组件不计命中、也不算安全 —— 报告里如实标成「未收录」。
- 「代码级 P0」列取同仓的**独立根因数**（去重后），与 `wild_hunt.json` 同一口径。

扫描组件 104 个，命中已知 advisory 的仓库 **7 个**，涉及 CVE：CVE-2013-7459、CVE-2017-12794、CVE-2018-1000656、CVE-2018-14574、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548、CVE-2020-25626、CVE-2022-21363、CVE-2022-29217、CVE-2023-24162。

| 仓库 | 语言 | 组件（版本） | CVE | 代码级 P0 根因 | 交叉结论 |
|---|---|---|---|---|---|
| jeecg-boot | Java | `mysql-connector-java` 8.0.27 | CVE-2022-21363 | 27 | **双重实锤**（1 个组件 / 1 条 advisory + 27 个代码根因） |
| DjanGoat | Python | `django` 1.11.1、`pycrypto` 2.6.1 | CVE-2013-7459、CVE-2017-12794、CVE-2018-14574 | 12 | **双重实锤**（2 个组件 / 3 条 advisory + 12 个代码根因） |
| spring-boot-demo | Java | `hutool-all` 5.4.5、`mysql-connector-java` 8.0.21 | CVE-2022-21363、CVE-2023-24162 | 12 | **双重实锤**（2 个组件 / 2 条 advisory + 12 个代码根因） |
| django-realworld | Python | `django` 1.10.5、`djangorestframework` 3.4.4、`pyjwt` 1.4.2 | CVE-2017-12794、CVE-2018-14574、CVE-2020-25626、CVE-2022-29217 | 2 | **双重实锤**（3 个组件 / 4 条 advisory + 2 个代码根因） |
| mall-tiny | Java | `hutool-all` 5.8.9 | CVE-2023-24162 | 1 | **双重实锤**（1 个组件 / 1 条 advisory + 1 个代码根因） |
| flask-realworld | Python | `sqlalchemy` 1.1.9 | CVE-2019-7548 | 0 | 仅组件（代码侧未发现 P0） |
| flasky | Python | `flask` 0.12.2、`jinja2` 2.9.6、`requests` 2.18.2 …+3 | CVE-2018-1000656、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548 | 0 | 仅组件（代码侧未发现 P0） |
| ruoyi-vue-pro | Java | — | — | 46 | 仅代码（组件版本未命中已知 advisory） |
| eladmin-mp | Java | — | — | 12 | 仅代码（组件版本未命中已知 advisory） |
| eladmin-JPA | Java | — | — | 12 | 仅代码（组件版本未命中已知 advisory） |
| newbee-mall | Java | — | — | 11 | 仅代码（组件版本未命中已知 advisory） |
| newbee-mall-api | Java | — | — | 9 | 仅代码（组件版本未命中已知 advisory） |
| mall | Java | — | — | 8 | 仅代码（组件版本未命中已知 advisory） |
| My-Blog | Java | — | — | 6 | 仅代码（组件版本未命中已知 advisory） |
| apollo | Java | — | — | 6 | 仅代码（组件版本未命中已知 advisory） |
| litemall | Java | — | — | 5 | 仅代码（组件版本未命中已知 advisory） |
| mall4j | Java | — | — | 5 | 仅代码（组件版本未命中已知 advisory） |
| xxl-job | Java | — | — | 5 | 仅代码（组件版本未命中已知 advisory） |
| RuoYi | Java | — | — | 3 | 仅代码（组件版本未命中已知 advisory） |
| My-Blog-layui | Java | — | — | 3 | 仅代码（组件版本未命中已知 advisory） |
| Employee-Management-System | Python | — | — | 2 | 仅代码（组件版本未命中已知 advisory） |
| solmate | Solidity | — | — | 2 | 仅代码（组件版本未命中已知 advisory） |
| waynboot-mall | Java | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |
| Synthetix V3 | Solidity | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |

**双重实锤仓 5 个**：jeecg-boot、DjanGoat、spring-boot-demo、django-realworld、mall-tiny

> 口径说明：「仅组件」不等于「有漏洞可利用」—— 组件是否存在可达的危险入口要看同一行的代码列；「仅代码」也不是「组件没问题」，只是版本没落进维护清单里。两类都如实列出，不做合并。
