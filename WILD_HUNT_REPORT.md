# 野战白皮书 —— 30 个真实开源生产仓库（M119–M150 收官）

> 本文所有数字由 `benchmarks/wild_hunt.py` **实跑**产出，唯一事实源是
> `benchmarks/results/wild_hunt.json`（`cli.py doctor` 第六段会对账，
> 数字漂了当场 FAIL）。规则层离线可复现，不含模型层数字。

## 一、总量（30 仓 / 独立根因 / 零误报）

| 项 | 数值 |
|---|---|
| 真实仓库 | **30 个**（Java 13 + Python 7 + Solidity 10） |
| 路由/合约入口 | **8,364 个** |
| 路由级 P0 命中 | **1,545 条** |
| 去重后的独立根因 P0 | **98 个** |
| GHSA 披露草稿 | **98 份**（按独立根因，不按路由） |
| benchmark 层误报 | **0 条** |
| benchmark 层计划外 True | **0 条** |
| `benchmark_* --strict` | **30/30 exit 0**（零误报 / 零漏报 / 零判反） |
| 供应链命中已知 advisory 的仓库 | **3 个** |
| 供应链 × 代码**双重实锤** | **2 个** |

一句话：**在 8,364 个从未见过的真实入口上，规则层没有确认误报；98 个独立根因全部逐条人工核查过源码（作者自述 + 代码形态双重确认）。**

## 二、逐仓数字

| 仓库 | 语言 | 入口 | 路由级 P0 | 独立根因 | benchmark | 组件 CVE |
|---|---|---|---|---|---|---|
| jeecg-boot | Java | 458 | 479 | 24 | ✔ | — |
| DjanGoat | Python | 36 | 12 | 12 | ✔ | CVE-2013-7459、CVE-2017-12794、CVE-2018-14574 |
| eladmin-mp | Java | 65 | 74 | 10 | ✔ | — |
| eladmin-JPA | Java | 66 | 75 | 10 | ✔ | — |
| mall | Java | 246 | 253 | 8 | ✔ | — |
| newbee-mall | Java | 73 | 6 | 6 | ✔ | — |
| litemall | Java | 219 | 223 | 5 | ✔ | — |
| mall4j | Java | 139 | 143 | 5 | ✔ | — |
| newbee-mall-api | Java | 62 | 65 | 4 | ✔ | — |
| My-Blog | Java | 54 | 3 | 3 | ✔ | — |
| My-Blog-layui | Java | 64 | 3 | 3 | ✔ | — |
| Employee-Management-System | Python | 4 | 2 | 2 | ✔ | — |
| django-realworld | Python | 11 | 2 | 2 | ✔ | CVE-2017-12794、CVE-2018-14574、CVE-2020-25626、CVE-2022-29217 |
| RuoYi | Java | 305 | 1 | 1 | ✔ | — |
| waynboot-mall | Java | 163 | 163 | 1 | ✔ | — |
| Synthetix V3 | Solidity | 1411 | 1 | 1 | ✔ | — |
| mall-tiny | Java | 40 | 40 | 1 | ✔ | — |
| Compound | Solidity | 450 | 0 | 0 | ✔ | — |
| Comet | Solidity | 357 | 0 | 0 | ✔ | — |
| OpenZeppelin | Solidity | 1989 | 0 | 0 | ✔ | — |
| AaveV3 | Solidity | 553 | 0 | 0 | ✔ | — |
| flaskr | Python | 8 | 0 | 0 | ✔ | — |
| sushiswap-zapper | Solidity | 75 | 0 | 0 | ✔ | — |
| Uniswap V2 | Solidity | 29 | 0 | 0 | ✔ | — |
| fastapi-realworld | Python | 19 | 0 | 0 | ✔ | — |
| UniswapV3 | Solidity | 67 | 0 | 0 | ✔ | — |
| FastAPI | Python | 9 | 0 | 0 | ✔ | — |
| MakerDAO dss | Solidity | 234 | 0 | 0 | ✔ | — |
| flasky | Python | 39 | 0 | 0 | ✔ | CVE-2018-1000656、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548 |
| OZ Upgradeable | Solidity | 1119 | 0 | 0 | ✔ | — |

> Solidity 十仓规则层全部 0 条 P0（Compound V2/V3、Uniswap V2/V3、OpenZeppelin ×2、Aave V3、Synthetix V3、sushiswap-zapper、MakerDAO dss）—— 这是「规则不会把安全写法当漏洞」的硬证据。

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

## 四、逐仓独立根因（人工逐条核查）

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
- **[hardcoded_secret]** `[secret-file] JeecgBaseConfig.java`（file-level，影响 1 条路由） @ `JeecgBaseConfig.java:1`

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
- **[hardcoded_secret]** `[secret-file] settings.py`（file-level，影响 1 条路由） @ `settings.py:1`

### eladmin-mp（10 个根因）

- **[authz]** `AliPayController.toPayAsPc`（端点，影响 1 条路由） @ `AliPayController.java:68`
- **[cors]** `AliPayController.toPayAsPc`（全局配置，影响 65 条路由） @ `AliPayController.java:68`
- **[authz]** `AliPayController.toPayAsWeb`（端点，影响 1 条路由） @ `AliPayController.java:78`
- **[authz]** `VerifyController.resetEmail`（端点，影响 1 条路由） @ `VerifyController.java:44`
- **[authz]** `VerifyController.resetPass`（端点，影响 1 条路由） @ `VerifyController.java:52`
- **[authz]** `VerifyController.validated`（端点，影响 1 条路由） @ `VerifyController.java:60`
- **[authz]** `GenConfigController.queryGenConfig`（端点，影响 1 条路由） @ `GenConfigController.java:40`
- **[authz]** `GeneratorController.queryTables`（端点，影响 1 条路由） @ `GeneratorController.java:53`
- **[authz]** `GeneratorController.queryColumns`（端点，影响 1 条路由） @ `GeneratorController.java:59`
- **[authz]** `GeneratorController.generatorCode`（端点，影响 1 条路由） @ `GeneratorController.java:82`

### eladmin-JPA（10 个根因）

- **[authz]** `AliPayController.toPayAsPc`（端点，影响 1 条路由） @ `AliPayController.java:68`
- **[cors]** `AliPayController.toPayAsPc`（全局配置，影响 66 条路由） @ `AliPayController.java:68`
- **[authz]** `AliPayController.toPayAsWeb`（端点，影响 1 条路由） @ `AliPayController.java:78`
- **[authz]** `VerifyController.resetEmail`（端点，影响 1 条路由） @ `VerifyController.java:44`
- **[authz]** `VerifyController.resetPass`（端点，影响 1 条路由） @ `VerifyController.java:52`
- **[authz]** `VerifyController.validated`（端点，影响 1 条路由） @ `VerifyController.java:60`
- **[authz]** `GenConfigController.queryGenConfig`（端点，影响 1 条路由） @ `GenConfigController.java:40`
- **[authz]** `GeneratorController.queryTables`（端点，影响 1 条路由） @ `GeneratorController.java:58`
- **[authz]** `GeneratorController.queryColumns`（端点，影响 1 条路由） @ `GeneratorController.java:67`
- **[authz]** `GeneratorController.generatorCode`（端点，影响 1 条路由） @ `GeneratorController.java:90`

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
- **[hardcoded_secret]** `[secret-file] JwtHelper.java`（file-level，影响 1 条路由） @ `JwtHelper.java:1`

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

### My-Blog-layui（3 个根因）

- **[hash]** `AdminController.login#2`（端点，影响 1 条路由） @ `AdminController.java:100`
- **[hash]** `AdminController.userInfoUpdate`（端点，影响 1 条路由） @ `AdminController.java:179`
- **[xss]** `BlogController.gotoBlogEdit`（端点，影响 1 条路由） @ `BlogController.java:57`

### Employee-Management-System（2 个根因）

- **[authz]** `delete`（端点，影响 1 条路由） @ `app.py:63`
- **[hardcoded_secret]** `[secret-file] app.py`（file-level，影响 1 条路由） @ `app.py:1`

### django-realworld（2 个根因）

- **[authz]** `ArticleViewSet.update`（端点，影响 1 条路由） @ `views.py:87`
- **[hardcoded_secret]** `[secret-file] settings.py`（file-level，影响 1 条路由） @ `settings.py:1`

### RuoYi（1 个根因）

- **[sqli]** `GenController.create`（端点，影响 1 条路由） @ `GenController.java:195`

### waynboot-mall（1 个根因）

- **[cors]** `SeckillOrderCallbackController.submit`（全局配置，影响 163 条路由） @ `SeckillOrderCallbackController.java:32`

### Synthetix V3（1 个根因）

- **[unchecked_low_level_calls]** `processCcipReceive`（端点，影响 1 条路由） @ `CrossChain.sol:50`

### mall-tiny（1 个根因）

- **[cors]** `UmsAdminController.register`（全局配置，影响 40 条路由） @ `UmsAdminController.java:48`

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

## 七、30 仓供应链组件风险 × 代码入口可达性对照（M145）

这一节回答一个单看任一表都答不出的问题：**哪些仓既用了已知有漏洞的组件版本，又真有一条代码级 P0？**

- 组件版本来自构建清单（Maven `pom.xml` + Python `requirements*.txt`/`requirements/*.txt`）。**不解析 `package.json`**：这 30 个仓里的 JS 依赖基本是 hardhat / editormd 这类构建期工具，不在运行时链路上。
- CVE 对照表是**人工维护的保守清单**（每条都带修复版本与编号），未收录的组件不计命中、也不算安全 —— 报告里如实标成「未收录」。
- 「代码级 P0」列取同仓的**独立根因数**（去重后），与 `wild_hunt.json` 同一口径。

扫描组件 79 个，命中已知 advisory 的仓库 **3 个**，涉及 CVE：CVE-2013-7459、CVE-2017-12794、CVE-2018-1000656、CVE-2018-14574、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548、CVE-2020-25626、CVE-2022-29217。

| 仓库 | 语言 | 组件（版本） | CVE | 代码级 P0 根因 | 交叉结论 |
|---|---|---|---|---|---|
| DjanGoat | Python | `django` 1.11.1、`pycrypto` 2.6.1 | CVE-2013-7459、CVE-2017-12794、CVE-2018-14574 | 12 | **双重实锤**（2 个组件 / 3 条 advisory + 12 个代码根因） |
| django-realworld | Python | `django` 1.10.5、`djangorestframework` 3.4.4、`pyjwt` 1.4.2 | CVE-2017-12794、CVE-2018-14574、CVE-2020-25626、CVE-2022-29217 | 2 | **双重实锤**（3 个组件 / 4 条 advisory + 2 个代码根因） |
| flasky | Python | `flask` 0.12.2、`jinja2` 2.9.6、`requests` 2.18.2 …+3 | CVE-2018-1000656、CVE-2018-18074、CVE-2019-10906、CVE-2019-11324、CVE-2019-14322、CVE-2019-7548 | 0 | 仅组件（代码侧未发现 P0） |
| jeecg-boot | Java | — | — | 24 | 仅代码（组件版本未命中已知 advisory） |
| eladmin-mp | Java | — | — | 10 | 仅代码（组件版本未命中已知 advisory） |
| eladmin-JPA | Java | — | — | 10 | 仅代码（组件版本未命中已知 advisory） |
| mall | Java | — | — | 8 | 仅代码（组件版本未命中已知 advisory） |
| newbee-mall | Java | — | — | 6 | 仅代码（组件版本未命中已知 advisory） |
| litemall | Java | — | — | 5 | 仅代码（组件版本未命中已知 advisory） |
| mall4j | Java | — | — | 5 | 仅代码（组件版本未命中已知 advisory） |
| newbee-mall-api | Java | — | — | 4 | 仅代码（组件版本未命中已知 advisory） |
| My-Blog | Java | — | — | 3 | 仅代码（组件版本未命中已知 advisory） |
| My-Blog-layui | Java | — | — | 3 | 仅代码（组件版本未命中已知 advisory） |
| Employee-Management-System | Python | — | — | 2 | 仅代码（组件版本未命中已知 advisory） |
| RuoYi | Java | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |
| waynboot-mall | Java | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |
| Synthetix V3 | Solidity | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |
| mall-tiny | Java | — | — | 1 | 仅代码（组件版本未命中已知 advisory） |

**双重实锤仓 2 个**：DjanGoat、django-realworld

> 口径说明：「仅组件」不等于「有漏洞可利用」—— 组件是否存在可达的危险入口要看同一行的代码列；「仅代码」也不是「组件没问题」，只是版本没落进维护清单里。两类都如实列出，不做合并。
