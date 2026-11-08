# STAGE REPORT · v1.4.5（M345–M348：假阳收口、冷却翻页、org-hunt 落地）

> 日期：2026-11-08 ｜ 基线：v1.4.4（707593c）
> 结论：M345 收口 3 类新假阳；M346 冷却感知翻页落地；M347 org-hunt
> 固化为 CLI；M348 门禁 1,935 项全绿。下一批组织矿脉（gz-yami / elunez /
> linlinjava）得到 2 条 eladmin authz 候选，需角色模型确认，未按真洞提交。

## 一、M345：三类假阳收口

### 1.1 JDBC DatabaseMetaData

DataFlow-Engine 的 SourceController.extractTable 走
DatabaseMetaData.getTables/getColumns/getPrimaryKeys；tableName 是元数据
API 参数，不是 SQL 文本。sqli_verdict 现在在“源码含 DatabaseMetaData /
getMetaData，且入口体无 createStatement/JdbcTemplate/execute”时返回 False。

验证：SourceController.extractTable 由 True → **False**。

### 1.2 具体 POJO / TypeReference 反序列化

deserial_verdict 新增：

- readValue(input, ConcreteModel.class) 且无 enableDefaultTyping /
  activateDefaultTyping、无 Id.CLASS/NAME → False；
- TypeReference<List<Concrete>> 同样按具体类型处理；
- Map/Object/Serializable 等可承载任意类型的目标不改判。

验证：

| 样本 | 结果 |
| --- | --- |
| Digital ImportExportController.importAppJson（AppJsonModel.class） | True → **False** |
| WorkFlow OpinionSignRestController.save（OpinionSignModel.class） | True → **False** |
| Enterprise resolveExecution（TypeReference<List<ExecutionReference>>） | True → **False** |

### 1.3 参数化条件构造器 / MyBatis-Plus

- CommonUtils.buildQueryConditions：字段名是编译期常量，值走 params.add
  与 ? 绑定；切片同时带 helper、whereSql、params.add 和 ? 时判 False。
- SQLI_JDBCTEMPLATE_RE 只认 jdbcTemplate / namedParameterJdbcTemplate
  接收者，不再把裸 .update( 当成 JdbcTemplate。
- .last("limit " + UPPER_CONST) 视为整数常量。

验证：

| 样本 | 结果 |
| --- | --- |
| WorkFlow TodoRestController.allTodoList | True → **False** |
| Enterprise claimPageAction / submitPageActionResult | True → **False** |
| Enterprise PlatformRunCenterConversationController.list/detail | True → **False** |
| 真实 WorkFlow doingList4All / recycleList / todoList4Other | 仍 **True** |

## 二、M346：冷却感知自动翻页

target_scout.scout_daily 新增 exclude_slugs；daily_hunt 在调用 scout 前把
仍在 cooldown_days 内的 slug 传入。当前页剔除冷却仓后不足 2 个且还有下一页
时，自动请求 page+1/+2（单查询最多 2 页），并记录 cooldown_pages。

验证：page1 只有 old1/old2（全部排除）时，自动翻到 page2 拿到
new1/new2；不改变无 exclude 时的原有 page 轮转。

## 三、M347：org-hunt CLI

新增 core/context/org_hunt.py：

- list_org_repos：GitHub /orgs/<org>/repos，404 回退 /users/<org>/repos；
  过滤 archived/fork、教学仓、工具库、语言；
- run：复用 daily_hunt.process_repo，max_roots 默认 25、min_units 默认 5，
  输出 Markdown + JSON + packs。

CLI：

    python cli.py org-hunt --orgs gz-yami,elunez,linlinjava \
      --languages java --max-roots 20 --min-units 5 --limit 8

首次运行：4 个业务仓、实扫 3、根因 6、机器 A 2、B 4。1 个仓因低路由密度
被跳过。

### eladmin 的 2 条 A（需角色模型确认，未提交）

| 入口 | 事实 |
| --- | --- |
| AliPayController.updateAliPayConfig（PUT /api/aliPay） | 无 @PreAuthorize；SpringSecurityConfig anyRequest().authenticated() |
| S3StorageController.uploadS3Storage（POST /api/s3Storage） | 同文件 query/download 有 @PreAuthorize("@el.check('storage:list')")，upload 没有 |

这两条是**方法级授权缺失**候选，不是 SQLi/RCE。是否可被非管理员账号利用，
取决于 eladmin 的角色模型与部署；在确认前不按第 6 单提交，也不伪造 CVSS。
其余 4 条 B 为 UNVERIFIED_WILD_AUTHZ。

## 四、M348：门禁

- smoke_test_chains.py：**PASS，1,935 项**
- triage_fallbacks.py --check-floor：**16/16**
- cli.py doctor：**PASS（12 段全绿）**

新增：

- [319] DatabaseMetaData / typed POJO / TypeReference / buildQueryConditions /
  MyBatis-Plus update；
- [320] exclude_slugs 翻页、org_hunt 离线注入、max_roots/min_units 透传。

## 五、结论与下一步

1. M345 把组织深扫的三类噪声压掉，真实 SQLi 未被误伤。
2. M346 解决了“22 候选 18 个冷却期只扫 1 仓”的供给侧问题；冷却期本身仍是
   正常策略，下一轮可用 --cooldown-days 0 做补充而不是改算法。
3. M347 已把组织矿脉从临时脚本变成 CLI；下一批建议优先
   jeecgboot / dromara / macrozheng，且对 eladmin 两条 authz 先做角色模型
   验证。
4. 第 4 单 WorkFlow（9 路由）与第 5 单 Network-Drive 仍未对外提交；第 2/3
   单（metasfresh / x-springboot）仍待你本人走外部流程。
