# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-01 10:15:32
- 总条数：22 ｜ 板块 A：**11** ｜ 板块 B：**11**
- 状态计数：ZERO_RECORD_FRESH 11 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 11

<!-- live_hunt_counts: {"BOARD_A": 11, "BOARD_B": 11, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 11, "ZERO_RECORD_FRESH": 11} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 7 个缓存。

- 候选仓：10 ｜ 实扫：5 ｜ 跳过：5 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：22 ｜ 板块 A：11 ｜ 拦截进 B：11
- 冷却期免克隆：3 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| dromara/skyeye | b211328dbee6 | SCANNED | 3 |
| yujian0815/fnmedia-ext | 8098bd743846 | SCANNED | 5 |
| getrebuild/rebuild | 4d64ea904bdb | SKIPPED | 0 |
| jowilf/starlette-admin | ea4d71470672 | SKIPPED | 0 |
| w8123/EnterpriseAgentFramework | 1f1230d50db0 | SCANNED | 6 |
| insistence/RuoYi-FastAPI | 7f7c66d373b6 | SKIPPED | 0 |
| guchengwuyue/yshop-oa-crm | 398e0e9b5ee2 | SCANNED | 4 |
| strimzi/strimzi-kafka-oauth | 4d1f76bbca06 | SKIPPED | 0 |
| SpringSunYY/LZ-litchi | af0dc34f1b41 | SCANNED | 4 |
| apache/jackrabbit-oak | 85d5497b7e13 | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | EnterpriseAgentFramework | sqli | BusinessUserDirectoryController.listBusinessUsers | — | 2026-10-27 (4.5d) | 1f1230d50db0 | [reachai-control-service/src/main/java/com/enterprise/ai/control/identity/BusinessUserDirectoryController.java:33](https://github.com/w8123/EnterpriseAgentFramework/blob/1f1230d50db03bd5018734731f91be3d410526d7/reachai-control-service/src/main/java/com/enterprise/ai/control/identity/BusinessUserDirectoryController.java#L33) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_listBusinessUsers/SUBMISSION_PLAYBOOK.md) |
| 2 | EnterpriseAgentFramework | sqli | PersonalMemoryIndexInternalController.apply | — | 2026-10-27 (4.5d) | 1f1230d50db0 | [reachai-knowledge-service/src/main/java/com/enterprise/ai/personalmemory/PersonalMemoryIndexInternalController.java:24](https://github.com/w8123/EnterpriseAgentFramework/blob/1f1230d50db03bd5018734731f91be3d410526d7/reachai-knowledge-service/src/main/java/com/enterprise/ai/personalmemory/PersonalMemoryIndexInternalController.java#L24) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_apply/SUBMISSION_PLAYBOOK.md) |
| 3 | EnterpriseAgentFramework | sqli | PlatformAccountRoleController.listAuditEvents | — | 2026-10-27 (4.5d) | 1f1230d50db0 | [reachai-control-service/src/main/java/com/enterprise/ai/control/identity/PlatformAccountRoleController.java:290](https://github.com/w8123/EnterpriseAgentFramework/blob/1f1230d50db03bd5018734731f91be3d410526d7/reachai-control-service/src/main/java/com/enterprise/ai/control/identity/PlatformAccountRoleController.java#L290) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_listAuditEvents/SUBMISSION_PLAYBOOK.md) |
| 4 | EnterpriseAgentFramework | sqli | RetrievalController.test | — | 2026-10-27 (4.5d) | 1f1230d50db0 | [reachai-knowledge-service/src/main/java/com/enterprise/ai/controller/RetrievalController.java:24](https://github.com/w8123/EnterpriseAgentFramework/blob/1f1230d50db03bd5018734731f91be3d410526d7/reachai-knowledge-service/src/main/java/com/enterprise/ai/controller/RetrievalController.java#L24) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_test/SUBMISSION_PLAYBOOK.md) |
| 5 | EnterpriseAgentFramework | sqli | RuntimeTraceCenterController.listGuardDecisions | — | 2026-10-27 (4.5d) | 1f1230d50db0 | [reachai-runtime-service/src/main/java/com/enterprise/ai/runtime/runops/RuntimeTraceCenterController.java:19](https://github.com/w8123/EnterpriseAgentFramework/blob/1f1230d50db03bd5018734731f91be3d410526d7/reachai-runtime-service/src/main/java/com/enterprise/ai/runtime/runops/RuntimeTraceCenterController.java#L19) | [Advisory](https://github.com/w8123/EnterpriseAgentFramework/security/advisories/new) · [Issue](https://github.com/w8123/EnterpriseAgentFramework/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/EnterpriseAgentFramework_sqli_listGuardDecisions/SUBMISSION_PLAYBOOK.md) |
| 6 | LZ-litchi | redir | FileController.getFileContent | — | 2026-10-25 (6.7d) | af0dc34f1b41 | [litchi-module-infra/src/main/java/com/lz/module/infra/controller/admin/file/FileController.java:93](https://github.com/SpringSunYY/LZ-litchi/blob/af0dc34f1b41061dca9d2da86a6025835d8b0734/litchi-module-infra/src/main/java/com/lz/module/infra/controller/admin/file/FileController.java#L93) | [Advisory](https://github.com/SpringSunYY/LZ-litchi/security/advisories/new) · [Issue](https://github.com/SpringSunYY/LZ-litchi/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/LZ-litchi_redir_getFileContent/SUBMISSION_PLAYBOOK.md) |
| 7 | LZ-litchi | xss | VectorImageController.uploadImage | — | 2026-10-25 (6.7d) | af0dc34f1b41 | [litchi-module-infra/src/main/java/com/lz/module/infra/controller/admin/vector/VectorImageController.java:51](https://github.com/SpringSunYY/LZ-litchi/blob/af0dc34f1b41061dca9d2da86a6025835d8b0734/litchi-module-infra/src/main/java/com/lz/module/infra/controller/admin/vector/VectorImageController.java#L51) | [Advisory](https://github.com/SpringSunYY/LZ-litchi/security/advisories/new) · [Issue](https://github.com/SpringSunYY/LZ-litchi/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/LZ-litchi_xss_uploadImage/SUBMISSION_PLAYBOOK.md) |
| 8 | skyeye | pathtraver | StencilsetRestResource.getStencilset | — | 2026-10-31 (0.6d) | b211328dbee6 | [skyeye-flowable/flowable-main/src/main/java/com/skyeye/flowable/main/StencilsetRestResource.java:39](https://github.com/dromara/skyeye/blob/b211328dbee68a7b3383660e09431266191a43a8/skyeye-flowable/flowable-main/src/main/java/com/skyeye/flowable/main/StencilsetRestResource.java#L39) | [Advisory](https://github.com/dromara/skyeye/security/advisories/new) · [Issue](https://github.com/dromara/skyeye/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/skyeye_pathtraver_getStencilset/SUBMISSION_PLAYBOOK.md) |
| 9 | skyeye | redir | IndexController.toLogin | — | 2026-10-31 (0.6d) | b211328dbee6 | [xxl-job-2.3.0/xxl-job-admin/src/main/java/com/xxl/job/admin/controller/IndexController.java:54](https://github.com/dromara/skyeye/blob/b211328dbee68a7b3383660e09431266191a43a8/xxl-job-2.3.0/xxl-job-admin/src/main/java/com/xxl/job/admin/controller/IndexController.java#L54) | [Advisory](https://github.com/dromara/skyeye/security/advisories/new) · [Issue](https://github.com/dromara/skyeye/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/skyeye_redir_toLogin/SUBMISSION_PLAYBOOK.md) |
| 10 | skyeye | xss | IndexController.toLogin | — | 2026-10-31 (0.6d) | b211328dbee6 | [xxl-job-2.3.0/xxl-job-admin/src/main/java/com/xxl/job/admin/controller/IndexController.java:54](https://github.com/dromara/skyeye/blob/b211328dbee68a7b3383660e09431266191a43a8/xxl-job-2.3.0/xxl-job-admin/src/main/java/com/xxl/job/admin/controller/IndexController.java#L54) | [Advisory](https://github.com/dromara/skyeye/security/advisories/new) · [Issue](https://github.com/dromara/skyeye/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/skyeye_xss_toLogin/SUBMISSION_PLAYBOOK.md) |
| 11 | yshop-oa-crm | authz | CrmFlowController.deleteFlowStep | HIGH | 2026-10-30 (1.8d) | 398e0e9b5ee2 | [yshop-crm/yshop-module-crm/yshop-module-crm-biz/src/main/java/co/yixiang/yshop/module/crm/controller/admin/crmflow/CrmFlowController.java:102](https://github.com/guchengwuyue/yshop-oa-crm/blob/398e0e9b5ee29b484dc891c9d2233f4ee5dc9e45/yshop-crm/yshop-module-crm/yshop-module-crm-biz/src/main/java/co/yixiang/yshop/module/crm/controller/admin/crmflow/CrmFlowController.java#L102) | [Advisory](https://github.com/guchengwuyue/yshop-oa-crm/security/advisories/new) · [Issue](https://github.com/guchengwuyue/yshop-oa-crm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/yshop-oa-crm_authz_deleteFlowStep/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | EnterpriseAgentFramework | unchecked_low_level_calls | RuntimePublicController.clearAgentSession | **UNKNOWN** | — | RULE_LANGUAGE_MISMATCH: unchecked_low_level_calls 是 Solidity 类目，入口文件是 .java | — |
| 2 | LZ-litchi | authz | AreaController.getAreaTree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | LZ-litchi | authz | TenantPackageController.getTenantPackageList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | fnmedia-ext | authz | episode_list_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | fnmedia-ext | authz | item_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | fnmedia-ext | authz | mdb_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | fnmedia-ext | authz | season_list_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | fnmedia-ext | authz | stream_list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | yshop-oa-crm | authz | AppDictDataController.getDictDataListByType | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | yshop-oa-crm | authz | DictDataController.getDictDataListByType | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | yshop-oa-crm | authz | MailTemplateController.getMailTemplatePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 11 |
| B（其余状态） | 11 |
| 合计 | 22 |
