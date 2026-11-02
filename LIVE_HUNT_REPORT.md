# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-02 09:00:33
- 总条数：16 ｜ 板块 A：**6** ｜ 板块 B：**10**
- 状态计数：ZERO_RECORD_FRESH 6 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 10

<!-- live_hunt_counts: {"BOARD_A": 6, "BOARD_B": 10, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 10, "ZERO_RECORD_FRESH": 6} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 9 个缓存。

- 候选仓：18 ｜ 实扫：8 ｜ 跳过：10 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：16 ｜ 板块 A：6 ｜ 拦截进 B：10
- 冷却期免克隆：9 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| getrebuild/rebuild | 4d64ea904bdb | SKIPPED | 0 |
| yujian0815/fnmedia-ext | 8098bd743846 | SKIPPED | 0 |
| euler-xyz/euler-vault-kit | 93a1de491531 | SCANNED | 0 |
| enonic/xp | f62672f6a226 | SCANNED | 0 |
| KoalixSwitzerland/koalixcrm | 883e6e51b042 | SKIPPED | 0 |
| dromara/skyeye | b211328dbee6 | SKIPPED | 0 |
| dromara/ujcms | d4aa397006c2 | SCANNED | 3 |
| xnx3/wangmarket | c4cb414e2cc1 | SCANNED | 5 |
| w8123/EnterpriseAgentFramework | 1f1230d50db0 | SKIPPED | 0 |
| guchengwuyue/yshop-oa-crm | 398e0e9b5ee2 | SKIPPED | 0 |
| strimzi/strimzi-kafka-oauth | 4d1f76bbca06 | SKIPPED | 0 |
| jobmission/oauth2-server | 8a151c348162 | SCANNED | 2 |
| LiuYuYang01/ThriveX-Server | 60b24e559a9a | SCANNED | 0 |
| SpringSunYY/LZ-litchi | af0dc34f1b41 | SKIPPED | 0 |
| sunkaifei/FlyCms | 77c58e637b38 | SCANNED | 2 |
| ilscipio/scipio-erp | ef67e214fd06 | SKIPPED | 0 |
| 201206030/novel-plus | 4a010cda28e0 | SCANNED | 4 |
| apache/jackrabbit-oak | 85d5497b7e13 | SKIPPED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | FlyCms | pathtraver | ApiToolsController.download | — | 2026-10-24 (8.9d) | 77c58e637b38 | [backend/src/main/java/com/flycms/web/api/ApiToolsController.java:78](https://github.com/sunkaifei/FlyCms/blob/77c58e637b3891970c4f47da06697d3f61722f22/backend/src/main/java/com/flycms/web/api/ApiToolsController.java#L78) | [Advisory](https://github.com/sunkaifei/FlyCms/security/advisories/new) · [Issue](https://github.com/sunkaifei/FlyCms/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/FlyCms_pathtraver_download/SUBMISSION_PLAYBOOK.md) |
| 2 | wangmarket | arbitrary_file_delete | PluginManageController.uploadPluginZip | — | 2026-10-30 (2.7d) | c4cb414e2cc1 | [src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java:829](https://github.com/xnx3/wangmarket/blob/c4cb414e2cc1621afdba372d4108bf6e17037039/src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java#L829) | [Advisory](https://github.com/xnx3/wangmarket/security/advisories/new) · [Issue](https://github.com/xnx3/wangmarket/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/wangmarket_arbitrary_file_delete_uploadPluginZip/SUBMISSION_PLAYBOOK.md) |
| 3 | wangmarket | pathtraver | PluginManageController.exportPlugin | — | 2026-10-30 (2.7d) | c4cb414e2cc1 | [src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java:1209](https://github.com/xnx3/wangmarket/blob/c4cb414e2cc1621afdba372d4108bf6e17037039/src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java#L1209) | [Advisory](https://github.com/xnx3/wangmarket/security/advisories/new) · [Issue](https://github.com/xnx3/wangmarket/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/wangmarket_pathtraver_exportPlugin/SUBMISSION_PLAYBOOK.md) |
| 4 | wangmarket | pathtraver | PluginManageController.uploadPluginZip | — | 2026-10-30 (2.7d) | c4cb414e2cc1 | [src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java:829](https://github.com/xnx3/wangmarket/blob/c4cb414e2cc1621afdba372d4108bf6e17037039/src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java#L829) | [Advisory](https://github.com/xnx3/wangmarket/security/advisories/new) · [Issue](https://github.com/xnx3/wangmarket/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/wangmarket_pathtraver_uploadPluginZip/SUBMISSION_PLAYBOOK.md) |
| 5 | wangmarket | unsafe_reflection | PluginManageController.installPlugin | — | 2026-10-30 (2.7d) | c4cb414e2cc1 | [src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java:349](https://github.com/xnx3/wangmarket/blob/c4cb414e2cc1621afdba372d4108bf6e17037039/src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java#L349) | [Advisory](https://github.com/xnx3/wangmarket/security/advisories/new) · [Issue](https://github.com/xnx3/wangmarket/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/wangmarket_unsafe_reflection_installPlugin/SUBMISSION_PLAYBOOK.md) |
| 6 | wangmarket | unsafe_reflection | PluginManageController.upgradePlugin | — | 2026-10-30 (2.7d) | c4cb414e2cc1 | [src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java:111](https://github.com/xnx3/wangmarket/blob/c4cb414e2cc1621afdba372d4108bf6e17037039/src/main/java/com/xnx3/wangmarket/superadmin/controller/PluginManageController.java#L111) | [Advisory](https://github.com/xnx3/wangmarket/security/advisories/new) · [Issue](https://github.com/xnx3/wangmarket/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/wangmarket_unsafe_reflection_upgradePlugin/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | FlyCms | log_injection | IndexController.language | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 2 | novel-plus | authz | AiAssistantController.getTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | novel-plus | authz | AiAssistantController.initPlan | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | novel-plus | authz | AiAssistantController.saveParams | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | novel-plus | authz | AiAssistantController.startTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | oauth2-server | authz | ManageClientController.listObjects | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | oauth2-server | authz | ManageClientController.setupDetails | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | ujcms | authz | CommentController.remove | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | ujcms | authz | ContributeController.remove | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | ujcms | authz | ContributeController.show | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 6 |
| B（其余状态） | 10 |
| 合计 | 16 |
