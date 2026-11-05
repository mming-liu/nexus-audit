# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-05 09:00:23
- 总条数：36 ｜ 板块 A：**13** ｜ 板块 B：**23**
- 状态计数：ZERO_RECORD_FRESH 13 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 23

<!-- live_hunt_counts: {"BOARD_A": 13, "BOARD_B": 23, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 23, "ZERO_RECORD_FRESH": 13} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 11 个缓存。

- 候选仓：18 ｜ 实扫：10 ｜ 跳过：8 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：36 ｜ 板块 A：13 ｜ 拦截进 B：23
- 冷却期免克隆：7 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| continew-org/continew-admin | 35898a455cee | SCANNED | 0 |
| pallets-eco/flask-admin | c1c525cd7cbd | SCANNED | 1 |
| morpho-org/metamorpho | 21bb4c2df6d7 | SKIPPED | 0 |
| jingsewu/open-wes | c85c6ac50cbc | SKIPPED | 0 |
| vsdudakov/fastadmin | 9202a5e86b49 | SCANNED | 0 |
| euler-xyz/euler-vault-kit | 93a1de491531 | SKIPPED | 0 |
| getrebuild/rebuild | 4d64ea904bdb | SKIPPED | 0 |
| dromara/RuoYi-Cloud-Plus | 8bb23fa703bf | SCANNED | 10 |
| dromara/RuoYi-Vue-Plus | 835246ebeb7b | SCANNED | 9 |
| KouShenhai/KCloud-Platform-IoT | aea7ca8d6c3a | SCANNED | 3 |
| deegree/deegree3 | 25a868275cce | SKIPPED | 0 |
| yulichang/mybatis-plus-join | 07a372a9cd73 | SKIPPED | 0 |
| techa03/goodsKill | 1187aafc34bb | SCANNED | 4 |
| quuuuj/hrm | bed149de975f | SCANNED | 5 |
| yzcheng90/x-springboot | f4acf07c6b13 | SCANNED | 3 |
| GeoWebCache/geowebcache | da254e37117d | SKIPPED | 0 |
| geoserver/geoserver | edaa22c299f9 | SKIPPED | 0 |
| 201206030/novel-cloud | c602974ab597 | SCANNED | 1 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | KCloud-Platform-IoT | sqli | DevicesController.pageDevice | — | 2026-10-30 (5.9d) | aea7ca8d6c3a | [laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/DevicesController.java:104](https://github.com/KouShenhai/KCloud-Platform-IoT/blob/aea7ca8d6c3ae807cf3634889a9ba50d7e9e3115/laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/DevicesController.java#L104) | [Advisory](https://github.com/KouShenhai/KCloud-Platform-IoT/security/advisories/new) · [Issue](https://github.com/KouShenhai/KCloud-Platform-IoT/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/KCloud-Platform-IoT_sqli_pageDevice/SUBMISSION_PLAYBOOK.md) |
| 2 | KCloud-Platform-IoT | sqli | GatewaysController.pageGateway | — | 2026-10-30 (5.9d) | aea7ca8d6c3a | [laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/GatewaysController.java:104](https://github.com/KouShenhai/KCloud-Platform-IoT/blob/aea7ca8d6c3ae807cf3634889a9ba50d7e9e3115/laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/GatewaysController.java#L104) | [Advisory](https://github.com/KouShenhai/KCloud-Platform-IoT/security/advisories/new) · [Issue](https://github.com/KouShenhai/KCloud-Platform-IoT/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/KCloud-Platform-IoT_sqli_pageGateway/SUBMISSION_PLAYBOOK.md) |
| 3 | KCloud-Platform-IoT | sqli | ProductCategorysController.listTreeProductCategory | — | 2026-10-30 (5.9d) | aea7ca8d6c3a | [laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/ProductCategorysController.java:115](https://github.com/KouShenhai/KCloud-Platform-IoT/blob/aea7ca8d6c3ae807cf3634889a9ba50d7e9e3115/laokou-service/laokou-iot/laokou-iot-adapter/src/main/java/org/laokou/iot/web/ProductCategorysController.java#L115) | [Advisory](https://github.com/KouShenhai/KCloud-Platform-IoT/security/advisories/new) · [Issue](https://github.com/KouShenhai/KCloud-Platform-IoT/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/KCloud-Platform-IoT_sqli_listTreeProductCategory/SUBMISSION_PLAYBOOK.md) |
| 4 | flask-admin | xss | execute_view | — | 2026-11-01 (3.1d) | c1c525cd7cbd | [flask_admin/contrib/rediscli.py:182](https://github.com/pallets-eco/flask-admin/blob/c1c525cd7cbd953b67c84381ce55680c6769c4e2/flask_admin/contrib/rediscli.py#L182) | [Advisory](https://github.com/pallets-eco/flask-admin/security/advisories/new) · [Issue](https://github.com/pallets-eco/flask-admin/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/flask-admin_xss_execute_view/SUBMISSION_PLAYBOOK.md) |
| 5 | goodsKill | sqli | KnowledgeController.delete | — | 2026-10-24 (12.0d) | 1187aafc34bb | [goodskill-ai/src/main/java/com/goodskill/ai/controller/KnowledgeController.java:54](https://github.com/techa03/goodsKill/blob/1187aafc34bb0d4a8815e7988dbf19cd8145f7a4/goodskill-ai/src/main/java/com/goodskill/ai/controller/KnowledgeController.java#L54) | [Advisory](https://github.com/techa03/goodsKill/security/advisories/new) · [Issue](https://github.com/techa03/goodsKill/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/goodsKill_sqli_delete/SUBMISSION_PLAYBOOK.md) |
| 6 | goodsKill | xss | GoodsEsController.save | — | 2026-10-24 (12.0d) | 1187aafc34bb | [goodskill-seckill-provider/goodskill-service/src/main/java/com/goodskill/service/controller/GoodsEsController.java:17](https://github.com/techa03/goodsKill/blob/1187aafc34bb0d4a8815e7988dbf19cd8145f7a4/goodskill-seckill-provider/goodskill-service/src/main/java/com/goodskill/service/controller/GoodsEsController.java#L17) | [Advisory](https://github.com/techa03/goodsKill/security/advisories/new) · [Issue](https://github.com/techa03/goodsKill/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/goodsKill_xss_save/SUBMISSION_PLAYBOOK.md) |
| 7 | hrm | xss | SalaryController.createExportTask | — | 2026-11-01 (3.7d) | bed149de975f | [hrm-server/src/main/java/com/qiujie/salary/controller/SalaryController.java:97](https://github.com/quuuuj/hrm/blob/bed149de975f8c238e2c339368e0f6766f8f134e/hrm-server/src/main/java/com/qiujie/salary/controller/SalaryController.java#L97) | [Advisory](https://github.com/quuuuj/hrm/security/advisories/new) · [Issue](https://github.com/quuuuj/hrm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/hrm_xss_createExportTask/SUBMISSION_PLAYBOOK.md) |
| 8 | hrm | xss | SalaryController.createImportTask | — | 2026-11-01 (3.7d) | bed149de975f | [hrm-server/src/main/java/com/qiujie/salary/controller/SalaryController.java:90](https://github.com/quuuuj/hrm/blob/bed149de975f8c238e2c339368e0f6766f8f134e/hrm-server/src/main/java/com/qiujie/salary/controller/SalaryController.java#L90) | [Advisory](https://github.com/quuuuj/hrm/security/advisories/new) · [Issue](https://github.com/quuuuj/hrm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/hrm_xss_createImportTask/SUBMISSION_PLAYBOOK.md) |
| 9 | hrm | xss | StaffOvertimeController.createExportTask | — | 2026-11-01 (3.7d) | bed149de975f | [hrm-server/src/main/java/com/qiujie/overtime/controller/StaffOvertimeController.java:75](https://github.com/quuuuj/hrm/blob/bed149de975f8c238e2c339368e0f6766f8f134e/hrm-server/src/main/java/com/qiujie/overtime/controller/StaffOvertimeController.java#L75) | [Advisory](https://github.com/quuuuj/hrm/security/advisories/new) · [Issue](https://github.com/quuuuj/hrm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/hrm_xss_createExportTask/SUBMISSION_PLAYBOOK.md) |
| 10 | hrm | xss | StaffOvertimeController.createImportTask | — | 2026-11-01 (3.7d) | bed149de975f | [hrm-server/src/main/java/com/qiujie/overtime/controller/StaffOvertimeController.java:68](https://github.com/quuuuj/hrm/blob/bed149de975f8c238e2c339368e0f6766f8f134e/hrm-server/src/main/java/com/qiujie/overtime/controller/StaffOvertimeController.java#L68) | [Advisory](https://github.com/quuuuj/hrm/security/advisories/new) · [Issue](https://github.com/quuuuj/hrm/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/hrm_xss_createImportTask/SUBMISSION_PLAYBOOK.md) |
| 11 | novel-cloud | xss | FrontUserController.submitFeedback | — | 2026-10-31 (4.7d) | c602974ab597 | [novel-user/novel-user-service/src/main/java/io/github/xxyopen/novel/user/controller/front/FrontUserController.java:81](https://github.com/201206030/novel-cloud/blob/c602974ab59784d4efd1cdacc38ae904e6a5f80a/novel-user/novel-user-service/src/main/java/io/github/xxyopen/novel/user/controller/front/FrontUserController.java#L81) | [Advisory](https://github.com/201206030/novel-cloud/security/advisories/new) · [Issue](https://github.com/201206030/novel-cloud/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/novel-cloud_xss_submitFeedback/SUBMISSION_PLAYBOOK.md) |
| 12 | x-springboot | pathtraver | TbApkVersionController.uploadApk | — | 2026-10-30 (5.6d) | f4acf07c6b13 | [src/main/java/com/suke/czx/modules/apk/controller/TbApkVersionController.java:83](https://github.com/yzcheng90/x-springboot/blob/f4acf07c6b134af9ad3e6284d65b40997087b14f/src/main/java/com/suke/czx/modules/apk/controller/TbApkVersionController.java#L83) | [Advisory](https://github.com/yzcheng90/x-springboot/security/advisories/new) · [Issue](https://github.com/yzcheng90/x-springboot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/x-springboot_pathtraver_uploadApk/SUBMISSION_PLAYBOOK.md) |
| 13 | x-springboot | unrestricted_upload | TbApkVersionController.uploadApk | — | 2026-10-30 (5.6d) | f4acf07c6b13 | [src/main/java/com/suke/czx/modules/apk/controller/TbApkVersionController.java:83](https://github.com/yzcheng90/x-springboot/blob/f4acf07c6b134af9ad3e6284d65b40997087b14f/src/main/java/com/suke/czx/modules/apk/controller/TbApkVersionController.java#L83) | [Advisory](https://github.com/yzcheng90/x-springboot/security/advisories/new) · [Issue](https://github.com/yzcheng90/x-springboot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/x-springboot_unrestricted_upload_uploadApk/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | RuoYi-Cloud-Plus | authz | EsCrudController.delete | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 2 | RuoYi-Cloud-Plus | authz | EsCrudController.insert | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 3 | RuoYi-Cloud-Plus | authz | EsCrudController.update | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 4 | RuoYi-Cloud-Plus | authz | McpDemoController.receive | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 5 | RuoYi-Cloud-Plus | authz | McpDemoController.resource | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 6 | RuoYi-Cloud-Plus | hardcoded_secret | [secret-file] TestDemoEncrypt.java | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 7 | RuoYi-Cloud-Plus | log_injection | PrometheusController.alerts | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | RuoYi-Cloud-Plus | xss | EsCrudController.insert | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 9 | RuoYi-Cloud-Plus | xss | EsCrudController.update | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 10 | RuoYi-Cloud-Plus | xss | TestEncryptController.test | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 11 | RuoYi-Vue-Plus | authz | EsCrudController.delete | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 12 | RuoYi-Vue-Plus | authz | EsCrudController.insert | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 13 | RuoYi-Vue-Plus | authz | EsCrudController.update | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 14 | RuoYi-Vue-Plus | authz | McpDemoController.receive | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 15 | RuoYi-Vue-Plus | authz | McpDemoController.resource | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 16 | RuoYi-Vue-Plus | hardcoded_secret | [secret-file] TestDemoEncrypt.java | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 17 | RuoYi-Vue-Plus | xss | EsCrudController.insert | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 18 | RuoYi-Vue-Plus | xss | EsCrudController.update | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 19 | RuoYi-Vue-Plus | xss | TestEncryptController.test | **UNKNOWN** | — | DEMO_CONTROLLER: demo/示例入口（非生产代码） | — |
| 20 | goodsKill | authz | GoodsController.batchDeleteGoods | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | goodsKill | authz | GoodsEsController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | hrm | authz | NotificationController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | x-springboot | authz | TbPlatformTenancyController.getInfo | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 13 |
| B（其余状态） | 23 |
| 合计 | 36 |
