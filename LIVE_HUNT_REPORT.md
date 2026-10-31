# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-31 13:26:18
- 总条数：21 ｜ 板块 A：**11** ｜ 板块 B：**10**
- 状态计数：ZERO_RECORD_FRESH 11 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 10

<!-- live_hunt_counts: {"BOARD_A": 11, "BOARD_B": 10, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 10, "ZERO_RECORD_FRESH": 11} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 11 个缓存。

- 候选仓：17 ｜ 实扫：10 ｜ 跳过：7 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：21 ｜ 板块 A：11 ｜ 拦截进 B：10
- 冷却期免克隆：6 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| Sallyn0225/eidolon-sc | bebc13a8a736 | SCANNED | 2 |
| 3441293738/creatorhub | d54012e0bb2a | SKIPPED | 0 |
| zhinianboke/xianyu-auto-reply | 3dbe45bae153 | SCANNED | 5 |
| feiyuchuixue/sz-boot-parent | 9f01a86dd145 | SCANNED | 3 |
| metasfresh/metasfresh | 13c8982c7459 | SKIPPED | 0 |
| remsky/Kokoro-FastAPI | 7719de034c28 | SCANNED | 2 |
| JoshuaC215/agent-service-toolkit | 3ab8aeb950d1 | SCANNED | 1 |
| PlaytikaOSS/testcontainers-spring-boot | 18718673d143 | SKIPPED | 0 |
| jowilf/starlette-admin | ea4d71470672 | SCANNED | 0 |
| TracecatHQ/tracecat | e66cbcf2b00f | SKIPPED | 0 |
| dramaclaw/dramaclaw | b1a424b12da8 | SCANNED | 3 |
| apocas/restai | 2ccb9d557caa | SCANNED | 0 |
| terrakube-io/terrakube | 8baefe470bbc | SKIPPED | 0 |
| dunossauro/fastapi-do-zero | 2af572203c34 | SKIPPED | 0 |
| urlaubsverwaltung/urlaubsverwaltung | 7bfcd7c0241e | SKIPPED | 0 |
| SenteLabsAI/OpenExecutive | 337e02188d5e | SCANNED | 3 |
| Soju06/codex-lb | 72630bbfeee9 | SCANNED | 2 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Kokoro-FastAPI | log_injection | download_audio_file | — | 2026-10-30 (0.1d) | 7719de034c28 | [api/src/routers/openai_compatible.py:583](https://github.com/remsky/Kokoro-FastAPI/blob/7719de034c2881791c08523735255b0baf1d7808/api/src/routers/openai_compatible.py#L583) | [Advisory](https://github.com/remsky/Kokoro-FastAPI/security/advisories/new) · [Issue](https://github.com/remsky/Kokoro-FastAPI/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/Kokoro-FastAPI_log_injection_download_audio_file/SUBMISSION_PLAYBOOK.md) |
| 2 | codex-lb | sqli | list_api_keys | — | 2026-10-17 (14.3d) | 72630bbfeee9 | [app/modules/api_keys/api.py:186](https://github.com/Soju06/codex-lb/blob/72630bbfeee9e3b0d9acfb95e2b1e706b8b0188e/app/modules/api_keys/api.py#L186) | [Advisory](https://github.com/Soju06/codex-lb/security/advisories/new) · [Issue](https://github.com/Soju06/codex-lb/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/codex-lb_sqli_list_api_keys/SUBMISSION_PLAYBOOK.md) |
| 3 | codex-lb | sqli | list_automation_filter_options | — | 2026-10-17 (14.3d) | 72630bbfeee9 | [app/modules/automations/api.py:74](https://github.com/Soju06/codex-lb/blob/72630bbfeee9e3b0d9acfb95e2b1e706b8b0188e/app/modules/automations/api.py#L74) | [Advisory](https://github.com/Soju06/codex-lb/security/advisories/new) · [Issue](https://github.com/Soju06/codex-lb/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/codex-lb_sqli_list_automation_filter_options/SUBMISSION_PLAYBOOK.md) |
| 4 | sz-boot-parent | xss | GeneratorTableController.updateGenerator | — | 2026-10-31 (0.1d) | 9f01a86dd145 | [sz-module/sz-module-generator/src/main/java/com/sz/generator/controller/GeneratorTableController.java:78](https://github.com/feiyuchuixue/sz-boot-parent/blob/9f01a86dd1454448703829f0a542c9a288a3e2cf/sz-module/sz-module-generator/src/main/java/com/sz/generator/controller/GeneratorTableController.java#L78) | [Advisory](https://github.com/feiyuchuixue/sz-boot-parent/security/advisories/new) · [Issue](https://github.com/feiyuchuixue/sz-boot-parent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/sz-boot-parent_xss_updateGenerator/SUBMISSION_PLAYBOOK.md) |
| 5 | sz-boot-parent | xss | SysUserController.updateContact | — | 2026-10-31 (0.1d) | 9f01a86dd145 | [sz-module/sz-module-admin/src/main/java/com/sz/admin/system/controller/SysUserController.java:168](https://github.com/feiyuchuixue/sz-boot-parent/blob/9f01a86dd1454448703829f0a542c9a288a3e2cf/sz-module/sz-module-admin/src/main/java/com/sz/admin/system/controller/SysUserController.java#L168) | [Advisory](https://github.com/feiyuchuixue/sz-boot-parent/security/advisories/new) · [Issue](https://github.com/feiyuchuixue/sz-boot-parent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/sz-boot-parent_xss_updateContact/SUBMISSION_PLAYBOOK.md) |
| 6 | sz-boot-parent | xss | SysUserController.updateProfile | — | 2026-10-31 (0.1d) | 9f01a86dd145 | [sz-module/sz-module-admin/src/main/java/com/sz/admin/system/controller/SysUserController.java:161](https://github.com/feiyuchuixue/sz-boot-parent/blob/9f01a86dd1454448703829f0a542c9a288a3e2cf/sz-module/sz-module-admin/src/main/java/com/sz/admin/system/controller/SysUserController.java#L161) | [Advisory](https://github.com/feiyuchuixue/sz-boot-parent/security/advisories/new) · [Issue](https://github.com/feiyuchuixue/sz-boot-parent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/sz-boot-parent_xss_updateProfile/SUBMISSION_PLAYBOOK.md) |
| 7 | xianyu-auto-reply | log_injection | upload_image | — | 2026-10-31 (0.0d) | 3dbe45bae153 | [backend-web/app/api/routes/upload.py:15](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/upload.py#L15) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_log_injection_upload_image/SUBMISSION_PLAYBOOK.md) |
| 8 | xianyu-auto-reply | sqli | get_agree_deliver_config | — | 2026-10-31 (0.0d) | 3dbe45bae153 | [backend-web/app/api/routes/agree_deliver.py:111](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/agree_deliver.py#L111) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_sqli_get_agree_deliver_config/SUBMISSION_PLAYBOOK.md) |
| 9 | xianyu-auto-reply | sqli | health_check | — | 2026-10-31 (0.0d) | 3dbe45bae153 | [backend-web/_bootstrap.py:272](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/_bootstrap.py#L272) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_sqli_health_check/SUBMISSION_PLAYBOOK.md) |
| 10 | xianyu-auto-reply | sqli | health_check | — | 2026-10-31 (0.0d) | 3dbe45bae153 | [scheduler/_bootstrap.py:238](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/scheduler/_bootstrap.py#L238) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_sqli_health_check/SUBMISSION_PLAYBOOK.md) |
| 11 | xianyu-auto-reply | sqli | upload_image | — | 2026-10-31 (0.0d) | 3dbe45bae153 | [backend-web/app/api/routes/upload.py:15](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/upload.py#L15) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_sqli_upload_image/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Kokoro-FastAPI | authz | download_audio_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | OpenExecutive | authz | delete_goal | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | OpenExecutive | authz | get_department | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | OpenExecutive | authz | reopen_alert | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | agent-service-toolkit | authz | agui_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | dramaclaw | authz | delete_character | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | dramaclaw | authz | delete_prop | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | dramaclaw | authz | delete_scene | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | eidolon-sc | authz | delete_user | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | eidolon-sc | authz | user_details | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 11 |
| B（其余状态） | 10 |
| 合计 | 21 |
