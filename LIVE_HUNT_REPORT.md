# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-07 22:02:04
- 总条数：52 ｜ 板块 A：**4** ｜ 板块 B：**48**
- 状态计数：ZERO_RECORD_FRESH 4 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 48

<!-- live_hunt_counts: {"BOARD_A": 4, "BOARD_B": 48, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 48, "ZERO_RECORD_FRESH": 4} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 9 个缓存。

- 候选仓：10 ｜ 实扫：8 ｜ 跳过：1 ｜ 失败：1 ｜ 候选来源：github_search
- 本次新增根因：52 ｜ 板块 A：4 ｜ 拦截进 B：48
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| higher-kinded-j/higher-kinded-j | 56a28c1f0f09 | SCANNED | 5 |
| 3441293738/creatorhub | b96ee378d92d | SCANNED | 4 |
| grimmory-tools/grimmory | c03164ce2213 | SCANNED | 0 |
| vstorm-co/agenticos | 0306cad25cb5 | SCANNED | 9 |
| ClawRunr/JavaClaw | 1f1ab317a297 | SCANNED | 1 |
| antiv/mate |  | FAILED | 0 |
| axelixlabs/axelix | 276ef9148860 | SCANNED | 0 |
| ikeda042/PhenoPixel | 1e2ca9004f47 | SCANNED | 5 |
| sivaprasadreddy/spring-modular-monolith | 52435a0c60a1 | SKIPPED | 0 |
| geolens-io/geolens | e7f2ebdb8121 | SCANNED | 28 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | JavaClaw | redir | OnboardingController.postStep | — | 2026-11-07 (0.1d) | 1f1ab317a297 | [app/src/main/java/ai/javaclaw/onboarding/OnboardingController.java:71](https://github.com/ClawRunr/JavaClaw/blob/1f1ab317a2975e4c44948f25693296194f927097/app/src/main/java/ai/javaclaw/onboarding/OnboardingController.java#L71) | [Advisory](https://github.com/ClawRunr/JavaClaw/security/advisories/new) · [Issue](https://github.com/ClawRunr/JavaClaw/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/JavaClaw_redir_postStep/SUBMISSION_PLAYBOOK.md) |
| 2 | creatorhub | arbitrary_file_delete | del_account | — | 2026-11-04 (3.1d) | b96ee378d92d | [app/main.py:3263](https://github.com/3441293738/creatorhub/blob/b96ee378d92d4228c1503d69987e1df9678d6e32/app/main.py#L3263) | [Advisory](https://github.com/3441293738/creatorhub/security/advisories/new) · [Issue](https://github.com/3441293738/creatorhub/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/creatorhub_arbitrary_file_delete_del_account/SUBMISSION_PLAYBOOK.md) |
| 3 | creatorhub | unrestricted_upload | publish_upload | — | 2026-11-04 (3.1d) | b96ee378d92d | [app/main.py:10128](https://github.com/3441293738/creatorhub/blob/b96ee378d92d4228c1503d69987e1df9678d6e32/app/main.py#L10128) | [Advisory](https://github.com/3441293738/creatorhub/security/advisories/new) · [Issue](https://github.com/3441293738/creatorhub/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/creatorhub_unrestricted_upload_publish_upload/SUBMISSION_PLAYBOOK.md) |
| 4 | higher-kinded-j | xss | AsyncController.updateEmailAsync | — | 2026-11-07 (0.1d) | 56a28c1f0f09 | [hkj-spring/example/src/main/java/org/higherkindedj/spring/example/controller/AsyncController.java:113](https://github.com/higher-kinded-j/higher-kinded-j/blob/56a28c1f0f0944cec9af0159495079b923e25d54/hkj-spring/example/src/main/java/org/higherkindedj/spring/example/controller/AsyncController.java#L113) | [Advisory](https://github.com/higher-kinded-j/higher-kinded-j/security/advisories/new) · [Issue](https://github.com/higher-kinded-j/higher-kinded-j/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/higher-kinded-j_xss_updateEmailAsync/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | PhenoPixel | authz | get_cell_areas | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | PhenoPixel | authz | get_cell_contour_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | PhenoPixel | authz | get_cell_ids_by_label_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | PhenoPixel | authz | get_cell_ids_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | PhenoPixel | authz | get_manual_labels_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | agenticos | authz | list_project_chats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | agenticos | cmdi | run_trigger_now | **UNKNOWN** | — | NO_CMD_SINK: 入口文件无任何命令执行调用（os.system/subprocess/asyncio.create_subprocess），cmdi 来自切片里未被入口调用的辅助函数 | — |
| 8 | agenticos | log_injection | hosted_logo | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | agenticos | log_injection | kerberos_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 10 | agenticos | log_injection | mattermost_action | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 11 | agenticos | log_injection | provider_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 12 | agenticos | log_injection | teams_messages | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 13 | agenticos | sqli | get_user_detail | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 14 | agenticos | sqli | list_background_jobs | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 15 | creatorhub | authz | login_channels_start | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | creatorhub | authz | login_tiktok_start | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | geolens | log_injection | add_column_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 18 | geolens | log_injection | alter_column_type_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 19 | geolens | log_injection | cancel_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 20 | geolens | log_injection | commit_fan_out | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 21 | geolens | log_injection | create_layer_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 22 | geolens | log_injection | delete_features_batch | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 23 | geolens | log_injection | delete_single_feature | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 24 | geolens | log_injection | discover_connector_resources_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 25 | geolens | log_injection | dispatch_connector_ingest_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 26 | geolens | log_injection | download_cog | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 27 | geolens | log_injection | drop_column_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 28 | geolens | log_injection | export_dataset_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 29 | geolens | log_injection | get_collection_item | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 30 | geolens | log_injection | oauth_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 31 | geolens | log_injection | oauth_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 32 | geolens | log_injection | preview_service_layer | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 33 | geolens | log_injection | rename_column_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 34 | geolens | log_injection | stac_collections | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 35 | geolens | log_injection | stac_import | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 36 | geolens | log_injection | upload_og_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 37 | geolens | log_injection | upload_thumbnail | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 38 | geolens | sqli | add_column_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 39 | geolens | sqli | alter_column_type_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 40 | geolens | sqli | drop_column_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 41 | geolens | sqli | get_shared_map_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 42 | geolens | sqli | list_all_datasets | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 43 | geolens | sqli | list_map_stories_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 44 | geolens | sqli | rename_column_endpoint | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 45 | higher-kinded-j | authz | AsyncController.getEnrichedUserAsync | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | higher-kinded-j | authz | AsyncController.getUserAsync | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | higher-kinded-j | authz | AsyncController.getUserByEmailAsync | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | higher-kinded-j | authz | AsyncController.updateEmailAsync | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 4 |
| B（其余状态） | 48 |
| 合计 | 52 |
