# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-31 15:34:19
- 总条数：144 ｜ 板块 A：**7** ｜ 板块 B：**137**
- 状态计数：ZERO_RECORD_FRESH 7 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 137

<!-- live_hunt_counts: {"BOARD_A": 7, "BOARD_B": 137, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 137, "ZERO_RECORD_FRESH": 7} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 10 个缓存。

- 候选仓：13 ｜ 实扫：10 ｜ 跳过：3 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：144 ｜ 板块 A：7 ｜ 拦截进 B：137
- 冷却期免克隆：3 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| xerrors/Yuxi | cdcb1fed26f9 | SCANNED | 27 |
| metasfresh/metasfresh | 13c8982c7459 | SKIPPED | 0 |
| Sallyn0225/eidolon-sc | bebc13a8a736 | SCANNED | 2 |
| 3441293738/creatorhub | d54012e0bb2a | SKIPPED | 0 |
| polarsource/polar | 8dd9956f4eb9 | SCANNED | 31 |
| Soju06/codex-lb | 72630bbfeee9 | SCANNED | 4 |
| zhinianboke/xianyu-auto-reply | 3dbe45bae153 | SCANNED | 69 |
| feiyuchuixue/sz-boot-parent | 9f01a86dd145 | SCANNED | 0 |
| remsky/Kokoro-FastAPI | 7719de034c28 | SCANNED | 6 |
| JoshuaC215/agent-service-toolkit | 3ab8aeb950d1 | SCANNED | 0 |
| jowilf/starlette-admin | ea4d71470672 | SCANNED | 0 |
| TracecatHQ/tracecat | e66cbcf2b00f | SKIPPED | 0 |
| dramaclaw/dramaclaw | b1a424b12da8 | SCANNED | 5 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | codex-lb | cmdi | run_cache_isolation_probe | — | 2026-10-17 (14.4d) | 72630bbfeee9 | [app/modules/cache_isolation_probe/api.py:139](https://github.com/Soju06/codex-lb/blob/72630bbfeee9e3b0d9acfb95e2b1e706b8b0188e/app/modules/cache_isolation_probe/api.py#L139) | [Advisory](https://github.com/Soju06/codex-lb/security/advisories/new) · [Issue](https://github.com/Soju06/codex-lb/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/codex-lb_cmdi_run_cache_isolation_probe/SUBMISSION_PLAYBOOK.md) |
| 2 | dramaclaw | pathtraver | export_zip | — | 2026-10-30 (0.9d) | b1a424b12da8 | [src/novelvideo/api/routes/generation.py:5996](https://github.com/dramaclaw/dramaclaw/blob/b1a424b12da8caf9e43445f1aee0567888d6b69d/src/novelvideo/api/routes/generation.py#L5996) | [Advisory](https://github.com/dramaclaw/dramaclaw/security/advisories/new) · [Issue](https://github.com/dramaclaw/dramaclaw/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dramaclaw_pathtraver_export_zip/SUBMISSION_PLAYBOOK.md) |
| 3 | dramaclaw | pathtraver | sketch_grid_preview | — | 2026-10-30 (0.9d) | b1a424b12da8 | [src/novelvideo/api/routes/generation.py:5823](https://github.com/dramaclaw/dramaclaw/blob/b1a424b12da8caf9e43445f1aee0567888d6b69d/src/novelvideo/api/routes/generation.py#L5823) | [Advisory](https://github.com/dramaclaw/dramaclaw/security/advisories/new) · [Issue](https://github.com/dramaclaw/dramaclaw/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/dramaclaw_pathtraver_sketch_grid_preview/SUBMISSION_PLAYBOOK.md) |
| 4 | xianyu-auto-reply | arbitrary_file_delete | delete_face_verification_screenshot | — | 2026-10-31 (0.1d) | 3dbe45bae153 | [backend-web/app/api/routes/face_verification.py:415](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/face_verification.py#L415) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_arbitrary_file_delete_delete_face_verification_screenshot/SUBMISSION_PLAYBOOK.md) |
| 5 | xianyu-auto-reply | arbitrary_file_delete | send_image | — | 2026-10-31 (0.1d) | 3dbe45bae153 | [backend-web/app/api/routes/chat_new_image.py:45](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/chat_new_image.py#L45) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_arbitrary_file_delete_send_image/SUBMISSION_PLAYBOOK.md) |
| 6 | xianyu-auto-reply | unrestricted_upload | send_image | — | 2026-10-31 (0.1d) | 3dbe45bae153 | [backend-web/app/api/routes/chat_new_image.py:45](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/chat_new_image.py#L45) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_unrestricted_upload_send_image/SUBMISSION_PLAYBOOK.md) |
| 7 | xianyu-auto-reply | unrestricted_upload | upload_qrcode | — | 2026-10-31 (0.1d) | 3dbe45bae153 | [backend-web/app/api/routes/qrcode.py:47](https://github.com/zhinianboke/xianyu-auto-reply/blob/3dbe45bae153926160ffef92537f13b878952363/backend-web/app/api/routes/qrcode.py#L47) | [Advisory](https://github.com/zhinianboke/xianyu-auto-reply/security/advisories/new) · [Issue](https://github.com/zhinianboke/xianyu-auto-reply/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/xianyu-auto-reply_unrestricted_upload_upload_qrcode/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Kokoro-FastAPI | authz | serve_web_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | Kokoro-FastAPI | log_injection | multi_stream_input | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 3 | Kokoro-FastAPI | log_injection | retrieve_model | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 4 | Kokoro-FastAPI | log_injection | serve_web_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 5 | Kokoro-FastAPI | log_injection | tts_websocket | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 6 | Kokoro-FastAPI | log_injection | tune_speech | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 7 | Yuxi | log_injection | add_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | Yuxi | log_injection | add_uploaded_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | Yuxi | log_injection | create_knowledge_base | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 10 | Yuxi | log_injection | delete_knowledge_base | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 11 | Yuxi | log_injection | fetch_url | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 12 | Yuxi | log_injection | get_document_basic_info | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 13 | Yuxi | log_injection | get_document_content | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 14 | Yuxi | log_injection | get_document_info | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 15 | Yuxi | log_injection | get_model_status_by_spec | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 16 | Yuxi | log_injection | get_remote_models | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 17 | Yuxi | log_injection | index_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 18 | Yuxi | log_injection | index_pending_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 19 | Yuxi | log_injection | move_document | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 20 | Yuxi | log_injection | parse_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 21 | Yuxi | log_injection | parse_pending_documents | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 22 | Yuxi | log_injection | query_knowledge_base | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 23 | Yuxi | log_injection | query_test | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 24 | Yuxi | log_injection | update_knowledge_base_info | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 25 | Yuxi | log_injection | update_knowledge_base_query_params | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 26 | Yuxi | log_injection | update_provider | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 27 | Yuxi | log_injection | upload_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 28 | Yuxi | sqli | delete_feedback | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 29 | Yuxi | sqli | list_public_session_items | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 30 | Yuxi | sqli | list_public_turn_items | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 31 | Yuxi | sqli | list_public_turns | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 32 | Yuxi | sqli | retrieve_public_turn | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 33 | Yuxi | sqli | retrieve_turn_trace | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 34 | codex-lb | authz | get_automation_run_details | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | codex-lb | authz | get_fleet_summary | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | codex-lb | log_injection | update_telemetry_consent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 37 | dramaclaw | authz | delete_identity_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | dramaclaw | log_injection | freezone_audio_speech | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 39 | dramaclaw | log_injection | stream_project_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 40 | eidolon-sc | authz | set_limits | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | eidolon-sc | authz | take_off_limits | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | polar | log_injection | add_payment_method | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 43 | polar | log_injection | add_payment_method_domain | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 44 | polar | log_injection | callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 45 | polar | log_injection | cancel | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 46 | polar | log_injection | client_embed_policy | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 47 | polar | log_injection | create_review_ticket | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 48 | polar | log_injection | delete | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 49 | polar | log_injection | delete_payment_method | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 50 | polar | log_injection | delete_payout_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 51 | polar | log_injection | discord_bot_callback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 52 | polar | log_injection | get_email_log | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 53 | polar | log_injection | list_members | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 54 | polar | log_injection | list_organizations | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 55 | polar | log_injection | make_owner | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 56 | polar | log_injection | outpost | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 57 | polar | log_injection | remove_member | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 58 | polar | log_injection | request_email_update | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 59 | polar | log_injection | resync_stripe_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 60 | polar | log_injection | revoke | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 61 | polar | log_injection | revoke | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 62 | polar | log_injection | stripe_connect_refresh | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 63 | polar | log_injection | update | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 64 | polar | log_injection | update | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 65 | polar | log_injection | webhook | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 66 | polar | sqli | get | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 67 | polar | sqli | get_statistics_by_customer | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 68 | polar | sqli | get_statistics_by_property | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 69 | polar | sqli | get_statistics_by_variance | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 70 | polar | sqli | list | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 71 | polar | sqli | list_webhook_deliveries | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 72 | polar | sqli | rotate | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 73 | xianyu-auto-reply | authz | check_login_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | xianyu-auto-reply | log_injection | batch_delete_items | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 75 | xianyu-auto-reply | log_injection | batch_offline_items | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 76 | xianyu-auto-reply | log_injection | cancel_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 77 | xianyu-auto-reply | log_injection | chat_new_websocket | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 78 | xianyu-auto-reply | log_injection | clear_api_cookie_renew_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 79 | xianyu-auto-reply | log_injection | clear_close_notice_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 80 | xianyu-auto-reply | log_injection | clear_login_renew_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 81 | xianyu-auto-reply | log_injection | clear_polish_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 82 | xianyu-auto-reply | log_injection | clear_proxy_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 83 | xianyu-auto-reply | log_injection | clear_publish_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 84 | xianyu-auto-reply | log_injection | clear_rate_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 85 | xianyu-auto-reply | log_injection | clear_red_flower_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 86 | xianyu-auto-reply | log_injection | clear_redelivery_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 87 | xianyu-auto-reply | log_injection | connect_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 88 | xianyu-auto-reply | log_injection | create_chat | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 89 | xianyu-auto-reply | log_injection | create_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 90 | xianyu-auto-reply | log_injection | create_shared_session | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 91 | xianyu-auto-reply | log_injection | create_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 92 | xianyu-auto-reply | log_injection | delete_face_verification_screenshot | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 93 | xianyu-auto-reply | log_injection | delete_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 94 | xianyu-auto-reply | log_injection | delete_shared_session | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 95 | xianyu-auto-reply | log_injection | disconnect_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 96 | xianyu-auto-reply | log_injection | fetch_xianyu_orders | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 97 | xianyu-auto-reply | log_injection | generate_qr_code | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 98 | xianyu-auto-reply | log_injection | generate_renew_activation | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 99 | xianyu-auto-reply | log_injection | generate_trial_activation | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 100 | xianyu-auto-reply | log_injection | get_conversations | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 101 | xianyu-auto-reply | log_injection | get_face_verification_screenshot | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 102 | xianyu-auto-reply | log_injection | get_messages | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 103 | xianyu-auto-reply | log_injection | get_order_detail | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 104 | xianyu-auto-reply | log_injection | get_publish_account_capability | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 105 | xianyu-auto-reply | log_injection | list_provider_models | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 106 | xianyu-auto-reply | log_injection | manual_delivery | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 107 | xianyu-auto-reply | log_injection | password_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 108 | xianyu-auto-reply | log_injection | password_login | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 109 | xianyu-auto-reply | log_injection | password_login_refresh | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 110 | xianyu-auto-reply | log_injection | public_status | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 111 | xianyu-auto-reply | log_injection | query_avatars | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 112 | xianyu-auto-reply | log_injection | recall_message | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 113 | xianyu-auto-reply | log_injection | recommend_category | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 114 | xianyu-auto-reply | log_injection | refresh_token | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 115 | xianyu-auto-reply | log_injection | restart_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 116 | xianyu-auto-reply | log_injection | run_once_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 117 | xianyu-auto-reply | log_injection | search_items | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 118 | xianyu-auto-reply | log_injection | send_email_verification_code | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 119 | xianyu-auto-reply | log_injection | send_image | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 120 | xianyu-auto-reply | log_injection | send_message | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 121 | xianyu-auto-reply | log_injection | send_message | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 122 | xianyu-auto-reply | log_injection | solve_captcha | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 123 | xianyu-auto-reply | log_injection | start_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 124 | xianyu-auto-reply | log_injection | start_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 125 | xianyu-auto-reply | log_injection | stop_account | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 126 | xianyu-auto-reply | log_injection | stop_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 127 | xianyu-auto-reply | log_injection | sync_account_cookie | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 128 | xianyu-auto-reply | log_injection | test_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 129 | xianyu-auto-reply | log_injection | trigger_manual_refresh | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 130 | xianyu-auto-reply | log_injection | trigger_scheduled_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 131 | xianyu-auto-reply | log_injection | update_agree_deliver_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 132 | xianyu-auto-reply | log_injection | update_item | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 133 | xianyu-auto-reply | log_injection | update_proxy_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 134 | xianyu-auto-reply | log_injection | update_refund_cancel_config | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 135 | xianyu-auto-reply | log_injection | update_scheduled_task | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 136 | xianyu-auto-reply | log_injection | update_seller_item | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 137 | xianyu-auto-reply | log_injection | upload_qrcode | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 7 |
| B（其余状态） | 137 |
| 合计 | 144 |
