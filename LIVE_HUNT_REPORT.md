# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-15 15:50:49
- 总条数：452 ｜ 板块 A：**8** ｜ 板块 B：**444**
- 状态计数：ZERO_RECORD_FRESH 8 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 444

<!-- live_hunt_counts: {"BOARD_A": 8, "BOARD_B": 444, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 444, "ZERO_RECORD_FRESH": 8} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：13 ｜ 实扫：8 ｜ 跳过：3 ｜ 失败：2 ｜ 候选来源：github_search
- 本次新增根因：452 ｜ 板块 A：8 ｜ 拦截进 B：444
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个
- 侦察缓存与回填：缓存命中 5 页 / 限流回填 0 仓

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| mateaix/mateclaw |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| tubecreate/tubecli | 476e1d09437a | SCANNED | 227 |
| wb04307201/spring-ai-loom-agent | 34a6dcdcb8af | SCANNED | 0 |
| ghost-in-the-droid/android-agent | 8974838fd74c | SCANNED | 40 |
| IBM/mcp-context-forge |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| LvcidPsyche/auto-browser | 168def7890e1 | SCANNED | 27 |
| imfeh2/fora | f2fee6fa75f7 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| aixisstudio/Snitch | f3adce0d12b7 | SKIPPED (all_local_or_demo) | 0 |
| Pipelex/pipelex | 31f28c315cda | SCANNED | 0 |
| JJJJSTIYYYY/alira | 1eca81795451 | SKIPPED (low_units_1) | 0 |
| ljxpython/ai-agent-platform | 4d5c9ec5e333 | SCANNED | 85 |
| ydsgangge-ux/dramatica-flow | 1c4efc0a557e | SCANNED | 64 |
| aegra/aegra | b907dab9740a | SCANNED | 9 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | ai-agent-platform | ssrf | enqueue_message | — | 2026-11-13 (1.8d) | 4d5c9ec5e333 | [apps/runtime-service/src/runtime_service/webapp.py:263](https://github.com/ljxpython/ai-agent-platform/blob/4d5c9ec5e333f05687e17b1f9de57c64beb81676/apps/runtime-service/src/runtime_service/webapp.py#L263) | [Advisory](https://github.com/ljxpython/ai-agent-platform/security/advisories/new) · [Issue](https://github.com/ljxpython/ai-agent-platform/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-agent-platform_ssrf_enqueue_message/SUBMISSION_PLAYBOOK.md) |
| 2 | android-agent | arbitrary_file_delete | api_skill_delete | — | 2026-11-14 (0.5d) | 8974838fd74c | [gitd/routers/skills.py:612](https://github.com/ghost-in-the-droid/android-agent/blob/8974838fd74c06944583c9dcea66570bc4c5c161/gitd/routers/skills.py#L612) | [Advisory](https://github.com/ghost-in-the-droid/android-agent/security/advisories/new) · [Issue](https://github.com/ghost-in-the-droid/android-agent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/android-agent_arbitrary_file_delete_api_skill_delete/SUBMISSION_PLAYBOOK.md) |
| 3 | android-agent | arbitrary_file_delete | explorer_delete | — | 2026-11-14 (0.5d) | 8974838fd74c | [gitd/routers/explorer.py:217](https://github.com/ghost-in-the-droid/android-agent/blob/8974838fd74c06944583c9dcea66570bc4c5c161/gitd/routers/explorer.py#L217) | [Advisory](https://github.com/ghost-in-the-droid/android-agent/security/advisories/new) · [Issue](https://github.com/ghost-in-the-droid/android-agent/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/android-agent_arbitrary_file_delete_explorer_delete/SUBMISSION_PLAYBOOK.md) |
| 4 | tubecli | arbitrary_file_delete | api_cookie_import | — | 2026-11-15 (0.2d) | 476e1d09437a | [tubecli/extensions/browser/routes.py:440](https://github.com/tubecreate/tubecli/blob/476e1d09437a6d84e33b304470dd359d1c89230f/tubecli/extensions/browser/routes.py#L440) | [Advisory](https://github.com/tubecreate/tubecli/security/advisories/new) · [Issue](https://github.com/tubecreate/tubecli/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/tubecli_arbitrary_file_delete_api_cookie_import/SUBMISSION_PLAYBOOK.md) |
| 5 | tubecli | arbitrary_file_delete | api_delete_cookies | — | 2026-11-15 (0.2d) | 476e1d09437a | [tubecli/extensions/browser/routes.py:616](https://github.com/tubecreate/tubecli/blob/476e1d09437a6d84e33b304470dd359d1c89230f/tubecli/extensions/browser/routes.py#L616) | [Advisory](https://github.com/tubecreate/tubecli/security/advisories/new) · [Issue](https://github.com/tubecreate/tubecli/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/tubecli_arbitrary_file_delete_api_delete_cookies/SUBMISSION_PLAYBOOK.md) |
| 6 | tubecli | ssrf | api_download_engine | — | 2026-11-15 (0.2d) | 476e1d09437a | [tubecli/extensions/browser/routes.py:1679](https://github.com/tubecreate/tubecli/blob/476e1d09437a6d84e33b304470dd359d1c89230f/tubecli/extensions/browser/routes.py#L1679) | [Advisory](https://github.com/tubecreate/tubecli/security/advisories/new) · [Issue](https://github.com/tubecreate/tubecli/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/tubecli_ssrf_api_download_engine/SUBMISSION_PLAYBOOK.md) |
| 7 | tubecli | unrestricted_upload | upload_media | — | 2026-11-15 (0.2d) | 476e1d09437a | [tubecli/extensions/video_editor/video_api.py:264](https://github.com/tubecreate/tubecli/blob/476e1d09437a6d84e33b304470dd359d1c89230f/tubecli/extensions/video_editor/video_api.py#L264) | [Advisory](https://github.com/tubecreate/tubecli/security/advisories/new) · [Issue](https://github.com/tubecreate/tubecli/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/tubecli_unrestricted_upload_upload_media/SUBMISSION_PLAYBOOK.md) |
| 8 | tubecli | zip_slip | api_download_engine | — | 2026-11-15 (0.2d) | 476e1d09437a | [tubecli/extensions/browser/routes.py:1679](https://github.com/tubecreate/tubecli/blob/476e1d09437a6d84e33b304470dd359d1c89230f/tubecli/extensions/browser/routes.py#L1679) | [Advisory](https://github.com/tubecreate/tubecli/security/advisories/new) · [Issue](https://github.com/tubecreate/tubecli/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/tubecli_zip_slip_api_download_engine/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | aegra | log_injection | cancel_run_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 2 | aegra | log_injection | cancel_runs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 3 | aegra | log_injection | delete_run | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 4 | aegra | log_injection | delete_thread | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 5 | aegra | log_injection | get_run | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 6 | aegra | log_injection | get_thread_history_post | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 7 | aegra | log_injection | list_runs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | aegra | log_injection | stream_run | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | aegra | log_injection | update_run | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 10 | ai-agent-platform | authz | authorize_runtime_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | ai-agent-platform | authz | authorize_runtime_message | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | ai-agent-platform | authz | cancel_background_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | ai-agent-platform | authz | cancel_thread | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | ai-agent-platform | authz | cancel_thread | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | ai-agent-platform | authz | change_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | ai-agent-platform | authz | close | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | ai-agent-platform | authz | close_terminal | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | ai-agent-platform | authz | content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | ai-agent-platform | authz | content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | ai-agent-platform | authz | create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | ai-agent-platform | authz | create_terminal | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | ai-agent-platform | authz | create_thread_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | ai-agent-platform | authz | create_tool_restriction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | ai-agent-platform | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | ai-agent-platform | authz | delete_runtime_model | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 26 | ai-agent-platform | authz | delete_service_account_project_grant | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | ai-agent-platform | authz | delete_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 28 | ai-agent-platform | authz | delete_thread | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 29 | ai-agent-platform | authz | detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 30 | ai-agent-platform | authz | enqueue_message | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 31 | ai-agent-platform | authz | enqueue_thread_message | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 32 | ai-agent-platform | authz | fork_workspace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 33 | ai-agent-platform | authz | get_assistant_parameter_schema | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 34 | ai-agent-platform | authz | get_background_output | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 35 | ai-agent-platform | authz | get_background_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 36 | ai-agent-platform | authz | get_project_access | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 37 | ai-agent-platform | authz | get_run_completion | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 38 | ai-agent-platform | authz | get_stop | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 39 | ai-agent-platform | authz | get_stop_request | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 40 | ai-agent-platform | authz | get_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 41 | ai-agent-platform | authz | get_trace_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 42 | ai-agent-platform | authz | join_thread_run_stream | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 43 | ai-agent-platform | authz | list_announcements | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | ai-agent-platform | authz | list_audit_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | ai-agent-platform | authz | list_background_tasks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | ai-agent-platform | authz | list_messages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | ai-agent-platform | authz | list_project_member_candidates | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | ai-agent-platform | authz | list_stop_requests | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | ai-agent-platform | authz | list_terminals | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | ai-agent-platform | authz | listing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 51 | ai-agent-platform | authz | mark_announcement_read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | ai-agent-platform | authz | output | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | ai-agent-platform | authz | pause_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | ai-agent-platform | authz | preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | ai-agent-platform | authz | project_dashboard | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | ai-agent-platform | authz | project_runs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 57 | ai-agent-platform | authz | read_memory | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | ai-agent-platform | authz | read_thread_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 59 | ai-agent-platform | authz | read_thread_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | ai-agent-platform | authz | reset_user_password | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | ai-agent-platform | authz | resize | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | ai-agent-platform | authz | resume_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | ai-agent-platform | authz | run_usage_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | ai-agent-platform | authz | send_input | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | ai-agent-platform | authz | send_thread_command | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | ai-agent-platform | authz | stream_archive | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | ai-agent-platform | authz | stream_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 68 | ai-agent-platform | authz | stream_thread_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | ai-agent-platform | authz | stream_thread_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | ai-agent-platform | authz | summarize_thread_title_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | ai-agent-platform | authz | task_history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | ai-agent-platform | authz | terminal_input | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | ai-agent-platform | authz | terminal_output | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | ai-agent-platform | authz | terminal_resize | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | ai-agent-platform | authz | thread_artifacts | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | ai-agent-platform | authz | thread_usage_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | ai-agent-platform | authz | toggle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 78 | ai-agent-platform | authz | tree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 79 | ai-agent-platform | authz | trigger_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 80 | ai-agent-platform | authz | update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | ai-agent-platform | authz | update_runtime_model | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | ai-agent-platform | authz | update_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | ai-agent-platform | authz | update_thread | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | ai-agent-platform | authz | upload_thread_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | ai-agent-platform | authz | upload_thread_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | ai-agent-platform | authz | upload_thread_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 87 | ai-agent-platform | authz | upload_thread_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 88 | ai-agent-platform | authz | upsert_service_account_project_grant | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 89 | ai-agent-platform | authz | workspace_content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 90 | ai-agent-platform | authz | workspace_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 91 | ai-agent-platform | authz | workspace_tree | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 92 | ai-agent-platform | authz | workspace_zip | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 93 | ai-agent-platform | authz | zip_archive | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 94 | android-agent | authz | api_get_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 95 | android-agent | authz | api_skill_actions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 96 | android-agent | authz | api_skill_compat_reset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | android-agent | authz | api_skill_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 98 | android-agent | authz | api_skill_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 99 | android-agent | authz | api_skill_run_action | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 100 | android-agent | authz | api_skill_run_resume | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 101 | android-agent | authz | api_skill_update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 102 | android-agent | authz | api_skill_verify | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 103 | android-agent | authz | api_skill_workflows | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 104 | android-agent | authz | api_stream_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 105 | android-agent | authz | boot_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | android-agent | authz | bot_queue_remove | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | android-agent | authz | delete_avd | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 108 | android-agent | authz | delete_conversation_endpoint | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | android-agent | authz | delete_trace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 110 | android-agent | authz | explorer_run_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 111 | android-agent | authz | get_trace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 112 | android-agent | authz | install_apk | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 113 | android-agent | authz | list_snapshots | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 114 | android-agent | authz | resume_conversation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 115 | android-agent | authz | scheduler_history_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 116 | android-agent | authz | scheduler_history_result | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | android-agent | authz | scheduler_queue_kill | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | android-agent | authz | scheduler_queue_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 119 | android-agent | authz | scheduler_run_restart | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 120 | android-agent | authz | schedules_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 121 | android-agent | authz | schedules_run_now | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | android-agent | authz | schedules_toggle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 123 | android-agent | authz | schedules_update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 124 | android-agent | authz | setup_emulator | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 125 | android-agent | authz | snapshot_load | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 126 | android-agent | authz | snapshot_save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 127 | android-agent | authz | start_emulator | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 128 | android-agent | authz | stop_emulator | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 129 | android-agent | authz | tr_recording_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 130 | android-agent | authz | tr_recording_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | android-agent | authz | tr_recording_log | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 132 | auto-browser | authz | cancel_agent_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | auto-browser | authz | cdp_element_intelligence | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 134 | auto-browser | authz | cdp_raw_command | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | auto-browser | authz | delete_proxy_persona | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 136 | auto-browser | authz | discard_agent_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 137 | auto-browser | authz | enqueue_agent_run | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | auto-browser | authz | enqueue_agent_step | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 139 | auto-browser | authz | export_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 140 | auto-browser | authz | export_session_witness_bundle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 141 | auto-browser | authz | get_agent_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 142 | auto-browser | authz | get_proxy_persona | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 143 | auto-browser | authz | get_remote_access | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 144 | auto-browser | authz | get_session | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 145 | auto-browser | authz | get_takeover_link | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 146 | auto-browser | authz | get_trace | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 147 | auto-browser | authz | network_get_requests | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | auto-browser | authz | network_list_hooks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | auto-browser | authz | network_register_hook | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | auto-browser | authz | network_remove_hook | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | auto-browser | authz | resume_agent_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | auto-browser | authz | revoke_session_share | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | auto-browser | authz | run_agent_step | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | auto-browser | authz | session_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 155 | auto-browser | authz | session_replay | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | auto-browser | authz | share_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 157 | auto-browser | authz | shared_screenshot | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 158 | auto-browser | authz | trigger_cron_job_via_webhook | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 159 | dramatica-flow | authz | add_arc | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 160 | dramatica-flow | authz | add_novel_plan_event | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 161 | dramatica-flow | authz | ai_continue_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 162 | dramatica-flow | authz | ai_generate_arc_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 163 | dramatica-flow | authz | ai_generate_chapter_content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 164 | dramatica-flow | authz | ai_generate_chapter_outlines | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 165 | dramatica-flow | authz | ai_generate_detailed_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | dramatica-flow | authz | ai_generate_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | dramatica-flow | authz | ai_generate_setup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 168 | dramatica-flow | authz | ai_generate_single_chapter_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 169 | dramatica-flow | authz | ai_rewrite_segment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 170 | dramatica-flow | authz | auto_generate_threads | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | dramatica-flow | authz | continue_writing | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 172 | dramatica-flow | authz | create_thread_api | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 173 | dramatica-flow | authz | delete_arc | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 174 | dramatica-flow | authz | delete_novel_plan_event | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 175 | dramatica-flow | authz | delete_style_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 176 | dramatica-flow | authz | delete_thread_api | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 177 | dramatica-flow | authz | export_storycanvas | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 178 | dramatica-flow | authz | extract_from_novel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 179 | dramatica-flow | authz | extract_story_state | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 180 | dramatica-flow | authz | extract_story_state_batch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 181 | dramatica-flow | authz | extract_style | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 182 | dramatica-flow | authz | get_audit_result | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 183 | dramatica-flow | authz | get_book | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 184 | dramatica-flow | authz | get_book_config | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 185 | dramatica-flow | authz | get_causal_chain | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 186 | dramatica-flow | authz | get_chapter | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 187 | dramatica-flow | authz | get_chapter_outlines | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 188 | dramatica-flow | authz | get_detailed_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 189 | dramatica-flow | authz | get_emotional_arcs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 190 | dramatica-flow | authz | get_hooks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 191 | dramatica-flow | authz | get_novel_plan | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 192 | dramatica-flow | authz | get_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 193 | dramatica-flow | authz | get_relationships | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 194 | dramatica-flow | authz | get_style_profiles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 195 | dramatica-flow | authz | get_thread_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 196 | dramatica-flow | authz | get_threads | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 197 | dramatica-flow | authz | import_chapter_outlines | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 198 | dramatica-flow | authz | import_chapters | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 199 | dramatica-flow | authz | import_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 200 | dramatica-flow | authz | list_audit_results | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 201 | dramatica-flow | authz | list_chapters | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 202 | dramatica-flow | authz | list_novel_plan_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 203 | dramatica-flow | authz | promote_chapter | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 204 | dramatica-flow | authz | reopen_hook_api | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 205 | dramatica-flow | authz | resolve_hook_api | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 206 | dramatica-flow | authz | save_chapter_outlines | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 207 | dramatica-flow | authz | save_detailed_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 208 | dramatica-flow | authz | save_novel_plan | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 209 | dramatica-flow | authz | save_outline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 210 | dramatica-flow | authz | save_style_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 211 | dramatica-flow | authz | setup_init_templates | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 212 | dramatica-flow | authz | setup_load | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 213 | dramatica-flow | authz | setup_read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 214 | dramatica-flow | authz | setup_save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 215 | dramatica-flow | authz | setup_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 216 | dramatica-flow | authz | switch_arc | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 217 | dramatica-flow | authz | three_layer_audit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 218 | dramatica-flow | authz | update_arc | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 219 | dramatica-flow | authz | update_book_config | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 220 | dramatica-flow | authz | update_chapter_content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 221 | dramatica-flow | authz | update_thread_api | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 222 | dramatica-flow | authz | upload_novel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 223 | tubecli | arbitrary_file_delete | delete_workflow | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 224 | tubecli | authz | account_delete | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 225 | tubecli | authz | account_patch | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 226 | tubecli | authz | activate | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 227 | tubecli | authz | add_agent_fact | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 228 | tubecli | authz | add_team_briefing | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 229 | tubecli | authz | agent_chat | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 230 | tubecli | authz | agent_scraped | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 231 | tubecli | authz | agent_scraped_guide | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 232 | tubecli | authz | ai_generate_steps_at | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 233 | tubecli | authz | api_authorize | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 234 | tubecli | authz | api_delegate_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 235 | tubecli | authz | api_delete_credential | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 236 | tubecli | authz | api_get_access_token_full | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 237 | tubecli | authz | api_get_active_token | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 238 | tubecli | authz | api_get_team | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 239 | tubecli | authz | api_get_template | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 240 | tubecli | authz | api_gsheets_add_tab | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 241 | tubecli | authz | api_gsheets_append | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 242 | tubecli | authz | api_gsheets_format | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 243 | tubecli | authz | api_gsheets_grid | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 244 | tubecli | authz | api_gsheets_merge | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 245 | tubecli | authz | api_gsheets_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 246 | tubecli | authz | api_gsheets_values | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 247 | tubecli | authz | api_list_calendars | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 248 | tubecli | authz | api_list_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 249 | tubecli | authz | api_org_chart | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 250 | tubecli | authz | api_preview_upload_chunk | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 251 | tubecli | authz | api_refresh_token | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 252 | tubecli | authz | api_reveal_credential | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 253 | tubecli | authz | api_revoke_node_key | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 254 | tubecli | authz | api_revoke_token | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 255 | tubecli | authz | api_update_credential | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 256 | tubecli | authz | api_update_event | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 257 | tubecli | authz | api_update_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 258 | tubecli | authz | api_update_team | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 259 | tubecli | authz | api_video_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 260 | tubecli | authz | app_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 261 | tubecli | authz | approval | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 262 | tubecli | authz | assign_to_profile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 263 | tubecli | authz | brief | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 264 | tubecli | authz | buy_item | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 265 | tubecli | authz | cancel_deploy_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 266 | tubecli | authz | capability | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 267 | tubecli | authz | check_extension_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 268 | tubecli | authz | check_installed | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 269 | tubecli | authz | clear_agent_memory | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 270 | tubecli | authz | clear_agent_runs | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 271 | tubecli | authz | clear_chat_history | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 272 | tubecli | authz | clear_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 273 | tubecli | authz | clear_team_memory | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 274 | tubecli | authz | clone_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 275 | tubecli | authz | crypto_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 276 | tubecli | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 277 | tubecli | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 278 | tubecli | authz | delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 279 | tubecli | authz | delete_account | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 280 | tubecli | authz | delete_agent | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 281 | tubecli | authz | delete_collection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 282 | tubecli | authz | delete_dna | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 283 | tubecli | authz | delete_download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 284 | tubecli | authz | delete_download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 285 | tubecli | authz | delete_group_context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 286 | tubecli | authz | delete_market_item | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 287 | tubecli | authz | delete_processing_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 288 | tubecli | authz | delete_scene | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 289 | tubecli | authz | delete_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 290 | tubecli | authz | delete_server_entry | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 291 | tubecli | authz | delete_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 292 | tubecli | authz | delete_skill | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 293 | tubecli | authz | delete_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 294 | tubecli | authz | delete_workflow | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 295 | tubecli | authz | disable_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 296 | tubecli | authz | drive_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 297 | tubecli | authz | drive_fetch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 298 | tubecli | authz | drive_list | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 299 | tubecli | authz | drive_permissions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 300 | tubecli | authz | drive_progress | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 301 | tubecli | authz | drive_sync_start | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 302 | tubecli | authz | drive_upload_content | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 303 | tubecli | authz | enable_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 304 | tubecli | authz | execution_history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 305 | tubecli | authz | export_json | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 306 | tubecli | authz | extension_info | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 307 | tubecli | authz | extension_locale | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 308 | tubecli | authz | force_check | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 309 | tubecli | authz | generate_agent_routine_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 310 | tubecli | authz | generate_content_from_today | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 311 | tubecli | authz | get_account | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 312 | tubecli | authz | get_agent | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 313 | tubecli | authz | get_agent_history | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 314 | tubecli | authz | get_agent_knowledge | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 315 | tubecli | authz | get_agent_memory | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 316 | tubecli | authz | get_agent_runs | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 317 | tubecli | authz | get_agent_sessions | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 318 | tubecli | authz | get_autopublish | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 319 | tubecli | authz | get_collection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 320 | tubecli | authz | get_dna | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 321 | tubecli | authz | get_events | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 322 | tubecli | authz | get_execution_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 323 | tubecli | authz | get_execution_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 324 | tubecli | authz | get_function | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 325 | tubecli | authz | get_group_context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 326 | tubecli | authz | get_group_log | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 327 | tubecli | authz | get_item_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 328 | tubecli | authz | get_messages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 329 | tubecli | authz | get_one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 330 | tubecli | authz | get_one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 331 | tubecli | authz | get_one | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 332 | tubecli | authz | get_pipeline | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 333 | tubecli | authz | get_processing_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 334 | tubecli | authz | get_scene | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 335 | tubecli | authz | get_scraped_article_detail | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 336 | tubecli | authz | get_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 337 | tubecli | authz | get_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 338 | tubecli | authz | get_script_by_slug | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 339 | tubecli | authz | get_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 340 | tubecli | authz | get_skill | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 341 | tubecli | authz | get_skill_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 342 | tubecli | authz | get_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 343 | tubecli | authz | get_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 344 | tubecli | authz | get_team | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 345 | tubecli | authz | get_workflow | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 346 | tubecli | authz | import_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 347 | tubecli | authz | install_app | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 348 | tubecli | authz | install_from_market | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 349 | tubecli | authz | job_cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 350 | tubecli | authz | job_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 351 | tubecli | authz | list_groups | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 352 | tubecli | authz | login_cancel | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 353 | tubecli | authz | login_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 354 | tubecli | authz | package_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 355 | tubecli | authz | patch_autopublish | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 356 | tubecli | authz | pause_agent_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 357 | tubecli | authz | pick_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 358 | tubecli | authz | plan_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 359 | tubecli | authz | post_review | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 360 | tubecli | authz | post_server_entry | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 361 | tubecli | authz | preview_prompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 362 | tubecli | authz | publish_job_get | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 363 | tubecli | authz | publish_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 364 | tubecli | authz | publish_task_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 365 | tubecli | authz | put_group_context | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 366 | tubecli | authz | put_public_agent | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 367 | tubecli | authz | queue_single_job | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 368 | tubecli | authz | regenerate_agent_keywords | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 369 | tubecli | authz | reload_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 370 | tubecli | authz | remove_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 371 | tubecli | authz | rename | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 372 | tubecli | authz | rename_collection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 373 | tubecli | authz | resolve_browser_ai_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 374 | tubecli | authz | resume_agent_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 375 | tubecli | authz | review_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 376 | tubecli | authz | rewrite_scraped_article | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 377 | tubecli | authz | run_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 378 | tubecli | authz | run_skill | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 379 | tubecli | authz | run_skill_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 380 | tubecli | authz | save_element | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 381 | tubecli | authz | save_scene | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 382 | tubecli | authz | scraped_articles | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 383 | tubecli | authz | scraped_export | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 384 | tubecli | authz | scraped_stats | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 385 | tubecli | authz | send_message | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 386 | tubecli | authz | serve_ai_arena_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 387 | tubecli | authz | serve_chat_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 388 | tubecli | authz | serve_codex_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 389 | tubecli | authz | serve_download | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 390 | tubecli | authz | serve_edu_video_studio_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 391 | tubecli | authz | serve_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 392 | tubecli | authz | serve_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 393 | tubecli | authz | serve_file_manager_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 394 | tubecli | authz | serve_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 395 | tubecli | authz | serve_livestream_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 396 | tubecli | authz | serve_sheets_manager_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 397 | tubecli | authz | serve_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 398 | tubecli | authz | serve_subtitle_extractor_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 399 | tubecli | authz | serve_template_designer_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 400 | tubecli | authz | serve_tts_vibevoice_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 401 | tubecli | authz | serve_video_editor_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 402 | tubecli | authz | serve_video_manager_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 403 | tubecli | authz | serve_web_crawler_static | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 404 | tubecli | authz | set_cast | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 405 | tubecli | authz | sheet | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 406 | tubecli | authz | start_app | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 407 | tubecli | authz | start_learn | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 408 | tubecli | authz | stop_execution | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 409 | tubecli | authz | stream_logs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 410 | tubecli | authz | task_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 411 | tubecli | authz | test_agent_routine | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 412 | tubecli | authz | thread_archive | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 413 | tubecli | authz | thread_delete | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 414 | tubecli | authz | thread_interrupt | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 415 | tubecli | authz | thread_read | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 416 | tubecli | authz | thread_rename | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 417 | tubecli | authz | thread_send | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 418 | tubecli | authz | thread_unarchive | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 419 | tubecli | authz | uninstall_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 420 | tubecli | authz | uninstall_from_market | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 421 | tubecli | authz | update_account | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 422 | tubecli | authz | update_agent | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 423 | tubecli | authz | update_agent_daily_keywords | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 424 | tubecli | authz | update_dna | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 425 | tubecli | authz | update_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 426 | tubecli | authz | update_extension | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 427 | tubecli | authz | update_item | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 428 | tubecli | authz | update_local_extension | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 429 | tubecli | authz | update_script | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 430 | tubecli | authz | update_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 431 | tubecli | authz | update_skill_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 432 | tubecli | authz | update_steps | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 433 | tubecli | authz | update_task | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 434 | tubecli | authz | update_tracker | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 435 | tubecli | authz | update_website | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 436 | tubecli | authz | upload_file | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 437 | tubecli | authz | upload_media | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 438 | tubecli | authz | usage_scan_cancel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 439 | tubecli | authz | usage_scan_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 440 | tubecli | authz | youtube_video_edit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 441 | tubecli | authz | youtube_video_edit_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 442 | tubecli | log_injection | queue_single_job | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 443 | tubecli | log_injection | ws_preview_proxy | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 444 | tubecli | unrestricted_upload | api_preview_upload_files | **UNKNOWN** | — | NON_EXECUTABLE_UPLOAD: 已防路径穿越 / 已做扩展名白名单+固定命名，落盘目录非 Web 静态挂载（无 StaticFiles/addResourceHandlers 指向上传目录），上传物不可执行 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 8 |
| B（其余状态） | 444 |
| 合计 | 452 |
