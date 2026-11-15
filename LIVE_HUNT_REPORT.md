# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-16 00:07:47
- 总条数：193 ｜ 板块 A：**7** ｜ 板块 B：**186**
- 状态计数：ZERO_RECORD_FRESH 7 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 186

<!-- live_hunt_counts: {"BOARD_A": 7, "BOARD_B": 186, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 186, "ZERO_RECORD_FRESH": 7} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：16 ｜ 实扫：4 ｜ 跳过：8 ｜ 失败：4 ｜ 候选来源：github_search
- 本次新增根因：193 ｜ 板块 A：7 ｜ 拦截进 B：186
- 证据不足未列：0 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| tmseidel/ai-git-bot | d1e8b3b5b52c | SCANNED | 60 |
| siddsachar/row-bot | ec7007a66874 | SKIPPED (all_local_or_demo) | 0 |
| silentchainai/SILENTCHAIN | eed72be5c440 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| pipeshub-ai/pipeshub-ai |  | FAILED (TimeoutExpired: Command '['C:\\Users\\ee) | 0 |
| kstevica/captain-claw | 4c859d5c2ffa | SKIPPED (all_local_or_demo) | 0 |
| ldbumble/taskuary |  | FAILED (clone_failed: Cloning into 'C:\myFloders) | 0 |
| roandejager/Hillock | b5e2569ab3aa | SKIPPED (low_units_3) | 0 |
| Lethe044/hermes-life-os | d344941e1af0 | SKIPPED (all_local_or_demo) | 0 |
| xuiltul/animaworks | 104f809b1ec1 | SCANNED | 90 |
| ttlequals0/MinusPod |  | FAILED (clone_failed: benchmarks/llm/results/raw) | 0 |
| Aseiel/VideoHighlighter | eaff178fd25f | SCANNED | 0 |
| grregis/MuckScraper | 04fc19d290dc | SCANNED | 43 |
| crow-hq/llm-wiki-v2 | 436fcd148f9e | SKIPPED (all_local_or_demo) | 0 |
| SudoHopeX/KaliGPT | c97c910ee6c8 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| ghbalf/freecad-ai | 6160a2b3a618 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| aayushch/laya |  | FAILED (clone_failed: ed: Command '['git', '-c',) | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | MuckScraper | redir | save_feed_defaults | — | 2026-11-12 (3.4d) | 04fc19d290dc | [aggregator/blueprints/auth.py:162](https://github.com/grregis/MuckScraper/blob/04fc19d290dc6477339d932662a4dd36e505ce62/aggregator/blueprints/auth.py#L162) | [Advisory](https://github.com/grregis/MuckScraper/security/advisories/new) · [Issue](https://github.com/grregis/MuckScraper/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/MuckScraper_redir_save_feed_defaults/SUBMISSION_PLAYBOOK.md) |
| 2 | ai-git-bot | deserial | UnifiedWebhookController.handleWebhook | — | 2026-11-13 (2.1d) | d1e8b3b5b52c | [src/main/java/org/remus/giteabot/webhook/UnifiedWebhookController.java:65](https://github.com/tmseidel/ai-git-bot/blob/d1e8b3b5b52c71ada9ba1bc9b6f14b62bca781c8/src/main/java/org/remus/giteabot/webhook/UnifiedWebhookController.java#L65) | [Advisory](https://github.com/tmseidel/ai-git-bot/security/advisories/new) · [Issue](https://github.com/tmseidel/ai-git-bot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-git-bot_deserial_handleWebhook/SUBMISSION_PLAYBOOK.md) |
| 3 | ai-git-bot | xss | AiIntegrationController.save | — | 2026-11-13 (2.1d) | d1e8b3b5b52c | [src/main/java/org/remus/giteabot/admin/AiIntegrationController.java:72](https://github.com/tmseidel/ai-git-bot/blob/d1e8b3b5b52c71ada9ba1bc9b6f14b62bca781c8/src/main/java/org/remus/giteabot/admin/AiIntegrationController.java#L72) | [Advisory](https://github.com/tmseidel/ai-git-bot/security/advisories/new) · [Issue](https://github.com/tmseidel/ai-git-bot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-git-bot_xss_save/SUBMISSION_PLAYBOOK.md) |
| 4 | ai-git-bot | xss | BotController.save | — | 2026-11-13 (2.1d) | d1e8b3b5b52c | [src/main/java/org/remus/giteabot/admin/BotController.java:90](https://github.com/tmseidel/ai-git-bot/blob/d1e8b3b5b52c71ada9ba1bc9b6f14b62bca781c8/src/main/java/org/remus/giteabot/admin/BotController.java#L90) | [Advisory](https://github.com/tmseidel/ai-git-bot/security/advisories/new) · [Issue](https://github.com/tmseidel/ai-git-bot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-git-bot_xss_save/SUBMISSION_PLAYBOOK.md) |
| 5 | ai-git-bot | xss | GitIntegrationController.save | — | 2026-11-13 (2.1d) | d1e8b3b5b52c | [src/main/java/org/remus/giteabot/admin/GitIntegrationController.java:108](https://github.com/tmseidel/ai-git-bot/blob/d1e8b3b5b52c71ada9ba1bc9b6f14b62bca781c8/src/main/java/org/remus/giteabot/admin/GitIntegrationController.java#L108) | [Advisory](https://github.com/tmseidel/ai-git-bot/security/advisories/new) · [Issue](https://github.com/tmseidel/ai-git-bot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-git-bot_xss_save/SUBMISSION_PLAYBOOK.md) |
| 6 | ai-git-bot | xss | SystemSettingsController.mcpToolSelection | — | 2026-11-13 (2.1d) | d1e8b3b5b52c | [src/main/java/org/remus/giteabot/systemsettings/SystemSettingsController.java:93](https://github.com/tmseidel/ai-git-bot/blob/d1e8b3b5b52c71ada9ba1bc9b6f14b62bca781c8/src/main/java/org/remus/giteabot/systemsettings/SystemSettingsController.java#L93) | [Advisory](https://github.com/tmseidel/ai-git-bot/security/advisories/new) · [Issue](https://github.com/tmseidel/ai-git-bot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/ai-git-bot_xss_mcpToolSelection/SUBMISSION_PLAYBOOK.md) |
| 7 | animaworks | jndi_injection | get_approval_page | — | 2026-11-15 (0.6d) | 104f809b1ec1 | [server/routes/approve.py:26](https://github.com/xuiltul/animaworks/blob/104f809b1ec11b1111c7f354d61053b1e07865a6/server/routes/approve.py#L26) | [Advisory](https://github.com/xuiltul/animaworks/security/advisories/new) · [Issue](https://github.com/xuiltul/animaworks/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/animaworks_jndi_injection_get_approval_page/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | MuckScraper | authz | ai_task_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | MuckScraper | authz | deep_report_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | MuckScraper | authz | delete_ingestion_block | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | MuckScraper | authz | delete_pipeline_schedule | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | MuckScraper | authz | delete_rss_feed | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | MuckScraper | authz | delete_scheduled_fetch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | MuckScraper | authz | edit_prompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | MuckScraper | authz | enrich_story_balance | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | MuckScraper | authz | rate_article | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | MuckScraper | authz | rerank_outlet | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 11 | MuckScraper | authz | rescrape_article_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 12 | MuckScraper | authz | reset_prompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 13 | MuckScraper | authz | reset_user_password | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 14 | MuckScraper | authz | restart_container | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 15 | MuckScraper | authz | scrape_article_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 16 | MuckScraper | authz | summarize_article_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 17 | MuckScraper | authz | summarize_story_route | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 18 | MuckScraper | authz | update_ingestion_block | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 19 | MuckScraper | authz | update_pipeline_schedule | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | MuckScraper | authz | update_prompt | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | MuckScraper | authz | update_rss_feed | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | MuckScraper | authz | update_scheduled_fetch | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | MuckScraper | authz | update_topic | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | MuckScraper | authz | view_story | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | MuckScraper | log_injection | add_ingestion_block | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 26 | MuckScraper | log_injection | add_pipeline_schedule | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 27 | MuckScraper | log_injection | add_rss_feed | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 28 | MuckScraper | log_injection | add_scheduled_fetch | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 29 | MuckScraper | log_injection | add_topic | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 30 | MuckScraper | log_injection | backfill_control | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 31 | MuckScraper | log_injection | deep_report_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 32 | MuckScraper | log_injection | fetch_articles | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 33 | MuckScraper | log_injection | rate_article | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 34 | MuckScraper | log_injection | rerank_outlet | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 35 | MuckScraper | log_injection | rescrape_article_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 36 | MuckScraper | log_injection | scrape_article_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 37 | MuckScraper | log_injection | summarize_article_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 38 | MuckScraper | log_injection | summarize_story_route | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 39 | MuckScraper | log_injection | toggle_analyze_all_stories | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 40 | MuckScraper | log_injection | toggle_auto_article_deep_analysis | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 41 | MuckScraper | log_injection | unblock_domain | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 42 | MuckScraper | log_injection | wake_ollama | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 43 | ai-git-bot | authz | AiIntegrationController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 44 | ai-git-bot | authz | AiIntegrationController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 45 | ai-git-bot | authz | AiIntegrationController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 46 | ai-git-bot | authz | BotController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 47 | ai-git-bot | authz | BotController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 48 | ai-git-bot | authz | BotController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 49 | ai-git-bot | authz | BotController.selectedBuiltinTools | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 50 | ai-git-bot | authz | BotController.selectedMcpTools | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 51 | ai-git-bot | authz | DeploymentTargetController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 52 | ai-git-bot | authz | DeploymentTargetController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 53 | ai-git-bot | authz | DeploymentTargetController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 54 | ai-git-bot | authz | EventHookController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 55 | ai-git-bot | authz | EventHookController.deliveries | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 56 | ai-git-bot | authz | EventHookController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 57 | ai-git-bot | authz | EventHookController.retryDelivery | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 58 | ai-git-bot | authz | EventHookController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 59 | ai-git-bot | authz | EventHookController.toggle | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 60 | ai-git-bot | authz | GitIntegrationController.confirmSshSetup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 61 | ai-git-bot | authz | GitIntegrationController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 62 | ai-git-bot | authz | GitIntegrationController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 63 | ai-git-bot | authz | GitIntegrationController.previewSshSetup | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 64 | ai-git-bot | authz | GitIntegrationController.retryDelete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 65 | ai-git-bot | authz | GitIntegrationController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 66 | ai-git-bot | authz | IssueWorkflowConfigurationController.cloneForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 67 | ai-git-bot | authz | IssueWorkflowConfigurationController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 68 | ai-git-bot | authz | IssueWorkflowConfigurationController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 69 | ai-git-bot | authz | IssueWorkflowConfigurationController.saveWorkflowSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 70 | ai-git-bot | authz | IssueWorkflowConfigurationController.selectedWorkflows | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 71 | ai-git-bot | authz | IssueWorkflowConfigurationController.workflowSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 72 | ai-git-bot | authz | SetupController.createAdmin | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 73 | ai-git-bot | authz | SystemSettingsController.botToolSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 74 | ai-git-bot | authz | SystemSettingsController.cloneBotToolForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 75 | ai-git-bot | authz | SystemSettingsController.cloneForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 76 | ai-git-bot | authz | SystemSettingsController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 77 | ai-git-bot | authz | SystemSettingsController.deleteBotTool | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 78 | ai-git-bot | authz | SystemSettingsController.deleteMcp | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 79 | ai-git-bot | authz | SystemSettingsController.editBotToolForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 80 | ai-git-bot | authz | SystemSettingsController.editForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 81 | ai-git-bot | authz | SystemSettingsController.editMcpForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 82 | ai-git-bot | authz | SystemSettingsController.mcpToolSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 83 | ai-git-bot | authz | SystemSettingsController.preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 84 | ai-git-bot | authz | SystemSettingsController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 85 | ai-git-bot | authz | SystemSettingsController.saveBotTool | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 86 | ai-git-bot | authz | SystemSettingsController.saveBotToolSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 87 | ai-git-bot | authz | SystemSettingsController.saveMcp | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 88 | ai-git-bot | authz | SystemSettingsController.saveMcpToolSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 89 | ai-git-bot | authz | UnifiedWebhookController.handleWebhook | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 90 | ai-git-bot | authz | WorkflowCallbackController.callback | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 91 | ai-git-bot | authz | WorkflowCallbackController.log | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 92 | ai-git-bot | authz | WorkflowConfigurationController.cloneForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 93 | ai-git-bot | authz | WorkflowConfigurationController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 94 | ai-git-bot | authz | WorkflowConfigurationController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 95 | ai-git-bot | authz | WorkflowConfigurationController.saveWorkflowSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 96 | ai-git-bot | authz | WorkflowConfigurationController.selectedWorkflows | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 97 | ai-git-bot | authz | WorkflowConfigurationController.workflowSelection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 98 | animaworks | authz | ask_ack | **UNKNOWN** | — | LOCAL_UNIX_SOCKET_SERVER: AF_UNIX 本地控制通道（0700/0600 + 对端 UID 校验），设计上不可从网络到达 | — |
| 99 | animaworks | authz | ask_cancel | **UNKNOWN** | — | LOCAL_UNIX_SOCKET_SERVER: AF_UNIX 本地控制通道（0700/0600 + 对端 UID 校验），设计上不可从网络到达 | — |
| 100 | animaworks | authz | ask_status | **UNKNOWN** | — | LOCAL_UNIX_SOCKET_SERVER: AF_UNIX 本地控制通道（0700/0600 + 对端 UID 校验），设计上不可从网络到达 | — |
| 101 | animaworks | authz | cancel_remake_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 102 | animaworks | authz | chat | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 103 | animaworks | authz | chat_stream | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 104 | animaworks | authz | clear_conversation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 105 | animaworks | authz | compact_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 106 | animaworks | authz | compress_conversation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 107 | animaworks | authz | delete_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 108 | animaworks | authz | delete_user | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 109 | animaworks | authz | disable_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 110 | animaworks | authz | enable_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 111 | animaworks | authz | episode_calendar | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 112 | animaworks | authz | generate_assets | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 113 | animaworks | authz | generate_expression_on_demand | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 114 | animaworks | authz | get_active_stream | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 115 | animaworks | authz | get_activity_group | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 116 | animaworks | authz | get_anima_aliases | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 117 | animaworks | authz | get_anima_config | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 118 | animaworks | authz | get_anima_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 119 | animaworks | authz | get_anima_state | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 120 | animaworks | authz | get_anima_summary | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 121 | animaworks | authz | get_approval_page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 122 | animaworks | authz | get_asset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 123 | animaworks | authz | get_asset_metadata | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 124 | animaworks | authz | get_attachment | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 125 | animaworks | authz | get_attachment_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 126 | animaworks | authz | get_channel_info | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 127 | animaworks | authz | get_channel_mentions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 128 | animaworks | authz | get_channel_messages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 129 | animaworks | authz | get_channel_reads | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 130 | animaworks | authz | get_conversation | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 131 | animaworks | authz | get_conversation_background | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 132 | animaworks | authz | get_conversation_history | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 133 | animaworks | authz | get_conversation_tool_calls | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 134 | animaworks | authz | get_episode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 135 | animaworks | authz | get_face_asset | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 136 | animaworks | authz | get_knowledge | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 137 | animaworks | authz | get_procedure | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 138 | animaworks | authz | get_session_detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 139 | animaworks | authz | get_stream_progress | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 140 | animaworks | authz | get_transcript | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 141 | animaworks | authz | greet | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 142 | animaworks | authz | interrupt_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 143 | animaworks | authz | list_episodes | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 144 | animaworks | authz | list_knowledge | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 145 | animaworks | authz | list_procedures | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 146 | animaworks | authz | list_sessions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 147 | animaworks | authz | mark_channel_read | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | animaworks | authz | memory_connection_entity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | animaworks | authz | memory_connections | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | animaworks | authz | memory_graph | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | animaworks | authz | memory_stats | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | animaworks | authz | post_to_channel | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | animaworks | authz | put_discord_channel_members | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | animaworks | authz | read_log | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 155 | animaworks | authz | record_voice_call | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | animaworks | authz | regenerate_asset_step | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 157 | animaworks | authz | reload_anima_config | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 158 | animaworks | authz | remake_preview | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 159 | animaworks | authz | rename_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 160 | animaworks | authz | repair_anima_bootstrap | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 161 | animaworks | authz | reply_to_notification | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 162 | animaworks | authz | resolve_interaction | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 163 | animaworks | authz | restart_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 164 | animaworks | authz | start_anima | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 165 | animaworks | authz | submit_approval | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | animaworks | authz | trigger_heartbeat | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | animaworks | authz | update_anima_aliases | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 168 | animaworks | authz | update_anima_background_model | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 169 | animaworks | authz | update_anima_identity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 170 | animaworks | authz | update_anima_injection | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | animaworks | authz | update_anima_model | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 172 | animaworks | authz | update_anima_role | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 173 | animaworks | authz | update_channel_settings | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 174 | animaworks | authz | vault_delete_shared | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 175 | animaworks | authz | vault_reissue_hub_token | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 176 | animaworks | authz | vault_rollback_shared | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 177 | animaworks | authz | vault_set_shared | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 178 | animaworks | authz | voice_websocket | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 179 | animaworks | log_injection | add_user | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 180 | animaworks | log_injection | delete_anima | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 181 | animaworks | log_injection | get_asset_metadata | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 182 | animaworks | log_injection | phone_media_stream | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 183 | animaworks | log_injection | remake_preview | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 184 | animaworks | log_injection | rename_anima | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 185 | animaworks | log_injection | voice_websocket | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 186 | animaworks | log_injection | websocket_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 7 |
| B（其余状态） | 186 |
| 合计 | 193 |
