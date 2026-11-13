# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-13 10:24:29
- 总条数：38 ｜ 板块 A：**0** ｜ 板块 B：**38**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 38

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 38, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 38, "ZERO_RECORD_FRESH": 0} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 17 个缓存。

- 候选仓：17 ｜ 实扫：10 ｜ 跳过：7 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：38 ｜ 板块 A：0 ｜ 拦截进 B：38
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| Sallyn0225/eidolon-sc | 5875cdfffbf0 | SCANNED | 0 |
| fim-ai/fim-one | a731a5fec6c6 | SCANNED | 1 |
| dnotitia/akb | 73853fa0ceeb | SKIPPED | 0 |
| scub-france/docling-Studio | 1de192940769 | SCANNED | 0 |
| apowerb/apowerb | 5d119e2b528b | SCANNED | 23 |
| brekkylab/backlot | e5fbc4632ad6 | SCANNED | 0 |
| xr843/fojin | 0731c3b7f5a1 | SCANNED | 0 |
| caura-ai/caura | 7286c4b3b83d | SCANNED | 5 |
| GroundedCoreAI/nexusdesk | 3969258b81e0 | SKIPPED | 0 |
| skygazer42/MimirQ | 5d08b54beb80 | SCANNED | 9 |
| Johnson-Durui/Companion-Space | 4177484549c1 | SKIPPED | 0 |
| cuic19053-hue/stardust-agent | c97aed913a90 | SCANNED | 0 |
| manor-os/manor-ai | 02c2db6709c5 | SKIPPED | 0 |
| MoMoM101/RAG-ReActAgent | 3c57e634feaf | SKIPPED | 0 |
| didilili/deepsearch-agents | 8263e95444fd | SKIPPED | 0 |
| didilili/shopkeeper-agent | 5f9ec8d85e06 | SKIPPED | 0 |
| haoyiyin/basjoo | 448f833a2a56 | SCANNED | 0 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | MimirQ | log_injection | create_dataset | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 2 | MimirQ | log_injection | create_evidence_item_from_feedback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 3 | MimirQ | log_injection | create_regression_case_from_feedback | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 4 | MimirQ | log_injection | delete_kg_entity_alias | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 5 | MimirQ | log_injection | delete_kg_for_document | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 6 | MimirQ | log_injection | delete_kg_predicate_ontology | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 7 | MimirQ | log_injection | purge_audit_logs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 8 | MimirQ | log_injection | purge_ragas_regression_runs | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 9 | MimirQ | log_injection | update_dataset | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 10 | apowerb | log_injection | create_agent_trigger | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 11 | apowerb | log_injection | create_session | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 12 | apowerb | log_injection | delete_dashboard_schedule | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 13 | apowerb | log_injection | list_all_sessions | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 14 | apowerb | log_injection | run_agent | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 15 | apowerb | log_injection | run_agent_from_jwt_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 16 | apowerb | log_injection | run_agent_now_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 17 | apowerb | log_injection | run_agent_sse | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 18 | apowerb | log_injection | schedule_agent_run_endpoint | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 19 | apowerb | log_injection | schedule_chart_refresh | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 20 | apowerb | log_injection | schedule_dashboard_refresh | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 21 | apowerb | log_injection | upload_chunk | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 22 | apowerb | log_injection | upload_complete | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 23 | apowerb | log_injection | upload_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 24 | apowerb | sqli | connection_status | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 25 | apowerb | sqli | get_dashboard_agent | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 26 | apowerb | sqli | get_hub | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 27 | apowerb | sqli | list_agents | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 28 | apowerb | sqli | list_gdrive_configs | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 29 | apowerb | sqli | list_hub | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 30 | apowerb | sqli | list_keys | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 31 | apowerb | sqli | read_agent | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 32 | apowerb | sqli | run_adk_agent | **UNKNOWN** | — | NO_SQL_SINK: 入口文件无任何 SQL 执行语句（.execute/.executemany/.executescript），sqli 来自切片里未被入口调用的辅助函数 | — |
| 33 | caura | log_injection | delete_all_memories | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 34 | caura | log_injection | fanout_lifecycle_action | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 35 | caura | log_injection | get_graph | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 36 | caura | log_injection | get_memory | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 37 | caura | log_injection | heartbeat | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 38 | fim-one | log_injection | authorize | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 38 |
| 合计 | 38 |
