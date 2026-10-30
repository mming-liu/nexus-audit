# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt_huntr1.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-30 22:52:45
- 总条数：47 ｜ 板块 A：**0** ｜ 板块 B：**47**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 47

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 47, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 47, "ZERO_RECORD_FRESH": 0} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | vllm | authz | RoutedExperts | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 2 | vllm | authz | _legacy_get_route | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 3 | vllm | authz | create_deployment | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 4 | vllm | authz | create_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 5 | vllm | authz | create_mcp_access_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 6 | vllm | authz | delete_assessment | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 7 | vllm | authz | delete_deployment | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 8 | vllm | authz | delete_mcp_access_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 9 | vllm | authz | delete_mcp_server | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 10 | vllm | authz | delete_mcp_server_alias | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 11 | vllm | authz | delete_mcp_server_version | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 12 | vllm | authz | delete_skill_tag_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 13 | vllm | authz | delete_skill_version_tag_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 14 | vllm | authz | delete_trace_tag | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 15 | vllm | authz | delete_traces | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 16 | vllm | authz | explain | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 17 | vllm | authz | get_assessment | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 18 | vllm | authz | get_deployment | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 19 | vllm | authz | get_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 20 | vllm | authz | get_endpoint_v3 | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 21 | vllm | authz | get_mcp_access_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 22 | vllm | authz | get_mcp_server | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 23 | vllm | authz | get_mcp_server_version | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 24 | vllm | authz | get_route_v3 | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 25 | vllm | authz | import_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 26 | vllm | authz | invocations | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 27 | vllm | authz | predict | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 28 | vllm | authz | raw_proxy | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 29 | vllm | authz | register_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 30 | vllm | authz | register_git_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 31 | vllm | authz | register_oci_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 32 | vllm | authz | register_zip_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 33 | vllm | authz | search_mcp_server_versions | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 34 | vllm | authz | set_mcp_server_alias | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 35 | vllm | authz | set_skill_tag_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 36 | vllm | authz | set_skill_version_tag_command | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 37 | vllm | authz | stream_response | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 38 | vllm | authz | update_mcp_access_endpoint | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 39 | vllm | authz | update_mcp_server | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 40 | vllm | authz | update_mcp_server_version | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 41 | vllm | log_injection | create_score_v1 | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 42 | vllm | log_injection | reset_encoder_cache | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 43 | vllm | log_injection | reset_mm_cache | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 44 | vllm | log_injection | reset_prefix_cache | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 45 | vllm | log_injection | start_profile | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 46 | vllm | log_injection | stop_profile | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |
| 47 | vllm | zip_slip | handle | **UNKNOWN** | — | head_unavailable: not_a_git_repo | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 47 |
| 合计 | 47 |
