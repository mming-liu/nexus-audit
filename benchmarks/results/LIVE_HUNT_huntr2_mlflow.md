# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/live_hunt_huntr2_mlflow.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-10-30 23:35:54
- 总条数：45 ｜ 板块 A：**0** ｜ 板块 B：**45**
- 状态计数：ZERO_RECORD_FRESH 0 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 39 / PATCHED_UPSTREAM 6 / STALE_REPO 0 / UNKNOWN 0

<!-- live_hunt_counts: {"BOARD_A": 0, "BOARD_B": 45, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 39, "PATCHED_UPSTREAM": 6, "STALE_REPO": 0, "UNKNOWN": 0, "ZERO_RECORD_FRESH": 0} -->

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | mlflow | authz | _legacy_get_route | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 2 | mlflow | authz | cancel_job | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 3 | mlflow | authz | create_deployment | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 4 | mlflow | authz | create_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 5 | mlflow | authz | create_mcp_access_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 6 | mlflow | authz | create_mcp_server_version | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 7 | mlflow | authz | delete_assessment | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 8 | mlflow | authz | delete_deployment | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 9 | mlflow | authz | delete_mcp_access_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 10 | mlflow | authz | delete_mcp_server | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 11 | mlflow | authz | delete_mcp_server_alias | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 12 | mlflow | authz | delete_mcp_server_version | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 13 | mlflow | authz | delete_skill_tag_command | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 14 | mlflow | authz | delete_skill_version_tag_command | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 15 | mlflow | authz | delete_trace_tag | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 16 | mlflow | authz | delete_traces | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 17 | mlflow | authz | explain | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 18 | mlflow | authz | get_assessment | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 19 | mlflow | authz | get_deployment | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 20 | mlflow | authz | get_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 21 | mlflow | authz | get_endpoint_v3 | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 22 | mlflow | authz | get_job | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 23 | mlflow | authz | get_mcp_access_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 24 | mlflow | authz | get_mcp_server | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 25 | mlflow | authz | get_mcp_server_version | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 26 | mlflow | authz | get_route_v3 | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 27 | mlflow | authz | get_version_by_alias | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 28 | mlflow | authz | import_command | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/cli/skills.py#L451 |
| 29 | mlflow | authz | invocations | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 30 | mlflow | authz | predict | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 31 | mlflow | authz | raw_proxy | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 32 | mlflow | authz | register_command | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/cli/skills.py#L359 |
| 33 | mlflow | authz | register_git_command | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/cli/skills.py#L393 |
| 34 | mlflow | authz | register_oci_command | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/cli/skills.py#L413 |
| 35 | mlflow | authz | register_zip_command | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/cli/skills.py#L432 |
| 36 | mlflow | authz | search_mcp_server_versions | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 37 | mlflow | authz | search_server_access_endpoints | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 38 | mlflow | authz | set_mcp_server_alias | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 39 | mlflow | authz | set_skill_tag_command | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 40 | mlflow | authz | set_skill_version_tag_command | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 41 | mlflow | authz | stream_response | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 42 | mlflow | authz | update_mcp_access_endpoint | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 43 | mlflow | authz | update_mcp_server | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 44 | mlflow | authz | update_mcp_server_version | **DUPLICATE_ISSUE_OR_GHSA** | GHSA-4449-4cjp-ffp5、GHSA-j7qq-vr8c-xvw3、GHSA-2wqp-q3c6-ccj5、GHSA-26p8-2jq9-3vq9、GHSA-7gwp-5pfp-969j | local_seed_hit | https://api.github.com/repos/mlflow/mlflow/security-advisories |
| 45 | mlflow | zip_slip | handle | **PATCHED_UPSTREAM** | — | empty_method_body_on_head | https://github.com/mlflow/mlflow/blob/bdb94c654505e8d02249b4895b75b0c1ff61bb75/mlflow/tracing/distributed/__init__.py#L53 |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 0 |
| B（其余状态） | 45 |
| 合计 | 45 |
