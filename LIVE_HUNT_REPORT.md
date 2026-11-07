# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-07 19:30:25
- 总条数：28 ｜ 板块 A：**1** ｜ 板块 B：**27**
- 状态计数：ZERO_RECORD_FRESH 1 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 27

<!-- live_hunt_counts: {"BOARD_A": 1, "BOARD_B": 27, "DUPLICATE_CVE": 0, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 27, "ZERO_RECORD_FRESH": 1} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 21 天有提交的 java/python 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 20 个缓存。

- 候选仓：26 ｜ 实扫：8 ｜ 跳过：18 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：28 ｜ 板块 A：1 ｜ 拦截进 B：27
- 冷却期免克隆：6 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| jingsewu/open-wes | c85c6ac50cbc | SKIPPED | 0 |
| lasswellt/govee-homeassistant | 7216551ad43a | SKIPPED | 0 |
| opentiny/tiny-engine-backend-java | b06d169ea6df | SKIPPED | 0 |
| Sived80/vedetta | 134a81299f44 | SCANNED | 6 |
| oinone/oinone-pamirs | 32d4a041f66d | SKIPPED | 0 |
| ffunes/Omnibattery | 7eb5144b4dc4 | SKIPPED | 0 |
| suoten/ProtoForge | ec88708ad14b | SKIPPED | 0 |
| jfmlima/shelly-manager | 98fe7503c11e | SCANNED | 1 |
| noiwid/HAFamilyLink | 6257aa82616e | SCANNED | 1 |
| cmgrayb/hass-dyson | d4774279cea1 | SKIPPED | 0 |
| DAB-LABS/HAIR | ce6b13f477eb | SKIPPED | 0 |
| tonylofgren/aurora-smart-home | bdf9802f5007 | SKIPPED | 0 |
| Extelligence-ai/bagel | bd3f65c88533 | SKIPPED | 0 |
| Ecowitt/ha-ecowitt-iot | f73b3a131cd2 | SKIPPED | 0 |
| Phil-Barker/hass-bosch-ebike | 1daf1ae3073c | SKIPPED | 0 |
| MaxGramser/homeassistant_espscreen | 9c7c6a674d2e | SKIPPED | 0 |
| ha-china/HAOS-CN | ac3c12f6b3cc | SKIPPED | 0 |
| vsdudakov/fastadmin | 9202a5e86b49 | SKIPPED | 0 |
| Jezza34000/homeassistant_petkit | 79131c860d2e | SKIPPED | 0 |
| 3dg1luk43/ha_washdata | c0c7f44c0231 | SCANNED | 0 |
| Python-roborock/local_roborock_server | 02a1770b7f22 | SCANNED | 3 |
| hiall-fyi/tado_ce | 249eeab52517 | SKIPPED | 0 |
| TKXB/iotsploit | 5b1ae551c626 | SCANNED | 12 |
| huangjunsen0406/py-xiaozhi | f1883ad49097 | SCANNED | 0 |
| adrienbrault/geekmagic-hacs | ed54a9234802 | SKIPPED | 0 |
| Roninton/IoT-items-of-thoughts | f8ba644b36fd | SCANNED | 5 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | shelly-manager | sqli | list_devices | — | 2026-10-30 (8.4d) | 98fe7503c11e | [packages/cli/src/cli/commands/device_commands.py:100](https://github.com/jfmlima/shelly-manager/blob/98fe7503c11eac1fd549a5846bf3cc336a3ede98/packages/cli/src/cli/commands/device_commands.py#L100) | [Advisory](https://github.com/jfmlima/shelly-manager/security/advisories/new) · [Issue](https://github.com/jfmlima/shelly-manager/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/shelly-manager_sqli_list_devices/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | HAFamilyLink | authz | check_auth_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 2 | IoT-items-of-thoughts | authz | get_audit | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 3 | IoT-items-of-thoughts | authz | get_state | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 4 | IoT-items-of-thoughts | authz | list_turns | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 5 | IoT-items-of-thoughts | authz | run_round | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 6 | IoT-items-of-thoughts | authz | say | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 7 | iotsploit | authz | execute_recovery | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 8 | iotsploit | authz | get_plugin_group | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 9 | iotsploit | authz | get_tool_details | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 10 | iotsploit | log_injection | ai_fetch_models | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 11 | iotsploit | log_injection | ai_model_update | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 12 | iotsploit | log_injection | disable_exploit_plugin | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 13 | iotsploit | log_injection | enable_exploit_plugin | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 14 | iotsploit | log_injection | execute_recovery | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 15 | iotsploit | log_injection | firmware_info | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 16 | iotsploit | log_injection | get_plugin_group | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 17 | iotsploit | log_injection | preview_arxml_import | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 18 | iotsploit | log_injection | upload_file | **UNKNOWN** | — | LOW_SEVERITY_LOG_INJECTION: CWE-117 日志伪造（CRLF 注入）属低危，不作为首杀交单项 | — |
| 19 | local_roborock_server | authz | admin_auth_delete_session | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 20 | local_roborock_server | authz | admin_onboarding_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 21 | local_roborock_server | authz | admin_onboarding_status | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 22 | vedetta | authz | api_device_delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 23 | vedetta | authz | api_device_override | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 24 | vedetta | authz | api_device_presence | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 25 | vedetta | authz | api_device_rename | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 26 | vedetta | authz | api_device_wake | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 27 | vedetta | cmdi | api_export_job | **UNKNOWN** | — | NO_CMD_SINK: 入口文件无任何命令执行调用（os.system/subprocess/asyncio.create_subprocess），cmdi 来自切片里未被入口调用的辅助函数 | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 1 |
| B（其余状态） | 27 |
| 合计 | 28 |
