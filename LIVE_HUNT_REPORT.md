# 活水首杀作战大盘（LIVE_HUNT）

> 机器事实源：benchmarks/results/daily_hunt.json。本报告的 A/B 行数必须与 JSON 计数一致；ZERO_RECORD_FRESH 只代表四个来源**实际查过且 0 命中**，不代表漏洞一定成立，更不代表人工已核验。

- 生成时间：2026-11-24 09:12:45
- 总条数：284 ｜ 板块 A：**9** ｜ 板块 B：**275**
- 状态计数：ZERO_RECORD_FRESH 9 / DUPLICATE_CVE 4 / DUPLICATE_ISSUE_OR_GHSA 0 / PATCHED_UPSTREAM 0 / STALE_REPO 0 / UNKNOWN 271

<!-- live_hunt_counts: {"BOARD_A": 9, "BOARD_B": 275, "DUPLICATE_CVE": 4, "DUPLICATE_ISSUE_OR_GHSA": 0, "PATCHED_UPSTREAM": 0, "STALE_REPO": 0, "UNKNOWN": 271, "ZERO_RECORD_FRESH": 9} -->

## 今日巡猎（daily-hunt）

> 自动流水线：近 14 天有提交的 java/python/solidity 仓 → 同 HEAD 直接跳过 → 只报新引入或尚未导出的 ZERO_RECORD_FRESH 根因；本次即扫即焚 0 个缓存。

- 候选仓：22（已处理 10） ｜ 实扫：6 ｜ 跳过：4 ｜ 失败：0 ｜ 候选来源：github_search
- 本次新增根因：284 ｜ 板块 A：9 ｜ 拦截进 B：275
- 证据不足未列：1 条（NVD 熔断 / 全网 Issue 限流，未宣称 FRESH，需人工复核）
- 冷却期免克隆：0 个（--cooldown-days 7：距上次扫描不足 7 天的仓直接 0 秒顺延）
- 侦察免克隆排除（未变老仓）：0 个

| 仓库 | HEAD | 结果 | 新增 |
|---|---|---|---|
| javashub/CourseArragement | e83d26b0e0cd | SCANNED | 78 |
| rubiin/tsumiki | 69496094f99b | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| youlaitech/youlai-boot | 4203ef6dcdd7 | SCANNED | 43 |
| salitronic/eda-agent | 9c0a14f7795d | SCANNED | 0 |
| techgenius1/tvOS-Launcher | b14942965c24 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| BinceQu/RoboHarness | 8de010092f8a | SCANNED | 2 |
| opanel-mc/opanel | 8c8df45b0be8 | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| POLESNIESOVETI12/web-panel-proxy | 148e7eed150a | SKIPPED (ZERO_ENTRY_LIB) | 0 |
| makunet/maku-boot | 489cb23dbbb7 | SCANNED | 16 |
| PRVTPRO/Amnezia-Web-Panel | 8e2598c07b8e | SCANNED | 145 |

## 板块 A｜🟢 可直接交单的 ZERO_RECORD_FRESH

| # | 仓库 | 类目 | 根因 | 置信度 | HEAD 提交日期 | HEAD | 源码行 | 提单入口 | 本地手册 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CourseArragement | authz | RbacAssignController.assignRoleMenus | — | 2026-11-23 (0.8d) | e83d26b0e0cd | [src/main/java/com/lyk/coursearrange/system/rbac/controller/RbacAssignController.java:42](https://github.com/javashub/CourseArragement/blob/e83d26b0e0cda205bda5e1f020f315210af3140f/src/main/java/com/lyk/coursearrange/system/rbac/controller/RbacAssignController.java#L42) | [Advisory](https://github.com/javashub/CourseArragement/security/advisories/new) · [Issue](https://github.com/javashub/CourseArragement/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/CourseArragement_authz_assignRoleMenus/SUBMISSION_PLAYBOOK.md) |
| 2 | CourseArragement | authz | RbacAssignController.assignRolePermissions | — | 2026-11-23 (0.8d) | e83d26b0e0cd | [src/main/java/com/lyk/coursearrange/system/rbac/controller/RbacAssignController.java:48](https://github.com/javashub/CourseArragement/blob/e83d26b0e0cda205bda5e1f020f315210af3140f/src/main/java/com/lyk/coursearrange/system/rbac/controller/RbacAssignController.java#L48) | [Advisory](https://github.com/javashub/CourseArragement/security/advisories/new) · [Issue](https://github.com/javashub/CourseArragement/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/CourseArragement_authz_assignRolePermissions/SUBMISSION_PLAYBOOK.md) |
| 3 | CourseArragement | xss | AdminClassOptionController.create | — | 2026-11-23 (0.8d) | e83d26b0e0cd | [src/main/java/com/lyk/coursearrange/schedule/controller/AdminClassOptionController.java:45](https://github.com/javashub/CourseArragement/blob/e83d26b0e0cda205bda5e1f020f315210af3140f/src/main/java/com/lyk/coursearrange/schedule/controller/AdminClassOptionController.java#L45) | [Advisory](https://github.com/javashub/CourseArragement/security/advisories/new) · [Issue](https://github.com/javashub/CourseArragement/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/CourseArragement_xss_create/SUBMISSION_PLAYBOOK.md) |
| 4 | CourseArragement | xss | AdminClassOptionController.update | — | 2026-11-23 (0.8d) | e83d26b0e0cd | [src/main/java/com/lyk/coursearrange/schedule/controller/AdminClassOptionController.java:53](https://github.com/javashub/CourseArragement/blob/e83d26b0e0cda205bda5e1f020f315210af3140f/src/main/java/com/lyk/coursearrange/schedule/controller/AdminClassOptionController.java#L53) | [Advisory](https://github.com/javashub/CourseArragement/security/advisories/new) · [Issue](https://github.com/javashub/CourseArragement/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/CourseArragement_xss_update/SUBMISSION_PLAYBOOK.md) |
| 5 | RoboHarness | pathtraver | api_agent_monitor_image | — | 2026-11-21 (2.8d) | 8de010092f8a | [eval/behavior/behavior_interface/web.py:1943](https://github.com/BinceQu/RoboHarness/blob/8de010092f8abc87f941429274afa8b2056a46e4/eval/behavior/behavior_interface/web.py#L1943) | [Advisory](https://github.com/BinceQu/RoboHarness/security/advisories/new) · [Issue](https://github.com/BinceQu/RoboHarness/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/RoboHarness_pathtraver_api_agent_monitor_image/SUBMISSION_PLAYBOOK.md) |
| 6 | youlai-boot | authz | FileController.deleteFile | HIGH | 2026-11-22 (1.5d) | 4203ef6dcdd7 | [src/main/java/com/youlai/boot/system/controller/FileController.java:55](https://github.com/youlaitech/youlai-boot/blob/4203ef6dcdd710c0b6a7279312af191914c68459/src/main/java/com/youlai/boot/system/controller/FileController.java#L55) | [Advisory](https://github.com/youlaitech/youlai-boot/security/advisories/new) · [Issue](https://github.com/youlaitech/youlai-boot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/youlai-boot_authz_deleteFile/SUBMISSION_PLAYBOOK.md) |
| 7 | youlai-boot | authz | FileController.uploadFile | HIGH | 2026-11-22 (1.5d) | 4203ef6dcdd7 | [src/main/java/com/youlai/boot/system/controller/FileController.java:38](https://github.com/youlaitech/youlai-boot/blob/4203ef6dcdd710c0b6a7279312af191914c68459/src/main/java/com/youlai/boot/system/controller/FileController.java#L38) | [Advisory](https://github.com/youlaitech/youlai-boot/security/advisories/new) · [Issue](https://github.com/youlaitech/youlai-boot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/youlai-boot_authz_uploadFile/SUBMISSION_PLAYBOOK.md) |
| 8 | youlai-boot | authz | UserController.bindOrChangeEmail | HIGH | 2026-11-22 (1.5d) | 4203ef6dcdd7 | [src/main/java/com/youlai/boot/system/controller/UserController.java:277](https://github.com/youlaitech/youlai-boot/blob/4203ef6dcdd710c0b6a7279312af191914c68459/src/main/java/com/youlai/boot/system/controller/UserController.java#L277) | [Advisory](https://github.com/youlaitech/youlai-boot/security/advisories/new) · [Issue](https://github.com/youlaitech/youlai-boot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/youlai-boot_authz_bindOrChangeEmail/SUBMISSION_PLAYBOOK.md) |
| 9 | youlai-boot | authz | UserController.bindOrChangeMobile | HIGH | 2026-11-22 (1.5d) | 4203ef6dcdd7 | [src/main/java/com/youlai/boot/system/controller/UserController.java:250](https://github.com/youlaitech/youlai-boot/blob/4203ef6dcdd710c0b6a7279312af191914c68459/src/main/java/com/youlai/boot/system/controller/UserController.java#L250) | [Advisory](https://github.com/youlaitech/youlai-boot/security/advisories/new) · [Issue](https://github.com/youlaitech/youlai-boot/issues/new) · [CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) | [SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/youlai-boot_authz_bindOrChangeMobile/SUBMISSION_PLAYBOOK.md) |

## 板块 B｜🔴 自动拦截 / 不可交单

| # | 仓库 | 类目 | 根因 | 状态 | 命中证据 | 拦截原因 | 官方链接 |
|---|---|---|---|---|---|---|---|
| 1 | Amnezia-Web-Panel | authz | api_add_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 2 | Amnezia-Web-Panel | authz | api_add_user_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 3 | Amnezia-Web-Panel | authz | api_awg_plugin_changelog | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 4 | Amnezia-Web-Panel | authz | api_awg_plugin_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 5 | Amnezia-Web-Panel | authz | api_awg_plugin_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 6 | Amnezia-Web-Panel | authz | api_awg_plugin_update_cancel | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 7 | Amnezia-Web-Panel | authz | api_awg_plugin_update_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 8 | Amnezia-Web-Panel | authz | api_awg_settings_get | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 9 | Amnezia-Web-Panel | authz | api_awg_settings_save | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 10 | Amnezia-Web-Panel | authz | api_backup_restore | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 11 | Amnezia-Web-Panel | authz | api_cheburcheck_get | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 12 | Amnezia-Web-Panel | authz | api_cheburcheck_run | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 13 | Amnezia-Web-Panel | authz | api_check_protocol_port | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 14 | Amnezia-Web-Panel | authz | api_check_server | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 15 | Amnezia-Web-Panel | authz | api_clear_conn_warnings | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 16 | Amnezia-Web-Panel | authz | api_clear_server | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 17 | Amnezia-Web-Panel | authz | api_container_toggle | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 18 | Amnezia-Web-Panel | authz | api_delete_server | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 19 | Amnezia-Web-Panel | authz | api_delete_user | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 20 | Amnezia-Web-Panel | authz | api_docker_ipv6_apply | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 21 | Amnezia-Web-Panel | authz | api_edit_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 22 | Amnezia-Web-Panel | authz | api_edit_server | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 23 | Amnezia-Web-Panel | authz | api_exit_link | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 24 | Amnezia-Web-Panel | authz | api_exit_link_check_egress | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 25 | Amnezia-Web-Panel | authz | api_exit_link_dns | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 26 | Amnezia-Web-Panel | authz | api_exit_link_failover | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 27 | Amnezia-Web-Panel | authz | api_exit_link_failover_check | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 28 | Amnezia-Web-Panel | authz | api_exit_link_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 29 | Amnezia-Web-Panel | authz | api_exit_peer_add | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 30 | Amnezia-Web-Panel | authz | api_exit_peer_remove | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 31 | Amnezia-Web-Panel | authz | api_exit_peers | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 32 | Amnezia-Web-Panel | authz | api_exit_relink | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 33 | Amnezia-Web-Panel | authz | api_exit_transit_version | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 34 | Amnezia-Web-Panel | authz | api_exit_unlink | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 35 | Amnezia-Web-Panel | authz | api_get_connection_config | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 36 | Amnezia-Web-Panel | authz | api_get_connections | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 37 | Amnezia-Web-Panel | authz | api_get_server_clients | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 38 | Amnezia-Web-Panel | authz | api_get_user_connections | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 39 | Amnezia-Web-Panel | authz | api_host_tuning | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 40 | Amnezia-Web-Panel | authz | api_install_progress | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 41 | Amnezia-Web-Panel | authz | api_install_protocol | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 42 | Amnezia-Web-Panel | authz | api_instance_copy_cancel | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 43 | Amnezia-Web-Panel | authz | api_instance_copy_preflight | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 44 | Amnezia-Web-Panel | authz | api_instance_copy_start | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 45 | Amnezia-Web-Panel | authz | api_instance_copy_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 46 | Amnezia-Web-Panel | authz | api_instance_ipv6 | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 47 | Amnezia-Web-Panel | authz | api_ip_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 48 | Amnezia-Web-Panel | authz | api_ipv4_egress | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 49 | Amnezia-Web-Panel | authz | api_ipv4_ingress | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 50 | Amnezia-Web-Panel | authz | api_ipv4_ingress_recreate | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 51 | Amnezia-Web-Panel | authz | api_ipv4_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 52 | Amnezia-Web-Panel | authz | api_ipv6_operation | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 53 | Amnezia-Web-Panel | authz | api_mail_send_user | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 54 | Amnezia-Web-Panel | authz | api_my_connection_config | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 55 | Amnezia-Web-Panel | authz | api_my_connection_delete | **UNKNOWN** | — | AUTHZ_CLASS_OR_BASE_GUARD: 入口挂有 Depends(...) 鉴权依赖 / WS token 校验 / 显式 verify_* 守卫 | — |
| 56 | Amnezia-Web-Panel | authz | api_nginx_site_get | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 57 | Amnezia-Web-Panel | authz | api_nginx_site_save | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 58 | Amnezia-Web-Panel | authz | api_orphan_recovery_preview | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 59 | Amnezia-Web-Panel | authz | api_peer_poll_interval | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 60 | Amnezia-Web-Panel | authz | api_protocol_backup_create | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 61 | Amnezia-Web-Panel | authz | api_protocol_backup_delete | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 62 | Amnezia-Web-Panel | authz | api_protocol_backup_download | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 63 | Amnezia-Web-Panel | authz | api_protocol_backup_restore | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 64 | Amnezia-Web-Panel | authz | api_protocol_backup_upload | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 65 | Amnezia-Web-Panel | authz | api_protocol_backups_list | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 66 | Amnezia-Web-Panel | authz | api_reboot_server | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 67 | Amnezia-Web-Panel | authz | api_remove_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 68 | Amnezia-Web-Panel | authz | api_rename_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 69 | Amnezia-Web-Panel | authz | api_rename_protocol | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 70 | Amnezia-Web-Panel | authz | api_revoke_token | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 71 | Amnezia-Web-Panel | authz | api_rkn_scans | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 72 | Amnezia-Web-Panel | authz | api_rkn_scans_clear | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 73 | Amnezia-Web-Panel | authz | api_rknblock_enable | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 74 | Amnezia-Web-Panel | authz | api_rknblock_install | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 75 | Amnezia-Web-Panel | authz | api_rknblock_install_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 76 | Amnezia-Web-Panel | authz | api_rknblock_options | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 77 | Amnezia-Web-Panel | authz | api_rknblock_repair | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 78 | Amnezia-Web-Panel | authz | api_rknblock_uninstall | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 79 | Amnezia-Web-Panel | authz | api_rknblock_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 80 | Amnezia-Web-Panel | authz | api_save_connection_config | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 81 | Amnezia-Web-Panel | authz | api_server_config | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 82 | Amnezia-Web-Panel | authz | api_server_ipv6_preference | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 83 | Amnezia-Web-Panel | authz | api_server_stats | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 84 | Amnezia-Web-Panel | authz | api_set_connection_speed | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 85 | Amnezia-Web-Panel | authz | api_set_protocol_public_endpoint | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 86 | Amnezia-Web-Panel | authz | api_share_config | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 87 | Amnezia-Web-Panel | authz | api_smartroute_dns | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 88 | Amnezia-Web-Panel | authz | api_smartroute_dns_servers | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 89 | Amnezia-Web-Panel | authz | api_smartroute_enable | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 90 | Amnezia-Web-Panel | authz | api_smartroute_install | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 91 | Amnezia-Web-Panel | authz | api_smartroute_install_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 92 | Amnezia-Web-Panel | authz | api_smartroute_own_subnets | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 93 | Amnezia-Web-Panel | authz | api_smartroute_split | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 94 | Amnezia-Web-Panel | authz | api_smartroute_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 95 | Amnezia-Web-Panel | authz | api_smartroute_uninstall | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 96 | Amnezia-Web-Panel | authz | api_smartroute_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 97 | Amnezia-Web-Panel | authz | api_socks5_get_credentials | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 98 | Amnezia-Web-Panel | authz | api_socks5_update_credentials | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 99 | Amnezia-Web-Panel | authz | api_srv_warp_dns | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 100 | Amnezia-Web-Panel | authz | api_srv_warp_exit_egress | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 101 | Amnezia-Web-Panel | authz | api_srv_warp_failover | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 102 | Amnezia-Web-Panel | authz | api_srv_warp_force_unlink | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 103 | Amnezia-Web-Panel | authz | api_srv_warp_install | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 104 | Amnezia-Web-Panel | authz | api_srv_warp_link | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 105 | Amnezia-Web-Panel | authz | api_srv_warp_reissue | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 106 | Amnezia-Web-Panel | authz | api_srv_warp_repair | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 107 | Amnezia-Web-Panel | authz | api_srv_warp_status | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 108 | Amnezia-Web-Panel | authz | api_srv_warp_switch | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 109 | Amnezia-Web-Panel | authz | api_srv_warp_uninstall | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 110 | Amnezia-Web-Panel | authz | api_srv_warp_unlink | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 111 | Amnezia-Web-Panel | authz | api_ssh_cooldown | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 112 | Amnezia-Web-Panel | authz | api_ssh_trust_confirm | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 113 | Amnezia-Web-Panel | authz | api_subscription_reset | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 114 | Amnezia-Web-Panel | authz | api_toggle_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 115 | Amnezia-Web-Panel | authz | api_toggle_user | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 116 | Amnezia-Web-Panel | authz | api_torrent_plugin_enabled | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 117 | Amnezia-Web-Panel | authz | api_torrent_plugin_install | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 118 | Amnezia-Web-Panel | authz | api_torrent_plugin_marks_clear | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 119 | Amnezia-Web-Panel | authz | api_torrent_plugin_mode | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 120 | Amnezia-Web-Panel | authz | api_torrent_plugin_refresh | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 121 | Amnezia-Web-Panel | authz | api_torrent_plugin_settings | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 122 | Amnezia-Web-Panel | authz | api_torrent_plugin_state | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 123 | Amnezia-Web-Panel | authz | api_torrent_plugin_uninstall | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 124 | Amnezia-Web-Panel | authz | api_uninstall_protocol | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 125 | Amnezia-Web-Panel | authz | api_unlink_user_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 126 | Amnezia-Web-Panel | authz | api_update_user | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 127 | Amnezia-Web-Panel | authz | api_used_ports | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 128 | Amnezia-Web-Panel | authz | api_user_share_setup | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 129 | Amnezia-Web-Panel | authz | api_wgeasy_import | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 130 | Amnezia-Web-Panel | authz | api_wgeasy_preview | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 131 | Amnezia-Web-Panel | authz | api_xray_core_version | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 132 | Amnezia-Web-Panel | authz | api_xray_encryption_state | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 133 | Amnezia-Web-Panel | authz | api_xray_encryption_toggle | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 134 | Amnezia-Web-Panel | authz | api_xray_fingerprint_get | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 135 | Amnezia-Web-Panel | authz | api_xray_fingerprint_save | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 136 | Amnezia-Web-Panel | authz | api_xray_selfsteal_apply | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 137 | Amnezia-Web-Panel | authz | api_xray_selfsteal_plan | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 138 | Amnezia-Web-Panel | authz | api_xray_update | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 139 | Amnezia-Web-Panel | log_injection | api_add_user_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 140 | Amnezia-Web-Panel | log_injection | api_check_protocol_port | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 141 | Amnezia-Web-Panel | log_injection | api_duckdns_apply | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 142 | Amnezia-Web-Panel | log_injection | api_install_protocol | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 143 | Amnezia-Web-Panel | log_injection | api_rename_connection | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 144 | Amnezia-Web-Panel | log_injection | api_rknblock_repair | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 145 | Amnezia-Web-Panel | log_injection | api_uninstall_protocol | **UNKNOWN** | — | LOCAL_LOOPBACK_ONLY: 显式仅允许 loopback 客户端的单机工作台（LocalAccessMiddleware / 127.0.0.1 校验），无远程攻击面 | — |
| 146 | CourseArragement | authz | AdminClassOptionController.create | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 147 | CourseArragement | authz | AdminClassOptionController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 148 | CourseArragement | authz | AdminClassOptionController.options | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 149 | CourseArragement | authz | AdminClassOptionController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 150 | CourseArragement | authz | AdminClassOptionController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 151 | CourseArragement | authz | BaseResourceExcelController.exportClassrooms | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 152 | CourseArragement | authz | BaseResourceExcelController.exportCourses | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 153 | CourseArragement | authz | BaseResourceExcelController.exportStudents | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 154 | CourseArragement | authz | BaseResourceExcelController.exportTeachbuilds | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 155 | CourseArragement | authz | BaseResourceExcelController.exportTeachers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 156 | CourseArragement | authz | BaseResourceExcelController.importClassrooms | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 157 | CourseArragement | authz | BaseResourceExcelController.importCourses | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 158 | CourseArragement | authz | BaseResourceExcelController.importStudents | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 159 | CourseArragement | authz | BaseResourceExcelController.importTeachbuilds | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 160 | CourseArragement | authz | BaseResourceExcelController.importTeachers | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 161 | CourseArragement | authz | ClassTaskExcelController.importClassTasks | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 162 | CourseArragement | authz | OrgCampusController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 163 | CourseArragement | authz | OrgCampusController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 164 | CourseArragement | authz | OrgCollegeController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 165 | CourseArragement | authz | OrgCollegeController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 166 | CourseArragement | authz | OrgStageController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 167 | CourseArragement | authz | OrgStageController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 168 | CourseArragement | authz | RbacAssignController.assignUserRoles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 169 | CourseArragement | authz | RbacAssignController.assignedRoleMenus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 170 | CourseArragement | authz | RbacAssignController.assignedRolePermissions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 171 | CourseArragement | authz | RbacAssignController.assignedUserRoles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 172 | CourseArragement | authz | RbacAssignController.batchAssignUserRoles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 173 | CourseArragement | authz | ResourceClassroomController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 174 | CourseArragement | authz | ResourceClassroomController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 175 | CourseArragement | authz | ResourceClassroomController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 176 | CourseArragement | authz | ResourceClassroomController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 177 | CourseArragement | authz | ResourceCourseController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 178 | CourseArragement | authz | ResourceCourseController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 179 | CourseArragement | authz | ResourceCourseController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 180 | CourseArragement | authz | ResourceCourseController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 181 | CourseArragement | authz | ResourceCourseController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 182 | CourseArragement | authz | ResourceStudentController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 183 | CourseArragement | authz | ResourceStudentController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 184 | CourseArragement | authz | ResourceStudentController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 185 | CourseArragement | authz | ResourceStudentController.nextCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 186 | CourseArragement | authz | ResourceStudentController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 187 | CourseArragement | authz | ResourceStudentController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 188 | CourseArragement | authz | ResourceTeacherController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 189 | CourseArragement | authz | ResourceTeacherController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 190 | CourseArragement | authz | ResourceTeacherController.detail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 191 | CourseArragement | authz | ResourceTeacherController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 192 | CourseArragement | authz | ResourceTeacherController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 193 | CourseArragement | authz | SchedulePlanController.adjust | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 194 | CourseArragement | authz | SchedulePlanController.adjustLogs | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 195 | CourseArragement | authz | SchedulePlanController.byClass | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 196 | CourseArragement | authz | SchedulePlanController.byTeacher | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 197 | CourseArragement | authz | ScheduleTaskController.createExecution | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 198 | CourseArragement | authz | ScheduleTaskController.deleteStandard | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 199 | CourseArragement | authz | ScheduleTaskController.getExecutionDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 200 | CourseArragement | authz | ScheduleTaskController.listExecutions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 201 | CourseArragement | authz | ScheduleTaskController.update | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 202 | CourseArragement | authz | SysMenuController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 203 | CourseArragement | authz | SysMenuController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 204 | CourseArragement | authz | SysMenuController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 205 | CourseArragement | authz | SysPermissionController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 206 | CourseArragement | authz | SysPermissionController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 207 | CourseArragement | authz | SysPermissionController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 208 | CourseArragement | authz | SysRoleController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 209 | CourseArragement | authz | SysRoleController.delete | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 210 | CourseArragement | authz | SysRoleController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 211 | CourseArragement | authz | SysUserController.changeStatus | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 212 | CourseArragement | authz | SysUserController.save | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 213 | CourseArragement | authz | SystemConfigController.createScheduleRule | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 214 | CourseArragement | authz | SystemConfigController.getScheduleConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 215 | CourseArragement | authz | SystemConfigController.getScheduleConfigByRuleId | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 216 | CourseArragement | authz | SystemConfigController.listFeatureToggles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 217 | CourseArragement | authz | SystemConfigController.updateFeatureToggles | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 218 | CourseArragement | authz | SystemConfigController.updateScheduleRule | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 219 | CourseArragement | authz | SystemConfigController.updateTimeSlots | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 220 | RoboHarness | authz | api_plan_grasp_image | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 221 | maku-boot | authz | SysAuthController.mobile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 222 | maku-boot | authz | SysAuthController.sendCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 223 | maku-boot | authz | SysAuthController.third | **DUPLICATE_CVE** | CVE-2026-110123 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_CVE: CVE-2026-110123） | https://cve.circl.lu/api/search/makunet/maku-boot |
| 224 | maku-boot | authz | SysAuthController.token | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 225 | maku-boot | authz | SysMailConfigController.list | **DUPLICATE_CVE** | CVE-2026-110123 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_CVE: CVE-2026-110123） | https://cve.circl.lu/api/search/makunet/maku-boot |
| 226 | maku-boot | authz | SysOrgController.listByPid | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 227 | maku-boot | authz | SysOrgController.nameList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 228 | maku-boot | authz | SysPostController.nameList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 229 | maku-boot | authz | SysPostController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 230 | maku-boot | authz | SysRoleController.nameList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 231 | maku-boot | authz | SysSmsConfigController.list | **DUPLICATE_CVE** | CVE-2026-110123 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_CVE: CVE-2026-110123） | https://cve.circl.lu/api/search/makunet/maku-boot |
| 232 | maku-boot | authz | SysThirdLoginController.renderAuth | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 233 | maku-boot | authz | SysThirdLoginController.unBind | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 234 | maku-boot | authz | SysUserController.nameList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 235 | maku-boot | authz | SysUserController.orgUserList | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 236 | maku-boot | authz | SysUserController.page | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 237 | youlai-boot | authz | CodegenController.deleteGenConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 238 | youlai-boot | authz | CodegenController.downloadZip | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 239 | youlai-boot | authz | CodegenController.fillConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 240 | youlai-boot | authz | CodegenController.getGenTableFormData | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 241 | youlai-boot | authz | CodegenController.getTablePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 242 | youlai-boot | authz | CodegenController.getTablePreviewData | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 243 | youlai-boot | authz | CodegenController.saveGenConfig | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 244 | youlai-boot | authz | DeptController.getDeptForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 245 | youlai-boot | authz | FormController.getFormDefinitionForm | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 246 | youlai-boot | authz | FormController.getFormDefinitionPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 247 | youlai-boot | authz | FormController.getFormMenu | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 248 | youlai-boot | authz | FormController.getFormRender | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 249 | youlai-boot | authz | FormController.getPublicFormRender | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 250 | youlai-boot | authz | MenuController.aiFillMenu | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 251 | youlai-boot | authz | MenuController.getMenuOptions | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 252 | youlai-boot | authz | OidcUserIdentityController.getIdentity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 253 | youlai-boot | authz | OidcUserIdentityController.removeIdentity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 254 | youlai-boot | authz | OidcUserIdentityController.setIdentity | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 255 | youlai-boot | authz | QrCodeAuthController.status | **DUPLICATE_CVE** | CVE-2026-110216、CVE-2026-110215、CVE-2026-7672 | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A（REPO_LEVEL_CVE: CVE-2026-110216, CVE-2026-110215, CVE-2026-7672） | https://cve.circl.lu/api/search/youlaitech/youlai-boot、https://cve.circl.lu/api/search/youlaitech/youlai-boot、https://cve.circl.lu/api/search/youlaitech/youlai-boot |
| 256 | youlai-boot | authz | RoleController.getRoleMenuIds | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 257 | youlai-boot | authz | SmsAuthController.sendCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 258 | youlai-boot | authz | UserController.changeCurrentUserPassword | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 259 | youlai-boot | authz | UserController.sendEmailCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 260 | youlai-boot | authz | UserController.sendMobileCode | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 261 | youlai-boot | authz | UserController.unbindEmail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 262 | youlai-boot | authz | UserController.unbindMobile | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 263 | youlai-boot | authz | WorkflowDefinitionController.listProcessStages | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 264 | youlai-boot | authz | WorkflowInstanceController.getInstanceDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 265 | youlai-boot | authz | WorkflowInstanceController.getInstancePage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 266 | youlai-boot | authz | WorkflowInstanceController.getProcessDiagram | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 267 | youlai-boot | authz | WorkflowInstanceController.startProcess | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 268 | youlai-boot | authz | WorkflowTaskController.completeTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 269 | youlai-boot | authz | WorkflowTaskController.getDoneTaskPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 270 | youlai-boot | authz | WorkflowTaskController.getTaskDetail | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 271 | youlai-boot | authz | WorkflowTaskController.getTodoTaskPage | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 272 | youlai-boot | authz | WorkflowTaskController.listRejectTargets | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 273 | youlai-boot | authz | WorkflowTaskController.rejectTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 274 | youlai-boot | authz | WorkflowTaskController.summarizeTask | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |
| 275 | youlai-boot | authz | WxMaAuthController.silentLogin | **UNKNOWN** | — | UNVERIFIED_WILD_AUTHZ: 无兄弟鉴权反差且非 /admin 入口，野仓模式不直接进 A | — |

## 对账

| 板块 | 行数 |
|---|---|
| A（ZERO_RECORD_FRESH） | 9 |
| B（其余状态） | 275 |
| 合计 | 284 |
