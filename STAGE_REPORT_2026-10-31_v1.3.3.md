# STAGE REPORT · v1.3.3（M299 → M300，对应施工单 M297 → M300）

> 日期：2026-10-31 ｜ 基线：v1.3.2（70c2907）
> 结论：**冒烟 PASS（1,704 项断言）** ｜ doctor 12/12 PASS ｜ 实盘 daily-hunt：候选 24 → 实扫 10（冷却期免克隆 6）→ **板块 A = 11**（上一轮 A = 0）。
> 编号说明：施工单里的 M297/M298 已在 v1.3.2 被“Solidity 语言闸门 / Python 限定词去 panel”占用，
> 本批按连续序号落为 M299（冷却期免克隆）、M300（工具词过滤），冒烟顺延 [287]–[288]。

## 一、修了什么

| 编号 | 问题（2026-10-31 09:00 实盘暴露） | 修复 |
| --- | --- | --- |
| M299 | 候选 34 个，却只实扫前 10 个；metasfresh 这类每隔几小时推一次 Commit 的活跃大仓，因为 `head_sha` 变了，每天都被重新完整克隆重扫，第 11–34 名的新仓永远轮不到 | `daily_hunt.run()` 遍历 `scout_daily` 返回的**完整候选池**，并在 `sync_fn(slug)` 之前先查账本 `last_scanned_at`：距上次扫描不足 `--cooldown-days`（默认 7 天）的仓，无论远端是否有新 Commit，直接 0 秒记 `SKIPPED (cooldown_7d)` 并顺延；`--cooldown-days 0` 关闭。账本只记 `age_days`，不改写跳过仓的 `last_scanned_at` |
| M300 | 实扫 10 个里混进 datamodel-code-generator（代码生成器）、logfire（日志 SDK）、citrus（测试框架）、spring-tools（IDE 工具），白占 4 个名额 | `target_scout.py` 非业务黑名单补入 `generator/generators/codegen/datamodel/telemetry/observability/logfire/spring-tools/citrus/test-framework/testing-framework`，以及 `ide-/vscode-/intellij-/eclipse-` 连字符前缀（描述里写 “IDE integration” 的业务仓不误杀） |
| — | `report_auto.md` 未跟踪临时文件；MONETIZATION_PLAN 仍把 newbee-mall-api 当可投递标的 | 删除 `report_auto.md` 并加入 `.gitignore`；MONETIZATION_PLAN 三处（路径 2 第一步 / 本周三步走 / 跟踪表）统一标 **已永久废弃（STALE_REPO：HEAD 0879d5a1 / 2023-05-31，停更 1,246 天）**；A=0 时不提交 `LIVE_HUNT_REPORT.md`（本轮 A=11，故正常提交） |

## 二、实盘验证（2026-10-31 13:26 → 13:39）

命令：`python cli.py daily-hunt --languages java,python --days 14 --limit 10 --max-roots 5 --evict-cache`
（未配 `GITHUB_TOKEN`，按 README 预算加 `--max-roots 5`，避免 60 次/小时 core 限额被单轮打穿。）

| 指标 | 结果 |
| --- | --- |
| 候选 / 实扫 / 跳过 / 失败 | 24 / 10 / 7 / 0 |
| 冷却期免克隆 | 6（creatorhub、metasfresh、testcontainers-spring-boot、tracecat、terrakube、fastapi-do-zero、urlaubsverwaltung 中除 1 个零入口外全部命中） |
| 新增根因 / 板块 A / 拦截进 B | 21 / **11** / 10 |
| 即扫即焚 | 11 个缓存目录 |
| 新扫业务仓 | sz-boot-parent、xianyu-auto-reply、Kokoro-FastAPI、codex-lb、dramaclaw、OpenExecutive、agent-service-toolkit、starlette-admin、restai、eidolon-sc |

对比 09:00 那轮（候选 34 / 实扫 10 / A=0 / 4 个工具库占名额）：**同样的 10 个名额，产出从 0 条变成 11 条**。

## 三、门禁

| 项目 | 结果 |
| --- | --- |
| `python benchmarks/smoke_test_chains.py` | PASS ✔ **1,704 项**（新增 [287] 冷却期 / [288] 工具词过滤） |
| `python cli.py doctor` | PASS（12 段全绿，40 类规则 / 35 类补丁器 / 50 仓对账） |
| `LIVE_HUNT_REPORT.md` ↔ `daily_hunt.json` | 计数守恒 A 11 / B 10 / 合计 21（冒烟 [270] 已复核） |

## 四、遗留问题（下一批，不在本单范围）

1. **板块 A 仍有 3 条明显误报**，需人工/LLM 复核后再决定是否交单：
   - `xianyu-auto-reply` sqli `health_check` @ `scheduler/_bootstrap.py:238` 与 `backend-web/_bootstrap.py:272`：实码是 `@app.get("/health")` + `conn.execute(text("SELECT 1"))`，常量 SQL，无污点；
   - `xianyu-auto-reply` sqli `upload_image` @ `backend-web/app/api/routes/upload.py:15`：该文件及 `image_manager.save_image` 全链路无任何 SQL 调用。
   根因是 Python 侧缺少“切片内确无 SQL sink 就否决 sqli”的收口规则，建议单开一条 `NO_SQL_SINK` 降噪（优先级高于继续扩词）。
2. `testcontainers-spring-boot` 仍被当业务仓克隆（靠 `ZERO_ENTRY_LIB` 兜底），可把 `testcontainers` 补进工具词。
3. `health_check` / `upload_image` 这类顶层函数名容易在 A 板块重复出现，建议按“同仓同文件同函数只留一条”折叠。
