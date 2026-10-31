# STAGE REPORT · v1.3.4（M301 → M303）

> 日期：2026-10-31 ｜ 基线：v1.3.3（01eeb10）
> 结论：**Python SQLi 三态收口**，把昨日板块 A 11 条里的 6 条假阳全部证伪并修掉；
> 冒烟 [1]–[290] 全绿（1,7xx 项断言）；doctor 12/12 PASS；实盘两仓 755 个入口 sqli True 由 11 → 0。

## 一、先开箱验鱼：13:39 那轮 A=11 逐条核验

| # | 候选 | 结论 | 证据 |
| --- | --- | --- | --- |
| 1 | codex-lb sqli `list_api_keys` | **假阳** | `repository.py:1754` 用 `AutomationJob.id.ilike(like)` —— SQLAlchemy 绑定参数，值不进 SQL 文本 |
| 2 | codex-lb sqli `list_automation_filter_options` | **假阳** | 同上，`_build_job_conditions` 全是 `== / .in_() / .ilike()` |
| 3 | xianyu sqli `get_agree_deliver_config` | **假阳** | `select(XYAccount).where(*conditions)` + `session.execute(stmt)`，ORM 语句对象 |
| 4–5 | xianyu sqli `health_check` ×2 | **假阳** | 实码是 `@app.get("/health")` + `conn.execute(text("SELECT 1"))`，常量 SQL 且入口无参 |
| 6 | xianyu sqli `upload_image` | **假阳** | 切片把 `listing_monitor_service.get()` 的 `session.execute(stmt)` 带进来，入口根本没调它；该文件全链路无 SQL |
| 7–8 | xianyu log_injection `upload_image` / Kokoro `download_audio_file` | **真但低危** | `logger.info(f"...filename={image.filename}")` 与 `logger.warning(f"...{filename}")`：CWE-117 日志伪造，需 CRLF 可控；CVSS 低，不足以单独交单 |
| 9–11 | sz-boot-parent xss ×3（`updateGenerator` / `updateContact` / `updateProfile`） | **待人工** | 都是写接口（PUT）+ `@SaCheckPermission`，是否有存储型 XSS 取决于前端渲染是否转义，规则层拿不到证据 → NEEDS_HUMAN，不当首杀交单 |

结论：**没有新的可直接交单 P0**；第 3 单仍是 metasfresh（等 11-02 / 11-06 的通道节点）。

## 二、M301：Python SQLi 判据收口（根因四条，不是打补丁）

| 根因 | 修法 |
| --- | --- |
| `text("SELECT 1")` 被当字符串拼接 | 新增 `_py_text_wrapper_inner()`：`(sa./sqlalchemy.)text(...)` 整串包装就剥开递归判内层——字面量→False，f-string→True |
| `session.execute(stmt)` 里 `stmt = select(...)` 判成注入 | 新增 `_py_orm_expr()`：直接构造 / 变量持有（含 PEP 8 折行）/ `.where/.limit/.offset` 链式追加 / `self._xxx_stmt(...)` 构造器 → 都是 SQLAlchemy 语句对象（绑定参数），永不携带 SQL 文本 |
| 裸标识符"找不到赋值就 return True" | `_py_interp_text_capable()` 增加 `pos`：按 **sink 所在函数**找局部赋值（旧实现只看入口区域，Hop 段看不见）；仍找不到时只认 `def` 的**真实形参**（排除 self/cls/db/session/conn/file 与全大写常量），其余 None |
| 跨跳证据未归属 | 新增 `_py_sink_reachable()`：从入口出发沿 Hop 段做**传递闭包**（`do_key_create → keygen → login`），未被入口调用的辅助函数里的 sink 不进证据链 |
| 无参入口 | 新增 `_py_entry_has_no_input()`：入口既无请求形参、也不读 `request` → 直接 False（health_check 这类） |

## 三、M302：兜底与选靶

- `wild_noise.NO_SQL_SINK`：Python sqli 但入口文件里一个 `.execute/.executemany/.executescript` 都没有 → 板块 B（跨跳污染的最后一道闸，宁可 B 不漏 A）；
- `target_scout` 工具词补 `testcontainers`。

## 四、验证

| 项 | 结果 |
| --- | --- |
| 真实切片回归 | xianyu-auto-reply 554 入口：sqli True **5 → 0**；codex-lb 201 入口：**2 → 0** |
| 真阳不丢 | `text(f"...{name}")`、`"..." + uid`、`.format(username)`、多跳 `do_key_create→keygen→login` 全部仍 True |
| `benchmark_vulpy --strict` | PASS（多跳 sqli 一度被新归属规则误杀，改成传递闭包后恢复） |
| pygoat / djangoat / flaskr / fastapi_rw / flasky / flask_admin / fastapi_fullstack / django_rw / flask_rw --strict | 全 PASS |
| `smoke_test_chains.py` | PASS ✔ **1,725 项**（新增 [289] 判据三态 19 项 / [290] NO_SQL_SINK + testcontainers） |
| `cli.py doctor` | PASS（12 段全绿） |

## 五、遗留

1. `LIVE_HUNT_REPORT.md` 仍是 13:39 的快照（A=11 里那 6 条假阳已在本版修掉，下次 daily-hunt 重扫会自动消失）；未回填改写历史快照。
2. `NO_SQL_SINK` 偏保守：入口文件无 SQL 但经 import 的 dao 才有 sink 的真多跳，会被压进 B（不会丢，只是需要人工复核捞回）。
3. sz-boot-parent 三条 xss 需要前端渲染证据才能定性，建议放到「存储型 XSS 需要 sink 端证据」的下一批。
