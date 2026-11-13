# 2026-11-13 重扫复核（v1.5.5 后，8 仓）

> 命令：`python cli.py daily-hunt --repos <8 仓> --max-roots 5 --cooldown-days 0 --state .tmp/rescan_state_1113.json`
> 产物：[rescan_2026-11-13_report.md](rescan_2026-11-13_report.md)（原始 JSON 在
> `.tmp/rescan_1113.json`，gitignored；未覆盖当日正式报告）
> 结论：**9 条板块 A 候选全部为假阳**，不进交单；705 条本地降噪进 B。

## 一、效率对比

| 指标 | 上午（v1.5.4 前） | 重扫（v1.5.5） |
|---|---|---|
| 实扫仓 | 10 | 8 |
| dedup 联网调用 | **515** | **14** |
| GitHub 403 | 171 | **0** |
| 板块 A | 0 | 9（全部假阳） |
| 耗时 | 82 分钟 | ~17 分钟（8 个仓全是冷克隆；热缓存复跑约 3–5 分钟） |

M367 生效：705 条裸 authz / 低危项在**联网前**直接进 B，0 次请求。

## 二、9 条 A 候选逐条精核

| # | 仓库 | 类目 | 入口 | 判定 | 依据 |
|---|---|---|---|---|---|
| 1 | MimirQ | mass_assignment | `preview_dataset_table` (`app/api/v1/dataset_tables.py:924`) | **假阳** | 只读 GET；`get_tenant_id` + `get_current_account_id` 双依赖；SQL 仅 `SELECT * FROM {quote_sqlite_ident(...)}`，标识符白名单 + 值参数化 |
| 2 | apowerb | sqli | `export_skill` (`src/apowerb/routers/skills.py:268`) | **假阳** | SQLAlchemy Core `t.select().where(t.c.skill_id == skill_id, t.c.organization_id == ...)`，全绑定参数 |
| 3 | apowerb | sqli | `get_skill` (`skills.py:354`) | **假阳** | 同上 |
| 4 | apowerb | sqli | `list_skills` (`skills.py:44`) | **假阳** | 函数体内**没有任何 SQL**，只是 `list_all_skills(organization_id=...)` |
| 5 | apowerb | sqli | `get_tool_configs` (`tools.py:97`) | **假阳** | `fetch_tool_configs(tool_config_id=..., owner_id=current_user.email)`，按 owner 绑定 |
| 6 | apowerb | sqli | `list_tool_configs` (`tools.py:83`) | **假阳** | 无 SQL，`list_user_tool_configs(user_id=current_user.email)` |
| 7 | fojin | sqli | `export_kg_json` (`backend/app/api/exports.py:113`) | **假阳** | `select(KGEntity).where(KGEntity.entity_type == entity_type)`，ORM 参数化 |
| 8 | fojin | sqli | `export_kg_jsonld` (`exports.py:202`) | **假阳** | 同上 |
| 9 | fojin | sqli | `export_metadata_csv` (`exports.py:58`) | **假阳** | `select(BuddhistText).where(BuddhistText.dynasty == dynasty)` 等，全参数化 |

## 三、根因：sqli 规则不认 SQLAlchemy

9 条全是 `sqli` / `mass_assignment` 被 **SQLAlchemy ORM/Core 写法**触发：

- `select(Model).where(Model.col == param)`、`table.select().where(t.c.col == param)`
  是**绑定参数**，规则层却按"拼接"处理；
- `list_skills` / `list_tool_configs` 体内根本没有 SQL，仍被判 sqli ——
  说明切片把同文件/同模块的 SQL 语句贴进了入口（NO_SQL_SINK 只在
  "整个文件无 .execute" 时才拦，这里文件里有 `.execute`，所以漏过）。

这是下一轮该修的判据（建议 M371）：
1. `sqli_verdict` 识别 `select(...).where(... == 参数)` / `t.c.x == v` /
   `Model.col.in_(...)` 为参数化，不判 True；
2. 入口体内**没有** SQL 字面量/SQL 执行调用时，不因切片里的兄弟函数判 sqli
   （把 NO_SQL_SINK 从"文件级"收紧到"入口级"）。

## 四、B 板构成（705 条）

| 噪声码 | 数量 | 说明 |
|---|---|---|
| `UNVERIFIED_WILD_AUTHZ` | **667** | 无兄弟鉴权反差的裸 authz，M367 本地拦截 |
| `LOW_SEVERITY_LOG_INJECTION` | **29** | CWE-117 低危 |
| `NO_SQL_SINK` | **9** | 入口文件无 SQL 执行语句 |
| （板块 A） | 9 | 见上表，全部假阳 |

按仓：MimirQ 374 / caura 183 / backlot 48 / fojin 41 / apowerb 31 /
eidolon-sc 13 / fim-one 13 / docling-Studio 11。
