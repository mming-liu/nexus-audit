# STAGE REPORT · v1.5.6（M371–M374：Python SQLi 假阳清零 + 重扫验证）

> 日期：2026-11-14 ｜ 基线：v1.5.5（16565c4）
> 结论：上一轮 9 条板块 A 假阳**全部清零**（重扫 A=9 → 3），剩余 3 条是
> `unrestricted_upload`，逐条精核后 1 条已由规则修复、2 条属"无后缀白名单"
> 的加固缺口（有鉴权 + attachment 下载，不构成可利用的 CWE-434）。

## 一、M371：不再把任意函数调用当透传包装

`_py_value_text_capable()` 末尾的 `re.match(r"[\w.]+\s*\(", e)` 会把
`quote_sqlite_ident(table)` 剥壳成 `table` 判 True。现在：

| 调用形态 | 判定 |
|---|---|
| 名字含 `sql` / `ident` / `quote` 的转义/白名单函数 | **False** |
| `str()` / `repr()` / `format()` | 剥壳看实参（透传） |
| 其余未知函数 | **None**（与 Java `_concat_only_sanitized` 同口径） |

## 二、M372：ORM 语句识别 + 入口级 NO_SQL_SINK

1. `_py_assignments()` 支持带类型注解的赋值（`stmt: Select = select(...)`）；
2. `_py_orm_expr()` 识别 `.where/.filter/.filter_by/.in_/.join/...` 链式语句对象
   （含 `text(` 的除外）；
3. 新增 `_py_param_receives_orm()`：`_fetch_batch(stmt)` 里的 `stmt` 在调用点
   收到的是 `stmt.where(...)` 时按 ORM 处理（fojin 三个导出接口）；
4. 新增 `python_entry_sql_sink()`：`NO_SQL_SINK` 从"整份文件有没有 `.execute`"
   收紧到"入口函数体 + 其可达辅助函数"（apowerb `list_skills` / `list_tool_configs`）；
5. `mass_assignment`：`Model(**payload)` 的 `payload` 必须来自 `request.*`
   或本身是入口形参；DB 查询结果不再判批量赋值（MimirQ）。

## 三、M373：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,626 项**（+10：`[329]`） |
| `triage_fallbacks.py --check-floor` | 16/16 |
| `cli.py doctor` | PASS（死正则审计通过） |
| `.githooks/pre-push` | exit 0 |
| `benchmark_vulpy.py --strict` / `benchmark_pygoat.py --strict --offline` | exit 0（真洞不回归） |

`[329]` 覆盖：转义函数不判注入 / 未知函数不剥壳 / `str()` 仍判注入 /
注解 ORM 赋值 / 链式 where / 形参收到 ORM / 入口体无 SQL → NO_SQL_SINK /
入口可达辅助有 SQL → 不拦 / `**payload` 两种来源。

## 四、M374：重扫验证（8 仓，热缓存）

| 指标 | v1.5.5 重扫 | v1.5.6 重扫 |
|---|---|---|
| 板块 A | 9（全假阳） | **3** |
| 其中 SQLi / mass_assignment | 9 | **0** |
| 板块 B | 705 | 714 |
| dedup 调用 | 14 | 14 |

### 剩余 3 条（unrestricted_upload，apowerb）

| 入口 | 判定 | 依据 |
|---|---|---|
| `upload_csv` (`bi/data/upload_router.py:87`) | **假阳（已修规则）** | `extension not in SUPPORTED_EXTENSIONS` 是真白名单，旧正则只认 ALLOWED/SAFE/VALID → 补 `supported/accepted` 后判 False |
| `upload_file` (`routers/files.py:106`) | **加固缺口，不交单** | `os.path.basename` + `_contained_upload_path` 防穿越；无后缀白名单；下载端 `download_file` 需 Bearer+归属或 scoped token，且 `Content-Disposition: attachment` → 不构成可利用的 CWE-434 |
| `index_files` (`routers/rag/index_files.py:29`) | **加固缺口，不交单** | 文件名 `re.sub` 白名单字符 + 前导点替换 + 50MB 限制；无后缀白名单；落盘目录为 RAG 语料，无静态服务/执行面 |

建议下一轮（M375）：`unrestricted_upload` 判 True 前要求"可服务/可执行"
证据（静态挂载、`FileResponse`/`send_file` 内联、或落在 Web 根目录），
否则归 `UPLOAD_STORAGE_ONLY` 进 B 板。

## 五、提交

- `32cf475` — v1.5.6 规则修复（M371/M372）+ `[329]`
- 后续小提交 — `SUPPORTED_EXTENSIONS` 白名单常量名
