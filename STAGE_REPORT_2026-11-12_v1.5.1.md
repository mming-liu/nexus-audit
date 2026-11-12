# STAGE REPORT · v1.5.1（M357–M360：redcell WS 精核 + 四个结构缺口）

> 日期：2026-11-12 ｜ 基线：v1.5.0（6a55506）
> 结论：redcell 5 条 WebSocket authz **全部误报**（鉴权存在），不交单；
> 三引号示例误切、查重证据缺口、同仓 loopback 撕裂、完成时间戳偏差四处
> 结构性问题一次修掉；门禁 1,583 项 PASS。

## 一、M357：redcell WebSocket 路由人工精核

**结论：5 条全部误报，不交单。** 详见
[benchmarks/results/redcell_ws_review_2026-11-12.md](benchmarks/results/redcell_ws_review_2026-11-12.md)。

| 路由 | 定义行 | 鉴权 | `accept()` 前？ | 判定 |
|---|---|---|---|---|
| `ws_events` | 59 | `_authed(ws)` → 4401 | 是 | 误报 |
| `ws_chat` | 68 | `_authed(ws)` → 4401 | 是 | 误报 |
| `ws_notifications` | 77 | `_authed(ws)` → 4401 | 是 | 误报 |
| **`ws_shell`** | **86** | **`_authed(ws)` → 4401** | **是** | **误报** |
| `ws_browser` | 137 | `_authed` + session 归属 | 是 | 误报 |
| `ws_device` | 200 | `_authed` + session 归属 | 是 | 误报 |

关键事实：

1. `_authed()` 校验 `rc_session` Cookie 的 JWT（HS256，`settings.jwt_secret`）；
   密钥在生产环境**强制非空**（`config.py:98-128`），compose 用
   `secrets.token_urlsafe(48)` 生成，不存在默认弱密钥。
2. API 容器**不发布宿主机端口**，只经 Caddy `handle /api/* → api:8080` 暴露；
   宿主机只开 80/443。
3. `ws_shell` 只订阅 `shell:{id}` 输出；输入走 HTTP
   `POST /shells/{id}/write`（router 级 `Depends(current_user)`）；命令在
   worker 的 `redcell-opsh` 容器（或 SSH VPS）里执行 —— 链路第一环就需要
   合法会话。

残余观察（不作为漏洞）：`_authed` 不校验用户是否仍存在；`ws_shell` 不校验
shell 归属（当前单管理员单租户）。已写入复核文档第 6 节。

## 二、M358：三引号字符串遮蔽 + 语料目录/安全工具过滤

AutoCVE 的 `knowledge/frameworks/fastapi.py:57`、`flask.py:51` 把漏洞示例
（`@app.get(...)` + `def get_file(...)`）整段写在 docstring 里。旧实现直接对
全文跑 `DEF_RE` / `ROUTE_DECORATOR_RE`，示例代码被切成"路由"，同一行同时
命中 `hardcoded_secret` / `jwt_weakness` / `sqli` 三个类目。

| 改动 | 位置 |
|---|---|
| 新增 `_mask_multiline_strings()`：`"""…"""` / `'''…'''` 内部除 `\n` 外全部换成空格，**逐字符保长**，行号零偏移 | `core/context/symbol_indexer.py` |
| `_index_definitions` 的 `DEF_RE` / `ROUTE_DECORATOR_RE` / `_BARE_DECORATOR_RE` 全部改跑遮蔽文本；函数体仍按原行切 | 同上 |
| `IGNORE_DIRS += knowledge / prompts / corpus` | `core/context/symbol_indexer.py`、`core/slicer/java_servlet.py` |
| `_TOOL_LIB_RE += autocve / vuln-scanner / pentest / exploit-db / honeypot` | `core/context/target_scout.py` |

## 三、M359：查重证据门禁 / 仓级 loopback / 时间戳

### 3.1 `cve_dedup.py`

| 改动 | 行为 |
|---|---|
| 泛化方法名判定扩展 | `get_file` / `get_user` 这类「动词_名词」也算泛化（camelCase 仍精确搜索） |
| 退化检索 | 泛化方法名 + 非泛化文件名（且不在 `fastapi/flask/django/views/routes/api/app/main/index`）→ 搜 `"<repo>" "<file_stem>"`，不再直接 `skipped_generic` |
| `evidence_complete` / `evidence_gaps` | 六来源逐一核对；NVD 熔断、全网 Issue 跳过等逐条入 gaps |
| **板块 A 放行条件** | NVD 未查成时先**单独补查一次**（进程级预算 3 次）；查到 CVE 判重，仍失败则 `UNKNOWN` + `reason="INCOMPLETE_DEDUP_EVIDENCE: nvd_circuit_open"` 压 B |
| 缓存回填 | 旧缓存缺 `evidence_*` 时按同一口径回填；缓存里的"NVD 熔断 FRESH"读时降级 |

### 3.2 `wild_noise.py`：同仓 loopback 继承

新增 `_repo_loopback_only()`：扫主服务入口的 `uvicorn.run/app.run(host="127.0.0.1")`
或全局 `LocalAccessMiddleware`；只要仓内出现 `host="0.0.0.0"`、Dockerfile
`--host/--bind 0.0.0.0`、compose 裸端口映射，就不判整仓回环（宁可漏拦，不放
真远程服务）。命中后同仓子路由继承 `LOCAL_LOOPBACK_ONLY`，消除"server.py 进 B、
dashboard/app.py 进 A"的分类撕裂。

### 3.3 `daily_hunt.py`

- 本地降噪短路记录统一写 `coverage={"checked": [], "failed": [],
  "skipped": ["local_noise_shortcircuit"]}`（抽成 `noise_record()`，可单测）。
- `daily_meta` 新增 `started_at`，`generated_at` 改为**完成时刻**
  （`finished = _now()`），报告时间戳不再比实际完成早 10 分钟。

## 四、M360：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py`（`NEXUS_RULE_ONLY=1`） | **PASS ✔ 1,583 项**（+19：`[322]` 7 项 + `[323]` 12 项） |
| `triage_fallbacks.py --check-floor` | **16/16 地板达标 ✔** |
| `cli.py doctor` | **PASS（12 段全绿）** |

新增断言覆盖：遮蔽保长/保行、示例函数不进符号表、真实函数行号零偏移与
装饰器保留；NVD 熔断不放行 FRESH、补查成功仍可判 FRESH、泛化方法名回退
文件名搜索、框架同名文件不退化、仓级 loopback 继承、公网绑定不继承、
`started_at <= generated_at`、短路 coverage 结构。

## 五、已知边界

1. NVD 补查是**进程级预算 3 次**：熔断期间第 4 个及以后的候选直接
   `INCOMPLETE_DEDUP_EVIDENCE` 压 B（不逐条撞 8s 超时）。
2. 仓级 loopback 只认**显式**回环绑定；`gunicorn app:app`（未写 `--bind`）
   这类"默认值绑定"不推断，避免误杀。
3. `evidence_complete=False` 也可能出现在 DUPLICATE 记录上（短路后其余来源
   未查），它描述的是证据覆盖度，不是结论正确性。

## 六、下一步

- 观察一轮 daily-hunt：确认 A 板不再出现 `knowledge/` 下的示例根因、
  不再出现"NVD 熔断却判 FRESH"的条目。
- 可选：把 `_authed` 的 WebSocket 鉴权识别做成 `wild_noise` 规则
  （`WS_AUTH_PRESENT`），让 redcell 这类误报在扫描阶段就归 B 并标注原因。
