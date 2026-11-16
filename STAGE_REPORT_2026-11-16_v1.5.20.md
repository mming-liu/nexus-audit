# STAGE REPORT · v1.5.20（M427–M430：巡猎快照 / 9+3 条假阳清零 / 行号归属 / dify SSRF 归档 / 09:00 调度排查）

> 日期：2026-11-16 ｜ 基线：v1.5.19（`50f0819`）
> 主题：巡猎报告与 JSON 按 run 留不可变快照；清零 M426 的 3 类 9 条假阳
> （并附带清掉复扫暴露的 3 条）；修复根因 `line` 行号归属错位；归档
> `07_dify_for_dsl.md`；排查 09:00 定时巡猎未产出原因。
> 结论：3 仓复扫 **A 11 → 2**（只剩 `jm_image` 未授权 SSRF）；
> 门禁 smoke 1,783 / triage 16/16 / doctor PASS；09:00 调度**实际已投递**
> 并运行了会话，是执行会话主动选择"不重跑"，不是调度/阻塞进程故障。

## 一、M427：巡猎产出按 run 留不可变快照

`core/context/daily_hunt.py`：

- 新增参数 `runs_dir: Path | str | None = None`；默认
  `report.parent / "benchmarks/results/daily_hunt_runs"`；
- 每次非 dry-run 成功写主报告/JSON 后，按 `started` 生成
  `run_id = 20261116_224558`（同秒冲突追加 `_2`），复制两份快照：
  `{run_id}_LIVE_HUNT_REPORT.md` / `{run_id}_daily_hunt.json`；
- 只保留最近 **30 份**（report+json 成对删除）；
- `daily_meta["run_snapshot"]` 写入快照路径，JSON 与返回值同源；
- `[343]` 用临时 `runs_dir` 连跑两轮，验证 2 份独立快照互不覆盖。

这样开发/发版顺手跑 `daily-hunt` 只会覆盖主报告，09:00 定时产出仍可从
`daily_hunt_runs/` 追溯。

## 二、M428：3 类 9 条假阳 + 复扫暴露的 3 条

### 1. `mass_assignment` 排除输入校验模型

`mass_assignment_verdict()` 命中 `Cls(**request.data)` 时，若类名以
`Input/Schema/DTO/Dto/Request/Query/Payload/Filter/Params/Serializer`
结尾，或切片内有 `class Cls(BaseModel` / `@dataclass` 定义 → `False`；
`User.objects.create(**request.data)` 通过新增 `_MASS_PY_ORM_RE` 仍判 `True`。

### 2. JAX-RS JSON 与测试夹具

- `xss_verdict()` 的 `_rest_json` 增加
  `@Produces(...APPLICATION_JSON)`（且无 `TEXT_HTML`）信号；
- `wild_noise` 新增 `TEST_FIXTURE_ONLY`，对
  `tests-common|test-fixtures|fixtures|integration-tests` 路径直接拦截。

### 3. 配置变量 SSRF

`_config_rhs()` 增加"配置变量 + 字面量 / f-string 前缀"识别；
`_url_var_is_config()` 增加 `*_api_url` / `*_api_base` / `*_base_url`
以及裸 `*url/*uri`（切片内无赋值、非形参）的配置约定。
`siliconflow_api_url` / `video_api_base` / `audiourl` → `False`；
`request1.image_generation_url` → 仍 `True`。

### 4. 复扫暴露的 3 条附带假阳（M430 复扫时发现并一并修复）

| 根因 | 代码 | 修复 |
|---|---|---|
| `generate_audio` ssrf | `dsl/difyforgitee/giteeapiforall.py:206` `requests.post(audiourl)`，`audiourl = config.get(...)` 不在切片 | 裸 `*url` 配置约定 |
| `delete_audio` arbitrary_file_delete | `py/yewu2edgetts/app.py:588` `os.remove(f"static/audio/{audio_id}")`，路由 `{audio_id}` 单段 | 单段路径参数豁免（Java `_single_segment_pathvar_params` + Python `// Route:` 占位符） |
| `update_prompt` pathtraver | `py/yewu2videoaddsrt/app.py:325` `open(ROOT_DIR + "/prompt.json", 'w')` 常量路径 | `open()/send_file()` 实参 taint 判定（复合表达式逐标识符回溯） |

## 三、M429：根因 `line` 行号归属修复

**根因**：`upstream_sync.verify_unit_alive_on_head()` 把
`SIEMKeywordSearchView.post` 拆成 `name="post"` 后在**整个文件**里找
`post(`，命中的是文件里第一个 `post`（`CommentView.post`，343 行）。

**修复**：新增 `_class_span()`，`_method_span(..., cls=...)` 先缩到类体
（Python 按缩进、Java/TS 按花括号）再找方法；`verify_unit_alive_on_head()`
从 `unit_name` 取 `Class.method` 的类名。

验证：

| 单元 | 修复前 | 修复后 |
|---|---|---|
| `SIEMKeywordSearchView.post` | 343 | **506** |
| `SIEMAdaptiveQueryView.post` | 343 | **518** |
| `SIEMDiscoverFieldsView.post` | 343 | **530** |
| `SIEMSPLQueryView.post` | 343 | **542** |
| `SIEMESQLQueryView.post` | 343 | **551** |

复扫 A 记录的 `line` 也回到真实方法行（`jm_image` 242 / 25）。

## 四、M429：`cve_submission_kit/07_dify_for_dsl.md`

- 归属核验：`py/geekaiapp/` 由本仓作者 `zhouhui` 于 2025-07-31 首次提交
  （`c0463eb`），文件头无第三方版权声明，README 为作者自研 DSL 合集 →
  **不是搬运的第三方项目**；
- 记录 `g_jiekou.py:242-257` 与 `wenshengtu1/jm1_jiekou.py:25` 的源码行号、
  同仓 `generate_video` 的 `Depends(verify_auth_token)` 反差；
- 附最小防御 Unified Diff：补 `Depends(verify_auth_token)` +
  `urllib.parse` / `ipaddress` 拒绝私有/回环/链路本地地址与非 http(s) 协议；
- `cve_submission_kit/README.md` 新增第 7 行（状态：待用户决定是否提交）。

## 五、M430：门禁 + 3 仓复扫 + 09:00 调度排查

### 1. 门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,783 项断言**（v1.5.19 为 1,775；`[343]` 8 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

### 2. 3 仓离线复扫（临时空 state，`--max-roots 5`）

```
python cli.py daily-hunt --repos FunnyWolf/agentic-soc-platform,wwwzhouhui/dify-for-dsl,wso2/product-apim \
  --offline --cooldown-days 0 --max-roots 5 --state .tmp/m430d_state.json \
  --report .tmp/m430d_LIVE_HUNT_REPORT.md --json .tmp/m430d_daily_hunt.json \
  --packs-dir .tmp/m430d_packs --repo-timeout 300
```

| 轮次 | 根因 | 板块 A | 板块 B |
|---|---|---|---|
| v1.5.19 巡猎 | 173 | **11** | 162 |
| v1.5.20 复扫 | 40 | **2** | 38 |

A 板仅剩：

```
dify-for-dsl  ssrf  jm_image  py/geekaiapp/g_jiekou.py:242
dify-for-dsl  ssrf  jm_image  py/geekaiapp/wenshengtu1/jm1_jiekou.py:25
```

9 条假阳（5 mass_assignment + 3 配置 SSRF + 1 测试夹具 xss）全部清零；
复扫额外暴露的 3 条（`generate_audio` / `delete_audio` / `update_prompt`）
也已清零。

### 3. 09:00 定时巡猎未产出排查

| 检查项 | 结果 |
|---|---|
| 调度任务状态 | `schedule-b915b2aa-…` **active** |
| 最近投递 | `lastDelivery.scheduledAt = 2026-11-16T01:00:00Z`（= **09:00:00 +08**），`deliveredAt` 同一时刻 |
| 目标会话 | `session-3369aaef-…` 转录文件写入 **09:03:41**，turn 5 完整执行 |
| 报告/JSON | 仍是 **08:08:48**（M426 那轮），09:00–10:00 无任何 `last_scanned_at` 更新 |
| 阻塞进程 | 未发现；09:00 前后无 daily-hunt 扫描、无锁文件残留 |

**结论**：调度**没有故障**，09:00 消息已投递且会话已运行；是执行会话在
读到 `LIVE_HUNT_REPORT.md` 的"生成时间 2026-11-16 08:08"后，判断"已是
今日报告"而**主动选择不重跑**（转录原文："未重跑的理由：报告生成于今天
08:08（已是今日本轮，虽早于 09:00）… 再跑会因 90 天去重把 173 条/11 条 A
覆盖成近乎空报告"）。

**建议**（未改调度，待你拍板）：

1. 把定时任务 prompt 的新鲜度条件从"今天"收紧为
   `generated_at >= 今天 09:00`（或"存在今天 09:00 之后的 run 快照"）；
2. M427 的快照目录可直接作为"09:00 是否跑过"的判据：
   `daily_hunt_runs/*_LIVE_HUNT_REPORT.md` 中是否有今天 09:00 之后的文件；
3. 若担心 90 天去重导致"空报告"，可在 prompt 中允许 `--days 21` 或
   `--max-roots 5` 的兜底重跑，而不是直接跳过。

## 六、已知边界

1. **复扫用 `--max-roots 5` 才对齐 11 条**：`--max-roots 0` 会多暴露
   `generate_audio` / `delete_audio` / `update_prompt` 等根因（本轮已一并
   修复）；后续复扫建议固定与巡猎相同的 `max-roots`。
2. **配置变量启发式**：裸 `*url/*uri` 且切片内无赋值才视为配置；若某项目
   把用户输入赋给这类变量且赋值不在切片里，理论上会漏报。
3. **`open()` taint 回溯**最多 3 跳，超过则保守判 tainted（不漏报）。
4. **dify-for-dsl 的 SSRF 仍是真实项**：本轮未对外提交，等第 7 号交单包
   拍板。

## 七、提交清单

- `core/context/daily_hunt.py` — M427 快照归档（run_id / 30 份清理 / daily_meta）
- `core/agents/rule_detectors.py` — M428 DTO/JAX-RS/配置 SSRF + M430 三条附带修复
- `core/context/wild_noise.py` — M428 `TEST_FIXTURE_ONLY`
- `core/context/upstream_sync.py` — M429 类体限定方法行号
- `benchmarks/smoke_test_chains.py` — M430 `[343]` 8 项
- `cve_submission_kit/07_dify_for_dsl.md` + `README.md` — 第 7 号交单包
- `STAGE_REPORT_2026-11-16_v1.5.20.md` — 本报告
