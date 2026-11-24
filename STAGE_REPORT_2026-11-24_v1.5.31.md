# STAGE REPORT · v1.5.31（M471–M474：模板占位符 / safe_join / 服务端重命名上传 + Maestro & tubecli 白盒精核 + 11-24 披露复查）

> 日期：2026-11-24 ｜ 基线：v1.5.30（`b67c3f6`，巡猎产物快照 `352a00d`）+
> 11-24 披露跟进文档 `0f0ba0c`（已推送）
> 主题：清零 11-23 A 板 5 条假阳/低危（tubecli `hardcoded_secret` ×2、Maestro
> `arbitrary_file_delete` ×1、Maestro `upload_image` ×2）；对 Maestro
> `import_style` 加载链与 tubecli 4 条认证后 SSRF 做逐行白盒精核；按
> `FOLLOWUP_2026-11-21.md` 完成 11-24 满 7 天只读复查（本轮 0 发送）；新增门禁 `[354]`。
> 结论：smoke **1,851** 项断言 PASS / triage **16/16** / doctor PASS；
> 两仓离线复扫 A 板 **6 → 1**（5 条清零，`import_style` 保留观察）；
> 披露侧草稿 A/B 已经用户批准于 11-24 22:17/22:18 发出（评论 ID
> `396175` / `7134160570`），24h 观察窗至 11-25 22:17。

## 〇、背景（11-23 / 11-24 两次实盘）

| 轮次 | 起止（+08） | 耗时 | 候选 / 处理 / 实扫 / 跳过 / 失败 | 根因 | A | B |
|---|---|---|---|---|---|---|
| 11-23 09:00 | 09:01:07 → 09:10:22 | 9.25 min | 6 / 6 / 6 / 0 / 0 | 455 | **6** | 449 |
| 11-24 09:00 | 09:00:51 → 09:12:45 | 11.9 min | 22 / 10 / 6 / 4 / 0 | 284 | **9** | 275 |

- 11-23 首次在生产验证 M467 的候选口径：报告头 `候选仓：6`、JSON
  `candidates=6 / processed=6`，两处完全对齐；`daily_hunt_runs/20261123_090107_*`
  不可变快照与主报告逐字一致。
- 11-24 报告头按新口径写成 `候选仓：22（已处理 10）`，与 JSON
  `candidates=22 / processed=10` 同源；`DUPLICATE_CVE 4`。
- **本轮修复对象是 11-23 的 6 条 A**（11-24 的 9 条是新批次，见第五节遗留）：

| # | 仓库 | 类目 | 根因 | 处理方式 |
|---|---|---|---|---|
| 1 | Maestro | arbitrary_file_delete | `delete_output`（`app/launch.py:32242`） | M471-2 规则层清零 |
| 2 | Maestro | unrestricted_upload | `import_style`（`app/services/music_training_api.py:238`） | **保留 A**，M473-1 白盒精核 |
| 3 | Maestro | unrestricted_upload | `upload_image`（`app/launch.py:32333`） | M472 降噪归 B |
| 4 | Maestro | unrestricted_upload | `upload_image`（`app/models/wan/trajectory_editor/app.py:79`） | M472 降噪归 B |
| 5 | tubecli | hardcoded_secret | `ai_generate_script`（`script_routes.py:1030`） | M471-1 规则层清零 |
| 6 | tubecli | hardcoded_secret | `chat_with_script`（`script_routes.py:1216`） | M471-1 规则层清零 |

## 一、M471：模板占位符与 `safe_join` 守卫（`core/agents/rule_detectors.py`）

### 1. `hardcoded_secret` 排除模板占位符 / 代码片段

`hardcoded_secret_verdict()` 仍按「密钥型变量名 + 字符串字面量」判据，但字面量
现在先过 `_secret_placeholder()`：

```python
_SECRET_TEMPLATE_RE = re.compile(
    r"\{\{|\}\}"                      # Jinja / str.format 双花括号
    r"|\$\{"                          # shell / 模板插值
    r"|\{[A-Za-z_][\w.]*\}"           # 单花括号 {var}
    r"|%[sd]"                         # printf / format 占位符
    r"|<[^<>]{0,40}>"                 # <your_key_here>
    r"|[\w.]\($")                     # 以「函数名(」结尾的代码片段
```

`SECRET_PLACEHOLDER_RE` 同时补 `changeme` 与 `\bx{3,}\b`。

实测（tubecli `script_routes.py` 真实切片）：

| 切片 | 旧 | 新 | 命中值 |
|---|---|---|---|
| `ai_generate_script` | True | **False** | `{{{{totp_secret}}}}`（f-string 模板） |
| `chat_with_script` | True | **False** | `+encodeURIComponent(`（JS 拼接片段） |

> **首版回归与修复**：第一版把 `[()]` 直接放进占位符正则，结果 DjanGoat 的真实
> Django 密钥 `SECRET_KEY = '+f0x#go-9e-qd(mq0pdn9ma*ls!...'`（值里含左括号）
> 被判成占位符，`benchmarks/results/djangoat.json` 的 `correct 15 → 14`，
> `doctor` 的白皮书对账门禁立刻转红（smoke 6 项 doctor 断言全挂）。
> 改为「只排除以 `函数名(` 结尾的片段」后恢复 15/15 —— 门禁按设计拦下了一次
> 静默漏报。

### 2. `arbitrary_file_delete` 补齐 `safe_join` 系列守卫

```python
_FILE_DELETE_SAFE_RE = re.compile(
    ... r"|_?safe_(?:path_?)?join\s*\(")
```

覆盖 Werkzeug/Flask 的 `safe_join` 与项目自定义 `_safe_join`。Maestro 的
`delete_output` 正是先 `_safe_join(out_dir, name)`、返回 None 时直接 400：

```python
filepath = _safe_join(out_dir, name)
if filepath is None:
    raise HTTPException(status_code=400, detail="Invalid filename")
...
result = safe_delete(filepath)
```

| 切片 | 旧 | 新 |
|---|---|---|
| Maestro `delete_output` | True | **False** |

## 二、M472：服务端重写落盘名 / 重编码上传归 B（`core/context/wild_noise.py`）

`classify()` 的 `unrestricted_upload` 分支在原有「已防穿越 / 扩展名白名单」之外，
新增一类**落盘名归属**证据（`_upload_entry_text()` 只取入口自身函数体，避免把
Hop 里无关的 `uuid4()` 算到当前入口头上）：

```python
_UPLOAD_SERVER_INDEX_NAME_RE = re.compile(
    r"f[\"']\{[^}]{0,60}:\s*0?\d*d\s*\}[^\"']*[\"']")   # f"{idx:02d}.{ext}"
_UPLOAD_REENCODE_RE = re.compile(r"\bImage\s*\.\s*open\s*\(", re.I)  # PIL 解码→重编码
_MODEL_WEIGHT_UPLOAD_RE = re.compile(
    r"(?i)(?:import_style|read_upstream_adapter|upstream_adapter|load_model"
    r"|\badapter\b|checkpoint|\.ckpt|\.safetensors|torch\.load|pickle\.load"
    r"|weights_only|model_path)")                        # 模型/权重加载面：不降噪
```

命中「服务端重写落盘名 / 序号名 / 图片重编码」且全仓无静态上传挂载、且入口不
涉及模型权重加载时，归 `NON_EXECUTABLE_UPLOAD` 压 B；`_MODEL_WEIGHT_UPLOAD_RE`
命中则显式放行（`import_style` 继续留在 A 板等白盒结论）。

实测（Maestro 真实切片）：

| 切片 | 旧 | 新 |
|---|---|---|
| `app/launch.py` `upload_image`（`f"{uuid.uuid4().hex[:8]}{ext}"`） | A | **B**（`NON_EXECUTABLE_UPLOAD`） |
| `trajectory_editor/app.py` `upload_image`（`f"{idx:02d}.{ext}"` + `Image.open`/`save`） | A | **B**（`NON_EXECUTABLE_UPLOAD`） |
| `music_training_api.py` `import_style` | A | **A（保留）** —— 见第三节 |

> **计划与实测的两处校正（如实记录）**：
> 1. `trajectory_editor` 的文件名不是 `uuid4`，而是服务端计数 `f"{idx:02d}.{ext}"`
>    （原始文件名只贡献扩展名），并先 `PIL.Image.open` 解码、再 `img.save`
>    重编码落盘 —— 因此规则同时接受「序号命名」与「图片重编码」两类证据；
> 2. Maestro 确有 `StaticFiles` 挂载，但只挂 `ui/dist`（`app/launch.py:33689`），
>    上传目录没有静态挂载；上传物由 `/api/v1/uploads/{filename}` 经
>    `_safe_join` + `mimetypes.guess_type` 提供（白盒核实），因此"无静态挂载"
>    这一前提成立、但"固定 media_type"的说法不准确（实际是猜 MIME + 仅在 owner
>    配置后追加 CSP/attachment）。

## 三、M473：两组白盒精核 + 11-24 满 7 天只读复查

### 1. Maestro `import_style` → `read_upstream_adapter`：**不是 RCE 真洞**（置信 0.9）

- 加载链：`app/services/music_training_api.py:239` 收 `ar`/`nar` 上传 →
  `tempfile.TemporaryDirectory` 内落盘（单文件 1 GiB / 整包 2 GiB 上限）→
  zip 分支只允许 3 个固定条目（`style.json` / `ar.safetensors` /
  `nar.safetensors`，不解压路径）→ `.pt` / `.safetensors` 后缀白名单 →
  `read_upstream_adapter()`。
- **没有任何代码执行 sink**：`app/models/TTS/yue2/artist_adapter.py:60`
  是 `torch.load(path, map_location="cpu", weights_only=True)`；
  `safetensors.torch.load_file` 非 pickle；全链无 `pickle.load`、
  `weights_only=False`、`exec/eval`、`numpy(allow_pickle=True)`、
  `extractall`。张量键集合/形状/秩/有限性另有严格校验
  （`artist_adapter.py:22-47`）。
- 暴露面：默认 `host = os.environ.get("SERVER_NAME", "127.0.0.1")`
  （`app/launch.py:33724`），仅回环；用户显式开 Pinokio `share local`
  （`PINOKIO_SHARE_LOCAL=true` → `0.0.0.0`）或 Tailscale Serve 时才可远程。
  应用层无路由级鉴权，`AccessBoundary` 对不带 `Authorization` 的"legacy
  browser"请求整体跳过校验（`app/services/agent_access/boundary.py:883-893`），
  `launch.py:375-378` 注释自认 "the API has no authentication"——但这是全 API
  的既有设计取舍，不是 `import_style` 引入的洞。
- **结论**：非 RCE（`weights_only=True`）；真实残留是"若用户把服务暴露到局域网/
  tailnet，则无鉴权写入样式库 + 最高 2 GiB 解析开销"。本轮保留 A 板观察，
  建议下一轮评估是否按"认证后/本地预期功能"降噪（或先给该写路径加 owner/同源
  校验）。

### 2. tubecli 4 条认证后 SSRF：**维持 `AUTHENTICATED_LOCAL_ONLY` 压 B**（置信 0.95+）

| 入口 | 出站 URL 来源 | 结论 |
|---|---|---|
| `list_models`（`extensions/chat/routes.py:347`） | 常量 `http://localhost:11434/api/tags` + 管理员配置的 9router `base_url + "/models"` | 非 SSRF，维持 B |
| `list_ai_models`（`extensions/webui/story_api.py:63`） | 同上（`httpx.get` 字面量 + `_nr.models_url()`） | 非 SSRF，维持 B |
| `list_ai_providers`（`browser_scripts/script_routes.py:271`） | `tubecli/config.py:79` 模块常量 `OLLAMA_BASE_URL` + 9router 配置 | 非 SSRF，维持 B |
| `api_refresh_fingerprint`（`extensions/browser/routes.py:282`） | 源码常量 `api.tubecreate.com` / `fingerprints.bablosoft.com`；`name` 只用于选 profile 目录 | 连"可控 URL"都没有，维持 B |

- 鉴权：`tubecli/api/server.py:522` 全局 `_require_login` 中间件覆盖全部路由，
  4 条都不在免鉴权白名单；单管理员模型（一个 `password_hash`），guest token
  默认拒绝且 `/api/v1/cloud`（唯一能改 `9router.base_url` 的入口）属
  `_SENSITIVE` 永不放行 —— **不存在低权限用户改 base_url 的路径**。
- 唯一"请求体 URL → requests"的同仓入口是
  `extensions/cloud_api/routes.py:153-181`（owner 专属"保存前测试 endpoint"，
  仅 `9router` provider、guest 被封死），不属这 4 条。
- 这 4 条与 11-23 的 A 板无关（本来就在 B）；本轮只确认降噪判断仍成立，
  未为此改规则。

### 3. 11-24 满 7 天披露只读复查（本轮 0 发送）

`FOLLOWUP_2026-11-24.md`（07:32–07:40 采集）逐项复核后，本轮 23:1x 再次只读
核对（`gh api` + CVE.org）：

| 对象 | 11-21 基线 | 11-24 实测（23:1x 复核） | 判定 |
|---|---|---|---|
| `GHSA-368h-5897-269p` | `triage` / 0 评论 | **`triage` / `accepted=false` / 评论 1 条（我方 `396175`，22:17:36 发出）**；`updated_at` 仍为创建时间 | 满 7 天零维护者回应 |
| `dify-for-dsl` #23 | open / 0 评论 | **open / 评论 1 条（我方 `7134160570`，22:18:21 发出）**；HEAD `10bb63a` 只改了 docs，`jm_image` 仍无 `Depends(verify_auth_token)` | 满 7 天漏洞未修、Issue 未被回复 |
| android-agent 仓库 | HEAD `8974838` | **HEAD `8974838`（11-14）/ 最新 release v1.6.0（11-14）/ 无新提交** | 未修 |
| 5 个上游 Issue | 全 open | metasfresh #27079（2 条均我方）、WorkFlow-Engine #4 / Network-Drive #2 / eladmin #926 / x-springboot #47（各 0 条）**全部 open、时间戳未变** | 已满 16 天（metasfresh 25 天）零回复 |
| 6 个 MITRE CAN | 无公开记录 | CVE.org `cveawg` 对 6 个编号仍 **404 not-public**（1 次网络抖动重试后同） | 待 8 分钟 token 查 `--status` |

- 发送记录（依 `FOLLOWUP_2026-11-24.md` 第七节，**已由用户批准**）：草稿 A
  （GHSA 评论）/ 草稿 B（dify #23 评论）于 11-24 22:17:36 / 22:18:21 (+08)
  发出，评论 ID `396175` / `7134160570`，已 GET 复核在线；**本轮不再发送任何
  评论/邮件**。
- 下一步：草稿 C（邮件 `security@ghostinthedroid.com`）等 A 满 24h
  （**2026-11-25 22:17 +08 之后**）仍无响应再决策，发送前仍需用户确认；
  CAN 实态待用户提供 8 分钟 token。
- `FOLLOWUP_2026-11-24.md` 已作为 `0f0ba0c` 提交并推送（内容含 07:32–07:40
  只读复查、22:17/22:18 经批准后的草稿 A/B 发送记录）；本轮 23:1x 复核是在该
  提交之上的**只读**确认，未再发送任何评论/邮件。

## 四、M474：门禁 `[354]` + 离线复扫 + 全套验证

### 1. `benchmarks/smoke_test_chains.py` 新增 `[354]`（9 项，纯离线）

| 断言 | 结果 |
|---|---|
| M471：prompt 模板 `{{totp_secret}}` 占位符不判 `hardcoded_secret` | ✅ |
| M471：真实长密钥字面量仍判 True（防放宽） | ✅ |
| M471：`${...}` / `<your_...>` 占位符不判 True | ✅ |
| M471：`_safe_join` 守卫 + None 拒绝后 `os.remove` 不判任意删除 | ✅ |
| M471：直接 `os.remove(请求路径)` 仍判 True（防放宽） | ✅ |
| M472：`uuid4` 重命名 + 无静态挂载 → `NON_EXECUTABLE_UPLOAD` | ✅ |
| M472：序号命名 + PIL 重编码 + 无静态挂载 → `NON_EXECUTABLE_UPLOAD` | ✅ |
| M472：模型适配器导入上传保留放行（不压 B） | ✅ |
| M472：静态挂载上传目录时不压 B（防放宽） | ✅ |

### 2. 两仓逐条重放（真实切片，当前代码）

| 11-23 A 记录 | 旧（实盘） | 新 | 去向 |
|---|---|---|---|
| Maestro `delete_output` | `arbitrary_file_delete` True | **False** | 规则层不再产根因 |
| Maestro `upload_image`（`launch.py`） | `unrestricted_upload` True | True + `NON_EXECUTABLE_UPLOAD` | 归 B |
| Maestro `upload_image`（`trajectory_editor`） | `unrestricted_upload` True | True + `NON_EXECUTABLE_UPLOAD` | 归 B |
| tubecli `ai_generate_script` | `hardcoded_secret` True | **False** | 规则层不再产根因 |
| tubecli `chat_with_script` | `hardcoded_secret` True | **False** | 规则层不再产根因 |
| Maestro `import_style` | True | True（未降噪） | **保留 A（白盒观察）** |

→ **5 条清零 / A 板 6 → 1**（唯一保留项为 `import_style`，见第三节结论）。

### 3. 两仓离线复扫（`daily_hunt.run(offline=True, dedup_online=False)`，空 state）

```text
summary: {"total": 325, "board_a": 0, "board_b": 325}
daily  : {"candidates": 2, "processed": 2, "scanned": 2, "skipped": 0,
          "failed": 0, "new_roots": 325, "board_a": 0, "blocked": 325}
Maestro: 95 根因（unrestricted_upload 4 / ssrf / zip_slip / log_injection …）
tubecli: 230 根因
noise codes: UNVERIFIED_WILD_AUTHZ 93 / AUTHENTICATED_LOCAL_ONLY 153 /
             LOCAL_LOOPBACK_ONLY 75 / NON_EXECUTABLE_UPLOAD 3 /
             UPLOAD_SERVING_ONLY 1
```

> 离线模式不能判 `ZERO_RECORD_FRESH`（同 v1.5.29/v1.5.30 口径），A=0 不能单独
> 证明清零；"5 → 0" 由逐条重放与根因层消失共同证明。最严口径（注入 FRESH
> 查重桩）复扫：**A 板 = 1**，正是保留观察的 `Maestro|import_style`，与设计一致
> （`board_a=1`，其余 325 条全部本地降噪压 B）。

### 4. 全部门禁

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,851 项断言**（v1.5.30 为 1,842，+9 即 `[354]`） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿** |
| `python cli.py doctor` | **PASS（12 段全绿）** |
| `benchmark_djangoat.py`（smoke 内） | `correct 15/15`、`secret_ok=true`（首版回归已修复） |
| `benchmark_javaseccode.py --offline` / `benchmark_hellojavasec.py --offline` | 本轮规则改动不涉及这两个靶场的类目（无 arbitrary_file_delete / hardcoded_secret 样本），结论沿用 11-22 基线 |

## 五、说明与遗留

- **11-24 巡猎的新 A 板 9 条不在本轮范围**：`javashub/CourseArragement`
  （authz ×2 + xss ×2）、`BinceQu/RoboHarness`（pathtraver ×1）、
  `youlaitech/youlai-boot`（authz ×4，全部 HIGH）。这 9 条与 11-23 的 6 条是
  不同批次（Maestro / tubecli 已进 7 天冷却），作为下一轮巡检/白盒对象；
  其中 `RoboHarness` 的命中位于 `eval/behavior/...` 目录，需先确认是否生产面。
- **`import_style` 的定位**：白盒已排除 RCE；若后续要降噪，建议按"默认回环 +
  全 API 无应用层鉴权是既有取舍"归 `AUTHENTICATED_LOCAL_ONLY` 类，而不是塞进
  `NON_EXECUTABLE_UPLOAD`（它确实是模型/权重上传面，本轮显式豁免）。
- **tubecli 降噪的边界条件**：当前单管理员模型下 4 条 SSRF 均属预期功能；
  一旦引入多用户/团队账号，`9router.base_url`（`normalize_base_url` 允许任意
  http/https 主机）会变成真实的"低权限者可控出站 URL"边界，必须重评 ——
  已在 `wild_noise` 的 M472 注释与本节留下触发条件。
- **披露侧**：草稿 C 邮件与 CAN 状态查询都还有待用户侧输入/确认；
  `FOLLOWUP_2026-11-24.md` 按文档要求保留为未提交草稿。

## 六、提交清单

- `core/agents/rule_detectors.py` — M471 模板占位符 / `safe_join` 守卫
- `core/context/wild_noise.py` — M472 服务端重命名/重编码上传归 B + 模型加载面豁免
- `benchmarks/smoke_test_chains.py` — M474 门禁 `[354]` 9 项
- `STAGE_REPORT_2026-11-24_v1.5.31.md` — 本报告

> 验证用 `.cache/upstream/` 为巡猎即时缓存（`.gitignore` 已排除），不进入提交；
> `FOLLOWUP_2026-11-24.md` 已由并列会话以 `0f0ba0c` 单独提交（不在本提交内）。
