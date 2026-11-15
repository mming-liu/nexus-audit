# STAGE REPORT · v1.5.15（M407–M410：A 板假阳清零 / 克隆限时 / 4 条候选白盒精核）

> 日期：2026-11-15 ｜ 基线：v1.5.14（`18a7a89`）
> 主题：规则层清零 2 类确证假阳、保留 2 类"被误标为假阳"的真问题；克隆
> 超时不再二次全量重跑；对剩余 4 条板块 A 候选做逐行白盒精核。
> 结论：`ai-agent-platform` SSRF 与 `tubecli` 自建临时文件清理已从根因层
> 清零；`tubecli api_download_engine` 的 SSRF / zip_slip 经逐行核查是
> **真问题**（`body.get("download_url")` 直通 `requests.get` / `extractall`），
> 但受"仅回环 + 全局鉴权"限制，**不属于可远程利用 0-day**；`android-agent`
> 两条删除是 **0.0.0.0 无鉴权 + 路径穿越**，属于真实可远程利用问题。

## 一、M407：规则层假阳清零

### 1. SSRF：配置源 + 固定主机排除（`core/agents/rule_detectors.py`）

- 新增 `_CONFIG_READER_RE`（`os.getenv` / `os.environ.get` / `os.environ[...]`
  / `settings.*` / `config.*` / `app.config.*`）、`_FIXED_HOST_URL_RE`
  （`^f?["']https?://[A-Za-z0-9._-]+/`）与 `_SSRF_URL_ARG_RES`（requests /
  httpx / aiohttp / urllib / client / session 的 URL 实参）。
- `_ssrf_arg_safe()`：URL 实参是固定主机字面量、配置读取、全大写配置常量、
  `f"{base_url}/..."` 前缀变量（且 `base_url` 不是入口形参）、或一跳别名时
  判安全；任何入口形参控制主机部分时保守返回 False。
- 新增 `SSRF_PY_CLIENT_RE`：`requests.get(...)` 本身就是 sink，不再要求实参
  变量名含 `url`（旧规则连 `requests.get(f"{base_url}/v1")` 都识别不到）。
- `httpx.AsyncClient(base_url=os.getenv(...))` + 相对路径
  `client.get(f"/threads/{id}")`：主机由配置锁死、形参只能改路径 → False。
- Java 的 `SpringUtil.getProperty` 分支保持不变。

### 2. 任意文件删除：自建临时文件清理排除

`_self_created_temp()` 在删除语句之前检查四类证据：临时文件工厂赋值
（含 `tf.name` 的宿主变量）、`open(arg, "w/a/x...")`、`arg.write_bytes/
write_text/save()`、`save(arg)` / `shutil.copy*(..., arg)`、以及 `tmp/temp`
变量右值含 `temp/tmp/uuid/gettempdir`。命中即判 False。

### 3. zip_slip：固定源组件包降噪

`wild_noise.VENDOR_ARCHIVE_EXTRACT`：入口无上传入参（`UploadFile` /
`File(` / `request.files`）、且解压对象来自固定域名下载的组件包 → 压 B。
**加固**：若压缩包来源可由 `body.get("download_url"/"url")`、`request.json/
form/args` 或 `params.get(...)` 控制，则不降噪 —— 否则会把真 zip_slip 藏掉
（tubecli 正是这种形态，见 §3）。

## 二、M408：`sync_repo` 克隆限时 90s + 禁止超时二次重试

`upstream_sync.sync_repo(..., clone_timeout: int = 90)`：

1. 首次 `git clone --depth --filter=blob:none --single-branch --no-tags`
   的 `timeout` 从 300 改为 `int(clone_timeout)`（默认 90s）；
2. 仅当 `rc != 0` 且 git 输出命中
   `unknown option|invalid.*filter|not support.*filter|unrecognized argument`
   时才回退第二次无 `--filter` clone；超时/断网直接清理 `dest` 并返回
   `UNKNOWN (clone_failed: ...)`。

`[338]` 验证：默认 `clone_timeout == 90`；超时只调用 1 次 clone；仅
`unknown option 'filter=blob:none'` 时调用 2 次。

## 三、M409：离线重扫 + 剩余 4 条候选白盒精核

### 1. 离线重扫（临时 state，不烧在线配额）

```
python cli.py daily-hunt --repos ljxpython/ai-agent-platform,tubecreate/tubecli,ghost-in-the-droid/android-agent \
  --offline --offline-dedup --cooldown-days 0 --max-roots 0 \
  --state .tmp/m409b_state.json --report .tmp/m409b_LIVE_HUNT_REPORT.md \
  --json .tmp/m409b_daily_hunt.json --packs-dir .tmp/m409b_packs --repo-timeout 300
```

结果：候选 3 / 实扫 3 / 失败 0；344 条根因全部进 B（`--offline-dedup` 下
无法标记 FRESH，A=0 是预期；真实清零证据看下面的原始根因对比）。

**原始根因对比**（`live_hunt.scan_repo` 直接跑规则层）：

| 候选 | v1.5.14 | v1.5.15 | 判定 |
|---|---|---|---|
| ai-agent-platform · ssrf · `enqueue_message` | 1 | **0** | ✅ 假阳清零（`base_url=os.getenv` 固定主机） |
| tubecli · arbitrary_file_delete · `api_cookie_import` | 1 | **0** | ✅ 假阳清零（删除的是自己的 `NamedTemporaryFile`） |
| tubecli · ssrf · `api_download_engine` | 1 | 1 | ❌ **不是假阳**（见 §3.3） |
| tubecli · zip_slip · `api_download_engine` | 1 | 1 | ❌ **不是假阳**（见 §3.3） |
| android-agent · arbitrary_file_delete · `explorer_delete` | 1 | 1 | 真问题（见 §3.2） |
| android-agent · arbitrary_file_delete · `api_skill_delete` | 1 | 1 | 真问题（见 §3.2） |
| tubecli · unrestricted_upload · `upload_media` | 1 | 1 | 鉴权后问题（见 §3.3） |
| tubecli · arbitrary_file_delete · `api_delete_cookies` | 1 | 1 | 鉴权后问题（见 §3.3） |

> 结论修正：规格预设的 4 条"假阳"里，只有 2 条确证为假阳；
> `tubecli api_download_engine` 的 SSRF 与 zip_slip 是**真问题**（请求体
> 可控 `download_url`），规则层不应清零，故保留。

### 2. `android-agent` 两条删除：真实可远程利用

**启动绑定**：`run.py:11` → `uvicorn.run(app, host='0.0.0.0', port=5055)`
（全网卡监听）。

**全局鉴权**：`gitd/app.py:115-121` 只注册了 `CORSMiddleware`；`include_router`
（`app.py:136-153`）没有 `dependencies=`；`require_admin_token` 只挂在
`skills.py:190-194` 的 `/install`（RCE 敏感路由），删除路由没有。

#### 2.1 `explorer_delete`（`gitd/routers/explorer.py:217-224`）

```python
217 @router.delete("/delete/{name:path}", summary="Delete Exploration Run")
218 def explorer_delete(name: str):
219     """Delete an exploration run."""
220     run_dir = _EXPLORER_DIR / name
221     if not run_dir.exists() or not run_dir.is_dir():
222         raise HTTPException(status_code=404, detail="Not found")
223     shutil.rmtree(run_dir)
224     return {"ok": True}
```

`{name:path}` 允许斜杠，`name="../../.."` 直接穿越到任意目录；
`shutil.rmtree` 无规范化/前缀校验、无鉴权、服务监听 0.0.0.0。
**结论：是，真实可远程利用的未授权任意目录删除**（数据丢失 / DoS），
建议按高危处理（本轮只出精核报告，不对外发 Issue/Advisory）。

#### 2.2 `api_skill_delete`（`gitd/routers/skills.py:612-621`）

```python
612 @router.delete("/{name}", summary="Delete Custom Skill")
613 def api_skill_delete(name: str):
615     if name in ("_base", "tiktok", "instagram"):
616         raise HTTPException(status_code=400, detail="Cannot delete built-in skills")
617     skill_dir = _SKILLS_DIR / name
618     if not skill_dir.exists():
619         raise HTTPException(status_code=404, detail=f'Skill "{name}" not found')
620     shutil.rmtree(skill_dir)
621     return {"ok": True}
```

`{name}` 是单段路径（不能含 `/`），但 `name=".."` 可让
`_SKILLS_DIR / ".."` 指向父目录并 `rmtree` 整个父目录；同样无鉴权、0.0.0.0。
**结论：是，可远程利用**，但穿越只有一级、影响面小于 `explorer_delete`；
建议与 2.1 合并提交（同一根因：路径拼接 + rmtree 无校验）。

### 3. `tubecli` 两条 + 两条"伪假阳"

**启动绑定**：`tubecli/api/server.py:55-56` 注释明确 "it binds to loopback"，
默认端口 5295（OAuth 回调固定 `http://127.0.0.1:5295`）。

**全局鉴权**：`server.py:522` 的 `@app.middleware("http")` 对全部路由做
`auth.check_request`（`server.py:563`），仅 `_AUTH_EXEMPT_EXACT` /
`_AUTH_EXEMPT_PREFIX`（`server.py:71-111`）里的登录/健康/公开签名路由豁免；
`/api/v1/video/...` 与 `/api/v1/browser/...` 不在豁免表 → 需要 owner 会话。
浏览器请求另有 origin guard（`server.py:653` 起）。

#### 3.1 `upload_media`（`tubecli/extensions/video_editor/video_api.py:264-277`）

```python
264 @router.post("/upload")
265 async def upload_media(
266     file: UploadFile = File(...),
267     project_id: Optional[str] = Form(None),
268 ):
270     uploads_dir = _get_uploads_dir()
271     filename = file.filename or f"upload_{uuid.uuid4().hex[:8]}"
272     save_path = os.path.join(uploads_dir, filename)
275     with open(save_path, "wb") as f:
276         content = await file.read()
277         f.write(content)
```

`filename` 未做 basename/扩展名校验，`../` 可写出上传目录。
**结论：否，不属于可远程利用 0-day** —— 服务仅回环 + 全局鉴权，且 owner
本就拥有本机文件写权限；属"鉴权后加固项"，不建议对外提交。

#### 3.2 `api_delete_cookies`（`tubecli/extensions/browser/routes.py:616-625`）

```python
616 @router.delete("/profiles/{name}/cookies")
617 async def api_delete_cookies(name: str):
621     cookie_path = os.path.join(PROFILES_DIR, name, "cookies.json")
622     if os.path.exists(cookie_path):
623         os.remove(cookie_path)
```

`{name}` 单段，`..` 只能越一级；同样仅回环 + 鉴权。
**结论：否，不属于可远程利用 0-day**；属鉴权后加固项。

#### 3.3 被误标为假阳的两条：`api_download_engine`（`tubecli/extensions/browser/routes.py`）

```python
1922 download_url = body.get("download_url", "")
1960 urls_to_try.append(("local", download_url))
1976 resp = requests.get(url, stream=True, timeout=300)
...
2006 zf.extractall(target_dir)
```

请求体里的 `download_url` 直接进入 `urls_to_try` 并交给 `requests.get`，
解压时又用无校验的 `extractall` —— **SSRF + zip_slip 都成立**，不是固定
域名组件包（固定 CDN 只是 fallback）。但该路由需要 owner 会话，服务仅回环。
**结论：真实问题，但不属于可远程利用 0-day**；规则层保留 True 是正确的，
M407 的 `VENDOR_ARCHIVE_EXTRACT` 已加"请求体可控 URL 不降噪"护栏。

## 四、M410：门禁 `[338]` 与全套验证

`[338]` 共 10 项断言（纯离线）：

| 组 | 覆盖 |
|---|---|
| SSRF | `os.getenv` base_url + 相对路径 → False；固定主机字面量 → False；`requests.get(target_url)` → True；`f"http://{user_host}/v1"` → True |
| 删除 | 先 `open(tmp_path,"wb")` 写入再 `os.remove` → False；未写入直接删形参路径 → True |
| 解压 | 无上传入参 + 固定域名下载解压 → `VENDOR_ARCHIVE_EXTRACT` |
| 克隆 | 默认 `clone_timeout == 90`；超时 1 次 clone + UNKNOWN；仅 `unknown option` 才 2 次 |

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,741 项断言**（v1.5.14 为 1,731；`[338]` +10） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、已知边界与建议

1. **M409 的"4 条假阳"只有 2 条成立**：tubecli 的 SSRF/zip_slip 是请求体
   可控 `download_url` 导致的真问题。若坚持要"从 A 板清零"，正确做法是加
   一条 `AUTHENTICATED_LOCAL_ONLY` 降噪（服务仅回环 + 全局鉴权），而不是
   在规则层判 False —— 本轮未做，建议下一轮单独拍板。
2. **`android-agent` 两条是真实 0-day 候选**：本轮按约定只出精核报告，
   未发 Issue/Advisory；提交前建议先在本地复现 `DELETE /api/explorer/delete/..`
   并确认 0.0.0.0 暴露面。
3. **`clone_timeout=90s` 对大仓可能偏紧**：`android-agent`/`tubecli` 本地
   已有缓存不受影响；新仓若 90s 克隆不完会直接 UNKNOWN 并进入 3 天失败冷却，
   必要时可按仓大小调参。
4. **SSRF 规则新增 Python client sink** 会扩大 True 面；已用 16 靶场地板与
   pre-push 基线兜底，若真实项目出现新的 `requests.get(常量)` 误报，优先补
   `_config_rhs` 的常量/别名形态，而不是回退 sink。

## 六、提交清单

- `core/agents/rule_detectors.py` — M407 SSRF 配置源/固定主机/Python client sink + 自建临时文件排除
- `core/context/wild_noise.py` — M407 `VENDOR_ARCHIVE_EXTRACT` + 请求体可控 URL 护栏
- `core/context/upstream_sync.py` — M408 `clone_timeout=90` + 仅 filter 不支持时回退
- `benchmarks/smoke_test_chains.py` — M410 `[338]` 10 项
- `STAGE_REPORT_2026-11-15_v1.5.15.md` — 本报告（含 4 条候选逐行精核）
