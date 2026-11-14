# STAGE REPORT · v1.5.7（M375–M378：上传面门禁 + WS 鉴权补齐 + 零假阳巡猎）

> 日期：2026-11-14 ｜ 基线：v1.5.6（762908f）
> 结论：`apowerb` 剩余 2 条 upload 由 `UPLOAD_SERVING_ONLY` 拦入 B，
> **8 仓重扫板块 A 从 9 → 3 → 0**；随后用零假阳管线跑了一轮全新候选，
> 60 条根因里 A=1，人工精核后确认是**跨文件 helper 导致的假阳**（见 §4）。

## 一、M375：上传落盘面门禁（落点在 wild_noise）

按"不动 `rule_detectors` 单函数判据"的架构原则，门禁放在
`wild_noise.classify(record, repo_root)`（这里有完整 repo_root，能看到全局挂载）：

| 判据 | 实现 |
|---|---|
| 前提 A：已防路径穿越 | `os.path.basename` / `secure_filename` / `Path(...).name` / `re.sub` / `_contained_upload_path` / `relative_to` / `getCanonicalPath` / `FilenameUtils.getName` / `.normalize(` |
| 条件 B：无可服务/可执行出口 | 仓内无 `StaticFiles(...upload)` / `mount('/uploads')` / `addResourceHandlers` / `send_from_directory(...upload)` |
| 满足 A+B 且下载为 attachment 或仅 RAG 入库 | → `UPLOAD_SERVING_ONLY` |
| 满足 A+B、仅"非静态挂载" | → `NON_EXECUTABLE_UPLOAD` |

**验证（8 仓热缓存重扫）**：

| 轮次 | 板块 A | 说明 |
|---|---|---|
| v1.5.5 | 9 | 全为 SQLi/mass_assignment 假阳 |
| v1.5.6 | 3 | SQLi 清零，剩 3 条 upload |
| v1.5.7 | **0** | `upload_file` / `index_files` → `UPLOAD_SERVING_ONLY`；`upload_csv` 已由白名单规则判 False |

## 二、M376：WebSocket 前置鉴权补齐

- `_WS_DENY_CLOSE_RE` 补 `4001` / `4003`（原 1008/4401/4403）；
- `wild_noise._IDENTITY_GUARD_RE` 计入 `jwt.decode` / `_authed(` / `verify_token(`；
- redcell 的 6 条 WS 入口仍全部判 `False` / `WS_AUTH_PRESENT`（v1.5.2 起）。

## 三、M377：门禁

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS 1,632 项**（+6：`[330]`） |
| `triage_fallbacks.py --check-floor` | **16/16**（未动 rule_detectors 判据，地板零回退） |
| `cli.py doctor` | PASS（12 段全绿） |
| `.githooks/pre-push` | exit 0 |

`[330]` 覆盖：attachment → `UPLOAD_SERVING_ONLY`；RAG 索引 → `UPLOAD_SERVING_ONLY`；
`StaticFiles` 挂载上传目录 → 不拦；无防穿越 → 不拦；`close(4001)` 算前置鉴权；
`jwt.decode` 计入身份校验。

## 四、M378：零假阳管线跑全新候选

命令：

```
python cli.py daily-hunt --languages java,python --days 21 --limit 8 \
  --min-stars 300 --max-roots 5 --cooldown-days 7 --evict-cache --repo-timeout 300
```

| 项 | 值 |
|---|---|
| 候选 / 实扫 / 跳过 / 失败 | 3 / 2 / 1 / 0 |
| 根因 | 60（A=1，B=59） |
| 即扫即焚 | 3 个缓存 |
| 耗时 | ~1 分 44 秒（`11:44:35 → 11:46:19`） |

### 唯一 A 候选精核：`RAG_LearnLittleCode` `upload_chat_file` → **假阳**

`app/routers/chat.py:758`（HEAD `d23c142`）：

1. 入口 `Depends(get_current_user_id)` + `read_upload_limited(max_size_mb=50)`；
2. 真正的校验在 `app/services/chat_attachment_service.py:82 save_upload()`：
   - `validate_chat_attachment()` = **扩展名白名单 + magic bytes** 双重校验；
   - 落盘名是 `uuid.uuid4().hex + info.ext`（**服务端生成，不用原始文件名**）；
   - 目录 `data/chat_files/{user_id}/`，docstring 明示"不挂公开静态目录"；
3. 下载 `get_chat_file()` 要 JWT（Header 或短时效 query token）+ `get_owned` 归属校验，
   `FileResponse(..., content_disposition_type="inline")`，`media_type` 取自 magic bytes，
   只可能是 image/video。

**为什么规则仍判 True**：白名单与 UUID 命名都在**跨文件 service** 里，切片只带
`chat.py` 入口，`_py_upload_helper_bodies()` 追不到 `save_upload` 的实现。
这不是新门禁的漏洞，而是"跨文件 helper 不在切片"的已知盲区。

**建议 M379**：给 `unrestricted_upload` 加 repo 级 helper 解析 —— 入口调用的
`save_upload/upload_service` 若在仓内能找到定义，且其体含"白名单 + 固定命名"，
按已防护处理（与 M375 同一落点，零靶场地板风险）。

## 五、提交

- `3032e3d` — v1.5.7 代码（M375–M377）
- 后续 docs 提交 — 本报告 + 11-14 巡猎报告
