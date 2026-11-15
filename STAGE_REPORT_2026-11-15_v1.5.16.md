# STAGE REPORT · v1.5.16（M411–M414：AUTHENTICATED_LOCAL_ONLY / 克隆 180s / android-agent 交单档案）

> 日期：2026-11-15 ｜ 基线：v1.5.15（`3e4c4eb`）
> 主题：把 `tubecli` 的 4 条本地鉴权项精准收归 B 板（A=0），保留
> `android-agent` 2 条真洞（A=2）；`clone_timeout` 调优至 180s；整理
> `android-agent` 的交单前核验档案与防御补丁（本轮不对外发送）。
> 结论：3 仓离线复扫 **A=2 / B=356**，A 板只剩 `android-agent` 的
> `explorer_delete` 与 `api_skill_delete`；门禁全绿。

## 一、M411：`AUTHENTICATED_LOCAL_ONLY` + 间接回环绑定识别

### 1. 新增噪声码

```python
AUTHENTICATED_LOCAL_ONLY = "AUTHENTICATED_LOCAL_ONLY"
```

### 2. 间接回环绑定识别

`_LOOPBACK_BIND_RE` 只认字面量 `uvicorn.run(..., host="127.0.0.1")`；
tubecli 的真实写法是：

```python
host: str = "127.0.0.1"                      # 或
host = "0.0.0.0" if (_in_container() or _is_headless_server()) else "127.0.0.1"
...
uvicorn.run("tubecli.api.server:app", host=host, port=actual_port)
```

新增：

- `_LOOPBACK_DEFAULT_RE`：`host[: str] = "127.0.0.1"`、`os.getenv(..., "127.0.0.1")`、
  以及 `host = "0.0.0.0" if ... else "127.0.0.1"` 的**默认回环**三元式；
- `_HOST_VAR_BIND_RE`：`uvicorn.run/app.run/hypercorn.run/serve(... host=host)`；
- `_GLOBAL_AUTH_RE`：`@app.middleware("http")`、`@app.before_request`、
  `add_middleware(*Auth*)`、`auth.check_request(`、`verify_token(`、`check_auth(`。

### 3. 整仓识别 `_repo_authenticated_local()`

带 `_REPO_AUTH_LOCAL_MEMO` 缓存，条件：

- **A（默认回环）**：存在字面量回环绑定，或"默认 `host=127.0.0.1` + 变量
  `host=host`"形态；且**没有无条件**字面量 `0.0.0.0` 启动。
  （容器/headless 分支里的条件公网绑定不算无条件；`android-agent` 的
  `run.py:11` 是无条件 `host='0.0.0.0'` → 条件 A 不成立。）
- **B（全局鉴权）**：主服务挂有全局请求鉴权中间件/守卫。

`classify()` 在 `_repo_loopback_only()` 之后调用；命中返回：

```python
{"blocked": True, "code": AUTHENTICATED_LOCAL_ONLY,
 "reason": "服务默认回环绑定且挂有全局请求鉴权（…），属认证后本地管理面，不作为远程未授权 0-day 交单"}
```

实测：

| 仓 | `_repo_authenticated_local` |
|---|---|
| `tubecreate/tubecli` | `True`（`cli/api_cmd.py` 默认 host 变量 + `api/server.py` 全局中间件） |
| `ghost-in-the-droid/android-agent` | `False`（`run.py:11` 无条件 0.0.0.0、无全局鉴权） |
| `ljxpython/ai-agent-platform` | `False`（无回环绑定） |

## 二、M412：`clone_timeout` 调优至 180s

`sync_repo(..., clone_timeout: int = 180)`：单次 `--filter=blob:none` 克隆
最多等 180 秒；超时仍**不**触发二次无 filter 重试（M408 语义不变）。
`[338]`/`[339]` 同步断言默认值 180。

## 三、M413：3 仓离线复扫精确对账

### 1. 复扫命令（临时空账本，关闭 exported_roots 过滤）

```
python cli.py daily-hunt --repos ljxpython/ai-agent-platform,tubecreate/tubecli,ghost-in-the-droid/android-agent \
  --offline --cooldown-days 0 --max-roots 0 \
  --state .tmp/m413b_state.json --report .tmp/m413b_LIVE_HUNT_REPORT.md \
  --json .tmp/m413b_daily_hunt.json --packs-dir .tmp/m413b_packs --repo-timeout 300
```

> 说明：`--offline` 指复用本地克隆；查重仍走在线四源（命中 24h 磁盘缓存）。
> 两个 android 删除根的旧缓存因 "FRESH 但 NVD 失败" 会被 M359 门禁降级为
> UNKNOWN，复扫前清掉这两条缓存、让它们走一次实时查重（CIRCL+GHSA quorum
> 判 FRESH），才能观察到 A 板真实结果。

### 2. 对账结果

| 仓 | 根因 | 板块 A | 板块 B | 关键噪声码 |
|---|---|---|---|---|
| `ljxpython/ai-agent-platform` | 84 | **0** | 84 | `UNVERIFIED_WILD_AUTHZ` ×84 |
| `tubecreate/tubecli` | 234 | **0** | 234 | `AUTHENTICATED_LOCAL_ONLY` ×158、`LOCAL_LOOPBACK_ONLY` ×75、`NON_EXECUTABLE_UPLOAD` ×1 |
| `ghost-in-the-droid/android-agent` | 40 | **2** | 38 | `UNVERIFIED_WILD_AUTHZ` ×38 |
| **合计** | **358** | **2** | **356** | — |

A 板仅剩：

```
android-agent  arbitrary_file_delete  api_skill_delete   gitd/routers/skills.py:612
android-agent  arbitrary_file_delete  explorer_delete    gitd/routers/explorer.py:217
```

tubecli 4 条目标项全部收归 B 板：

| 项 | 噪声码 |
|---|---|
| `api_download_engine` SSRF | `AUTHENTICATED_LOCAL_ONLY` |
| `api_download_engine` zip_slip | `AUTHENTICATED_LOCAL_ONLY` |
| `upload_media` unrestricted_upload | `AUTHENTICATED_LOCAL_ONLY` |
| `api_delete_cookies` arbitrary_file_delete | `AUTHENTICATED_LOCAL_ONLY` |

## 四、`android-agent` 交单前核验档案（本轮不对外发送）

### 4.1 仓库元数据

| 项 | 值 |
|---|---|
| 仓库 | `ghost-in-the-droid/android-agent` |
| HEAD | `8974838fd74c06944583c9dcea66570bc4c5c161` |
| HEAD 提交时间 | 2026-11-14 21:21:24 +0100（`Merge pull request #56 …`） |
| 最近 push | 2026-11-15T00:22:49Z |
| Stars | 422（2026-11-15 搜索结果） |
| LICENSE | MIT（`Copyright (c) 2026 Ghost in the Droid Contributors`） |
| 默认分支 | `main` |
| 启动方式 | `run.py:11` → `uvicorn.run(app, host='0.0.0.0', port=5055)` |
| 鉴权现状 | `app.py` 仅 `CORSMiddleware`；`require_admin_token` 只挂 `/api/skills/install` |

`SECURITY.md` 自述（原文）：

> **No authentication** on the API by default — the server binds to
> `0.0.0.0:5055`. Do not expose to the public internet without adding auth.

即：厂商已知"默认 0.0.0.0 + 无鉴权"的风险，但 `explorer_delete` /
`api_skill_delete` 这两条破坏性路由没有像 `/install` 一样加管理员依赖。

### 4.2 披露通道与既有 Issue

- **披露通道**：`SECURITY.md` 要求 "Do NOT open a public issue"，
  走 **security@ghostinthedroid.com** 或 **GitHub 私密 Security Advisory**；
  Issue #39（closed）已启用 private vulnerability reporting。
- **既有 Issue/PR**：
  - **#31（closed）**：`fix(test-runner): prevent path traversal in recording
    endpoints` —— 同一类漏洞（`{filename:path}` + 路径直接拼接 + 无校验），
    已在 `/api/test-runner` 修复。说明维护者认可该类问题，但 `explorer` /
    `skills` 两处被漏掉。
  - 未检索到 `explorer_delete` / `api_skill_delete` 的重复 Issue/PR。

### 4.3 漏洞代码（远端 HEAD）

`gitd/routers/explorer.py:217-224`：

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

`gitd/routers/skills.py:612-621`：

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

- `explorer_delete`：`{name:path}` 允许 `/`，`name="../../.."` 穿越后
  `rmtree` 任意目录；服务 0.0.0.0、无鉴权 → **未授权远程任意目录删除**。
- `api_skill_delete`：`{name}` 单段，`name=".."` 让 `_SKILLS_DIR / ".."`
  指向父目录并 `rmtree`；同样无鉴权 → **可远程删除 skills 父目录**。

### 4.4 防御补丁（Unified Diff）

```diff
--- a/gitd/routers/explorer.py
+++ b/gitd/routers/explorer.py
@@ -6,10 +6,11 @@
 from pathlib import Path
 
-from fastapi import APIRouter, Body, HTTPException
+from fastapi import APIRouter, Body, Depends, HTTPException
 from fastapi.responses import FileResponse
 
 from gitd.bots.common.device import is_ios_ref
 from gitd.config import settings
+from gitd.services.admin_auth import require_admin_token
 
 router = APIRouter(prefix="/api/explorer", tags=["explorer"])
@@ -214,12 +215,19 @@
-@router.delete("/delete/{name:path}", summary="Delete Exploration Run")
+@router.delete("/delete/{name:path}", summary="Delete Exploration Run",
+               dependencies=[Depends(require_admin_token)])
 def explorer_delete(name: str):
     """Delete an exploration run."""
-    run_dir = _EXPLORER_DIR / name
+    base = _EXPLORER_DIR.resolve()
+    run_dir = (base / name).resolve()
+    try:
+        run_dir.relative_to(base)
+    except ValueError:
+        raise HTTPException(status_code=400, detail="Invalid run path")
+    if run_dir == base:
+        raise HTTPException(status_code=400, detail="Invalid run path")
     if not run_dir.exists() or not run_dir.is_dir():
         raise HTTPException(status_code=404, detail="Not found")
     shutil.rmtree(run_dir)
```

```diff
--- a/gitd/routers/skills.py
+++ b/gitd/routers/skills.py
@@ -609,13 +609,20 @@
-@router.delete("/{name}", summary="Delete Custom Skill")
+@router.delete("/{name}", summary="Delete Custom Skill",
+               dependencies=[Depends(require_admin_token)])
 def api_skill_delete(name: str):
     """Delete a custom skill."""
     if name in ("_base", "tiktok", "instagram"):
         raise HTTPException(status_code=400, detail="Cannot delete built-in skills")
-    skill_dir = _SKILLS_DIR / name
+    base = _SKILLS_DIR.resolve()
+    skill_dir = (base / name).resolve()
+    try:
+        skill_dir.relative_to(base)
+    except ValueError:
+        raise HTTPException(status_code=400, detail="Invalid skill path")
+    if skill_dir == base:
+        raise HTTPException(status_code=400, detail="Invalid skill path")
     if not skill_dir.exists():
         raise HTTPException(status_code=404, detail=f'Skill "{name}" not found')
     shutil.rmtree(skill_dir)
```

补丁要点：

1. 与 `/install` 一致，补 `Depends(require_admin_token)`；
2. `resolve()` + `relative_to(base)` + `!= base` 三重校验，阻断 `..` 穿越
   与父目录误删（`skills.py` 已 import `Depends` / `require_admin_token`，
   只需改装饰器与路径校验）。

### 4.5 交单结论与待办

- **结论**：两条均为**真实、可远程利用的未授权破坏性漏洞**（0.0.0.0 默认
  绑定 + 无鉴权 + 路径穿越删除）。按 CVSS 3.1 粗估：
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` ≈ **8.2（High）**。
- **建议**：优先走私密 Security Advisory（`security@ghostinthedroid.com`
  或 GitHub private advisory），附本报告的复现步骤与 4.4 补丁；
  **本轮未发送任何对外请求**，待你核对本报告后拍板。
- **复现要点（供后续验证）**：
  `curl -X DELETE http://<host>:5055/api/explorer/delete/..%2F..%2Ftmp%2Fpoc`
  观察目标目录被 `rmtree`；`/api/skills/..` 同理（一级）。

## 五、M414：门禁 `[339]` 与全套验证

`[339]` 6 项断言（纯离线）：

| 组 | 覆盖 |
|---|---|
| tubecli 夹具 | `host: str = "127.0.0.1"` + `uvicorn.run(app, host=host)` + `@app.middleware("http")` + `auth.check_request` → ssrf/zip_slip/unrestricted_upload/arbitrary_file_delete 全部 `blocked=True`，code ∈ {`AUTHENTICATED_LOCAL_ONLY`, `LOCAL_LOOPBACK_ONLY`} |
| android 夹具 | `run.py` 无条件 `host="0.0.0.0"` + 仅 CORS → `explorer_delete` `blocked=False` |
| 克隆 | `sync_repo` 默认 `clone_timeout == 180` |

| 项 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,747 项断言**（v1.5.15 为 1,741；`[338]` 默认值改 180 + `[339]` 6 项） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿**（新噪声码未误伤任何靶场） |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 六、已知边界与建议

1. **A=2 依赖一次实时查重**：NVD 当前熔断，`cve_dedup` 对"FRESH 但 NVD 失败"
   的缓存读会降级为 UNKNOWN（M359 门禁）。复扫前清掉两条旧缓存后，
   `explorer_delete` 经 CIRCL+GHSA quorum 判 FRESH；`api_skill_delete` 首次
   因 GitHub global issues SSL 失败被判 UNKNOWN，重试后 FRESH。
   生产环境若 NVD 长期不可达，A 板会自然收缩——这是证据完整性门禁的预期。
2. **`AUTHENTICATED_LOCAL_ONLY` 是整仓级判定**：会同时把该仓的 sqli/xss 等
   根因压 B（认证后本地管理面口径）。若后续要保留"认证后仍值得交单"的类目，
   需给噪声码加类目白名单。
3. **容器/headless 部署仍是 0.0.0.0**：tubecli 在容器/无显示服务器上会绑定
   公网，但全局鉴权与 origin guard 仍在；本降噪按"默认回环 + 全局鉴权"口径，
   不覆盖"运维手动 --host 0.0.0.0"的场景。

## 七、提交清单

- `core/context/wild_noise.py` — M411 `AUTHENTICATED_LOCAL_ONLY` + 间接回环绑定 + 整仓鉴权识别
- `core/context/upstream_sync.py` — M412 `clone_timeout` 默认 180
- `benchmarks/smoke_test_chains.py` — M414 `[339]` 6 项 + `[338]` 默认值断言同步
- `STAGE_REPORT_2026-11-15_v1.5.16.md` — 本报告（含 android-agent 交单档案与补丁）
