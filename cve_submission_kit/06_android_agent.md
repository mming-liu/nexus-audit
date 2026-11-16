# 候选 06：ghost-in-the-droid/android-agent 未授权目录删除（防御修复包）

> 模板版本：v1.5.17 ｜ 状态：**已提交（GHSA-368h-5897-269p，2026-11-17，triage）**
> 审计 HEAD：`8974838fd74c06944583c9dcea66570bc4c5c161`（2026-11-14 21:21:24 +0100）
> 提交入口：GitHub Private Security Advisory（2026-11-16T23:29:30Z 创建）
> 提交地址：https://github.com/ghost-in-the-droid/android-agent/security/advisories/GHSA-368h-5897-269p
> 仓库：https://github.com/ghost-in-the-droid/android-agent
> Stars：422（2026-11-15 搜索结果）｜ LICENSE：MIT ｜ 默认分支：`main`
> 说明：本文件**只含代码定位与防御补丁**，不含任何攻击载荷、利用脚本或
> `curl` 攻击命令；提交前请按 `SECURITY.md` 走私密渠道。

## 1. 仓库与披露入口

| 项 | 值 |
|---|---|
| owner/repo | `ghost-in-the-droid/android-agent` |
| 审计 HEAD | `8974838fd74c06944583c9dcea66570bc4c5c161` |
| HEAD 提交时间 | 2026-11-14 21:21:24 +0100 |
| 最近 push | 2026-11-15T00:22:49Z |
| Stars / License | 422 / MIT |
| 私密 Advisory | https://github.com/ghost-in-the-droid/android-agent/security/advisories/new |
| 安全邮箱 | security@ghostinthedroid.com（见仓内 `SECURITY.md`） |
| 披露要求 | `SECURITY.md`：**Do NOT open a public issue**；48 小时内确认 |

## 2. 同仓基线证据（为什么这是"漏加"，不是"设计如此"）

1. **Issue #31（closed）**：`fix(test-runner): prevent path traversal in
   recording endpoints` —— 同一类 `{filename:path}` + 路径直接拼接问题，
   维护者已在 `/api/test-runner` 修复，说明该仓认可"路径穿越删除"是漏洞。
2. **`/api/skills/install`**（`gitd/routers/skills.py:190-194`）显式挂了
   `dependencies=[Depends(require_admin_token)]`，并在 docstring 写明
   "unauthenticated caller = RCE"；同文件的 `api_skill_delete` 却没有。
3. **`SECURITY.md`** 自述："**No authentication** on the API by default —
   the server binds to `0.0.0.0:5055`." 即服务默认全网卡监听且无鉴权；
   破坏性路由必须自行补管理员依赖。

## 3. 受影响代码（远端 HEAD）

### 3.1 `gitd/routers/explorer.py:217-224`

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

- `{name:path}` 允许路径分隔符，`name` 未做规范化/前缀校验；
- `shutil.rmtree` 直接作用于拼接结果；
- 路由无 `Depends(require_admin_token)`，服务默认 `0.0.0.0:5055`。

### 3.2 `gitd/routers/skills.py:612-621`

```python
612 @router.delete("/{name}", summary="Delete Custom Skill")
613 def api_skill_delete(name: str):
614     """Delete a custom skill."""
615     if name in ("_base", "tiktok", "instagram"):
616         raise HTTPException(status_code=400, detail="Cannot delete built-in skills")
617     skill_dir = _SKILLS_DIR / name
618     if not skill_dir.exists():
619         raise HTTPException(status_code=404, detail=f'Skill "{name}" not found')
620     shutil.rmtree(skill_dir)
621     return {"ok": True}
```

- `{name}` 为单段路径，但 `..` 可让 `_SKILLS_DIR / ".."` 指向父目录；
- 同样无管理员依赖、无 `resolve()/relative_to()` 边界校验。

### 3.3 根因与影响（CWE）

- **CWE-22**：路径穿越（未规范化用户可控路径）；
- **CWE-862**：缺失授权（破坏性路由未挂管理员依赖）；
- 影响：网络可达的未授权调用者可删除 `data/app_explorer` 之外的任意
  目录（`explorer_delete`）或 `gitd/skills` 的父目录（`api_skill_delete`），
  造成数据丢失/服务不可用；不涉及读取或代码执行。
- CVSS 3.1 粗估：`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` ≈ **8.2（High）**。

## 4. 防御修复补丁（Unified Diff）

> 设计原则：与 `/install` 保持一致的 `Depends(require_admin_token)`；
> 删除前用 `resolve()` + `relative_to(base)` + `!= base` 三重校验，
> 阻断 `..` 穿越与父目录误删。

### 4.1 `gitd/routers/explorer.py`

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

### 4.2 `gitd/routers/skills.py`

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

说明：`skills.py` 已 import `Depends` 与 `require_admin_token`，只需改装饰器
与路径校验；`explorer.py` 需补 import。补丁不改变正常（合法名字）删除行为，
仅在越界时返回 400。

## 5. 验证建议（维护者侧，纯防御）

1. 为两个路由补单元测试：合法名字删除成功；`..`/绝对路径返回 400；
   未携带管理员 token 返回 401/403（`GITD_ADMIN_TOKEN` 已配置时）。
2. 回归 `/api/skills/install` 的既有鉴权测试，确认 `require_admin_token`
   行为一致（未配置 token 时 500，配置后无 token 401/403）。
3. 若维护者希望保持"单机零配置"体验，可仅合并路径校验（4.1/4.2 的第二段
   diff），鉴权部分按项目策略决定 —— 但至少应阻断穿越与父目录删除。

## 6. 提交前检查

- [ ] 通过 GitHub Private Security Advisory 私密提交（不要开公开 Issue）；
- [ ] 正文只引用本文件的代码定位与补丁，不附攻击脚本；
- [ ] 附 HEAD `8974838fd74c06944583c9dcea66570bc4c5c161` 与复现环境说明；
- [ ] 同步邮件 security@ghostinthedroid.com（可选，双通道更稳）；
- [ ] 等待 48 小时确认；未回复再考虑 MITRE CVE 表单（非 CNA 路径）。
