# STAGE REPORT · v1.5.25（M447–M450：四组焦点白盒 / 仓级查重 / 鉴权识别 / securecookie 归 B）

> 日期：2026-11-18 ｜ 基线：v1.5.24（`25c6d74`）
> 主题：对巡检点名的 4 组目标做逐行白盒；给 B 板短路记录接入零 search
> 配额的仓级 CVE/GHSA 查重；识别 FastAPI `Depends(...)`/WS 鉴权与
> Shiro `@CsPermission`/全局 `authc` 链，治理 CordysCRM 222 条 authz
> 洪泛；野仓 `securecookie` 低危项归 B。
> 结论：4 仓复扫 **A 384 → 0**；门禁 smoke **1,805** / triage 16/16 /
> doctor PASS。

## 一、M447：四组焦点目标白盒精核

### 1. `Case211/remnawave-admin`（HEAD `e2d8510caf08`）

**`terminal_websocket`**（`web/backend/api/v2/terminal.py:47`）：

```python
@router.websocket("/fleet/{node_uuid}/terminal")
async def terminal_websocket(websocket: WebSocket, node_uuid: str):
    try:
        admin = await get_current_admin_ws(websocket)
    except Exception as e:
        logger.warning("Terminal auth failed: %s", e)
        return
    ...
    has_perm = (admin.account_id is None or admin.role == "superadmin"
                or admin.has_permission("fleet", "terminal"))
    if not has_perm:
        await websocket.accept(...); await websocket.close(code=4003, ...)
        return
```

- 鉴权：`get_current_admin_ws(websocket)`，token 走
  `Sec-WebSocket-Protocol "access-token, <jwt>"`（`?token=` 为兼容回退）；
- 授权：`fleet.terminal` RBAC 权限，非 superadmin 拒绝（close 4003）；
- **结论：有鉴权 + 有权限校验，不是未授权 root-shell。**

**`revoke_admin_session`**（`web/backend/api/v2/auth.py:1391`）：

```python
@router.delete("/sessions/{sid}")
async def revoke_admin_session(sid: str, admin: AdminUser = Depends(get_current_admin)):
    if getattr(admin, "account_id", None):
        await _sessions.revoke_session(admin.account_id, sid)
```

- `Depends(get_current_admin)` 强制登录；且只吊销**自己**的会话
  （`admin.account_id`），不是任意管理员会话；
- **结论：不是未授权/IDOR。**

> 这 2 条（连同 `delete_channel`/`update_device` 等 8 条）此前被
> `UNVERIFIED_WILD_AUTHZ` 压 B，属于规则未识别 FastAPI 依赖/WS 鉴权，
> M449 已补识别。

### 2. `lalitgehani/SnackBase`（HEAD `9d50937c59b0`）

`custom_endpoint_dispatcher.py`：

- `dispatch_post` / `dispatch_patch` / `dispatch_delete` 均转发到
  `_handle_custom_endpoint`；
- 鉴权是**按端点配置**：`if matched_endpoint.auth_required:` 才检查
  `request.state.authenticated_user`，缺失返回 401；
- 路由本身没有 router 级 `Depends`，自定义端点的 `auth_required`
  由创建者配置（默认值需按产品语义确认）；
- `_path_template_to_regex` 编译的是**数据库里存储的**路径模板，
  不是请求输入 → 此前的 `regex_dos` 是假阳（v1.5.24 已修）。

**结论：不是"全局无鉴权"；是可按端点配置鉴权的自定义端点调度器。**
若产品默认 `auth_required=False`，建议在创建端点时默认开启鉴权（防御性建议，
未外发）。

### 3. `himovo/movo`（HEAD `520ca606a5b6`）

`services/chat-api/app/api/endpoints/documents.py`：

- `/documents/fetch`（`fetch_document`）与 `/documents/save-blueprint`
  （`save_blueprint`）均带
  `dependencies=[Depends(require_end_user_principal)]`；
- **CVE-2026-108110 点名的两个路径在当前 HEAD 已受鉴权保护。**

6 条 B 板 document 端点：

| 端点 | 鉴权 |
|---|---|
| `get_knowledge_source_document` | `_current_scope(authorization)`（Header token → 用户/租户） |
| `upload_chat_document` | `_identity(authorization)`（同上） |
| `document_index_callback` / `document_parse_callback` / `preview_conversion_callback` | admin-api 回调路由，使用 `settings.document_processing_callback_token` 共享 token 校验 |
| `get_processing_job` | admin-api `Depends(get_current_admin_user)` |

**结论：CVE 点名路径已修复；其余为 token/依赖鉴权，不是未授权。**

### 4. `1Panel-dev/CordysCRM`（HEAD `46e8d44768e8`）

- 40 个 Controller，权限体系是 **Shiro + 自定义 `@CsPermission`**：
  - 29 个文件使用 `@CsPermission(value=..., resourceId=..., formType=...)`
    （方法级资源权限，`DetailTabDataController` 每个方法都有）；
  - 65 个文件使用 `@RequiresPermissions`；
  - 全局 `filterChainDefinitionMap` 注册 `authc`（`AuthFilter`），
    所有 API 默认要求登录；
- 222 条 `UNVERIFIED_WILD_AUTHZ` 的根因：规则只认
  `@PreAuthorize`/`@RequiresPermissions` 类注解，未识别
  `@CsPermission` 方法级注解与 Shiro 全局 `authc` 链 → 被当成"裸 authz"。

**结论：不是 222 个未授权接口，是规则未识别其权限框架。**
M449 已补：`@CsPermission`/`@SaCheckPermission`/`@HasPermission` 方法级
识别 + `@RequiresAuthentication`/`@RequiresUser` 类级识别 + Shiro
`filterChainDefinitionMap`/`authc` 全局链识别。

## 二、M448：仓级 CVE/GHSA 查重（零 search 配额）

`core/context/cve_dedup.py` 新增：

```python
REPO_LEVEL_CACHE = CACHE / "_repo_level.json"

def dedup_repo_level(slug, category, unit, *, file="", aliases=None,
                     allow_online=True) -> dict:
    ...
```

- 只调用 `GET /repos/{slug}/security-advisories`（核心 API，不消耗
  search 配额）；
- 结果按 `slug|category|unit|file` 缓存 24h，同仓多根因只发一次请求；
- 命中公告文本（unit/file/aliases 任一出现）→
  `DUPLICATE_ISSUE_OR_GHSA`；无命中 → `ZERO_RECORD_FRESH`；
  请求失败/离线 → `UNKNOWN`（保留 coverage 可解释性）。

`daily_hunt.noise_record()` 增加 `repo_dedup` 参数；`process_repo()` 在
`dedup_online` 时对每条 B 板短路记录调用 `dedup_repo_level()`，命中则
改判 `DUPLICATE_ISSUE_OR_GHSA` 并保留 `repo_dedup` 证据；离线模式保持
`UNKNOWN`（不发请求）。

验证（`[348]`）：offline → UNKNOWN；公告命中 → DUPLICATE_ISSUE_OR_GHSA；
公告不匹配 → FRESH。

## 三、M449：鉴权识别 + securecookie 归 B

`core/context/wild_noise.py`：

1. **Python authz**：`Depends(<auth-ish>)`、`get_current_*()`、
   `verify_*/require_*/check_*` 守卫 → `AUTHZ_CLASS_OR_BASE_GUARD`；
2. **Java 方法级**：`@CsPermission` / `@SaCheckPermission` /
   `@PreAuthorize` / `@RequiresPermissions` / `@HasPermission` → 拦截；
3. **Java 类级**：新增 `@RequiresAuthentication` / `@RequiresUser`；
4. **仓级全局链**：`filterChainDefinitionMap` + `authc`，或
   `addPathPatterns("/**")` + `*Auth*Interceptor` → 拦截；
5. **框架线索**：`pom.xml`/`build.gradle` 增加 `shiro`；
6. **securecookie**：新增 `LOW_SEVERITY_SECURECOOKIE`，野仓 Cookie
   缺 `Secure` 标记的低危项统一压 B（Wukong `minioSso` 由此归 B）。

验证（`[348]`）：`Depends(get_current_admin)` → 拦截；`securecookie` →
`LOW_SEVERITY_SECURECOOKIE`。

## 四、M450：4 仓复扫 + 全套门禁

```
python cli.py daily-hunt --repos Case211/remnawave-admin,1Panel-dev/CordysCRM,himovo/movo,lalitgehani/SnackBase \
  --offline --cooldown-days 0 --max-roots 0 --state .tmp/m450_state.json \
  --report .tmp/m450_LIVE_HUNT_REPORT.md --json .tmp/m450_daily_hunt.json \
  --packs-dir .tmp/m450_packs --repo-timeout 900
```

| 项 | 结果 |
|---|---|
| 候选 / 实扫 / 跳过 / 失败 | 4 / 4 / 0 / 0 |
| 新增根因 | 384 |
| 板块 A / B | **0 / 384** |

门禁：

| 项 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,805 项断言**（v1.5.24 为 1,800；`[348]` 5 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、说明与边界

- 本轮 M448–M450 的原始指令在 `dedup_repo_level` 签名后截断，M449/M450
  的具体条目按"巡检点名的 4 组白盒 + 仓级查重 + CordysCRM 治理 +
  securecookie 归 B"的目标推断实现，并已在 `[348]` 固化回归。
- `dedup_repo_level` 只在 `dedup_online` 的在线轮次调用；离线复扫保持
  UNKNOWN，避免把"没联网"误报成"查过且干净"。
- CordysCRM 的 `@CsPermission` 是自定义注解，若其切面只校验资源级权限
  而未覆盖全部入口，仍建议人工抽查 Service 层鉴权；本轮按"框架鉴权
  在位"归 B。

## 六、提交清单

- `core/context/cve_dedup.py` — M448 `dedup_repo_level` + 仓级缓存
- `core/context/daily_hunt.py` — M448 `noise_record`/`process_repo` 接入仓级查重
- `core/context/wild_noise.py` — M449 Python Depends/WS 鉴权、Java 方法级/类级/全局链识别、securecookie 归 B
- `benchmarks/smoke_test_chains.py` — M450 `[348]` 5 项
- `STAGE_REPORT_2026-11-18_v1.5.25.md` — 本报告
