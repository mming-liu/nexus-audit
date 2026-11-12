# redcell WebSocket 路由人工精核（M357，2026-11-12）

> 结论：**5 条全部是误报，不交单。** 六条 WebSocket 路由在 `accept()` 之前
> 都做了 JWT Cookie 校验；生产部署下 JWT 密钥是 48 字节随机串且不可为空；
> API 容器不发布宿主机端口，只经 Caddy 反代暴露。不存在"未授权 WebSocket
> RCE / 设备控制"。

## 1. 核对对象

| 项 | 值 |
|---|---|
| 仓库 | `martian56/redcell`（REDCELL 红队编排平台） |
| 审计 HEAD | `01afb711829d31be7e82bef31d6edd4046d02ac0`（v0.12.17） |
| 复核日期 | 2026-11-12 |
| 待核条目 | `ws_shell` / `ws_browser` / `ws_device` / `ws_events` / `ws_chat`（5 条 authz） |
| 源码 | `apps/api/app/routers/ws.py` |

## 2. 逐路由鉴权核对

`apps/api/app/routers/ws.py` 里 **6 条** WebSocket 路由（含报告未列出的
`ws_notifications`），每一条的第一句都是 `_authed(ws)`，未通过即
`close(code=4401)`，**在 `accept()` 之前**：

| 路由 | 定义行 | 鉴权行 | `accept()` 行 |
|---|---|---|---|
| `ws_events` | 59 | 61 | 64 |
| `ws_chat` | 68 | 70 | 73 |
| `ws_notifications` | 77 | 79 | 82 |
| **`ws_shell`** | **86** | **88** | **91** |
| **`ws_browser`** | **137** | **141** | **153** |
| **`ws_device`** | **200** | **207** | **250** |

`_authed()` 的实现（同文件 22–30 行）：

```python
def _authed(ws: WebSocket) -> bool:
    token = ws.cookies.get(COOKIE_NAME)          # rc_session
    if not token:
        return False
    try:
        jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        return True
    except jwt.PyJWTError:
        return False
```

- Cookie 名 `rc_session`，`httponly=True`、`samesite="lax"`、生产
  `secure=True`（`packages/core/redcell_core/security.py:16,32-44`）。
- 签发只发生在 `/api/v1/auth/login`：bcrypt 校验密码后才 `issue_cookie`
  （`security.py:20-44`）。
- 同一 token 在 HTTP 侧由 `current_user` 依赖再校验一次"用户仍存在"
  （`security.py:51-63`）；所有业务 router（`resources` / `files` /
  `reports` / `ai` / `system` …）都是 `APIRouter(dependencies=[Depends(current_user)])`，
  只有 `ws.py` 例外，所以它自己写了 `_authed`。
- **JWT 密钥不可为空**：`config.py:98-128` 的 `_resolve_secrets` 在
  `env != "dev"` 时，`REDCELL_JWT_SECRET` 缺失/为空直接 `raise ValueError`；
  compose 的 `init-secrets` 用 `secrets.token_urlsafe(48)` 生成
  （`docker-compose.yml`）。

> 注：审计侧把它判成 `UNVERIFIED_WILD_AUTHZ`（无兄弟鉴权反差 → 进 B 板）
> 是**保守但方向正确**的：没有 A 板席位。人工精核后确认，连"疑似漏鉴权"
> 都不成立。

## 3. 部署与监听边界

| 组件 | 暴露方式 | 证据 |
|---|---|---|
| `caddy` | 宿主机 `80:80` / `443:443` / `443:443/udp` | `docker-compose.yml` ports |
| `api` | **不发布宿主机端口**（仅容器内 8080） | `api` 服务无 `ports:`，healthcheck 打 `localhost:8080` |
| 反代 | `handle /api/* → reverse_proxy api:8080` | `docker/caddy/Caddyfile` |
| `web` | 静态前端，`api` 之外的请求 | `docker/web/nginx.conf` |

`docker-compose.local.yml` 只把 `REDCELL_COOKIE_SECURE` 置 false（本机 http
调试），不改变端口发布；`docker-compose.dev.yml` 只发布 postgres/redis/
seaweedfs，不发布 api。也就是说：**WebSocket 只能经 Caddy 的 `/api/*` 到达，
且必须先有登录 Cookie。**

## 4. `ws_shell` 到底在哪儿开 shell

1. `ws_shell` 只做**只读订阅**：`_pump()` = `_forward`（订阅
   `shell:{shell_id}` 转发给浏览器）+ `_drain`（丢弃客户端上行）。
2. 键盘输入走 HTTP `POST /api/v1/shells/{shell_id}/write`
   （`routers/resources.py`，router 级 `Depends(current_user)`），
   发布到 `shellin:{shell_id}`。
3. 真正的执行在 worker 的 operator terminal（`packages/core/redcell_core/engine/opshell.py`）：
   - `LocalDockerBackend`：在 `redcell-opsh` 容器里逐条 `docker exec`；
   - `SSHBackend`：在配置的 VPS 上执行（`ssh-vps` 模式）。
4. 输出经 `shell:{shell_id}` 回到 `ws_shell`。

所以"未授权即 RCE"的链条断在第一环：没有合法 JWT Cookie，`ws_shell` 在
`accept()` 前就 4401 关闭，既订阅不到 `shell:*`，也发不出 `shellin:*`。

## 5. 为什么不交单

- 鉴权存在且在生产配置下不可绕过（随机 48 字节密钥 + 非空强制）。
- 攻击面不是"公网直连 API"：只有 Caddy 的 80/443，且 `/api/*` 全走同一套
  Cookie 鉴权。
- `ws_browser` / `ws_device` 额外校验 session 存在与 `server_id` 归属
  （`ws.py:144-151`、`210-219`），不是裸设备控制。
- 因此这 5 条属于**知识库/静态规则误报**（Python 路由装饰器被当成"无鉴权
  入口"），不满足"未授权 + 可远程"两个要件。

## 6. 残余观察（不作为漏洞，供上游参考）

1. `_authed()` 只验签，不查用户是否仍存在；HTTP 侧 `current_user` 会查。
   已删除用户的 Cookie 在 `jwt_ttl_hours`（默认 168h）内仍能开 WS。
2. `ws_shell` 不校验 `shell_id` 是否存在/归属，任意已登录用户可订阅任意
   shell 输出。当前是单管理员单租户模型，不构成越权；若将来引入多用户，
   这里需要补 `session/shell` 归属校验。
3. 建议把 `_authed` 与 `current_user` 合并成同一套依赖（WebSocket 也支持
   `Depends`），避免两套鉴权语义漂移。

## 6b. M361 之后的流水线状态（2026-11-13 补记）

复核结论已沉淀成静态规则：

- `rule_detectors.ws_auth_guard()` 识别「`@*.websocket` + `accept()` 之前的
  守卫调用（`_authed` / `jwt.decode` / `authenticate` …）+ `close(4401/4403/1008)`」，
  `authz_verdict()` 直接判 **False**；
- `wild_noise` 新增 `WS_AUTH_PRESENT`，作为降噪层的兜底分类。

实测：对上面 6 个 WS 入口逐个跑 `authz_verdict` 全部 `False`；对这 5 条
authz 记录跑 `wild_noise.classify` 全部 `WS_AUTH_PRESENT` —— 它们不会再进
板块 B。

## 7. 查重状态

未进入交单流程，因此**未跑完整四来源查重**（NVD / CIRCL / GitHub Issue /
GHSA）；结论是"鉴权存在"，与公开记录无关。若上游后续修改为无鉴权，再按
`SUBMISSION_PLAYBOOK` 流程重新查重。
