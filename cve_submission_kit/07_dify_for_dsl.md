# 候选 07：wwwzhouhui/dify-for-dsl 未授权 SSRF（防御修复包）

> 模板版本：v1.5.20 ｜ 状态：**已提交（Issue #23，2026-11-17；仓库未开启私密报告）**
> 审计 HEAD：`d835ecfa6cbe45a70326e4e3336bbf73f2c68a17`（2026-11-11 23:58 +0800）
> 提交入口：GitHub Issue（私密报告已关闭，API 返回 403）
> 提交地址：https://github.com/wwwzhouhui/dify-for-dsl/issues/23
> 仓库：https://github.com/wwwzhouhui/dify-for-dsl ｜ Stars：3,884（2026-11-16）
> 说明：本文件**只含代码定位与防御补丁**，不含任何攻击载荷或 `curl` 攻击命令。

## 1. 仓库与归属核验

| 项 | 值 |
|---|---|
| owner/repo | `wwwzhouhui/dify-for-dsl` |
| HEAD | `d835ecfa6cbe45a70326e4e3336bbf73f2c68a17` |
| HEAD 时间 | 2026-11-11 23:58 +0800 |
| Stars | 3,884 |
| LICENSE / SECURITY | 仓库根目录未见 LICENSE / SECURITY.md |
| 归属 | `py/geekaiapp/` 由本仓作者 `zhouhui` 于 2025-07-31 首次提交（`c0463eb`），文件头无第三方版权声明；README 明确为作者自研 Dify DSL 工作流合集与配套服务，**不是直接搬运的第三方项目** |

## 2. 同仓鉴权反差（为什么是"漏加"）

`py/geekaiapp/g_jiekou.py` 中同类接口普遍挂 `Depends(verify_auth_token)`：

- `generate_video`（:653-654）：`auth_token: str = Depends(verify_auth_token)`；
- `generate_html`（:885）等同理；
- 唯独 `jm_image`（:242）**没有** `Depends(verify_auth_token)`。

`verify_auth_token`（`g_utils.py:536-550`）校验 `Authorization: Bearer <token>`，
无头/错 token 分别 401/403 —— 说明作者已有鉴权机制，`jm_image` 属遗漏。

## 3. 受影响代码（远端 HEAD）

### 3.1 `py/geekaiapp/g_jiekou.py:241-257`

```python
241 @router.post("/jimeng/img")
242 async def jm_image(request1: JMRequest):
243     headers = {
244         "Authorization": f"Bearer {request1.image_api_key}",
245         "Content-Type": "application/json",
246     }
247     data = {
248         "model": request1.model,
...
256     try:
257         response = requests.post(request1.image_generation_url, headers=headers, json=data)
```

- `JMRequest.image_generation_url`（`g_model.py:57`）来自请求体；
- 直接进入 `requests.post(...)`，无协议/域名/内网校验；
- 路由无鉴权依赖；
- `app.include_router(router, prefix="/api")`（:1040）；
- `uvicorn.run(app, host="0.0.0.0", port=port, ...)`（:1054）→ 全网卡监听。

### 3.2 `py/geekaiapp/wenshengtu1/jm1_jiekou.py:24-27`

```python
24 @router.post("/jimeng/img")
25 async def jm_image(request1: JMRequest):
26     headers = {
27         "Authorization": f"Bearer {request1.image_api_key}",
...
        response = requests.post(request1.image_generation_url, headers=headers, json=data)
```

同一模式；该文件 `uvicorn.run(app, host="0.0.0.0", port=16004)`（:65）。

### 3.3 影响

- 未授权调用者可让服务端向任意 `http/https` 地址发起 POST（请求头可控、
  body 可控），用于内网探测、访问云元数据、与内网服务交互；
- CWE-918；CVSS 3.1 粗估 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` ≈ **5.3（Medium）**。

## 4. 防御修复补丁（Unified Diff）

> 设计原则：与同仓 `generate_video` 一致的 `Depends(verify_auth_token)`；
> 请求 URL 只允许 `http/https`，并解析 DNS 后拒绝私有/回环/链路本地/保留地址。

### 4.1 `py/geekaiapp/g_jiekou.py`

```diff
--- a/py/geekaiapp/g_jiekou.py
+++ b/py/geekaiapp/g_jiekou.py
@@ -1,6 +1,9 @@
 import json
+import ipaddress
 import os
+import socket
 import sys
 import uuid
 from pathlib import Path
 from typing import List
+from urllib.parse import urlparse
@@ -240,8 +243,31 @@
+def _assert_public_http_url(url: str) -> None:
+    """只允许 http/https，且解析后不得指向私有/回环/链路本地地址。"""
+    parsed = urlparse(url or "")
+    if parsed.scheme not in ("http", "https"):
+        raise HTTPException(status_code=400, detail="Only http/https URLs are allowed")
+    host = parsed.hostname or ""
+    if not host:
+        raise HTTPException(status_code=400, detail="Invalid URL")
+    try:
+        infos = socket.getaddrinfo(host, None)
+    except OSError:
+        raise HTTPException(status_code=400, detail="URL host cannot be resolved")
+    for info in infos:
+        ip = ipaddress.ip_address(info[4][0])
+        if (ip.is_private or ip.is_loopback or ip.is_link_local
+                or ip.is_reserved or ip.is_multicast):
+            raise HTTPException(status_code=400, detail="URL host is not allowed")
+
 @router.post("/jimeng/img")
-async def jm_image(request1: JMRequest):
+async def jm_image(request1: JMRequest,
+                   auth_token: str = Depends(verify_auth_token)):
+    _assert_public_http_url(request1.image_generation_url)
     headers = {
```

### 4.2 `py/geekaiapp/wenshengtu1/jm1_jiekou.py`

```diff
--- a/py/geekaiapp/wenshengtu1/jm1_jiekou.py
+++ b/py/geekaiapp/wenshengtu1/jm1_jiekou.py
@@ -1,9 +1,13 @@
 import os
+import ipaddress
+import socket
 import sys
+from urllib.parse import urlparse
 
 import requests
 
 from geekaiapp.g_model import JMRequest
+from geekaiapp.g_utils import verify_auth_token
@@ -8,7 +12,7 @@
-from fastapi import FastAPI, APIRouter
+from fastapi import FastAPI, APIRouter, Depends, HTTPException
@@ -24,7 +28,24 @@
 @router.post("/jimeng/img")
-async def jm_image(request1: JMRequest):
+async def jm_image(request1: JMRequest,
+                   auth_token: str = Depends(verify_auth_token)):
+    _assert_public_http_url(request1.image_generation_url)
     headers = {
```

补丁说明：

1. 两个入口都补 `Depends(verify_auth_token)`，与 `generate_video` 对齐；
2. `_assert_public_http_url` 只放行 `http/https`，并拒绝私有/回环/链路本地/
   保留/组播地址（IPv4/IPv6 均覆盖）；
3. 不改变正常公网图片生成 API 的行为；
4. 残余风险：DNS rebinding 需要在 HTTP 客户端层做连接后校验（`allow_redirects=False`
   + 固定解析结果），本补丁未覆盖，可在后续迭代加。

## 5. 提交前检查

- [ ] 确认走 GitHub Issue 还是私密 Security Advisory（仓库无 SECURITY.md）；
- [ ] 正文只引用本文件的代码定位与补丁，不附攻击脚本；
- [ ] 附 HEAD `d835ecfa6cbe45a70326e4e3336bbf73f2c68a17` 与部署说明；
- [ ] 提醒维护者：`jm_image` 与 `jm1_jiekou` 两处都要改，避免只修一处。
