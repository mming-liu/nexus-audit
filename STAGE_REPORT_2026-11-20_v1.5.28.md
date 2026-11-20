# STAGE REPORT · v1.5.28（M459–M462：假 DUPLICATE 回归 / 巡猎提速 / 4 条焦点白盒）

> 日期：2026-11-20 ｜ 基线：v1.5.27（`b0b4785`）
> 主题：修复 `representative` 未作为 dedup unit 导致的 373 条假
> `DUPLICATE_CVE/ISSUE`；加固通用文件名匹配与缓存键；豁免系统更新包
> 上传误压 B；侦察阶段剔除 >150 MB 巨型仓、仓级查重内存缓存 + 一次
> flush、clone 超时收紧；4 条焦点白盒精核。
> 结论：门禁 smoke **1,817** / triage 16/16 / doctor PASS；
> `[351]` 5 项固化回归。

## 一、M459：假 `DUPLICATE_CVE/ISSUE` 回归 + 更新包误降噪

### 1. `process_repo()` 的 dedup unit

```python
# 旧：_unit = str(rc.get("unit") or rc.get("unit_name") or "")
_unit = str(rc.get("unit_name") or rc.get("representative")
            or rc.get("unit") or "")
```

`blocked_roots` 的 `rc` 只有 `representative`（方法名）时，旧代码取到空串，
`dedup_repo_level()` 退化成"整仓任意公告都算命中"，一天刷出 373 条假
`DUPLICATE_CVE/ISSUE`。现在与 `_root_view()`/`_base_record()` 完全一致。

### 2. `_unit_in_text()` 通用文件名门禁

- 复用既有 `_GENERIC_FILE_STEMS`（fastapi/flask/django/views/routes/api/
  app/main/index/tools/utils/config/models/...），并补入 `admin`；
- 末尾 `not key and stem` 分支增加 `stem not in _GENERIC_FILE_STEMS`；
- `_class_wide_match()` 在"unit 为空 + 通用文件名"时同样跳过，避免
  `admin.py` 被 "Vulnerability in admin panel" 这类描述连坐。

### 3. 缓存键升级

```python
key = f"v2|{slug}|{category}|{unit}|{file}"
```

今天因 `_unit=""` 写脏的 373 条旧缓存自动失效（旧键无 `v2|` 前缀）。

### 4. 系统更新/插件/固件包上传豁免

```python
_EXEC_PACKAGE_UPLOAD_RE = re.compile(
    r"(?:update_package|upgrade|firmware|install_plugin|install_skill|"
    r"hotfix|patch_package)", re.I)
```

`unrestricted_upload` 的 `NON_EXECUTABLE_UPLOAD` / `UPLOAD_SERVING_ONLY`
分支在 unit/file 命中该正则时整体跳过，`upload_update_package` 不再被
当成"不可执行普通文件"压 B。

## 二、M460：巡猎提速

1. **侦察剔除 >150 MB 巨型仓**（`target_scout._parse_search`）：

   ```python
   if int(it.get("size") or 0) > 150000:   # GitHub size 单位 KB
       dropped_tool += 1
       continue
   ```

2. **仓级查重内存缓存**（`cve_dedup`）：

   - `_REPO_LEVEL_CACHE_MEMO` + `_REPO_LEVEL_MEMO_PATH`：首次调用读一次
     磁盘，之后只读写内存；
   - `_REPO_LEVEL_DIRTY`：命中/未命中只标脏；
   - `flush_repo_level_cache()`：每仓 `blocked_roots` 循环结束后由
     `process_repo()` 调用一次，写盘从 1,047 次降到每仓 1 次。

3. **超时收紧**：

   - `upstream_sync.sync_repo()` 默认 `clone_timeout` 180 → **120**；
   - `cve_dedup.query_nvd()` 已是 `timeout=8.0`（本轮确认，无需再改）；
   - 定时任务建议：09:00 调度把 `--limit 10 --evict-cache` 调整为
     `--limit 6`（或 `--limit 8`），磁盘充足时去掉 `--evict-cache`
     复用增量 `git fetch`，预计把 40–68 分钟压回 ~15 分钟级。

## 三、M461：4 条焦点白盒精核（0 外部提交）

### 1. `zhinianboke/xianyu-auto-reply`

- `backend-web/app/api/routes/upload.py:15` `upload_image`：
  `Depends(get_current_user)` 强制登录；`content_type` 必须 `image/*`；
  `image_manager.save_image()` 校验图片数据后用
  `{md5}_{uuid8}.{扩展名}` **服务端生成文件名**落盘，不接受原始文件名
  拼接路径；
- `product_publish.py` / `user_settings.py` / `cards.py` / `keywords.py`
  的入口统一 `Depends(get_current_active_user)`；
- **结论：有鉴权 + 服务端重命名，非未授权上传/穿越。**

### 2. `ithtelab/workbuddy-manager` `upload_update_package`

`server/routers/system.py:70`：

```python
@router.post('/update-package')
async def upload_update_package(
    request: Request, file: UploadFile = File(...),
    expected_sha256: str = Form(''),
    user: dict = Depends(security.require_session_admin),
):
```

- **管理员会话**依赖 `require_session_admin`；
- sha256 **默认必填**（仅 `WB_ALLOW_UNVERIFIED_PACKAGE=1` 可显式放行）；
- 先写 `.part`，校验大小上限、tar.gz 可解、包内 `.version`、sha256 后
  原子替换；
- **结论：不是未授权 RCE；是管理员+摘要校验的离线升级包上传。**
  M459 的豁免避免它被 `NON_EXECUTABLE_UPLOAD` 误压，保留人工复核入口
  是正确的（升级包本身是可执行面）。

### 3. `IBM/mcp-context-forge` `get_metrics`

`mcpgateway/main.py:10281`：

```python
@metrics_router.get("", response_model=MetricsResponse)
@require_permission("admin.metrics")
async def get_metrics(db: Session = Depends(get_db),
                      user=Depends(get_current_user_with_permissions)):
```

- 鉴权：`Depends(get_current_user_with_permissions)`；
- 授权：`@require_permission("admin.metrics")`；
- 无请求体模型绑定（纯 GET 聚合查询），**`mass_assignment` 为假阳**。

### 4. `IBM/mcp-context-forge` `admin_logout_post`

`mcpgateway/admin.py:5529` → `_admin_logout(request)`：清理认证 Cookie、
按 POST/GET 场景返回 303/200；这是**登出**端点，不涉及 JWT 验签逻辑。
**`jwt_weakness` 为假阳**（规则把 `_admin_logout` 里的 cookie 清理误判为
JWT 处理）。

## 四、M462：门禁 `[351]` + 全套验证

| 断言 | 结果 |
|---|---|
| `_unit_in_text("", "mcpgateway/admin.py", "Vulnerability in admin panel")` → False | ✅ |
| `process_repo` 用 `representative` 作为 dedup unit（`admin_get_logs`） | ✅ |
| `upload_update_package` 不返回 `NON_EXECUTABLE_UPLOAD` | ✅ |
| `_parse_search` 剔除 size=250000、保留 size=12000 | ✅ |
| 20 次 `dedup_repo_level` 只在 `flush_repo_level_cache()` 时写盘 1 次 | ✅ |

| 门禁 | 结果 |
|---|---|
| `smoke_test_chains.py` | **PASS，1,817 项断言**（v1.5.27 为 1,812；`[351]` 5 项） |
| `triage_fallbacks.py --check-floor` | **16/16 靶场地板全绿** |
| `cli.py doctor` | **PASS（12 段全绿）** |

## 五、说明

- `dedup_repo_level` 的 `checked_at`/`sources` 留证与 `STATUS_CVE` 同步
  沿用 v1.5.27；本轮只加内存缓存与 flush，不改变返回语义。
- `[351]` 的 `process_repo` 夹具用 mock 的 `scan_repo`/`classify`/
  `dedup_repo_level` 验证 unit 取值，不依赖真实仓库。
- 上一轮 v1.5.27 的 workflow 文件改动仍在工作树中（token 缺 `workflow`
  scope），远端工作流保持 `disabled_manually`；补 scope 后即可提交。

## 六、提交清单

- `core/context/daily_hunt.py` — M459 representative unit + M460 flush 接入
- `core/context/cve_dedup.py` — M459 通用文件名/缓存键 v2 + M460 内存缓存/flush
- `core/context/wild_noise.py` — M459 更新包上传豁免
- `core/context/target_scout.py` — M460 >150 MB 巨型仓剔除
- `core/context/upstream_sync.py` — M460 clone_timeout 120
- `benchmarks/smoke_test_chains.py` — M462 `[351]` 5 项 + 超时断言 120
- `STAGE_REPORT_2026-11-20_v1.5.28.md` — 本报告
