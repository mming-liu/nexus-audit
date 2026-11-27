# 候选 08：youlaitech/youlai-boot 认证后任意文件删除（防御修复包）

> 模板版本：v1.5.34 ｜ 状态：**候选（已归档，未外发）**
> 审计 HEAD（main）：`1b30213626c996445c206f8ddb3dfb8e104b1170`（2026-11-27 00:57 +0800）
> 最近正式 release：`v2.21.1`（2025-03-20，commit `65d06987634a420a652695d21262ac7bf68622be`）
> 结论：**CWE-862**（缺功能级授权，所有存储实现）+ **CWE-22**（仅本地存储启用时，`filePath` 穿越）
> CVSS 3.1：**8.1（High）**——启用本地存储的部署；默认对象存储部署下 CWE-22 不适用，
> 仅剩 CWE-862 的对象删除面（≈6.5 Medium）。
> ⚠ **触发前提**：2.x 需 `oss.type=local`，4.x 需 `storage.type=local`；两代默认值分别是
> **`minio`** 与 **`s3`**。报告正文必须显式写明，不得表述为「默认部署可任意文件删除」。
> 说明：本文件**只含代码定位与防御补丁**，不含攻击载荷、利用脚本或 `curl` 攻击命令。

## 0. 三项交单前核验（2026-11-27，只读）

| # | 核验项 | 结果 | 对报告的影响 |
|---|---|---|---|
| 1 | `application*.yml` 的 `oss.type` 默认值 | **v2.21.1：`minio`**（`application-dev.yml:100` / `-prod.yml` 同）；main 4.x 已改名 **`storage.type: s3`**（`application-dev.yml:48`） | 必须写成「启用本地存储时可触发」；`LocalFileService(Impl)` 只在 `local` 时装配 |
| 2 | 最新正式 release tag 是否包含该端点 | **包含**。`v2.21.1` 有 `FileController.deleteFile` 与本地删除 sink（路径为 `shared/file/...`，与 main 的 `system/...` 不同） | **不是 open-wes 那种未发布分支问题**；受影响版本可写 `through v2.21.1` |
| 3 | Issues / 全网查重 | 仓库 **19 条 Issue（6 open / 13 closed）**逐条看过，`deleteFile`/`文件删除`/`filePath`/`任意文件` 关键词 **0 命中**；全局 `"/api/v1/files"` 的 6 条命中全部是 **youlai-mall**（另一项目） | 与现有 CVE/Issue **零撞车** |

## 1. 仓库与披露入口

| 项 | 值 |
|---|---|
| owner/repo | `youlaitech/youlai-boot`（Gitee 镜像：`youlaiorg/youlai-boot`） |
| 审计 HEAD | `1b30213626c996445c206f8ddb3dfb8e104b1170`（main） |
| 最近正式 release | `v2.21.1` → `65d06987634a420a652695d21262ac7bf68622be`（2025-03-20） |
| Stars / Forks | 375 / 141（2026-11-27，只读 API） |
| 默认分支 | `master` |
| 私密 Advisory | **未开启**（`private-vulnerability-reporting: {"enabled": false}`） |
| `SECURITY.md` | **不存在**（GitHub / Gitee 均无） |
| 建议披露入口 | **MITRE CVE.org（CNA-LR）**：https://www.cve.org/ReportRequest/ReportRequestForNonCNAs ；公开 Issue 可选但会立即暴露，不作为首选 |
| CNA 归属 | `youlaitech` 无独立 CNA；历史编号分别由 MITRE / VulDB / VulnCheck 签发，**走 MITRE 流程在受理范围内** |

## 2. 同仓鉴权基线（为什么是"漏加"，不是"设计如此"）

1. `SecurityConfig`：`requestMatchers(ignoreUrls).permitAll()` + **`anyRequest().authenticated()`**；
   `/api/v1/files` **不在** `permit-all-urls`（`application-dev.yml` 的 `security.permit-all-urls`
   只有 auth/forms/health/realtime/swagger）→ 该端点**要求登录**，但不再要求任何权限。
2. 同仓破坏性接口普遍使用 `@PreAuthorize("@ss.hasPerm('sys:xxx:delete')")`：
   `ConfigController.java:82`（`sys:config:delete`）、`UserController.java:108`（`sys:user:update`）等。
3. `FileController` 的 `uploadFile` / `deleteFile` **两代都无任何 `@PreAuthorize`**（见 §3）。

→ 结论：项目已有成熟的函数级鉴权机制，文件删除接口属**遗漏**。

## 3. 受影响代码

### 3.1 `v2.21.1`（正式 release）

`src/main/java/com/youlai/boot/shared/file/controller/FileController.java:46-52`

```java
46  @DeleteMapping
47  @Operation(summary = "文件删除")
48  @SneakyThrows
49  public Result<?> deleteFile(
50          @Parameter(description = "文件路径") @RequestParam String filePath
51  ) {
52      boolean result = fileService.deleteFile(filePath);
```

`src/main/java/com/youlai/boot/shared/file/service/impl/LocalFileService.java:31,79-90`

```java
31  @ConditionalOnProperty(value = "oss.type", havingValue = "local")
...
79  public boolean deleteFile(String filePath) {
80      //判断文件是否为空
81      if (filePath == null || filePath.isEmpty()) {
82          return false;
83      }
84      // 判断filepath是否为文件夹
85      if (FileUtil.isDirectory(storagePath + filePath)) {
86          // 禁止删除文件夹
87          return false;
88      }
89      // 删除文件
90      return FileUtil.del(storagePath + filePath);
91  }
```

### 3.2 `main` HEAD（4.15.1 线，未发布）

`src/main/java/com/youlai/boot/system/controller/FileController.java:55-61`

```java
55  @DeleteMapping
56  @Operation(summary = "文件删除")
57  @SneakyThrows
58  public Result<Void> deleteFile(
59          @Parameter(description = "文件路径") @RequestParam String filePath
60  ) {
61      boolean result = fileService.deleteFile(filePath);
```

`src/main/java/com/youlai/boot/support/file/service/impl/LocalFileServiceImpl.java:28,66-73`

```java
28  @ConditionalOnProperty(value = "storage.type", havingValue = "local")
...
66  public boolean deleteFile(String filePath) {
67      if (filePath == null || filePath.isEmpty()) {
68          return false;
69      }
70      if (FileUtil.isDirectory(path + filePath)) {
71          return false;
72      }
73      return FileUtil.del(path + filePath);
74  }
```

### 3.3 配置前提（必须写进任何对外描述）

| 版本线 | 属性 | 默认值 | 本地实现装配条件 | 证据 |
|---|---|---|---|---|
| 2.x（`v2.21.1`） | `oss.type` | **`minio`** | `oss.type=local` | `application-dev.yml:98-100`；`LocalFileService.java:31` |
| 4.x（main） | `storage.type` | **`s3`** | `storage.type=local` | `application-dev.yml:46-48`；`LocalFileServiceImpl.java:28` |

- 默认 `minio`/`s3` 时注入的是 `MinioFileService` / `S3FileService`，`FileUtil.del(path + filePath)` **不会执行**；
- 启用 `local` 是项目**支持并文档化**的部署选项（`storage.local.path: ./uploads/`，dev 配置即给了本地路径示例），
  因此不是"不可达的死配置"，但属于**非默认配置**。

### 3.4 根因与影响

- **CWE-862（缺失授权，全存储类型）**：`/api/v1/files` 只要求认证，不要求任何 `file:*` 权限；
  任一低权登录用户可删除**任意路径**（本机）或**桶内任意对象**（`MinioFileService.deleteFile`（2.x）/
  `S3FileServiceImpl.deleteFile`（4.x）按 key 删除，同样无归属校验）。
- **CWE-22（路径穿越，仅 `local`）**：`filePath` 直接来自 `@RequestParam`，`storagePath + filePath`
  字符串拼接后交给 `FileUtil.del`，无 `normalize()` / 前缀校验；`../../` 可删除存储根之外的任意文件。
  `FileUtil.isDirectory` 只挡住目录，不挡穿越。
- 影响：数据丢失 / 应用不可用（可删配置、上传物、运行期文件）；不涉及读取或代码执行。
- CVSS 3.1：
  - 启用本地存储：`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` = **8.1（High）**；
  - 默认对象存储：`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` ≈ **6.5（Medium）**。

## 4. 防御修复补丁（Unified Diff）

> 设计原则：① 用同仓既有的 `@ss.hasPerm(...)` 做函数级授权；② 服务层
> `normalize()` + `startsWith(base)` 阻断穿越与根目录误删；③ 不改变正常删除行为。

### 4.1 控制器（两代同形，均需改）

```diff
--- a/src/main/java/com/youlai/boot/.../FileController.java
+++ b/src/main/java/com/youlai/boot/.../FileController.java
@@
     @DeleteMapping
     @Operation(summary = "文件删除")
+    @PreAuthorize("@ss.hasPerm('sys:file:delete')")
     @SneakyThrows
     public Result<Void> deleteFile(
```

说明：`sys:file:delete` 需在 `sys_menu` 中登记（项目现有文件模块没有权限点）；
若不想新增权限点，可退化为管理员专属：`@PreAuthorize("hasRole('ROOT')")`
（项目角色 authority 前缀为 `ROLE_`，`ROOT_ROLE_CODE = "ROOT"`）。

### 4.2 本地存储服务（`v2.21.1` 的 `LocalFileService` / main 的 `LocalFileServiceImpl`）

```diff
--- a/.../LocalFileService(Impl).java
+++ b/.../LocalFileService(Impl).java
@@
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
@@
     public boolean deleteFile(String filePath) {
         if (filePath == null || filePath.isEmpty()) {
             return false;
         }
-        if (FileUtil.isDirectory(storagePath + filePath)) {
+        Path base = Paths.get(storagePath).toAbsolutePath().normalize();
+        Path target = base.resolve(filePath).normalize();
+        // 绝对路径 / ../ 穿越 / 根目录本身 一律拒绝
+        if (target.equals(base) || !target.startsWith(base)) {
+            return false;
+        }
+        if (Files.isDirectory(target)) {
             return false;
         }
-        return FileUtil.del(storagePath + filePath);
+        try {
+            return Files.deleteIfExists(target);
+        } catch (IOException e) {
+            log.error("文件删除失败", e);
+            return false;
+        }
     }
```

> 字段名按版本替换：`v2.21.1` 是 `storagePath`，main 是 `path`（`@ConfigurationProperties(prefix = "storage.local")`）。

### 4.3 建议的后续加固（非本单必需）

- 登记上传物 owner（`FileInfo` 增加 `uploader_id`），删除时校验"上传者本人或管理员"，
  从根上消除 CWE-862 的横向越权面；
- 对象存储实现（MinIO/S3）对 `fileName` 做 key 前缀白名单，拒绝跨租户 key。

## 5. Step 3：CVE.org 表单 6 个框

| 字段 | 预填值 |
|---|---|
| Vendor | youlaitech |
| Product | youlai-boot |
| Version affected | through v2.21.1 (commit 65d06987634a420a652695d21262ac7bf68622be) and main branch 1b30213626c996445c206f8ddb3dfb8e104b1170, **when local file storage is enabled** (`oss.type=local` in 2.x / `storage.type=local` in 4.x) |
| Vulnerability Type | CWE-862 (primary) / CWE-22 (local-storage path traversal) |
| Affected Component | FileController.deleteFile (`DELETE /api/v1/files`) → LocalFileService.deleteFile / LocalFileServiceImpl.deleteFile |
| Suggested Description | youlai-boot's file deletion endpoint (DELETE /api/v1/files) requires authentication but performs no function-level authorization, so any authenticated low-privileged user can delete arbitrary files or object-storage keys. When local storage is enabled (`oss.type=local` in 2.x / `storage.type=local` in 4.x), the caller-controlled `filePath` is concatenated to the storage root and passed to `FileUtil.del` without normalization or prefix validation, allowing path traversal and deletion of arbitrary files outside the upload directory. CWE-862 + CWE-22; PR:L. |

## 6. Step 3B：CVE Services（MITRE CNA-LR）逐框填写

| CVE Services 字段 | 预填值 |
|---|---|
| Problem types | CWE-862（Missing Authorization）；CWE-22（Path Traversal，本地存储时） |
| Vendor or project | youlaitech |
| Product name | youlai-boot |
| Purl | pkg:github/youlaitech/youlai-boot |
| Source repository | https://github.com/youlaitech/youlai-boot （Gitee 镜像 https://gitee.com/youlaiorg/youlai-boot） |
| Program routines (OSS) | FileController.deleteFile；LocalFileService.deleteFile / LocalFileServiceImpl.deleteFile |

### Versions 表（versionType 选 custom）

| 列 | 值 |
|---|---|
| Affected | y |
| Version (or start of a range) | 0 |
| <= Version (range) | through v2.21.1 (commit 65d06987634a420a652695d21262ac7bf68622be) and main 1b30213626c996445c206f8ddb3dfb8e104b1170；仅 local 存储配置 |
| Default status | y |

### Description（整段粘贴）

~~~text
youlaitech/youlai-boot (through v2.21.1, commit 65d06987634a420a652695d21262ac7bf68622be, and main branch 1b30213626c996445c206f8ddb3dfb8e104b1170) exposes DELETE /api/v1/files (FileController.deleteFile) to any authenticated user without a function-level authorization check. The endpoint forwards a caller-supplied `filePath` to the storage service. When local storage is enabled (`oss.type=local` in 2.x, `storage.type=local` in 4.x), LocalFileService/LocalFileServiceImpl concatenates the storage root with `filePath` and calls FileUtil.del without normalize() or a prefix check, so `../` sequences delete arbitrary files outside the upload directory (CWE-22). With the default object-storage configuration (minio in 2.x, s3 in 4.x) the traversal primitive is not reachable, but the missing authorization still lets any authenticated user delete arbitrary object keys (CWE-862). The project already uses @PreAuthorize("@ss.hasPerm('sys:xxx:delete')") on other destructive endpoints, indicating an omission rather than intended design. The issue is distinct from CVE-2026-110215 (RoleController.updateRoleMenus), CVE-2026-110216 (UserController.updateUserStatus), CVE-2026-7672 (order SQL injection) and CVE-2025-66735/66736/55471/55469.
~~~

### 过审三要素

- 根因句：`deleteFile` 缺少同仓既有的 `@PreAuthorize("@ss.hasPerm('sys:file:delete')")` 函数级授权，
  且本地存储实现把用户可控 `filePath` 直接拼接到存储根后交给 `FileUtil.del`。
- 影响句：任一登录用户可删除任意文件/对象；启用本地存储时可 `../` 穿越删除存储根之外的文件。
- 修复状态句：v2.21.1 与 main `1b30213` 均未修复；默认配置为 minio/s3，穿越面需 local 存储。

### 表单问题区固定答法

| 问题 | 答法 |
|---|---|
| 确认已阅读 CNA-LR 主页信息 | yes |
| CVE partner onboarding 注册组织 | 留空（个人报告者） |
| 是否已联系供应商要 CVE | no（仓库无私密 Advisory/SECURITY.md；可先发公开 Issue 或直接走 MITRE） |
| 是否现在就在 CVE List 公开 | yes |
| Additional Information | 仅 local 存储配置可触发 CWE-22；默认 minio/s3 下为 CWE-862。请与 CVE-2026-110215/110216 区分 |

### Tags

若厂商 7 天不回应，加 `unsupported-when-assigned`。

### 单 CNA 红线

Do not merge with CVE-2026-110215（`RoleController.updateRoleMenus`）、CVE-2026-110216
（`UserController.updateUserStatus`）、CVE-2026-7672（`order` SQLi）、
CVE-2025-66735/66736（GHSA-8vpj-fwmm-xmcm）、CVE-2025-55471/55469。
One CVE for `FileController.deleteFile` only.

## 7. 提交前检查

- [ ] 确认报告正文写明「**仅启用本地存储（`oss.type=local` / `storage.type=local`）时** CWE-22 可达」；
- [ ] 受影响版本写 `through v2.21.1` + main `1b30213`，不要写「所有版本」；
- [ ] 渠道：优先 MITRE CVE.org（无私密 Advisory/SECURITY.md）；若先发 GitHub Issue，正文不贴攻击载荷；
- [ ] 与 CVE-2026-110215/110216 做端点级区分，避免被判同根因重复；
- [ ] 补丁同时覆盖 v2.21.1（`shared/file/...`）与 main（`system/...` + `support/file/...`）两套路径；
- [ ] 若维护者要求 PR，只提交 §4 的两段 diff，不附带任何利用代码。
