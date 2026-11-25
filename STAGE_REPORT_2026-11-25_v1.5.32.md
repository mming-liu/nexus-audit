# STAGE REPORT · v1.5.32（M475–M478：对象存储上传不判 XSS / 管理员专属入口降噪 / 11-25 A 板 4 条清零）

> 日期：2026-11-25 ｜ 基线：v1.5.31（`7f7bec1`）
> 主题：清零 11-25 巡猎的 4 条 A 板项（`liyupi/yu-picture` `FileController`
> 的 `header_injection` ×1、`unrestricted_upload` ×2、`xss` ×1）；对 4 条做
> 逐行白盒精核；新增门禁 `[355]`。
> 结论：smoke **1,859** 项断言 PASS / triage **16/16** / doctor PASS；
> 4 条 A 板项 **4 → 0**（1 条规则层不再产根因、2 条归 B、1 条管理员专属归 B）；
> 单仓离线复扫 **A=0 / B=37**。

## 〇、背景（11-25 09:00 巡猎）

| 项目 | 数值 |
|---|---|
| 起止 / 耗时 | 09:00 起 → 09:10:27 落盘（约 10 分钟） |
| 候选 / 处理 / 实扫 / 跳过 / 失败 | **23 / 14 / 6 / 8 / 0** |
| 新增根因 | 397（A **4** / B **393**） |
| 状态计数 | ZERO_RECORD_FRESH 4 / DUPLICATE_ISSUE_OR_GHSA **43** / UNKNOWN 350 |
| 候选口径 | 报告头 `候选仓：23（已处理 14）` 与 JSON 同源（M467 口径在生产持续生效） |

A 板 4 条全部落在同一个仓同一类文件（`liyupi/yu-picture`，HEAD `9e6a16e93fe2`）：

| # | 类目 | 根因 | 位置 |
|---|---|---|---|
| 1 | header_injection | `FileController.testDownloadFile` | `yu-picture-backend-ddd/.../FileController.java:70` |
| 2 | unrestricted_upload | `FileController.testUploadFile` | `yu-picture-backend-ddd/.../FileController.java:36` |
| 3 | unrestricted_upload | `FileController.testUploadFile` | `yu-picture-backend/.../FileController.java:37` |
| 4 | xss | `FileController.testUploadFile` | `yu-picture-backend-ddd/.../FileController.java:36` |

## 一、白盒精核（4 条同源，结论一致）

**1) 全部是管理员专属入口（已实锤执行）**

两个模块的同名方法都挂了自定义注解：

```java
@AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
@PostMapping("/test/upload")
public BaseResponse<String> testUploadFile(@RequestPart("file") MultipartFile multipartFile)
```

`annotation/AuthCheck.java` 只是 `@Target(METHOD)` 的注解；真正执行在
`aop/AuthInterceptor.java`：

```java
@Aspect @Component
public class AuthInterceptor {
    @Around("@annotation(authCheck)")
    public Object doInterceptor(ProceedingJoinPoint joinPoint, AuthCheck authCheck) {
        User loginUser = userService.getLoginUser(request);          // 未登录 → 异常
        UserRoleEnum mustRoleEnum = UserRoleEnum.getEnumByValue(authCheck.mustRole());
        if (mustRoleEnum == null) return joinPoint.proceed();
        ...
        if (UserRoleEnum.ADMIN.equals(mustRoleEnum)
                && !UserRoleEnum.ADMIN.equals(userRoleEnum)) {
            throw new BusinessException(ErrorCode.NO_AUTH_ERROR);    // 非管理员 → 403
        }
        return joinPoint.proceed();
    }
}
```

两个模块（`yu-picture-backend` 与 `-ddd`）的实现逐行同构。结论：**未登录/
普通用户到不了这 4 条路由**，它们不是远程未授权面。

**2) `testUploadFile`：文件落在腾讯 COS，不由本应用静态解析**

```java
String filename = multipartFile.getOriginalFilename();
String filepath = String.format("/test/%s", filename);   // COS key
File file = File.createTempFile(filepath, null);         // 本地临时文件（随机名）
multipartFile.transferTo(file);
cosManager.putObject(filepath, file);                    // 持久化 → COS
return ResultUtils.success(filepath);                    // JSON 包装体，不是 HTML
```

- `_repo_serves_uploads()` 实测 `False`：仓内没有把上传目录挂成静态资源；
- 同文件唯一的“对外提供”是 `testDownloadFile`，且响应头是
  `Content-Disposition: attachment` —— 浏览器只会下载，不会按上传扩展名渲染；
- 结论：**上传物不构成同源可执行面**（XSS/不可执行两条都据此判定）。

**3) `testDownloadFile`：`Content-Disposition` 拼接可控，但属管理员自伤**

```java
@AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
@GetMapping("/test/download/")
public void testDownloadFile(String filepath, HttpServletResponse response) {
    COSObject cosObject = cosManager.getObject(filepath);
    response.setHeader("Content-Disposition", "attachment; filename=" + filepath);
```

`filepath` 直接进入响应头且无 CRLF 过滤（`header_injection_verdict` 判 True 的
事实成立），但该路由要求 ADMIN；能触发的人本来就是管理员，注入目标也是
自己的响应 —— 属"管理员自伤/自配置"面，不是远程漏洞。

## 二、M475：规则层——对象存储上传 + JSON 包装体不判 XSS

`xss_verdict()` 的 2c 分支（上传扩展名可控 → XSS）新增两件可核对事实：

```python
_OBJECT_STORAGE_SINK_RE = re.compile(
    r"(?i)\b(?:putObject|putObjectRequest|cosClient|cosManager|ossClient|"
    r"s3Client|minioClient|uploadObject)\b")
_JSON_WRAPPER_RETURN_RE = re.compile(
    r"\b(?:BaseResponse|Result|ApiResponse|AjaxResult|CommonResult|"
    r"ResultUtils\.success)\s*[<(]")
...
    if _UPLOAD_SINK_RE.search(body) and XSS_UPLOAD_EXT_RE.search(body):
        if XSS_UPLOAD_EXT_ALLOWED_RE.search(body):
            return None
        if (_OBJECT_STORAGE_SINK_RE.search(body)
                and _JSON_WRAPPER_RETURN_RE.search(body)):
            return False
        return True
```

判据含义：上传物交给外部对象存储（COS/OSS/S3/MinIO），入口又只返回管理面
JSON 包装体 → 本应用从不按上传扩展名解析字节，浏览器拿不到同源 HTML 页面。
**不含对象存储的形态仍判 True**（`[355]` 有防放宽断言）。

| 切片 | 旧 | 新 |
|---|---|---|
| yu-picture `FileController.testUploadFile`（xss） | True | **False** |

## 三、M476：降噪层——管理员专属入口 + 对象存储上传

### 1. `ADMIN_ONLY_ENDPOINT`（`core/context/wild_noise.py`）

只认「自定义角色注解 + 同仓 AOP 实锤」，两层证据缺一不可：

```python
_ADMIN_GUARD_ANN_RE = re.compile(
    r"@\w+\s*\([^)]{0,240}?(?:mustRole|roles?|authorit(?:y|ies)|permission)"
    r"\w*\s*=\s*[^)]{0,120}?ADMIN", re.I)
_ADMIN_AOP_RE = re.compile(r"@Around\s*\(\s*[\"']@annotation\b", re.I)
# 仓内还需同时出现角色比较（UserRoleEnum.ADMIN.equals / hasRole('ADMIN')）
# 或拒绝（NO_AUTH_ERROR / 403），否则注解是死的，不降噪。
```

- 入口方法注解窗口用「行首修饰符 + 方法名」锚定（避免方法名先出现在注释/javadoc）；
- 带 `@Anonymous` / `@IgnoreToken` / `login=false` 等显式放行时优先放行；
- 只对 `header_injection` 与 `unrestricted_upload` 两类"管理员自伤/自配置"面生效；
  `sqli/cmdi/ssrf/pathtraver` 等即便管理员专属仍可能是真洞（管理员账号被拿下后
  可横向），**不套用**。

| 切片 | 旧 | 新 |
|---|---|---|
| yu-picture `FileController.testDownloadFile`（header_injection） | A | **B**（`ADMIN_ONLY_ENDPOINT`） |

### 2. 对象存储上传 → `NON_EXECUTABLE_UPLOAD` / `UPLOAD_SERVING_ONLY`

上传分支新增第三类落盘证据（与 M472 的 uuid4/序号名/重编码并列）：

```python
_OBJECT_STORAGE_UPLOAD_RE = re.compile(
    r"(?i)\b(?:putObject|putObjectRequest|cosClient|cosManager|ossClient|"
    r"s3Client|minioClient|uploadObject)\b")
...
_external_storage = bool(_OBJECT_STORAGE_UPLOAD_RE.search(_scope))
if ((_guarded or _whitelisted or _renamed or _external_storage)
        and not _model_loading and not _repo_serves_uploads(repo_root)):
```

上传物持久化在外部对象存储、本应用又不挂静态目录 → 不可执行；若同切片里还有
`Content-Disposition: attachment` 下载，则归 `UPLOAD_SERVING_ONLY`（更贴切）。

| 切片 | 旧 | 新 |
|---|---|---|
| yu-picture `testUploadFile`（ddd） | A | **B**（`UPLOAD_SERVING_ONLY`） |
| yu-picture `testUploadFile`（backend） | A | **B**（`UPLOAD_SERVING_ONLY`） |

## 四、M477：门禁 `[355]`（8 项，纯离线）

| 断言 | 结果 |
|---|---|
| M475：上传到 COS + JSON 包装体返回不判 XSS | ✅ |
| M475：同形态但只落本地（无对象存储）仍判 True（防放宽） | ✅ |
| M475：对象存储 + 扩展名白名单仍退 None（防放宽） | ✅ |
| M475：`@AuthCheck(ADMIN)` + AOP 角色校验 → `ADMIN_ONLY_ENDPOINT` | ✅ |
| M475：只有注解、仓内无 AOP 实锤 → 不降噪（防放宽） | ✅ |
| M475：无管理员注解的 header_injection 不降噪（防放宽） | ✅ |
| M476：上传物进 COS（无静态挂载）→ `NON_EXECUTABLE_UPLOAD` | ✅ |
| M476：只落本地且无防穿越/重命名 → 不降噪（防放宽） | ✅ |

## 五、M478：复扫与全套验证

### 1. 4 条 A 板项逐条重放（真实切片）

| 11-25 A 记录 | 旧（实盘） | 新 |
|---|---|---|
| `header_injection` `testDownloadFile`（ddd） | A | **B**（`ADMIN_ONLY_ENDPOINT`） |
| `unrestricted_upload` `testUploadFile`（ddd） | A | **B**（`UPLOAD_SERVING_ONLY`） |
| `unrestricted_upload` `testUploadFile`（backend） | A | **B**（`UPLOAD_SERVING_ONLY`） |
| `xss` `testUploadFile`（ddd） | A | 规则层 **False**（不再产根因） |

→ **A 板 4 → 0**。

### 2. 单仓离线复扫（`daily_hunt.run(offline=True, dedup_online=False)`，空 state）

```text
summary: {"total": 37, "board_a": 0, "board_b": 37}
daily  : {"candidates": 1, "processed": 1, "scanned": 1, "skipped": 0,
          "failed": 0, "new_roots": 37, "board_a": 0, "blocked": 37}
noise  : UPLOAD_SERVING_ONLY 2 / ADMIN_ONLY_ENDPOINT 2 /
         LOW_SEVERITY_LOG_INJECTION 2 / UNVERIFIED_WILD_AUTHZ 31
```

> 最严口径（注入 FRESH 查重桩）复扫：A 板 = 4，但**不是** 11-25 的这 4 条，
> 而是 `hash` ×2（`PictureController.listPictureVOByPageWithCache`）与
> `mass_assignment` ×2（`PictureController.updatePicture` /
> `SpaceController.updateSpace`）—— 实盘查重未给 FRESH 的潜在候选，见遗留。

### 3. 全部门禁

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,859 项断言**（v1.5.31 为 1,851，+8 即 `[355]`） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿** |
| `python cli.py doctor` | **PASS（12 段全绿）** |

## 六、披露侧 24h 节点（2026-11-25 22:17 +08 已到）

- 草稿 A（GHSA 评论 `396175`）/ 草稿 B（dify #23 评论 `7134160570`）于
  11-24 22:17/22:18 发出，**满 24h 仍无维护者回应**：
  - `GHSA-368h-5897-269p`：`triage` / `comments=1`（我方）/ `accepted=false`；
  - `dify-for-dsl` #23：`open` / `comments=1`（我方，`2026-11-24T14:18:21Z`）；
  - 5 个上游 Issue 仍全 open、零维护者回复；6 个 CAN 编号 CVE.org 仍 404。
- 复核过程中 `gh api` 对 GHSA/dify 多次 `EOF`（本机到 api.github.com 抖动），
  上述状态来自 11-24 23:1x 与 11-25 早间的连续只读查询，**本轮未发送任何
  评论/邮件**；草稿 C（邮件 `security@ghostinthedroid.com`）是否发送仍需用户确认。

## 七、说明与遗留

- **最严口径暴露的 4 条潜在候选**（`yu-picture`）：`hash` ×2
  （`listPictureVOByPageWithCache`）与 `mass_assignment` ×2
  （`PictureController.updatePicture` / `SpaceController.updateSpace`）。
  实盘因查重未给 FRESH 未进 A；建议下一轮做白盒（前者疑似缓存键 MD5，
  应走 M464 的非安全哈希豁免；后者需核查是否 DTO 逐字段更新）。
- **11-24 那批 A=9 仍未处理**（`CourseArragement` ×4、`RoboHarness` ×1、
  `youlai-boot` ×4），与 11-25 是不同批次；其中 `RoboHarness` 命中在 `eval/`
  目录，需先确认是否生产面。建议下一轮按批次清零。
- `ADMIN_ONLY_ENDPOINT` 只收录 `header_injection` / `unrestricted_upload`；
  注入类目即便管理员专属仍保留 A 机会，避免放宽真洞。
- `LIVE_HUNT_REPORT.md`（11-25 巡猎产物）随本轮一并作为 docs 提交。

## 八、提交清单

- `core/agents/rule_detectors.py` — M475 对象存储 + JSON 包装体的 XSS 排除
- `core/context/wild_noise.py` — M475 `ADMIN_ONLY_ENDPOINT` / M476 对象存储上传归 B
- `benchmarks/smoke_test_chains.py` — M477 门禁 `[355]` 8 项
- `LIVE_HUNT_REPORT.md` — 11-25 巡猎产物（docs 提交）
- `STAGE_REPORT_2026-11-25_v1.5.32.md` — 本报告

> 验证用 `.cache/upstream/` 为巡猎即时缓存（`.gitignore` 已排除），不进入提交。
