# STAGE REPORT · v1.5.34（M483–M486：Java 弱哈希免报 + 内容哈希命名 + 鉴权注解实锤 + 11-27 A 板清零）

> 日期：2026-11-27 ｜ 基线：v1.5.33（`0994e40`，门禁 1,870） ｜ 发布时门禁 **1,882**
> 主题：清零 11-27 巡猎 A 板 2 条（`ani-rss` `hash` / `unrestricted_upload`）与
> 11-25 遗留 `yu-picture` `hash` ×2；补上「Java 非密码学弱哈希」与
> 「上传内容哈希命名」两个整类漏报；自定义鉴权注解改为**必须有同仓落地实锤**；
> 3 组白盒候选 + `RoboHarness` `eval/` 遗留项完成只读核验（**0 外发**）。
> 结论：smoke **1,882** 项断言 PASS / triage **16/16** / doctor PASS；
> 三仓离线重放 **A=0 / B=163**（FRESH 桩最严口径也是 **A=0**）。

## 〇、背景（11-27 09:07 巡猎）

| 项目 | 数值 |
|---|---|
| 起始 / 耗时 | 09:01:40 → 09:07:04（约 5.5 分钟） |
| 候选 = 实扫 + 跳过 + 失败 | 6 = 3 + 3 + 0（跳过均为 `ZERO_ENTRY_LIB`） |
| 新增根因 | 164（A **2** / B **162**） |
| 状态计数 | ZERO_RECORD_FRESH 2 / DUPLICATE_CVE 0 / DUPLICATE_ISSUE_OR_GHSA 0 / UNKNOWN 162 |
| 实扫仓根因数 | ani-rss 24 / data-product-portal 133 / paperpush 7 |

A 板 2 条同仓同入口（`wushuo894/ani-rss` HEAD `0ea2d5a3`）：

| # | 类目 | 入口 | 命中行 | 根因本质 |
|---|---|---|---|---|
| 1 | hash | `UploadController.upload` | `UploadController.java:25` | `SecureUtil.md5(tempFile)` 是**内容寻址落盘名**，非口令/签名 |
| 2 | unrestricted_upload | `UploadController.upload` | 同上 | 落盘名由内容哈希服务端重写，且上传目录非静态挂载 |

## 一、M483：Java 非密码学弱哈希免报（`core/agents/rule_detectors.py`）

### 1) 判据扩展

`_weak_hash_is_non_security()` 原来只认 Python `hashlib.(md5|sha1)`，Java 的
`SecureUtil.md5` / `DigestUtils.md5DigestAsHex` 整类漏过。本轮：

| 项 | 改动 |
|---|---|
| 调用面 | 新增 `_JAVA_WEAK_HASH_CALL_RE`：`SecureUtil.md5|sha1`、`DigestUtils.md5DigestAsHex|md5Hex|sha1Hex|md5|sha1`、`MD5Utils.*`、`Hashing.md5|sha1`、`MessageDigest.getInstance("MD5"|"SHA-1")`；与 Python 正则合并为 `_WEAK_HASH_CALL_RE` |
| 非安全语境 | 补 `saveName|fileName|extName|tempFile|MultipartFile|fileKey|objectKey|redisKey|queryCondition`；窗口从 `[i-2, i]` 收到 **`[i-1, i+2]`**，覆盖 `String s = SecureUtil.md5(tempFile); String saveName = s + "." + extName;` |
| 安全护栏 | 方法体命中 `password|passwd|pwd|token|secret|sign|hmac|auth` 立即返回 False（继续报）；**所有**弱哈希调用都必须落在非安全语境才免报 |
| 注解剥离 | 新增 `_hash_body_view()`：剥掉注解行后再做安全语境判定。`@Auth` 是**入口权限**，不是「这段哈希为鉴权服务」的证据；不剥会把 ani-rss 整条判回 True |
| nosec 分支 | 仅对 Python `hashlib` 生效（Java 没有 `# nosec` / `usedforsecurity=False`），未被扩展误用 |

### 2) 实测（真实源码切片）

| 切片 | 旧 | 新 |
|---|---|---|
| ani-rss `UploadController.upload`（`SecureUtil.md5(tempFile)` → `saveName`） | True | **False** |
| yu-picture `PictureController.listPictureVOByPageWithCache`（backend） | True | **False** |
| yu-picture 同方法（ddd 模块） | True | **False** |
| yu-picture `UserServiceImpl.getEncryptPassword`（`SALT + userPassword`） | True | **True**（防放宽） |
| 形参 `pwd` 的 `SecureUtil.md5(pwd)` | True | **True**（防放宽） |

## 二、M484：内容哈希命名 + 有实锤的自定义鉴权注解（`core/context/wild_noise.py`）

### 1) 上传落盘名（`_UPLOAD_GENERATED_NAME_RE` / 新增两条正则）

- 服务端随机名补齐 Java：`UUID.randomUUID()`、`IdUtil.simpleUUID|fastSimpleUUID|randomUUID`；
- 新增 `_UPLOAD_CONTENT_HASH_NAME_RE`（`SecureUtil|DigestUtils|Hashing` 的 md5/sha1/sha256）
  **且** 必须同入口存在 `_UPLOAD_NAME_WIRING_RE`（`saveName|fileName|extName|FileUtil.move|transferTo`）——
  只有「内容哈希 + 名字装配/落盘」同时出现才算服务端重写落盘名，单纯去重指纹不豁免；
- 三重门禁不变：`_EXEC_PACKAGE_UPLOAD_RE`（可执行包面）、`_MODEL_WEIGHT_UPLOAD_RE`、
  `not _repo_serves_uploads(repo_root)`；
- `NON_EXECUTABLE_UPLOAD` 的 reason 文案补「内容哈希名」。

### 2) 自定义鉴权注解（`_java_authz_class_guard`，仅 `category == "authz"`）

- 方法/类注解块匹配 `@([A-Za-z0-9_]*(?:Auth|Login|Permission|Role|Guard)[A-Za-z0-9_]*)`；
- 排除：标准鉴权注解（`@Permission`/`@PreAuthorize`/`@SaCheckPermission`… 走原判据）、
  Lombok/Swagger/Jackson/Spring MVC/校验等框架注解、`_JAVA_ANON_ANN_RE`；
- 排除显式关闭：`required=false` / `ignore=true` / `skip=true` / **`value=false`**（ani-rss 的 `@Auth` 就是 `value()` 开关）；
- **必须**在 `repo_root` 内找到落地读取实现，否则不判守卫：
  - `getMethodAnnotation(Ann.class)` / `getAnnotation(Ann.class)` /
    `getDeclaredAnnotation(Ann.class)` / `isAnnotationPresent(Ann.class)`；或
  - AOP `@Around|@Before("@annotation(...)")` + 通知形参是 `Ann` + `@Aspect|*Interceptor|*Filter` 语义；
- 缓存按 `(repo_root, ann)`，有界扫描 800 个 `.java`。

### 3) 实测（真实仓 + 真实 repo_root）

| 记录 | 旧 | 新 |
|---|---|---|
| ani-rss `UploadController.upload`（unrestricted_upload） | A | **B（`NON_EXECUTABLE_UPLOAD`）** |
| ani-rss 22 条 authz 根因 | B（`UNVERIFIED_WILD_AUTHZ`） | **B（`AUTHZ_CLASS_OR_BASE_GUARD`）**：`@Auth` + 同仓 `AuthAspect`（`@Before("@annotation(auth)")` + `Auth` 形参 + 403）实锤 |
| 无实现的空壳 `@Auth` | — | **不压 B**（防 CourseArragement 式洗白） |
| `@Auth(required=false)` / `@Auth(value=false)` | — | **不压 B** |
| sqli 等注入类目 | — | **不受影响**（只进 authz 分支） |

## 三、M485：3 组高价值候选 + 1 条遗留的只读核验（0 外发）

> 全程只读：`gh api` / `raw.githubusercontent.com` / 本地缓存仓；未创建 Issue、
> 未发评论、未发邮件、未提交 Advisory。

### 1) `open-wes` `PluginController.install`（`POST /plugin/install`）

**代码链（HEAD `8da71f67`）**

| 环节 | 证据 |
|---|---|
| 入口 | `PluginController.java:40-41` `@PostMapping("install")`，无 `@PreAuthorize` |
| 落盘 | `FileUtils.saveFile(file, pluginDir)`：只做文件名字符清洗，无扩展名/大小/类型校验 |
| 加载执行 | `PluginService.java:32` `loadPlugin(Path.of(filePath))` → `:38` `startPlugin` → `PluginRegister` `scan + refresh` |
| PF4J 装配 | `PluginConfiguration.java:23` `new SpringPluginManager(Paths.get(pluginDir))`（`/plugins/wes/jar`） |
| 应用鉴权 | `SecurityConfiguration.java:54` `.anyRequest().permitAll()` |
| 容器 | `Dockerfile` 无 `USER`（root），`/plugins` 可写 |
| 端口 | `docker-compose.yml:77` wes-server `"9010:9010"` 直接发布到宿主机 |

**边界核验**

- 网关侧 `GlobalGatewayFilter` 对非白名单路径强制 JWT，`/plugin/**` 不在白名单
  （`AuthProperties.DEFAULT_AUTHENTICATE_WHITE_LIST`）——但网关路由
  `Path=/plugin/**` + `RewritePath=/plugin/(?<segment>.*) → /${segment}` 会把
  `/plugin/install` 改写成 `/install`（与控制器映射不一致，网关路径大概率 404）；
  **无论网关行为如何，宿主机 9010 直连都绕过网关**，而 wes 本身 `permitAll`。
- 版本面：`v1.0.0` tag（2025-01-20）树里**没有 `modules-plugin`**，该端点只存在于
  main / 未发布构建；compose 的 dev 默认部署（README 的 `docker-compose up -d`）
  从源码构建，包含该端点。

**项目画像（只读）**

| 字段 | 值 |
|---|---|
| star / fork / open issues | **339 / 44 / 7** |
| 最近 push | 2026-11-25（活跃） |
| Private Security Advisory | **disabled**；无 `SECURITY.md`；GHSA 0 条 |
| 相关公开 CVE/Issue | 无插件安装相关；仅有 **CVE-2026-111721 / GHSA-5ww9-qwj2-mr7g**（`GlobalGatewayFilter` 未校验 `auth_warehouse`，不同根因） |

**结论**：静态成立的高危候选（未鉴权上传 JAR → PF4J 实例化 → 代码执行），
证据强度中高；但**未发布版本 + 无私密通道 + 未动态验证 + 生产防火墙未知**。
→ **暂不外发**；若要推进，先走 CVE.org（MITRE CNA-LR）或经用户明确同意的公开 Issue。

### 2) `youlai-boot` `FileController.deleteFile` 与 `CourseArragement` RBAC 覆写

| 维度 | youlai-boot `deleteFile` | CourseArragement `assignRoleMenus` / `assignRolePermissions` |
|---|---|---|
| HEAD（远端） | `1b30213`（2026-11-27） | `517c1d4`（2026-11-24） |
| 是否仍成立 | **是**：`FileController.java:55-61` 无 `@PreAuthorize`，`@RequestParam String filePath` 直通；`LocalFileServiceImpl.java:73` `FileUtil.del(path + filePath)` 无规范化/根校验；`/api/v1/files` 不在 `permit-all-urls` → 认证后任意文件删除（仅文件，目录返回 false） | **是**：`RbacAssignController.java:43/49` 无鉴权；`SaTokenConfigure.java:18` 只有 `SaRouter.match("/**").notMatch(...)`，**没有 `.check()`** → 业务接口匿名可达 |
| star / fork | **375 / 141** | **407 / 101** |
| 维护活跃度 | 很高：HEAD 当天更新（Spring Boot 4.2.0 / 4.15.1） | 高：11-22～11-24 连续功能提交（RBAC 重构、行政区划、测试） |
| Private Advisory | disabled；无 `SECURITY.md` | disabled；无 `SECURITY.md` |
| 相关公开 CVE/Issue | **CVE-2026-110215**（`PUT /roles/{id}/menus`）、**CVE-2026-110216**（`PATCH /users/{id}/status`）——同类「缺 @PreAuthorize」但**不同端点**；`deleteFile` 无公开记录 | 无公开 CVE/GHSA/Issue |
| 交单价值 | **中高**：真实对象级越权 + 任意文件删除；但无私密通道，且 CNA（VulnCheck）已就同类根因发过两条，需防合并 | **低**：`SaTokenConfigure` 类注释明写「业务接口会在后续模块迁移时逐步切换到 @SaCheckLogin」——**维护者自述在建**；整站匿名面过宽，单端点交单易被判 known/预期 |
| 结论 | **记录，缓发**（先确认 CNA 归属与查重，不建议现在公开） | **不交单**（最多作为加固建议，但无渠道；保留 B 板记录） |

### 3) 11-24 遗留：`RoboHarness` `pathtraver` ×1（结案）

- 命中：`eval/behavior/behavior_interface/web.py:1943-1947`（`/api/agent_monitor/image`），
  污点 `session` → `os.path.join(root, alias)`（`_candidate_run_dirs`，无 sanitize）；
- 约束：`card_id` 先 `int()` 强转；最终只 `send_file` 形如
  `thumbs/card_%04d_{in,out}.{jpg,jpeg,png}` 的固定缩略图名 → **不是任意文件读**，
  只能探测/读取这一种命名的缩略图；
- 部署面：`eval/` 是**评测侧**（`eval/README.md:1` "Evaluation side"，runner 走 `./run.sh`
  → `python -m runner`），依赖 licensed BEHAVIOR 数据集 + NVIDIA 仿真栈；默认
  `--host 0.0.0.0 --port 5000` 但只在评测机上为被评测 Agent 提供观测/控制口，
  不是对外生产 Web 服务。
- **结论：非线上服务面 + 读原语受固定文件名约束 → 结案，不立项/不交单**
  （11-24 批次 A=9 至此全部有结论）。

## 四、M486：门禁、重放与全量验证

### 1) 门禁 `[357]`（12 项，纯离线）

| 组 | 断言 | 结果 |
|---|---|---|
| M483 | Java `SecureUtil.md5(tempFile)` 拼 `saveName` → False | ✅ |
| M483 | `DigestUtils.md5DigestAsHex` 缓存键 → False | ✅ |
| M483 | 同方法含 `password` → 仍 True（防放宽） | ✅ |
| M483 | `SecureUtil.md5(pwd)` → 仍 True（防放宽） | ✅ |
| M484 | 内容哈希命名 + 非静态挂载 → `NON_EXECUTABLE_UPLOAD` | ✅ |
| M484 | `UUID.randomUUID` 重写落盘名 → `NON_EXECUTABLE_UPLOAD` | ✅ |
| M484 | `install_plugin` 上传即使带 UUID 仍不压 B | ✅ |
| M484 | 自定义 `@Auth` + 落地 `getMethodAnnotation` 实锤 → `AUTHZ_CLASS_OR_BASE_GUARD` | ✅ |
| M484 | 自定义 `@Auth` 无落地实现 → 不压 B | ✅ |
| M484 | `@Auth(required=false)` → 不压 B | ✅ |
| M484 | `@Auth(value=false)` → 不压 B | ✅ |
| M484 | 自定义 `@Auth` 不豁免 sqli（只对 authz 生效） | ✅ |

### 2) 逐条重放（真实源码 + 真实 `repo_root`）

`a_board = 0`：ani-rss hash `False`、ani-rss upload `NON_EXECUTABLE_UPLOAD`、
yu-picture ×2 hash `False`（`.cache/v1534/replay.json`）。

### 3) 三仓离线重放（空账本，`min_units=8`，`max_roots=0`）

| 口径 | 根因 | 板块 A | 板块 B | by repo |
|---|---|---|---|---|
| 11-27 实盘（修复前） | 164 | **2** | 162 | ani-rss 24 / data-product-portal 133 / paperpush 7 |
| 离线重放（`offline=True, dedup_online=False`） | 163 | **0** | 163 | ani-rss 23 / data-product-portal 133 / paperpush 7 |
| FRESH 桩最严口径（任何规则层真阳都会进 A） | 163 | **0** | 163 | 同上 |

- 根因 164 → 163：`ani-rss|hash` 规则层判 False 后不再成根因；`unrestricted_upload`
  转入 B（`NON_EXECUTABLE_UPLOAD`）；
- **无误压高危**：`data-product-portal`（133）与 `paperpush`（7）逐条 code 不变；
  ani-rss 唯一变化是 22 条 authz 的 B 理由从 `UNVERIFIED_WILD_AUTHZ` 升级为
  `AUTHZ_CLASS_OR_BASE_GUARD`（**本来就是 B**，A/B 板未变）；
- 噪声分布：`AUTHZ_CLASS_OR_BASE_GUARD` 140 / `UNVERIFIED_WILD_AUTHZ` 22 /
  `NON_EXECUTABLE_UPLOAD` 1。

### 4) 全部门禁

| 门禁 | 结果 |
|---|---|
| `benchmarks/smoke_test_chains.py` | **PASS，1,882 项断言**（v1.5.33 为 1,870，+12 即 `[357]`） |
| `benchmarks/triage_fallbacks.py --check-floor` | **16/16 地板全绿** |
| `python cli.py doctor` | **PASS（12 段全绿）** |

## 五、披露状态与建议（本轮 0 外发）

- `GHSA-368h-5897-269p`（`android-agent`）只读复查（2026-11-27 15:42 +08）：
  `state=triage`、`updated_at` 仍等于创建时间、`published_at/closed_at=null`、
  评论仅 1 条（我方 2026-11-24 22:17 +08，id `396175`）；仓库 `pushed_at`
  仍是 2026-11-15。对方 `SECURITY.md` 承诺 48h 确认，实际已 **≈89h 零回复**。
- 建议：**可以发备用邮件（Draft C）**——`FOLLOWUP_2026-11-24.md` 第五节已有终稿，
  发送前只需三处小改：① "after 7 days" → "over a week"；② 日期改为发送当天；
  ③ 附 A 评论永久链接
  `https://github.com/ghost-in-the-droid/android-agent/security-advisories/GHSA-368h-5897-269p#advisory-comment-396175`。
  **本 Agent 无邮件通道且未获授权，未发送**；由用户从本人邮箱发出。
- M485 三组候选全部**未外发**：无 Issue / 无评论 / 无 Advisory / 无邮件。

## 六、说明与遗留

- `ani-rss` 的 `@Auth` 是**真守卫**（`value() default true` + `AuthUtil.test` 校验
  IP 白名单/Header/Form/API Key，失败抛 403），22 条 authz 归 B 是正确结论；
  该注解在 `AuthUtil.test` 里另有 `auth.value()==false` 的关闭分支，已同步进
  `_JAVA_ANN_DISABLED_RE`。
- M483 的注解剥离只作用于**弱哈希语境判定**，不影响其他类目的注解识别。
- 09:07 巡猎报告的 A=2 是**修复前快照**（`LIVE_HUNT_REPORT.md` 随 docs 提交），
  与本报告的 A=0 结论并不矛盾：前者是当日实盘，后者是 v1.5.34 重放。
- 下一轮可选：`open-wes` `PluginController.install` 若要做动态验证，需要在隔离
  环境起 compose（9010 暴露面）并只上传无害 PF4J 插件；仍属**需用户批准的对外**
  动作，不在本轮范围。

## 七、提交清单

- `core/agents/rule_detectors.py` — M483 Java 弱哈希免报（含注解剥离）
- `core/context/wild_noise.py` — M484 内容哈希命名 + Java UUID + 有实锤的自定义鉴权注解
- `benchmarks/smoke_test_chains.py` — M486 门禁 `[357]` 12 项
- `LIVE_HUNT_REPORT.md` — 11-27 巡猎产物（docs 提交，修复前快照 A=2/B=162）
- `STAGE_REPORT_2026-11-27_v1.5.34.md` — 本报告

> `.cache/upstream/`（巡猎克隆）与 `.cache/v1534/`（重放产物）、
> `benchmarks/results/daily_hunt*.json` 均由 `.gitignore` 排除，不进入提交。
