# STAGE REPORT · v1.4.0（M325–M328：跳出第 1 页老仓）

> 日期：2026-11-07 ｜ 基线：v1.3.19（206f736）
> 结论：新猎场轨道已生效（27 候选 / 3 实扫 / 1 条 A）；x-springboot
> `/sys/gen/create` 任意路径写入为 **FRESH**（PR:H，7.2），oinone
> `LocalFileClient.getStaticFile` 为 **FRESH 源码级路径遍历**，但运行时可达性
> 仍需容器验证。未提交任何外部 advisory / CVE。

## 一、为什么最近 4 天新洞变少（复核结论）

| 症结 | 复核结果 |
| --- | --- |
| 第 1 页老仓路灯 | 成立。v1.3.19 的候选仍是 x-springboot / FlyCms / wangmarket / ujcms 等 2018–2022 老仓；2026-11-07 09:00 的自动巡猎甚至 0 候选 |
| 仓内静态截断 | 成立。`--max-roots 5` 之前按扫描顺序截断，老 Controller 先占名额 |
| 后台写文件被放过 | 成立。`GenUtils.maker` 被规则层漏掉，只被判成 authz |

## 二、第 3 单候选：x-springboot `POST /sys/gen/create`

### 2.1 事实链（不是 `SysGeneratorController` / Shiro）

实际类名是 `SysGenController`（不是 `SysGeneratorController`），项目用的是
Spring Security + `AuthIgnoreConfig` + `CustomAuthorizationManager`，**没有
ShiroConfig，也没有 `@RequiresPermissions`**。

| 位置 | 事实 |
| --- | --- |
| `SysGenController.java:47-51` | `@PostMapping("/create")`，参数 `@RequestBody MakerConfigEntity` |
| `SysGenServiceImpl.java:30-37` | 先按 `config.getTableName()` 查表，再调 `genUtils.maker(config, table, columns)` |
| `GenUtils.java:57` | `maker(MakerConfigEntity makerConfig, ...)` |
| `GenUtils.java:140-151` | `getFileName(...)` 把 `moduleName` 原样拼进路径；`filePath` 取自请求 |
| `GenUtils.java:152-153` | `new FileWriter(filePath + path); writer.write(sw.toString());` |

没有 `normalize()`、`getCanonicalPath().startsWith()`、`FilenameUtils.getName()`
或目录白名单；`filePath` 可为任意绝对路径，`moduleName` 可含 `../`。

### 2.2 权限（默认 PR:H）

`/sys/gen/create` → `URLConvertUtil.convert` → `SysGenCreate`。初始化 SQL
`doc/x_springboot.sql` 的 `sys_permission` **没有这一行**，默认只有
`userId == "1"` 的超级管理员直接放行。若管理员新增该权限并授予普通角色，
则 PR:L。两种都仍是 CWE-22 / CWE-73。

CVSS 3.1：`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 (High)`；PR:L 时 8.8。

### 2.3 查重与交付物

- `dedup("yzcheng90/X-SpringBoot", "pathtraver", "SysGenController.create", file="GenUtils.java")`
  → `ZERO_RECORD_FRESH`，`matched_ids=[]`。
- CIRCL 该仓 12 条（6 个唯一 ID）无 `/sys/gen/create` / `GenUtils`；GitHub Issues /
  Advisories / 全局 advisories 均 0。
- 规则层：M327 前该入口只判 authz；修复后 `pathtraver_verdict` 对真实切片返回
  `True`，扫描器 root 数 29→30。
- 手册：[x-springboot_pathtraver_create/SUBMISSION_PLAYBOOK.md](benchmarks/results/daily_hunt_packs/x-springboot_pathtraver_create/SUBMISSION_PLAYBOOK.md)

## 三、新猎场实跑（2026-11-07 15:22–15:28）

命令：

~~~text
python cli.py daily-hunt --languages java,python --days 21 --limit 3 \
  --max-roots 4 --cooldown-days 0 --evict-cache --repo-timeout 300
~~~

结果：**候选 27 / 实扫 3 / 跳过 2 / 失败 0 / 新增根因 1（A 1 / B 0）**。
新生代轨道命中了 `jingsewu/open-wes`、`opentiny/tiny-engine-backend-java`、
`oinone/oinone-pamirs` 等 2024–2026 仓，不再只有第 1 页老仓。

### 3.1 人工精核：oinone `LocalFileClient.getStaticFile`

- 源码：`pamirs-framework/pamirs-connectors-cdn/.../LocalFileClient.java:76-95`。
- 路由：类上 `@RestController @RequestMapping("/file")`，方法
  `@RequestMapping("/static/{uniqueFileName}")`。
- 危险链：
  ~~~java
  String filePath = cdnConfig.getLocalFolderUrl() + "/" + uniqueFileName;
  File localFile = new File(filePath);
  byte[] content = FileUtils.readFileToByteArray(localFile);
  ~~~
- 无 `normalize` / 前缀校验 / 文件名截取；`uniqueFileName` 直接来自 path variable。
- **但**：运行时能否用 `../` 或 `%2e%2e%2f` 绕过 Tomcat 的路径规范化，取决于
  容器 `ALLOW_ENCODED_SLASH` 与 URI 归一化策略；本机无法仅凭源码证明。
- 结论：**FRESH 源码级 CWE-22 候选，先做容器复现再交单**。若可未授权读取，
  CVSS 3.1 = 7.5（`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`）；若需登录则 6.5。
- 当前状态：不提交，避免把"源码拼接"当成"已复现任意文件读取"。

## 四、M325：新生代赛道 + 页码轮转 + 星标分桶

文件：`core/context/target_scout.py`（不是 `benchmarks/target_scout.py`）。

- 新增 `NEW_GEN_CREATED_SINCE=2024-06-01`、`NEW_GEN_PUSHED_SINCE=2026-09-01`、
  `NEW_GEN_STARS=(80,5000)`，关键词覆盖 rag / agent / mcp / workflow /
  text2sql / chatbi / knowledge-base / lowcode / iot / wms / mes / his /
  lims / report / bi。
- 每个语言一轮 2 个词：1 个新生代 + 1 个传统（约 50%）；传统词按天轮转
  `page=1..4`，并使用 `stars:80..450` / `stars:451..2000` 分桶。
- 新生代词为空时自动顺延 1–2 个词，避免整条轨道空手。
- 实拉结果：27 候选；Traditional 词也不再永远第 1 页。

已知局限：短词（mes/bi/his）即使加引号仍会被 GitHub 的模糊匹配带偏；
因此采用"顺延 + 业务词"组合，而不是宣称零噪声。

## 五、M326：最近 90 天新提交提权

文件：`core/context/daily_hunt.py`。

- `recent_files(repo, days=90, depth=30)` 用
  `git log -n 30 --since="90 days ago" --name-only --pretty=format:` 取文件集合。
- `root_priority(record, confidence, recent_files)`：最近改动的高价值类目
  `(-2, rank)`，最近普通类目 `(-1, 0)`，陈旧的 sqli 仍为 `(0, 0)`。
  这样最近的新代码先被审计，但最近文件内部仍保留类目优先级。
- 记录写入 `recent_90d` 字段；`daily_meta.recent_90d_roots` 汇总。
- **浅克隆实际默认已是 `depth=50`**（不是 1），比要求的 30 更深；本轮没有
  为了"照抄 30"而降级。`recent_files` 的 log 窗口本身限制 30 条。

## 六、M327：FileWriter / FileOutputStream / Files.write / FileUtils 判据

文件：`core/agents/rule_detectors.py`。

- `PATH_SINK_RE` 的 `FileUtils` 分支从 `writeFile|read|copy|open` 扩到
  `write\w*`，覆盖 `writeStringToFile` / `writeByteArrayToFile` / `writeLines`。
- 新增 `_hop_param_names`：入口 DTO 类型（如 `MakerConfigEntity`）在 Hop 方法
  形参里的同名类型也视为污染源，解决
  `create(makerConfigEntity) → generatorCode(config) → maker(makerConfig)`
  的跨跳改名。
- 只有 **Hop 专属形参**才绕过"sink 与入口体零交集"门；避免把
  `CommonFileController.uploadFile` 这类已用 `encodingFilename/genNewFilename`
  重写文件名的路径误判。waynboot 的 6 条历史 FP 复测仍为 0。
- 收紧 `cve_dedup._unit_in_text` 的标识符边界：`create` 不再命中
  `"VulDB entry created"`，避免把 `SysGenController.create` 误判成
  CVE-2025-6731。
- 修复 `benchmark_waynboot.py` 在 Windows GBK stdout 下打印 ✔/✘ 的
  UnicodeEncodeError，避免门禁因编码而非检测结果转红。

## 七、M328：门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,870 项**（新增 [309] 7 项 + [310] 10 项） |
| cli.py doctor | PASS（12 段全绿） |
| waynboot --strict | PASS（163 入口 / 1 个 CORS 根因 / 0 误报） |
| x-springboot pathtraver root | 29 → 30（新增 SysGenController.create） |

## 八、metasfresh 与 CNA

- `#27079` 已过 7 天窗口（2026-10-30 发起，2026-11-02 72h 追问）。
- 本轮**没有**代替人工登录 MITRE CVE Services 提交；这需要你的 Google 账号、
  CAN 预留与表单红标清零，助手无法代填。完整英文报告在本地（静默期，不落
  公开文档）；提交前请确认厂商仍无回应、HEAD 仍未修。
- 不要把 oinone 的源码级候选提前写成"已复现"；先把容器复现做完。

## 九、下一步（按优先级）

1. 容器复现 oinone `/file/static/{uniqueFileName}`：Tomcat 默认配置 +
   `%2e%2e%2f` / `..%5c` / `..;/` 变体；确认未授权或 PR:L。
2. x-springboot `/sys/gen/create`：用真实超级管理员 token 在本地起服务，
   验证 `filePath=C:/Users/Public/` + `moduleName=../../..` 落盘；再交私密
   Advisory。
3. 下一轮 daily-hunt 把 `--limit` 提到 5–6，优先覆盖本次因名额未扫的
   `jingsewu/open-wes`（WMS）与 `opentiny/tiny-engine-backend-java`（低代码）。
4. metasfresh：人工完成 CNA-LR 表单；编号回来后再更新 MONETIZATION_PLAN。
