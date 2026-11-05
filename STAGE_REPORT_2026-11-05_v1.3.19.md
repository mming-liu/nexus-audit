# STAGE REPORT · v1.3.19（M323：今日 13 条 A 板块复核）

> 日期：2026-11-05 ｜ 基线：v1.3.18（213bbcb）
> 结论：11 条假阳（已修 7 条判据）、1 条真洞（x-springboot，未授权路径穿越上传）、1 条待人工确认（novel-cloud 存储型）。
>
> **2026-11-05 晚补记**：x-springboot `uploadApk` 经复核实为 **CVE-2025-6731**
> （VulDB，2025-06-26），已归档不发；novel-cloud 读取点不在本仓，维持"待人工
> 确认/不发"。详见第六节。

## 一、KCloud-Platform-IoT 3 条 sqli —— 假阳（已修）

`pageDevice/pageGateway/listTreeProductCategory` 的控制器只调
`devicePageQryExe.execute(qry)`；CQRS 的 `XxxQryExe` 不是 JDBC。

根因：`_SQLI_WHOLE_STMT_SINK_RE` 把 `.execute(` 一律当整句 SQL，且只排除数字型形参，
没校验实参必须是 `String`。

修复：形参类型不含 `String/CharSequence` → 跳过（DTO 执行器不再误判）。

## 二、hrm 4 条 xss —— 假阳（已修）

`createExportTask/createImportTask` → `salaryService.createExportTask(month, filename)`，
返回 `ResponseDTO`，不写内容也不回显。

根因：`_db_writer_takes_value()` 把 `Service.createExportTask(` 当成"值落库"，
再经 db 串接找到读取点 → 判存储型 XSS。

修复：Service 接收者只认 insert/add/save/update/persist；`createExportTask`/
`createImportTask` 这类异步任务不算写入（Mapper/Dao/Repository 不受影响）。

## 三、x-springboot 2 条（pathtraver + unrestricted_upload）—— 真洞

`POST /apk/upload/apk` 带 `@AuthIgnore`（permitAll，免 token）：

```java
String fileName = file.getOriginalFilename();
File tempFile = new File(fileName);                 // 路径穿越
FileUtil.writeFromStream(file.getInputStream(), tempFile);
...
tempFile.delete();                                  // 任意 .apk 删除
```

未授权任意文件写（.apk 后缀）+ 条件删除；仓库最后提交 2026-10-30（在维护）。
草稿：`.cache/advisories/x-springboot/ADVISORY.md`（CVSS 3.1 = 8.2）。

## 四、其余 5 条

| 仓库 | 单元 | 结论 |
| --- | --- | --- |
| goodsKill | KnowledgeController.delete (sqli) | 假阳：`tableName = properties.getTableName()` 是配置不是输入；且切片混入无关 SeckillController hop。判据未改（避免误伤） |
| goodsKill | GoodsEsController.save (xss) | 疑似假阳：ES 保存 DTO，无 HTML 回显；未改判据 |
| novel-cloud | submitFeedback (xss) | **待人工确认**：content 落库，后台是否原样渲染未核 |
| flask-admin | execute_view (xss) | 假阳：`Markup(f'...{msg}...')` 的 msg 是内部异常文本，且该视图仅管理员可达 |
| x-springboot | uploadApk | 真洞（见上） |

## 五、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,843 项**（新增 [307] 3 项） |
| cli.py doctor | PASS（12 段全绿） |

---

## 六、M323/M324 补记（2026-11-05 晚）：CVE-2025-6731 查重归零

### 6.1 公开记录实拉（CIRCL / CVE.org）

| ID | 发布方 / 日期 | 结论 |
| --- | --- | --- |
| CVE-2025-6731 | VulDB / 2025-06-26 | CWE-22；`uploadApk`；5.0 路径 `/sys/oss/upload/apk`；CVSS 3.1 **6.3**（PR:L，不是 8.2） |
| CVE-2026-97060 | VulnCheck / 2026-09-25 | CWE-639；`/sys/user/update`、`/sys/user/delete` 缺对象级鉴权 |
| CVE-2026-97063 | VulnCheck / 2026-09-25 | CWE-287；`/sys/mobile/code`、`/sys/email/code` 回显验证码 |
| CVE-2026-97064 | VulnCheck / 2026-09-25 | CWE-1392；默认万能验证码 `172839` |
| CVE-2026-100192 | VulnCheck / 2026-09-30 | CWE-306；`/application/manager/select` 未授权泄露 appKey/appSecret |
| CVE-2025-55948 | MITRE | RBAC 前后端权限表不同步（描述泛，未按 unit 入库） |

> 用户原清单只列了 4 个；实拉还发现 **CVE-2026-100192**（appSecret 泄露）和
> **CVE-2025-55948**。前者正好覆盖本次顺藤摸瓜查到的 `select` 读取点，故不再
> 作为新洞。

### 6.2 为什么旧版 dedup 漏掉 CVE-2025-6731

实拉 `GET /api/search/yzcheng90/x-springboot`：`total_count = 12`，
第 1 页 10 条 / 5 个唯一 ID，**CVE-2025-6731 在第 2 页**（被 2026 年的
97060/97063/97064/100192/55948 挤下去）。

因此：

- 用户指出的 `query_circl` "total=0 也 return" 早退 bug **确实存在**，但
  **不是本 CVE 的漏判原因**：第 1 页返回的是 200 + total=12，旧代码即使不早退
  也只会停在第 1 页。只修早退仍然抓不到 6731。
- 真正的漏判原因是 **CIRCL 固定 10 条/页、旧代码只翻第 1 页**。M323 已加翻页
  （最多 3 页，按 total 与新 ID 收敛）。
- `GET /advisories?affects=x-springboot` 实拉返回 `[]`：Java 仓没有 package
  ecosystem 元数据，affects 帮不上这个仓。该查询仍作为增量来源保留，但不能
  替代全局列表或 CIRCL。
- 最后一道网是本地种子：`known_public_cves.json` 已录入 6731 等 5 个 CVE
  （97060/97063 按端点拆成多条，避免连坐）。
- **关掉本地种子的实测**（`load_signatures → []`，只走在线）：`dedup` 仍返回
  `DUPLICATE_CVE`，`matched = ['CVE-2025-6731']`，CIRCL `total=12`、6 个
  item。证明是翻页修复本身在起作用，不是靠种子"作弊"。

### 6.3 代码变更

| 文件 | 变更 |
| --- | --- |
| `core/context/cve_dedup.py` | `query_circl` 翻页 + total=0 继续下一个 URL + 跨页去重；新增 `query_github_advisories_affects`；`query_github_issues_global` 支持仓库名兜底；dedup 传入 repo_name |
| `config/known_public_cves.json` | 新增 7 条 x-springboot 种子（6731 / 97060×2 / 97063×2 / 97064 / 100192） |
| `benchmarks/smoke_test_chains.py` | [308] 8 项断言；[301] 适配 affects 请求计数 |
| `.cache/advisories/_archived/DUPLICATE_CVE-2025-6731/` | 草稿归档 + STATUS.md，修正端点与 CVSS |

### 6.4 x-springboot 顺藤摸瓜（HEAD f4acf07）

**@AuthIgnore 全量（7 个方法）**

| 端点 | 方法 | 定性 |
| --- | --- | --- |
| `POST /apk/version/upload/apk` | `TbApkVersionController.uploadApk` | CVE-2025-6731（归档） |
| `GET /application/manager/select` | `XApplicationController.select` | CVE-2026-100192（appKey/appSecret 泄露 → 可打 `/api/msg/service/send`） |
| `GET /application/manager/generateKey` | `generateKey` | 仅返回 md5(时间戳)，无状态、无凭据，不成立 |
| `GET /sys/mobile/code` | `mobileCode` | CVE-2026-97063 |
| `GET /sys/email/code` | `emailCode` | CVE-2026-97063（同一根因） |
| `POST /sys/emailOrMobileLogin/login` | `emailOrMobileLogin` | CVE-2026-97064 |
| `GET /sys/code/{time}` | `captcha` | 验证码写 Redis，key 由 path 参数控制；无直接读取/绕过链，不成立 |
| `POST /register` | `register` | 强制 role=23 / status=0；userId 为 ASSIGN_UUID，未发现提权 |

**写接口 / SQL**

- 除 `uploadApk` 外，其余 `@AuthIgnore` 均已有公开 CVE 覆盖；`generateKey`、
  `register`、`captcha` 未发现独立可利用链。
- SQL：全仓没有用户可控的 `${}` 拼接；`SysGenMapper.xml` 的
  `${ew.sqlSegment}` 来自 MyBatis-Plus 参数化 wrapper（`eq/like`），
  不是注入点。未发现新的 SQLi。
- `POST /sys/gen/create` → `GenUtils.maker` 用请求里的 `filePath` +
  `moduleName` 直接 `FileWriter(filePath + path)`（GenUtils.java:152）。这是
  一个**需登录 + 代码生成权限**的任意路径写入面，权限模型未核完，暂不作为
  未授权洞提交。

### 6.5 novel-cloud `submitFeedback`

- `FrontUserController.submitFeedback` 把原始 `content` 落库
  （`UserServiceImpl.saveFeedback`），未转义。
- 本仓（novel-cloud）**没有后台反馈列表/模板**；grep 全仓只有前台
  submit/delete，没有读取渲染点。读取端在独立后台项目里，无法从本仓证实
  "原样渲染"。
- 结论：**维持待人工确认，不发**。按"查不到 ≠ 有洞"原则，没有读取点证据就
  不判存储型 XSS。`deleteFeedback` 已带 `user_id` 过滤，无 IDOR。

### 6.6 门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,853 项**（新增 [308] 8 项 + [301] 1 项） |
| cli.py doctor | PASS（12 段全绿） |
