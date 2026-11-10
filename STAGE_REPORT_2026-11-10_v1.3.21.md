# STAGE REPORT · v1.3.21（M330：今日 13 条 A 板块复核）

> 日期：2026-11-10 ｜ 基线：v1.3.20（7e91c2d）
> 结论：13 条 A 板块全部假阳；10 条已按根因修复，3 条（my-rag 2 + qKnow upload）已核安全但未改判据。

## 一、今日巡检

候选 9 ｜ 实扫 8 ｜ 跳过 1 ｜ 失败 0 ｜ A=13 ｜ B=18。

## 二、SSRF 3 条 → 假阳（已修）

| 仓库 | 单元 | 事实 |
| --- | --- | --- |
| Nubase | AssetsPublicController.serve | `assetsService.openStream(file)` 是对象存储读 key（DB 元数据），不是 URL |
| ragent | KnowledgeDocumentController.file | `fileStorageService.openStream(doc.getFileUrl())` 是 MinIO/OSS key |
| qKnow | SysLoginController.login | URL 来自 `SpringUtil.getProperty("flow.url")`，不是入参 |

修复：
- `.openStream(` 从强 sink 降为弱 sink（需 URL 旁证）；对象存储不再误判。
- Java 侧新增配置来源识别：`SpringUtil.getProperty / Environment.getProperty / properties.get*` 赋值的 URL 变量 → False。

## 三、pathtraver 6 条 → 假阳（已修）

| 仓库 | 事实 |
| --- | --- |
| TAgent SiteStatsController.stats | `reportPath` 来自 `@Value` 配置，用户只传 `days` |
| dive-into-spring-ai ×3 | `new File("F:\\workspace\\...").listFiles()` 硬编码，入口零形参 |
| qKnow Kg/KmcSync fileList | DTO + `@PreAuthorize`，路径由存储浏览器服务解析 |

修复：整条链无任何污染源（无入口形参、无 Hop 专属形参、不直接读 request）→ False。

## 四、sqli 1 条 → 假阳（已修）

TAgent `BackgroundTaskController.list`：

```java
String sql="SELECT ... WHERE "+EXACT_USER
    +" AND question LIKE ? ESCAPE '!'"+" ORDER BY ... LIMIT ? OFFSET ?";
Object[] args={user,user,user,"%"+like(word)+"%",limit,offset};
return db.queryForList(sql,args);
```

修复：拼接项全是全大写常量 + `?` 占位 + `queryForList(sql,args)` 绑定 → False
（JDBC 与 helper 两条分支都加）。

## 五、未改判据的 3 条

| 仓库 | 单元 | 核实结论 |
| --- | --- | --- |
| my-rag | DocumentController.upload (pathtraver) | `uploadDir.resolve(docId + fileExt)`，docId 服务端生成、扩展名走 `SUPPORTED_TYPES` 白名单 → 安全 |
| my-rag | DocumentController.upload (unrestricted_upload) | 同上，有类型/大小校验 |
| qKnow | CommonController.uploadFile (xss) | 走 RuoYi `FileUploadUtils.upload`（扩展名白名单+重命名）→ 安全 |

## 六、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔（恢复 9 个关键靶场后复核；新增 [310] 4 项） |
| cli.py doctor | PASS（12 段全绿） |

## 七、夹具解耦（M331）

`reference_repos/` 缺失或 `NEXUS_RULE_ONLY=1` 时，benchmark 段记 SKIP
并在末尾汇总；smartbugs 交叉核验等直接读夹具的段加了存在性守卫，规则断言照常判定。

## 八、M331 第二阶段（夹具解耦）

- VAmPI / JavaSecLab / My-Blog / litemall / [101] 三语言子集 / smartbugs M44 等段
  加 `_ref()` 存在性守卫：缺目录打印 SKIP，不再抛异常；
- `NEXUS_RULE_ONLY=1`（或 `reference_repos/` 为空时自动）下，benchmark、
  覆盖度里程碑、靶场统计类断言统一记 SKIP；
- 实测：规则模式 **1,564 项 PASS**（全量模式需 50 个靶场，当前仅恢复 9 个）。
