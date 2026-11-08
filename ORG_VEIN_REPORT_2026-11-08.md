# ORG VEIN REPORT · risesoft-y9（2026-11-08）

> 目标：对 WorkFlow-Engine 所属组织做一次全系兄弟仓扫描，验证
> “同团队/同架构会重复同一种错误”的矿脉假设。
> 范围：risesoft-y9 全部 9 个公开仓；max_roots=8、min_units=8、cooldown=0。

## 一、扫描结果

| 仓库 | 根因 | 机器 A | 人工结论 |
| --- | ---: | ---: | --- |
| Digital-Infrastructure | 6 | 3 | 3 条 deserial 假阳 |
| WorkFlow-Engine | 6 | 6 | 6 条 SQLi，同一根因，CONFIRM |
| DataFlow-Engine | 3 | 3 | 3 条 sqli 假阳 |
| Network-Drive | 2 | 1 | 1 条 path traversal，CONFIRM |
| Data-Labeling | 0 | 0 | 无根因 |
| Email | 6 | 0 | 均在 B 板，未升级 |
| Code-Generator | 1 | 0 | B 板 |
| Intelligent-Search | 0 | 0 | 无根因 |
| API-Platform | 0 | 0 | 无根因 |

合计：9 仓全扫，24 个根因，13 条机器 A 记录（WorkFlow 6 条同根因，
Digital 3 条同型，DataFlow 3 条同型，Network 1 条）。

## 二、WorkFlow-Engine：SQLi 从 3 条扩到 6 条

新增同根因路由（/vue/recycle）：

- RecycleRestController.recycleList:53
- RecycleRestController.recycleList4All:68
- RecycleRestController.recycleList4Dept:83

调用链与 doingList4* 完全一致：
RecycleRestController → WorkListServiceImpl.recycleList* →
ItemRecycleApiImpl.buildSearchSqlComponents →
Y9TableServiceImpl（LIKE '%" + value + "%' / ='" + value + "'）。

因此第 4 单应写成 1 个 CVE / 6 条 affected endpoints，不要拆成 6 单。
鉴权仍为 /vue/* Servlet 前缀映射 → PR:L / 8.8。

## 三、Network-Drive：真实路径穿越 / 任意文件写入

### 3.1 入口

- POST /vue/uploader/chunk → UploaderController.uploadChunk1:110
- POST /vue/uploader/mergeFile → UploaderController.mergeFile:152

### 3.2 根因

Chunk.identifier / Chunk.filename（以及 FileInfo 同名属性）没有
@Pattern / 规范化；FileUtils.generatePath（line 24-37）直接拼接：

    uploadFolder + "/" + identifier + "/" + filename + "-" + chunkNumber

uploadChunk1 随后：

    Path path = Paths.get(generatePath(chunckPath, chunk));
    Files.write(path, bytes);

mergeFile 同样用 identifier / filename 拼 file 和 folder，再
Files.createFile / 合并写盘。二者都可借 identifier=../../../../...
逃出 upload 根。

### 3.3 本地复现

path_repro.py 输出：

    identifier=../../../../tmp/pwn
    normalized=C:\app\tmp\pwn\shell-1
    ESCAPED=True

### 3.4 定级与查重

- /vue/uploader 位于 protectedUrlPatterns: /vue/* → 需登录，PR:L。
- 可覆盖 upload 根外文件，完整性高；是否 RCE 取决于部署目录权限。
- 暂定 CVSS 3.1 8.1 High（C:H/I:H/A:N），提交前按实际影响复核。
- dedup：ZERO_RECORD_FRESH；同仓无已知 CVE/Advisory。
- 与 WorkFlow SQLi 不同仓、不同根因，分开提交。

## 四、Digital-Infrastructure：3 条 deserial 假阳

ImportExportController.importAppJson / importOrgTreeJson / importSystemJson
使用 Y9JsonUtil.readValue(content, AppJsonModel.class) 等具体类型；
AppJsonModel 明确标注 @JsonTypeInfo(use = JsonTypeInfo.Id.NONE)，
没有 default typing / 多态 gadget。结论：DEMOTE。

## 五、DataFlow-Engine：3 条 sqli 假阳

- SourceController.extractTable → DataSourceServiceImpl.extractTable：
  使用 DatabaseMetaData.getTables(...) / getColumns(...)，tableName 是
  元数据 API 参数，不是 SQL 文本。
- DataLogApiController.saveLogData：dataLogRepository.save(...)（JPA）。
- DataLogApiController.cache：Y9JsonUtil.readHashMap + 缓存 get/put，
  没有 SQL 执行。
结论：DEMOTE。

## 六、矿脉结论

1. 同组织确实有复用：WorkFlow 的 searchMapStr 根因横向扩到 recycle 三条；
   这是同一根因，不是三个新 CVE。
2. Network-Drive 的 Chunk 路径拼接是另一条真实根因，值得独立 1 单。
3. Digital 的 typed JSON、DataFlow 的 metadata/JPA 说明“同组织”不等于
   “同漏洞”，仍要逐条看 sink。
4. 下一轮矿脉优先级：Network-Drive（已确认）、Email 的 6 条 B 板、
   DataFlow 其他文件上传/表达式入口。
