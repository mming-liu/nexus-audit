# STAGE REPORT · v1.3.19（M323：今日 13 条 A 板块复核）

> 日期：2026-11-05 ｜ 基线：v1.3.18（213bbcb）
> 结论：11 条假阳（已修 7 条判据）、1 条真洞（x-springboot，未授权路径穿越上传）、1 条待人工确认（novel-cloud 存储型）。

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
