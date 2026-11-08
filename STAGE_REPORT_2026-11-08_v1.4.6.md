# STAGE REPORT · v1.4.6（M349–M352：整类 CVE 查重、第 6 单封箱、第二波 org-hunt）

> 日期：2026-11-08 ｜ 基线：v1.4.5（ea87a4e）
> 结论：M349 补上“整类指名 CVE”查重并保住同文件未报方法；AliPay 正式
> 判重 CVE-2026-77036，S3 upload 保持 ZERO_RECORD_FRESH；门禁 1,941 项全绿；
> 第二波 org-hunt 未产出新 A。

## 一、M349：整类指名 CVE 查重

### 1.1 规则

cve_dedup._unit_in_text 新增 class-wide 分支：

- 从 unit/file 取具体 Controller 类名（长度 >= 8、非泛化类）；
- 描述中出现该类名（大小写不敏感、标识符边界）；
- 若描述还出现另一个 lowerCamel 方法 token（如 downloadS3Storage），
  则不按整类命中，避免 CVE-2026-108706 连坐 uploadS3Storage；
- URL 段（/api/s3Storage/...）不计入“其它方法”。

本地种子补齐：

- CVE-2026-77036 → EmailController / AliPayController /
  GeneratorController / GenConfigController（整类，无方法名）；
- CVE-2026-108706 → S3StorageController.downloadS3Storage（单方法）；
- CVE-2025-10084 → SysLogController.queryErrorLogDetail。

### 1.2 验证

| 查询 | 结果 |
| --- | --- |
| AliPayController.updateAliPayConfig | DUPLICATE_CVE / CVE-2026-77036 |
| S3StorageController.downloadS3Storage | DUPLICATE_CVE / CVE-2026-108706 |
| S3StorageController.uploadS3Storage | ZERO_RECORD_FRESH（未被 108706 连坐） |

在线 dedup 同样通过；不是只靠本地种子。

## 二、M350：AliPay 降级 + S3 第 6 单封箱

### 2.1 AliPay

playbook 顶部已加：

    ⛔ DUPLICATE OF CVE-2026-77036 & Issue #903 — DO NOT SUBMIT

CVE-2026-77036 官方描述只点名 Email/AliPay/Generator/GenConfig 四个类，
没有方法名；整类方法均重号，AliPayController.updateAliPayConfig 不再进入 A。

### 2.2 S3StorageController.uploadS3Storage

- POST /api/s3Storage，line 69-78，无 @PreAuthorize；
- 同文件 query/download 有 storage:list，deleteAll 有 storage:del；
- 同模块 LocalStorageController.createFile 有 storage:add（对照组成立）；
- Spring Security anyRequest().authenticated() → 任意低权限已认证用户可上传
  到 S3 并写 Y9_STORAGE 记录，CWE-862，PR:L；
- CVSS 3.1 建议 6.5（C:N/I:H/A:N）到 8.1（C:H/I:H/A:N），按桶策略复核。

官方判例：CVE-2026-108706 / GHSA-8j2c-pwgm-76r5 是**同文件
downloadS3Storage** 的缺失授权 CVE；uploadS3Storage 是写接口、不同方法，
不能合并，也不能当重号。playbook 已写入该对比。

## 三、M351：门禁

- smoke_test_chains.py：**PASS，1,941 项**
- triage_fallbacks.py --check-floor：**16/16**
- cli.py doctor：**PASS（12 段全绿）**

[321] 新增：整类描述命中 AliPay、单方法描述不连坐 upload、download 命中、
本地种子 AliPay 判 CVE-2026-77036、upload 非 DUPLICATE。

## 四、M352：第二波 org-hunt

命令：

    python cli.py org-hunt --orgs jeecgboot,macrozheng,xkcoding,yudaocode \
      --languages java --max-roots 20 --min-units 5 --limit 8

结果：

    candidates 8 / scanned 2 / skipped 5 / failed 1 / roots 19 / A 0 / B 19

8 个业务仓中多数是 MiniDao/autopoi/jimureport 等库或低路由密度仓，5 个被
min_units 跳过，1 个失败；实扫的 2 个仓 19 条根因全部进 B，无新 A。
因此本轮没有第 7 单候选；S3 upload 仍是第 6 单。

## 五、结论与下一步

1. M349 解决了“CVE 只写类名”与“CVE 写单方法”的边界，AliPay 不再误入 A。
2. S3 upload 的证据链、官方判例、对照注解齐全；对外提交前只需确认目标
   部署存在无 storage:add 的低权账号。
3. 第二波 org-hunt 没有新 A，说明 jeecgboot/macrozheng 这批仓的当前切片
   命中主要是 B 板/库仓；下一轮建议换 dromara 的 Web 后台或缩小到有
   Controller 的业务仓，而不是继续加 limit。
4. 第 4/5/6 单仍未对外提交；第 2/3 单仍待你本人走 CNA/邮件流程。
