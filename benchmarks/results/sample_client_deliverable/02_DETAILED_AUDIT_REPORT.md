# 详细审计与源码整改手册 —— newbee-mall-api

- 入口：62 ｜ 独立根因：9 ｜ 生成：2026-10-28 07:42:34

## 根因清单

### 1. [cors] NewBeeAdminCarouselAPI.list

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminCarouselAPI.java:54
- 影响路由：62
- 根因签名：cors:ae0c07e2f965

### 2. [unrestricted_upload] NewBeeAdminUploadAPI.upload

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49
- 影响路由：1
- 根因签名：unrestricted_upload:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49:NewBeeAdminUploadAPI.upload

### 3. [weakrand] NewBeeAdminUploadAPI.upload

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49
- 影响路由：1
- 根因签名：weakrand:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49:NewBeeAdminUploadAPI.upload

### 4. [xss] NewBeeAdminUploadAPI.upload

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49
- 影响路由：1
- 根因签名：xss:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49:NewBeeAdminUploadAPI.upload

### 5. [unrestricted_upload] NewBeeAdminUploadAPI.uploadV2

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83
- 影响路由：1
- 根因签名：unrestricted_upload:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83:NewBeeAdminUploadAPI.uploadV2

### 6. [weakrand] NewBeeAdminUploadAPI.uploadV2

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83
- 影响路由：1
- 根因签名：weakrand:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83:NewBeeAdminUploadAPI.uploadV2

### 7. [xss] NewBeeAdminUploadAPI.uploadV2

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83
- 影响路由：1
- 根因签名：xss:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83:NewBeeAdminUploadAPI.uploadV2

### 8. [hash] NewBeeMallPersonalAPI.updateInfo

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95
- 影响路由：1
- 根因签名：hash:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95:NewBeeMallPersonalAPI.updateInfo

### 9. [xss] NewBeeMallPersonalAPI.updateInfo

- 文件：C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95
- 影响路由：1
- 根因签名：xss:C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95:NewBeeMallPersonalAPI.updateInfo


## 附：原始扫描报告

# 野战扫描报告（--auto 全类目普查）—— C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master

- 切片单元：62
- 判定对：2294（unit × 类目），规则普查 786 ms
- P0 实锤：70（独立根因 9）；规则排除：289
- Sink 漏斗：过滤 1935，模型候选 0（过滤率 100%）

## P0 [Confirmed] 规则实锤（9 个独立根因 / 70 条路由级命中）

- **[cors]** 全局根因 `NeeBeeMallWebMvcConfigurer.java`（影响 62 条路由）
  - 代表入口：`NewBeeAdminCarouselAPI.list` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminCarouselAPI.java:54`
  - 前 5 条路由：`NewBeeAdminCarouselAPI.list`；`NewBeeAdminCarouselAPI.save`；`NewBeeAdminCarouselAPI.update`；`NewBeeAdminCarouselAPI.info`；`NewBeeAdminCarouselAPI.delete`
- **[unrestricted_upload]** `NewBeeAdminUploadAPI.upload` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49`
- **[weakrand]** `NewBeeAdminUploadAPI.upload` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49`
- **[xss]** `NewBeeAdminUploadAPI.upload` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:49`
- **[unrestricted_upload]** `NewBeeAdminUploadAPI.uploadV2` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83`
- **[weakrand]** `NewBeeAdminUploadAPI.uploadV2` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83`
- **[xss]** `NewBeeAdminUploadAPI.uploadV2` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\admin\NewBeeAdminUploadAPI.java:83`
- **[hash]** `NewBeeMallPersonalAPI.updateInfo` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95`
- **[xss]** `NewBeeMallPersonalAPI.updateInfo` @ `C:\myFloders\git\nexus-audit\reference_repos\newbee-mall-api-master\src\main\java\ltd\newbee\mall\api\mall\NewBeeMallPersonalAPI.java:95`

## P1 [High-Confidence] 模型双引证通过


## P2 [Review-Needed] Sink 门控候选（模型复核队列）
