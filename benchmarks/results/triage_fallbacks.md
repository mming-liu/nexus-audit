# 退回池五分类剖析（Module 33，只读诊断）

| 靶场/类目/桶 | 样本数 |
|---|---|
| xxe/缺 Sink | 1935 |
| ssrf/缺 Sink | 1934 |
| cmdi/缺 Sink | 1933 |
| deserial/缺 Sink | 1882 |
| sqli/缺 Sink | 1804 |
| authz/缺 Sink | 1668 |
| reentrancy/缺 Sink | 1276 |
| access_control/缺 Sink | 768 |
| access_control/含未知安全包装 | 422 |
| xss/缺 Sink | 271 |
| reentrancy/含未知安全包装 | 162 |
| access_control/缺 Source | 115 |
| reentrancy/缺 Source | 55 |
| xss/缺 Source | 48 |
| deserial/含未知安全包装 | 33 |
| pathtraver/含未知安全包装 | 28 |
| pathtraver/缺 Sink | 27 |
| xss/含未知安全包装 | 18 |
| deserial/缺 Source | 14 |
| pathtraver/缺 Source | 9 |
| authz/缺 Source | 8 |
| sqli/含未知安全包装 | 5 |
| authz/含未知安全包装 | 4 |
| authz/跨文件链路未闭合 | 3 |
| xxe/缺 Source | 2 |
| deserial/跨文件链路未闭合 | 2 |
| cmdi/缺 Source | 2 |
| access_control/跨文件链路未闭合 | 1 |
| ssrf/含未知安全包装 | 1 |

## 样本示例

- `RuoYi/sqli/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/cmdi/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/deserial/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/ssrf/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/xxe/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/reentrancy/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail
- `RuoYi/access_control/缺 Sink`：SysJobController.java:SysJobController.job；SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.changeStatus
- `RuoYi/xss/缺 Sink`：SysJobController.java:SysJobController.list；SysJobController.java:SysJobController.export；SysJobController.java:SysJobController.remove；SysJobController.java:SysJobController.detail；SysJobController.java:SysJobController.changeStatus
- `RuoYi/access_control/含未知安全包装`：SysJobController.java:SysJobController.detail；SysJobController.java:SysJobController.edit；SysJobLogController.java:SysJobLogController.jobLog；SysJobLogController.java:SysJobLogController.detail；SysOperlogController.java:SysOperlogController.detail
- `RuoYi/authz/缺 Source`：SysJobController.java:SysJobController.checkCronExpressionIsValid；SysDictTypeController.java:SysDictTypeController.treeData；SysIndexController.java:SysIndexController.lockscreen；SysIndexController.java:SysIndexController.switchSkin；SysIndexController.java:SysIndexController.main
- `RuoYi/authz/缺 Sink`：SysJobController.java:SysJobController.cron；GenController.java:GenController.createTable；CommonController.java:CommonController.fileDownload；CommonController.java:CommonController.uploadFile；CommonController.java:CommonController.uploadFiles
- `RuoYi/pathtraver/缺 Sink`：GenController.java:GenController.importTableSave；GenController.java:GenController.editSave；GenController.java:GenController.preview；GenController.java:GenController.download；GenController.java:GenController.batchGenCode
- `RuoYi/deserial/含未知安全包装`：GenController.java:GenController.download；CommonController.java:CommonController.fileDownload；CommonController.java:CommonController.uploadFile；CommonController.java:CommonController.uploadFiles；SysProfileController.java:SysProfileController.updateAvatar
- `RuoYi/pathtraver/含未知安全包装`：GenController.java:GenController.genCode；CommonController.java:CommonController.fileDownload
- `RuoYi/pathtraver/缺 Source`：CommonController.java:CommonController.resourceDownload
- `RuoYi/deserial/缺 Source`：CommonController.java:CommonController.resourceDownload；DemoFormController.java:DemoFormController.upload
- `RuoYi/access_control/缺 Source`：CacheController.java:CacheController.cache；CacheController.java:CacheController.getCacheNames；CacheController.java:CacheController.getCacheKeys；CacheController.java:CacheController.getCacheValue；ServerController.java:ServerController.server
- `RuoYi/xxe/缺 Source`：ServerController.java:ServerController.server；SysLoginController.java:SysLoginController.ajaxLogin
- `RuoYi/xss/含未知安全包装`：SysCaptchaController.java:SysCaptchaController.getKaptchaImage
- `RuoYi/authz/跨文件链路未闭合`：SysIndexController.java:SysIndexController.menuStyle；TestController.java:TestController.update；TestController.java:TestController.delete
- `RuoYi/authz/含未知安全包装`：SysLoginController.java:SysLoginController.login
- `RuoYi/access_control/跨文件链路未闭合`：TestController.java:TestController.update
- `eladmin-mp/sqli/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/xss/含未知安全包装`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；DeployController.java:DeployController.uploadDeploy；GeneratorController.java:GeneratorController.generatorCode
- `eladmin-mp/cmdi/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/deserial/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；DeptController.java:DeptController.getDeptSuperior；DictController.java:DictController.queryAllDict
- `eladmin-mp/ssrf/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/xxe/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/reentrancy/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/access_control/缺 Sink`：AliPayController.java:AliPayController.toPayAsPc；AliPayController.java:AliPayController.toPayAsWeb；AliPayController.java:AliPayController.notify；LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture
- `eladmin-mp/authz/含未知安全包装`：AliPayController.java:AliPayController.notify；AuthController.java:AuthController.getUserInfo；GeneratorController.java:GeneratorController.syncColumn
- `eladmin-mp/pathtraver/含未知安全包装`：LocalStorageController.java:LocalStorageController.exportFile；S3StorageController.java:S3StorageController.exportS3Storage；DeptController.java:DeptController.exportDept；DictController.java:DictController.exportDict；JobController.java:JobController.exportJob
- `eladmin-mp/deserial/含未知安全包装`：LocalStorageController.java:LocalStorageController.exportFile；LocalStorageController.java:LocalStorageController.uploadPicture；S3StorageController.java:S3StorageController.exportS3Storage；DeptController.java:DeptController.exportDept；DictController.java:DictController.exportDict
- `eladmin-mp/pathtraver/缺 Sink`：LocalStorageController.java:LocalStorageController.uploadPicture；S3StorageController.java:S3StorageController.downloadS3Storage；RoleController.java:RoleController.getRoleLevel；UserController.java:UserController.updateUserAvatar；VerifyController.java:VerifyController.resetEmail
- `eladmin-mp/xss/缺 Sink`：LocalStorageController.java:LocalStorageController.uploadPicture；S3StorageController.java:S3StorageController.downloadS3Storage；DeptController.java:DeptController.getDeptSuperior；DictDetailController.java:DictDetailController.getDictDetailMaps；DictDetailController.java:DictDetailController.deleteDictDetail
- `eladmin-mp/deserial/跨文件链路未闭合`：S3StorageController.java:S3StorageController.downloadS3Storage；UserController.java:UserController.updateUserAvatar
- `eladmin-mp/reentrancy/含未知安全包装`：VerifyController.java:VerifyController.resetEmail；VerifyController.java:VerifyController.resetPass
- `eladmin-mp/sqli/含未知安全包装`：QuartzJobController.java:QuartzJobController.exportQuartzJob；QuartzJobController.java:QuartzJobController.exportQuartzJobLog；QuartzJobController.java:QuartzJobController.queryQuartzJobLog；QuartzJobController.java:QuartzJobController.updateQuartzJobStatus；QuartzJobController.java:QuartzJobController.executionQuartzJob
- `eladmin-mp/access_control/含未知安全包装`：DatabaseController.java:DatabaseController.uploadDatabase；DeployController.java:DeployController.uploadDeploy
- `eladmin-mp/pathtraver/缺 Source`：SysLogController.java:SysLogController.exportLog；SysLogController.java:SysLogController.exportErrorLog
