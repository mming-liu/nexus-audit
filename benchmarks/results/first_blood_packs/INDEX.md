# Top-10 候选交单包（nexus-audit v1.3.2 · 非教学仓严选；9 条通过补丁自检）

> M259：剔除教学仓与纯 CORS，同函数多规则合并，每仓最多 2 条；补丁自检 True -> False 才入包。目标 Top-10，实测不足时**不拿未验证补丁凑数**，缺额如实标注。

| # | 包 | 角色 | 来源 | 类目 | CVSS | 四件套 |
|---|---|---|---|---|---|---|
| 1 | Sentinel_log_injection_login | production | KNOWN_CVE_BENCHMARK | log_injection | 8.1 | ✔ |
| 2 | Sentinel_log_injection_apiAssignAllClusterServersOfApp | production | ZERO_RECORD_FRESH | log_injection | 8.1 | ✔ |
| 3 | RuoYi_sqli_create | production | UNVERIFIED | sqli | 9.8 | ✔ |
| 4 | django-realworld_hardcoded_secret_py | production | UNVERIFIED | hardcoded_secret | 9.8 | ✔ |
| 5 | litemall_hardcoded_secret_java | production | UNVERIFIED | hardcoded_secret | 9.8 | ✔ |
| 6 | My-Blog_unrestricted_upload_uploadFileByEditormd | production | UNVERIFIED | unrestricted_upload | 8.1 | ✔ |
| 7 | My-Blog_unrestricted_upload_upload | production | UNVERIFIED | unrestricted_upload | 8.1 | ✔ |
| 8 | newbee-mall_unrestricted_upload_upload | production | STALE_REPO | unrestricted_upload | 8.1 | ✔ |
| 9 | newbee-mall-api_unrestricted_upload_upload | production | STALE_REPO | unrestricted_upload | 8.1 | ✔ |
