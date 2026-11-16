# CVE 傻瓜式三步交单套件（2026-11-08）

按“傻瓜式三步交单手册”模板生成的 5 份 CVE 文档；第 1 单 ruoyi-vue-pro 已有 CAN-2026-2041058，不在本套件内。5 份均已通过 MITRE CVE form API 提交。

| # | 单 | 文件 | Issue | CWE | CAN（2026-11-08） |
|---|---|---|---|---|---|
| 1 | metasfresh SQLi | 01_metasfresh.md | #27079 | CWE-89 | CAN-2026-2042689 |
| 2 | x-springboot /sys/gen/create | 02_x_springboot.md | #47 | CWE-22/73 | CAN-2026-2042693 |
| 3 | WorkFlow-Engine 9 路由 SQLi | 03_workflow.md | #4 | CWE-89 | CAN-2026-2042690 |
| 4 | Network-Drive chunk 路径穿越 | 04_network.md | #2 | CWE-22 | CAN-2026-2042691 |
| 5 | eladmin S3 upload 缺授权 | 05_eladmin.md | #926 | CWE-862 | CAN-2026-2042692 |

当前 6 单状态总表见 [CVE_AUTO_SUBMIT_2026-11-08.md](CVE_AUTO_SUBMIT_2026-11-08.md)：6 个 CAN 均为 PUBLISHED，等待 MITRE 审核分配正式 CVE。

## v1.5.17 新增候选（防御修复包，未提交）

| # | 单 | 文件 | 披露入口 | CWE | 状态 |
|---|---|---|---|---|---|
| 6 | android-agent 未授权目录删除 | [06_android_agent.md](06_android_agent.md) | GitHub Private Security Advisory / security@ghostinthedroid.com | CWE-22 / CWE-862 | 待用户通过 GitHub Private Security Advisory 私密提交 |

该文件只含代码定位与防御补丁，不含攻击载荷或 `curl` 攻击命令。

## v1.5.20 新增候选（防御修复包，未提交）

| # | 单 | 文件 | 披露入口 | CWE | 状态 |
|---|---|---|---|---|---|
| 7 | dify-for-dsl 未授权 SSRF | [07_dify_for_dsl.md](07_dify_for_dsl.md) | GitHub Issue / 私密 Security Advisory（仓库无 SECURITY.md） | CWE-918 | 待用户决定是否提交 |

该文件只含代码定位与防御补丁，不含攻击载荷或 `curl` 攻击命令。

每份都包含：Step 1 提交入口、Step 2 GitHub 标题/描述、Step 3 CVE.org 六框、Step 3B CVE Services 逐框值、过审三要素、固定答法、提交前检查。
