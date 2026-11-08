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

每份都包含：Step 1 提交入口、Step 2 GitHub 标题/描述、Step 3 CVE.org 六框、Step 3B CVE Services 逐框值、过审三要素、固定答法、提交前检查。
