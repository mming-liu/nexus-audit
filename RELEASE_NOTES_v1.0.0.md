# nexus-audit v1.0.0 发布说明（2026-10-26）

这是 M167 → M250 五波施工的封版版本。所有数字来自实跑：
wild_hunt.json（50 仓）、cross_repo_clusters.json（127 簇）、
advisories/INDEX.md（209 份）、run_all.md（68 PASS）、smoke（[1]-[250] 1503 断言）。

## 一、封版数字

| 项 | 数值 |
|---|---|
| 真实野仓 | 50（Java 20 + Python 15 + Solidity 15） |
| 入口/合约单元 | 15,617 |
| 路由级 P0 | 4,999 |
| 独立根因 / GHSA 草稿 | 209 / 209 |
| 跨仓簇 | 127 / 多仓共现 15 |
| 确定性规则 | 40 类 |
| 确定性补丁器 | 35 类 |
| run_all | 68 PASS / 0 FAIL / 0 SKIP |
| 冒烟 | [1]-[250] / 1,503 断言 |
| doctor | 12 段 PASS |

## 二、封版新增（M233-M250）

- cli.py matrix --check / --json：40 类 CWE + CVSS 3.1 全覆盖，幽灵类目即红。
- cli.py export-packs：Top-10 跨语言交单包 + INDEX.md（每包 ADVISORY /
  poc_test / 已验证 fix.patch / SUBMISSION_CHECKLIST / manifest）。
- cli.py ci-init：GitHub Actions / GitLab CI / Watchtower cron 三目标。
- benchmarks/verify_reproducibility.py：50 仓根因、聚类、排序的 canonical
  sha256 基线；--check 跨次运行字节级守恒。
- doctor 扩到 [1/12]-[12/12]：新增矩阵 CWE/CVSS 校验与确定性重现。
- run_all 68 项：新增确定性重现门禁。

## 三、Top-10 交单包

1. My-Blog / unrestricted_upload / BlogController.uploadFileByEditormd
2. newbee-mall / weakrand / UploadController.upload
3. RuoYi / sqli / GenController.create
4. newbee-mall / unrestricted_upload / UploadController.upload
5. newbee-mall-api / unrestricted_upload / NewBeeAdminUploadAPI.upload
6. newbee-mall-api / weakrand / NewBeeAdminUploadAPI.upload
7. My-Blog / weakrand / BlogController.uploadFileByEditormd
8. My-Blog / unrestricted_upload / UploadController.upload
9. My-Blog / weakrand / UploadController.upload
10. spring-boot-demo / unrestricted_upload / UploadController.local

十包补丁均实测 True → False；ADVISORY 带 [Auto-Fix Verified]。

## 四、诚实边界

1. halo 与 starlette 是函数式/对象式路由，注解切片器覆盖为 0；基准登记
   RouterFunction / Route+requires 机制与反向锚点，不等于整仓无漏洞。
2. 多个基准是**模块级**：ruoyi 只锁 system+infra，spring 只锁 5 个安全模块，
   xxl 只锁 authz+deserial；整仓剩余候选仍在 wild_hunt 根因里。
3. aave-v3-periphery 的 Collector.transfer 是已知真阳性，不是误报；
   WrappedTokenGatewayV3 因 aToken revert 语义被排除。
4. 209 根因中 ruoyi 46、spring 12 等含人工复核队列；零误报只对 benchmark
   层与已登记的真阳性集合负责。

## 五、复现

    python cli.py doctor
    python benchmarks/run_all.py --offline --jobs 4
    python benchmarks/smoke_test_chains.py
    python benchmarks/verify_reproducibility.py --check

沙箱禁止匿名管道时，run_all 会明确告警并顺序执行（并发是加速，不是门禁语义）。
