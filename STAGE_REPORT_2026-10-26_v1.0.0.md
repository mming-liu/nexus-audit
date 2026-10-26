# nexus-audit v1.0.0 封版阶段报告（2026-10-26）

M167 → M250 五波施工完成。四大门禁实跑：
doctor 12 段 PASS、run_all 68 PASS / 0 FAIL / 0 SKIP、
smoke [1]-[250] 1,503 断言 PASS、verify_reproducibility PASS。

## 一、最终数字

| 项 | 数值 |
|---|---|
| 真实野仓 | 50（Java 20 + Python 15 + Solidity 15） |
| 入口/合约单元 | 15,617 |
| 路由级 P0 | 4,999 |
| 独立根因 / GHSA 草稿 | 209 / 209 |
| 跨仓簇 | 127 / 多仓共现 15 |
| 规则 / 补丁器 | 40 / 35 |
| run_all | 68 PASS |
| 冒烟 | [1]-[250] / 1,503 断言 |
| doctor | [1/12]-[12/12] PASS |
| Top-10 交单包 | 10（四件套 + manifest + Auto-Fix） |

## 二、五波交付

1. 第一波 M167-M182：spring-boot-demo / xxl-job / flask-realworld /
   v3-periphery；nosqli / log_injection；38 仓 / 55 门禁。
2. 第二波 M183-M198：morpho-blue / flask-jwt-extended / ruoyi-vue-pro /
   solmate；unchecked_erc20_return / oracle_stale_price；42 仓 / 59 门禁。
3. 第三波 M199-M214：django-oauth-toolkit / flask-admin / Sentinel /
   aave-v3-periphery；csrf_disabled / regex_dos；46 仓 / 63 门禁。
4. 第四波 M215-M232：halo / sanic / litestar / starlette；
   jndi_injection / arbitrary_file_delete；50 仓 / 67 门禁。
5. 第五波 M233-M250：matrix --check、export-packs、ci-init、
   verify_reproducibility、doctor 12 段、run_all 68、v1.0.0。

## 三、封版命令与产物

- cli.py matrix --check / --json
- cli.py export-packs [--check]
- cli.py ci-init [--target github|gitlab|watchtower]
- benchmarks/verify_reproducibility.py --write/--check
- benchmarks/results/first_blood_packs/（10 包 + INDEX.md）
- .github/workflows/nexus-audit.yml / .gitlab-ci.yml / watchtower.cron
- RELEASE_NOTES_v1.0.0.md

## 四、诚实边界

1. halo / starlette 的函数式/对象式路由未被注解切片器覆盖（0 入口），
   基准登记 RouterFunction / Route+requires 与反向锚点，不是整仓无漏洞。
2. ruoyi 只锁 system+infra，spring 只锁 5 个安全模块，xxl 只锁 authz+deserial；
   整仓剩余候选仍在 209 根因里，属人工复核队列。
3. aave 的 Collector.transfer 是已知真阳性，不是误报；WrappedTokenGateway
   因 aToken revert 语义排除。
4. 209 根因中 ruoyi 46、spring 12 等含未逐条人工确认的候选；零误报只对
   benchmark 层与已登记真阳性集合负责。

## 五、复现

    python cli.py doctor
    python benchmarks/run_all.py --offline --jobs 4
    python benchmarks/smoke_test_chains.py
    python benchmarks/verify_reproducibility.py --check
    python cli.py export-packs --check

沙箱禁止匿名管道时 run_all 明确告警并顺序执行；并发是加速，不是门禁语义。
