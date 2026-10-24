"""一键多语言基准总控面板（Module 15 建，Module 26 加并发与计分板）。

    python benchmarks/run_all.py --offline            # 顺序执行
    python benchmarks/run_all.py --offline --jobs 4   # 多进程并发

跑全部**离线**门禁（不调模型），输出统一 Markdown 计分板：
  1. smoke_test_chains.py         —— [1]-[93] 判据链路断言
  2. export_disputes.py --check   —— 争议登记证据逐字核对
  3. 13 项靶场回归（12 个 --strict + dvdefi 健壮性抽检；缺仓库记 SKIP）

并发语义（--jobs N）：各靶场脚本相互独立、只读各自目录、只写各自的
results/*.json，天然可并行；冒烟与争议核对仍保持串行（快且是其余
一切的前置）。快速失败语义保留：任何 FAIL 后不再**启动**新作业。

额外产出 benchmarks/results/SCOREBOARD.md：汇总全靶场
覆盖率 / 正确率 / A·B 方向错误（读各 results/*.json 的规则层字段），
供阶段报告与 CI 摘要引用。只在全绿时刷新——红着的时候不许换墙上的数。

退出码：全部已执行项通过 → 0；任何 FAIL → 1；SKIP 不影响退出码。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
OUT = ROOT / "benchmarks" / "results" / "run_all.md"
SCOREBOARD = ROOT / "benchmarks" / "results" / "SCOREBOARD.md"

# (名称, 命令, 前置目录检查, 类别, 可并发)
#   可并发=False 的是冒烟/核对（快，且是语义前置），保持串行。
JOBS = [
    ("冒烟测试 [1]-[122]", ["benchmarks/smoke_test_chains.py"], None, "smoke", False),
    ("争议登记核对", ["benchmarks/export_disputes.py", "--check"], None, "smoke", False),
    ("OWASP 全量", ["benchmarks/regress_owasp_rules.py"],
     "reference_repos/BenchmarkJava-master", "target", True),
    ("java-sec-code", ["benchmarks/benchmark_javaseccode.py", "--offline"],
     "reference_repos/java-sec-code", "target", True),
    ("Hello-Java-Sec", ["benchmarks/benchmark_hellojavasec.py", "--offline"],
     "reference_repos/Hello-Java-Sec-master", "target", True),
    ("JavaSecLab", ["benchmarks/benchmark_javaseclab.py", "--offline"],
     "reference_repos/JavaSecLab-main", "target", True),
    ("micro_service_seclab", ["benchmarks/benchmark_msseclab.py", "--offline"],
     "reference_repos/micro_service_seclab-main", "target", True),
    ("newbee-mall", ["benchmarks/benchmark_newbeemall.py", "--strict"],
     "reference_repos/newbee-mall-master", "target", True),
    ("newbee-mall-api", ["benchmarks/benchmark_newbeemallapi.py", "--strict"],
     "reference_repos/newbee-mall-api-master", "target", True),
    ("vulpy (Python)", ["benchmarks/benchmark_vulpy.py", "--strict"],
     "reference_repos/vulpy-master", "target", True),
    # smartbugs 的模型层（Module 17）只跑规则退回批，需要真实模型网关；
    # 总控是**离线**门禁，必须显式 --offline 否则 197 条会开始发请求。
    ("smartbugs-curated (Solidity)", ["benchmarks/benchmark_smartbugs.py", "--strict",
                                      "--offline"],
     "reference_repos/smartbugs-curated-main", "target", True),
    # 第 9 靶场（Module 19）：成对 vuln/fixed 真值 + 0.8.x 语法。存在的唯一
    # 理由是 smartbugs 的 access_control 漏洞分母只有 18（<20 就不许下结论）。
    # 模型层同样需要网关，离线门禁必须显式 --offline。
    ("DeFiVulnLabs (Solidity 成对真值)", ["benchmarks/benchmark_defivulnlabs.py",
                                         "--strict", "--offline"],
     "reference_repos/DeFiVulnLabs-main", "target", True),
    # dvdefi 是**经济逻辑漏洞**靶场（预言机操纵 / 闪贷治理 / 价格偏差），我们
    # 没有对应类目与判据 —— 它不产 TPR/FPR，只做健壮性抽检：切片不退化
    # （164 单元）+ 判定面不爆炸（True ≤8）。防的是"改坏了没人知道"。
    ("damn-vulnerable-defi (健壮性抽检)", ["benchmarks/benchmark_dvdefi_sanity.py",
                                          "--sanity"],
     "reference_repos/damn-vulnerable-defi-master", "target", True),
    # 第 10 靶场（Module 20）：Trail of Bits 官方漏洞集，补 access_control 分母
    # 裕度。真值只收 README 指名条目（honeypots 是陷阱口径，不收）。
    ("not-so-smart-contracts (Solidity)", ["benchmarks/benchmark_nssc.py",
                                           "--strict", "--offline"],
     "reference_repos/not-so-smart-contracts-master", "target", True),
    # 第 11 靶场（Module 22/23）：RuoYi 企业级多模块。锁跨 Maven 子模块
    # 穿透（Hop 证据 ≥100 单元）与 @RequiresPermissions 注解语义；真实
    # 验证 ${params.dataScope} 被 @DataScope 切面 clear+overwrite，不是 SQLi。
    ("RuoYi (Java 多模块)", ["benchmarks/benchmark_ruoyi.py", "--strict", "--offline"],
     "reference_repos/RuoYi-master", "target", True),
    # 第 12 靶场（Module 24/25）：pygoat 20 个 Flask lab。逼出 SymbolIndexer
    # 同名符号覆盖修复（50→119 单元）与 Python deserial/pathtraver/xxe 判据。
    ("pygoat (Python Flask labs)", ["benchmarks/benchmark_pygoat.py", "--strict",
                                    "--offline"],
     "reference_repos/pygoat-master", "target", True),
    # 第 15 靶场（Module 29）：eladmin-mp。Spring Security 自定义 EL 权限
    # （@PreAuthorize("@el.check(...)") 53 条垂直授权声明）+ MyBatis-Plus
    # Wrapper 判据（拼接出口 True / 纯参数化 False，机制由冒烟 [75] 锁定）。
    ("eladmin-mp (MyBatis-Plus)", ["benchmarks/benchmark_eladminmp.py", "--strict",
                                   "--offline"],
     "reference_repos/eladmin-mp-master", "target", True),
    # 第 16 靶场（Module 37）：VAmPI。Connexion/OpenAPI 路由通道
    # （operationId → 零装饰器函数）+ JWT 主体链判据（decode_auth_token →
    # resp['sub']），机制由冒烟 [81] 锁定。
    ("VAmPI (Connexion/OpenAPI)", ["benchmarks/benchmark_vampi.py", "--strict",
                                   "--offline"],
     "reference_repos/VAmPI-main", "target", True),
    # 第 17 靶场（Module 38）：mall。生产级项目对照面——零误报门禁：
    # 全库 246 单元零 True。逼出仓库级全局鉴权豁免（[global-authz] 标记）、
    # getCurrentMember 主体链（2g-2）、MBG Example 参数化判据（sqli C2b），
    # 以及 _interface_index 列表化 / _pick_impl 后缀匹配（铁律 24 同构坑）。
    ("mall (生产级多模块对照)", ["benchmarks/benchmark_mall.py", "--strict"],
     "reference_repos/mall-main", "target", True),
    # 第 20 项（Module 41）：覆盖地板门禁。strict 只锁误报/判反，
    # 覆盖率下滑（新退回路径）没人拦 —— 这里锁各靶场确定性命中数下限。
    ("覆盖地板门禁", ["benchmarks/triage_fallbacks.py", "--check-floor"],
     None, "smoke", False),
    # 第 21 项（Module 46）：WebGoat。教学关卡成对真值（攻击关 vs 修复关，
    # 同库同构）。逼出 sqli 的"整句 SQL 由用户控制"判据（executeQuery(query)
    # 形参直传，非拼接形态）—— 这一整类经典注入此前全退 None。
    # 只登记口径一致的 sqli 关卡：pathtraversal/xxe/ssrf/idor 四门课程
    # 经探针判定为口径冲突或 sink 跨文件不可判，一律不登记。
    ("WebGoat (教学关卡成对真值)", ["benchmarks/benchmark_webgoat.py", "--strict"],
     "reference_repos/WebGoat-master", "target", True),
    # 第 23 靶场（Module 63）：My-Blog。首轮野战实弹——真实开源博客系统，
    # 真值来自盲测逐条人工核查（MD5 密码哈希 + 2 条弱随机上传文件名）。
    # 逼出三项通用淬火：Spring MVC 拦截器前缀覆盖 → [global-authz]、
    # 公开内容路由豁免（authz）、SSRF 接收者语义三分（强/谓词/弱+旁证）。
    ("My-Blog (野战实弹)", ["benchmarks/benchmark_myblog.py", "--strict"],
     "reference_repos/My-Blog-master", "target", True),
    # 第 24 靶场（Module 64）：litemall。20k Star 多模块小程序商城。
    # 逼出四项淬火：Bean Validation 白名单标记（@Sort/@Order + C2b 豁免）、
    # Shiro 过滤链前缀覆盖、显式 token 鉴权模块（@LoginUser 模型）、
    # path sink 与形参相关性（含 request.getInputStream 排除）。
    ("litemall (野战实弹)", ["benchmarks/benchmark_litemall.py", "--strict"],
     "reference_repos/litemall-master", "target", True),
    # 第 25 靶场（Module 72）：真实 Flask-SQLAlchemy CRUD。
    # 真值 2 条（delete 对象级 authz + app.secret_key 文件级密钥），
    # insert/update 的"缺失认证"单列人工复核，不掺真值。
    ("Employee-Management-System (Python 野战)",
     ["benchmarks/benchmark_flaskcrud.py", "--strict"],
     "reference_repos/employee-management-system", "target", True),
    # 第 26 靶场（Module 73）：compound-protocol 生产 contracts/。
    # 顶级 DeFi 协议压测 Solidity 规则层：450 入口 / 0 条 True 误报。
    ("compound-protocol (Solidity 生产协议)",
     ["benchmarks/benchmark_compound.py", "--strict"],
     "reference_repos/compound-protocol/contracts", "target", True),
    # 第 27 靶场（Module 79）：Uniswap V3 生产 contracts/。
    # 自定义状态互斥锁 lock() 通用识别；67 入口 / 0 True。
    ("uniswap-v3-core (Solidity DEX)",
     ["benchmarks/benchmark_uniswapv3.py", "--strict"],
     "reference_repos/uniswap-v3-core/contracts", "target", True),
    # 第 28 靶场（Module 87）：compound-finance/comet（Compound V3）生产 contracts/。
    # 0.8.15 时代的旗舰协议：437 入口里 37 个含 `unchecked {}`、206 个含
    # `revert CustomError()` —— M53 那套 0.4.x 溢出词表的**反面样本**。
    # 锁两件事：unchecked 分区语义（块外编译器保护 / 块内游标安全）与
    # 自定义错误中止识别。435 入口 / 0 True。
    ("compound-finance/comet (Solidity 0.8.x)",
     ["benchmarks/benchmark_comet.py", "--strict"],
     "reference_repos/comet/contracts", "target", True),
    # 第 29 靶场（Module 88）：DjanGoat（OWASP RailsGoat 的 Django 移植版）。
    # 纯 Django 应用：路由全部外置在 urls.py 的 urlpatterns 里、视图零装饰器。
    # M88 之前只认装饰器 → 13 个入口（其中 9 个还是 "GET" 碰巧命中 `get`）；
    # 路由表通道上线后 36 入口 / 23 条路由证据 / 真值 11/11 / 0 误报。
    ("DjanGoat (Django urls.py 路由表)",
     ["benchmarks/benchmark_djangoat.py", "--strict"],
     "reference_repos/DjanGoat", "target", True),
    # 第 28 靶场（Module 80）：FastAPI async + Depends + SQLAlchemy 2.0。
    # 9 异步入口 / users 全 authz False / 0 True。
    ("FastAPI (Python 异步真实模板)",
     ["benchmarks/benchmark_fastapi_wild.py", "--strict"],
     "reference_repos/fastapi-sql-template", "target", True),
]


def run_job(name: str, cmd: list[str]) -> tuple[str, float, str]:
    t0 = time.monotonic()
    p = subprocess.run([PY, *cmd], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    dt = time.monotonic() - t0
    ok = p.returncode == 0
    detail = (p.stdout + p.stderr).strip().splitlines()
    tail = detail[-1] if detail else ""
    return ("PASS" if ok else "FAIL"), dt, tail


def _run_parallel(jobs: list[tuple[str, list[str]]], jobs_n: int) -> dict[str, tuple[str, float, str]]:
    """并发跑作业。快速失败：首个 FAIL 后不再启动新作业。"""
    results: dict[str, tuple[str, float, str]] = {}
    with ProcessPoolExecutor(max_workers=jobs_n) as ex:
        futures = [(name, ex.submit(run_job, name, cmd)) for name, cmd in jobs]
        running = list(futures)
        failed = False
        idx = 0
        in_flight: list[tuple[str, object]] = []
        while idx < len(running) or in_flight:
            while idx < len(running) and len(in_flight) < jobs_n and not failed:
                in_flight.append(running[idx])
                idx += 1
            if not in_flight:
                break
            name, fut = in_flight.pop(0)
            if failed:
                results[name] = ("SKIP", 0.0, "快速失败：前序门禁 FAIL")
                continue
            status, dt, tail = fut.result()
            results[name] = (status, dt, tail)
            if status == "FAIL":
                failed = True
    return results


def build_scoreboard() -> str:
    """从各靶场的 results/*.json 汇总规则层计分板。

    白名单制：只收**字段完备的真值型靶场**（单元数/判定/判对/误报/判反
    五个标量齐全）。Hello-Java-Sec 等脚本的 json 不产这套字段——硬凑
    出来就是一列 0，宁可少一行也不放假数字。只报**规则层**（离线可
    复现），模型层字段一律不进计分板——模型非确定性，写上去就是让
    随机数上墙。ab_* 实验文件与 smartbugs_model（模型层副本）不进总数。
    """
    r = ROOT / "benchmarks" / "results"
    out = ["# nexus-audit 全语言计分板（规则层·离线可复现）", "",
           f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}", "",
           "| 靶场 | 单元 | 规则判定 | 判对 | 误报 | 判反 | 覆盖率 |",
           "|---|---|---|---|---|---|---|"]

    WHITELIST = [
        ("smartbugs-curated (Solidity)", "smartbugs.json", "total_functions"),
        ("DeFiVulnLabs (Solidity)", "defivulnlabs.json", "total_functions"),
        ("not-so-smart-contracts (Solidity)", "nssc.json", "total_functions"),
        ("vulpy (Python)", "vulpy.json", "total_units"),
        ("RuoYi (Java 多模块)", "ruoyi.json", "total_units"),
        ("pygoat (Python Flask labs)", "pygoat.json", "total_units"),
        ("eladmin-mp (MyBatis-Plus)", "eladminmp.json", "total_units"),
        ("VAmPI (Connexion/OpenAPI)", "vampi.json", "total_units"),
        ("mall (生产级多模块对照)", "mall.json", "total_units"),
        ("WebGoat (教学关卡成对真值)", "webgoat.json", "total_units"),
        ("compound-protocol (Solidity 生产协议)", "compound.json", "total_units"),
        ("uniswap-v3-core (Solidity DEX)", "uniswapv3.json", "total_units"),
        ("FastAPI (Python 异步真实模板)", "fastapi_wild.json", "total_units"),
        ("compound-finance/comet (Solidity 0.8.x)", "comet.json", "total_units"),
        ("DjanGoat (Django urls.py 路由表)", "djangoat.json", "total_units"),
    ]
    total_fp = total_rev = 0
    for label, fname, unit_key in WHITELIST:
        j = r / fname
        if not j.exists():
            continue
        d = json.loads(j.read_text(encoding="utf-8"))
        units = d.get(unit_key, 0)
        decided = d.get("decided", 0)
        correct = d.get("correct", 0)
        fp = d.get("fp", 0)
        rev = d.get("reverse_fn", 0)
        if not all(isinstance(x, (int, float)) for x in (units, decided, correct, fp, rev)):
            continue                      # 字段不完备的行不硬凑
        cov = f"{decided / units * 100:.0f}%" if units else "—"
        out.append(f"| {label} | {units} | {decided} | {correct} | {fp} | {rev} | {cov} |")
        total_fp += fp
        total_rev += rev
    out += ["", f"**计分板靶场合计：误报 {total_fp} · 判反 {total_rev}"
            f"（A/B 方向错误 = {total_fp + total_rev}）**",
            "", "> 模型层数字（TPR/FPR）不进计分板：非确定性，离线不可复现。",
            "> Java 教学靶场（OWASP/java-sec-code/Hello-Java-Sec/JavaSecLab/"
            "msseclab/newbee 双库）的 json 不产本表五字段，数字见各自脚本输出。", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", default=True,
                    help="只跑离线项（当前全部作业均为离线）")
    ap.add_argument("--jobs", type=int, default=1,
                    help="并发进程数（≥2 启用并发，默认顺序执行）")
    ap.add_argument("--output", default=str(OUT))
    args = ap.parse_args()

    rows: list[tuple[str, str, float, str]] = []
    print("=" * 72)
    print("nexus-audit 全量离线门禁" +
          (f"（--jobs {args.jobs}）" if args.jobs > 1 else ""))
    print("=" * 72)

    parallel_jobs: list[tuple[str, list[str]]] = []
    serial: list[tuple[str, list[str]]] = []
    for name, cmd, need, _kind, parallel in JOBS:
        if need and not (ROOT / need).exists():
            rows.append((name, "SKIP", 0.0, f"缺少 {need}"))
            print(f"  SKIP  {name}（缺少 {need}）")
            continue
        if parallel and args.jobs > 1:
            parallel_jobs.append((name, cmd))
        else:
            serial.append((name, cmd))

    # 串行段（冒烟/核对；未开并发时的一切靶场也在这段）
    failed = False
    for name, cmd in serial:
        if failed:
            rows.append((name, "SKIP", 0.0, "快速失败：前序门禁 FAIL"))
            continue
        print(f"  RUN   {name} ...", flush=True)
        status, dt, tail = run_job(name, cmd)
        rows.append((name, status, dt, tail))
        print(f"    {'✔' if status == 'PASS' else '✘'} {status}  {dt:.1f}s  {tail[:80]}")
        if status == "FAIL":
            failed = True

    # 并发段
    if parallel_jobs and not failed:
        print(f"  并发执行 {len(parallel_jobs)} 项（workers={args.jobs}）...", flush=True)
        t0 = time.monotonic()
        for name, (status, dt, tail) in _run_parallel(parallel_jobs, args.jobs).items():
            rows.append((name, status, dt, tail))
            print(f"    {'✔' if status == 'PASS' else '✘'} {status}  {dt:.1f}s  {name} | {tail[:60]}")
        print(f"    并发段耗时 {time.monotonic() - t0:.1f}s")

    out_lines = [
        "# nexus-audit 离线门禁计分板", "",
        f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}"
        + (f"（--jobs {args.jobs}）" if args.jobs > 1 else ""), "",
        "| 门禁 | 结果 | 耗时 | 尾行 |", "|---|---|---|---|",
    ]
    for name, status, dt, tail in rows:
        out_lines.append(f"| {name} | {status} | {dt:.1f}s | {tail[:60]} |")
    n_pass = sum(1 for _, s, *_ in rows if s == "PASS")
    n_fail = sum(1 for _, s, *_ in rows if s == "FAIL")
    n_skip = sum(1 for _, s, *_ in rows if s == "SKIP")
    out_lines += ["", f"**{n_pass} PASS / {n_fail} FAIL / {n_skip} SKIP**", ""]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(out_lines), encoding="utf-8")
    print(f"\n计分板写入 {args.output}")
    print(f"合计：{n_pass} PASS / {n_fail} FAIL / {n_skip} SKIP")

    # SCOREBOARD：只有全绿才刷新（红着的时候不许换墙上的数）
    if n_fail == 0:
        SCOREBOARD.write_text(build_scoreboard(), encoding="utf-8")
        print(f"全语言计分板写入 {SCOREBOARD}")

    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
