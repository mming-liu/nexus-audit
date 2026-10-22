"""一键多语言基准总控面板（Module 15）。

    python benchmarks/run_all.py --offline

顺序跑全部**离线**门禁（不调模型），输出统一 Markdown 计分板：
  1. smoke_test_chains.py         —— [1]-[65] 判据链路断言
  2. export_disputes.py --check   —— 争议登记证据逐字核对
  3. 8 个靶场规则层 --strict 回归（仓库存在才跑，缺失记 SKIP）

退出码：全部已执行项通过 → 0；任何 FAIL → 1；SKIP 不影响退出码。
耗时与结果同时写入 benchmarks/results/run_all.md，供 CI 与阶段报告引用。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
OUT = ROOT / "benchmarks" / "results" / "run_all.md"

# (名称, 命令, 前置目录检查, 类别)
JOBS = [
    ("冒烟测试 [1]-[65]", ["benchmarks/smoke_test_chains.py"], None, "smoke"),
    ("争议登记核对", ["benchmarks/export_disputes.py", "--check"], None, "smoke"),
    ("OWASP 全量", ["benchmarks/regress_owasp_rules.py"],
     "reference_repos/BenchmarkJava-master", "target"),
    ("java-sec-code", ["benchmarks/benchmark_javaseccode.py", "--offline"],
     "reference_repos/java-sec-code", "target"),
    ("Hello-Java-Sec", ["benchmarks/benchmark_hellojavasec.py", "--offline"],
     "reference_repos/Hello-Java-Sec-master", "target"),
    ("JavaSecLab", ["benchmarks/benchmark_javaseclab.py", "--offline"],
     "reference_repos/JavaSecLab-main", "target"),
    ("micro_service_seclab", ["benchmarks/benchmark_msseclab.py", "--offline"],
     "reference_repos/micro_service_seclab-main", "target"),
    ("newbee-mall", ["benchmarks/benchmark_newbeemall.py", "--strict"],
     "reference_repos/newbee-mall-master", "target"),
    ("newbee-mall-api", ["benchmarks/benchmark_newbeemallapi.py", "--strict"],
     "reference_repos/newbee-mall-api-master", "target"),
    ("vulpy (Python)", ["benchmarks/benchmark_vulpy.py", "--strict"],
     "reference_repos/vulpy-master", "target"),
    # smartbugs 的模型层（Module 17）只跑规则退回批，需要真实模型网关；
    # 总控是**离线**门禁，必须显式 --offline 否则 197 条会开始发请求。
    ("smartbugs-curated (Solidity)", ["benchmarks/benchmark_smartbugs.py", "--strict",
                                      "--offline"],
     "reference_repos/smartbugs-curated-main", "target"),
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", default=True,
                    help="只跑离线项（当前全部作业均为离线）")
    ap.add_argument("--output", default=str(OUT))
    args = ap.parse_args()

    rows: list[tuple[str, str, float, str]] = []
    print("=" * 72)
    print("nexus-audit 全量离线门禁")
    print("=" * 72)
    for name, cmd, need, _kind in JOBS:
        if need and not (ROOT / need).exists():
            rows.append((name, "SKIP", 0.0, f"缺少 {need}"))
            print(f"  SKIP  {name}（缺少 {need}）")
            continue
        print(f"  RUN   {name} ...", flush=True)
        status, dt, tail = run_job(name, cmd)
        rows.append((name, status, dt, tail))
        mark = "✔" if status == "PASS" else "✘"
        print(f"    {mark} {status}  {dt:.1f}s  {tail[:80]}")
        if status == "FAIL":
            break                      # 快速失败：第一个门禁红了就停

    out_lines = [
        "# nexus-audit 离线门禁计分板", "",
        f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}", "",
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
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
