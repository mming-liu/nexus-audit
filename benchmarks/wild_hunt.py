"""M69/M86：十一个真实开源项目的野战数据采集（scan --auto + benchmark --strict）。

所有数字由本脚本实跑产出，报告只引用 results/wild_hunt.json：

    python benchmarks/wild_hunt.py            # 采集（冷缓存会稍慢）
    python benchmarks/wild_hunt.py --skip-bench

产出：
  benchmarks/results/wild_hunt/<name>/{summary.json,report.md,report.html,report.sarif}
  benchmarks/results/wild_hunt.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
OUTDIR = ROOT / "benchmarks" / "results" / "wild_hunt"
AGG = ROOT / "benchmarks" / "results" / "wild_hunt.json"

# (显示名, 仓库相对路径, benchmark 脚本键, benchmark 额外参数)
REPOS = [
    ("newbee-mall", "reference_repos/newbee-mall-master",
     "newbeemall", ["--strict"]),
    ("newbee-mall-api", "reference_repos/newbee-mall-api-master",
     "newbeemallapi", ["--strict"]),
    ("RuoYi", "reference_repos/RuoYi-master",
     "ruoyi", ["--strict", "--offline"]),
    ("eladmin-mp", "reference_repos/eladmin-mp-master",
     "eladminmp", ["--strict", "--offline"]),
    ("mall", "reference_repos/mall-main", "mall", ["--strict"]),
    ("My-Blog", "reference_repos/My-Blog-master", "myblog", ["--strict"]),
    ("litemall", "reference_repos/litemall-master", "litemall", ["--strict"]),
    ("Employee-Management-System",
     "reference_repos/employee-management-system", "flaskcrud", ["--strict"]),
    ("Compound", "reference_repos/compound-protocol/contracts",
     "compound", ["--strict"]),
    ("UniswapV3", "reference_repos/uniswap-v3-core/contracts",
     "uniswapv3", ["--strict"]),
    ("FastAPI", "reference_repos/fastapi-sql-template",
     "fastapi_wild", ["--strict"]),
]

P0_LINE = re.compile(r"^- \*\*\[([a-z_]+)\]\*\* `")


def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str, float]:
    t0 = time.monotonic()
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or ""), time.monotonic() - t0


def collect_scan(name: str, rel: str) -> dict:
    repo = ROOT / rel
    out = OUTDIR / name
    out.mkdir(parents=True, exist_ok=True)
    cmd = [PY, "cli.py", "scan", rel, "--auto", "--offline",
           "--summary-json", str(out / "summary.json"),
           "--output", str(out / "report.md"),
           "--html", str(out / "report.html"),
           "--sarif", str(out / "report.sarif")]
    rc, log, wall = _run(cmd)
    summary = {}
    if (out / "summary.json").exists():
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    by_cat: dict[str, int] = {}
    report = out / "report.md"
    if report.exists():
        for line in report.read_text(encoding="utf-8").splitlines():
            m = P0_LINE.match(line)
            if m:
                by_cat[m.group(1)] = by_cat.get(m.group(1), 0) + 1
    return {"name": name, "path": rel, "scan_rc": rc, "wall_s": round(wall, 2),
            "summary": summary,
            "p0_route_level_hits": summary.get("p0_route_level_hits",
                                               summary.get("p0_confirmed", 0)),
            "p0_unique_root_causes": summary.get("p0_unique_root_causes",
                                                 len(by_cat)),
            "p0_route_by_cat": summary.get("p0_route_by_cat", by_cat),
            "p0_unique_by_cat": summary.get("p0_unique_by_cat", by_cat),
            "p0_by_cat": by_cat,
            "scan_tail": "\n".join(log.strip().splitlines()[-6:])}


def collect_benchmark(key: str, extra: list[str]) -> dict:
    cmd = [PY, f"benchmarks/benchmark_{key}.py", *extra]
    rc, log, wall = _run(cmd)
    tail = "\n".join([ln for ln in log.strip().splitlines() if ln.strip()][-3:])
    meta = {}
    result = ROOT / "benchmarks" / "results" / f"{key}.json"
    if result.exists():
        try:
            meta = json.loads(result.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            meta = {}
    return {"rc": rc, "wall_s": round(wall, 2), "tail": tail,
            "decided": meta.get("decided"),
            "fp": meta.get("fp", 0),
            "total_units": meta.get("total_units")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-bench", action="store_true")
    ap.add_argument("--only", default=None, help="只跑一个仓库（显示名）")
    args = ap.parse_args()

    records = []
    for name, rel, key, extra in REPOS:
        if args.only and name != args.only:
            continue
        if not (ROOT / rel).exists():
            print(f"SKIP {name}（缺少 {rel}）")
            continue
        print(f"[scan] {name} ...", flush=True)
        rec = collect_scan(name, rel)
        print(f"       rc={rec['scan_rc']} units={rec['summary'].get('total_units')}"
              f" p0={rec['summary'].get('p0_confirmed')}"
              f" wall={rec['wall_s']}s", flush=True)
        if not args.skip_bench:
            print(f"[bench] {name} ...", flush=True)
            rec["benchmark"] = collect_benchmark(key, extra)
            print(f"       rc={rec['benchmark']['rc']}"
                  f" wall={rec['benchmark']['wall_s']}s", flush=True)
        records.append(rec)

    agg = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
           "repos": records}
    if not args.only:
        AGG.write_text(json.dumps(agg, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(f"\n聚合结果：{AGG}")
    return 0 if all(r["scan_rc"] == 0 and r.get("benchmark", {}).get("rc", 0) == 0
                    for r in records) else 1


if __name__ == "__main__":
    sys.exit(main())
