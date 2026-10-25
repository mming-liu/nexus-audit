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
sys.path.insert(0, str(ROOT))
# M150：报告与终端都打印 `✔/✘`，写侧必须钉在 UTF-8（Windows 代码页防御）
from core.text_utils import ensure_utf8_stdio        # noqa: E402
ensure_utf8_stdio()

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
    ("DjanGoat", "reference_repos/DjanGoat", "djangoat", ["--strict"]),
    ("Compound", "reference_repos/compound-protocol/contracts",
     "compound", ["--strict"]),
    ("Comet", "reference_repos/comet/contracts", "comet", ["--strict"]),
    ("OpenZeppelin",
     "reference_repos/openzeppelin-contracts/contracts",
     "openzeppelin", ["--strict"]),
    ("AaveV3", "reference_repos/aave-v3-core/contracts",
     "aavev3", ["--strict"]),
    ("waynboot-mall", "reference_repos/waynboot-mall",
     "waynboot", ["--strict"]),
    ("mall4j", "reference_repos/mall4j", "mall4j", ["--strict"]),
    ("flaskr", "reference_repos/flaskr", "flaskr", ["--strict"]),
    ("Synthetix V3", "reference_repos/synthetix-v3", "synthetixv3",
     ["--strict"]),
    ("sushiswap-zapper", "reference_repos/sushiswap-zapper", "sushizapper",
     ["--strict"]),
    ("jeecg-boot", "reference_repos/jeecg-boot", "jeecg", ["--strict"]),
    ("Uniswap V2", "reference_repos/uniswap-v2-core", "uniswapv2",
     ["--strict"]),
    ("fastapi-realworld", "reference_repos/fastapi-realworld", "fastapi_rw",
     ["--strict"]),
    ("django-realworld", "reference_repos/django-realworld", "django_rw",
     ["--strict"]),
    ("eladmin-JPA", "reference_repos/eladmin", "eladmin_jpa", ["--strict"]),
    ("UniswapV3", "reference_repos/uniswap-v3-core/contracts",
     "uniswapv3", ["--strict"]),
    ("FastAPI", "reference_repos/fastapi-sql-template",
     "fastapi_wild", ["--strict"]),
    # —— M136/M137/M138/M143/M144：第 26–30 号野仓（30 仓里程碑）——
    ("MakerDAO dss", "reference_repos/dss", "makerdao_dss", ["--strict"]),
    ("flasky", "reference_repos/flasky", "flasky", ["--strict"]),
    ("mall-tiny", "reference_repos/mall-tiny", "mall_tiny", ["--strict"]),
    ("OZ Upgradeable", "reference_repos/openzeppelin-contracts-upgradeable",
     "openzeppelin_upgradeable", ["--strict"]),
    ("My-Blog-layui", "reference_repos/My-Blog-layui", "my_blog_layui",
     ["--strict"]),
]

P0_LINE = re.compile(r"^- \*\*\[([a-z_]+)\]\*\* `")


def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str, float]:
    t0 = time.monotonic()
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or ""), time.monotonic() - t0


def collect_scan(name: str, rel: str, advisory_root: str | None = None) -> dict:
    repo = ROOT / rel
    out = OUTDIR / name
    out.mkdir(parents=True, exist_ok=True)
    cmd = [PY, "cli.py", "scan", rel, "--auto", "--offline",
           "--summary-json", str(out / "summary.json"),
           "--output", str(out / "report.md"),
           "--html", str(out / "report.html"),
           "--sarif", str(out / "report.sarif")]
    # M99：按独立根因导出 GHSA 披露草稿（每仓一个子目录）。
    # 与 --advisory-dir 单仓用法同一口径：按根因去重，不按路由。
    if advisory_root:
        cmd += ["--advisory-dir", str(Path(advisory_root) / name)]
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
            "sca": collect_sca(repo),
            "scan_tail": "\n".join(log.strip().splitlines()[-6:])}


def collect_sca(repo: Path) -> dict:
    """M145：供应链组件版本 + 已知 advisory 命中（每仓一次）。

    **只做组件到 advisory 的对照**，不做"代码入口可达性"的判断 —— 后者
    由同一仓的 `p0_unique_root_causes` 表达。两张表在报告里并排呈现，
    "双重实锤"（组件 CVE ∧ 代码级 P0）就是两者的交集，不在这里下结论。
    """
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from core.context.dependency_versions import (
            collect_components, evaluate_components, uncovered_components)
        comps = collect_components(repo)
        hits = evaluate_components(comps)
        return {"components": len(comps), "hits": hits,
                "uncovered": len(uncovered_components(comps)),
                "cves": sorted({h["cve"] for h in hits})}
    except Exception as e:                                   # noqa: BLE001
        return {"components": 0, "hits": [], "uncovered": 0, "cves": [],
                "error": f"{type(e).__name__}: {e}"}


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


def render_sca_section(records: list[dict]) -> str:
    """M145：第七节「供应链组件风险 × 代码入口可达性」对照表。

    排序规则：**双重实锤**（组件 CVE ∧ 代码级 P0）排最前，然后是仅组件、
    仅代码。表格里的"代码级 P0"列直接取同仓的独立根因数 —— 两列挨着看，
    读者不需要自己做交集。
    """
    sca = [r for r in records if (r.get("sca") or {}).get("hits")]
    def rootn(r):
        return int(r.get("p0_unique_root_causes") or 0)
    dual = sorted([r for r in sca if rootn(r) > 0], key=lambda r: -rootn(r))
    dep_only = sorted([r for r in sca if rootn(r) == 0], key=lambda r: r["name"])
    code_only = sorted([r for r in records
                        if r not in sca and rootn(r) > 0],
                       key=lambda r: -rootn(r))
    n_comp = sum(int((r.get("sca") or {}).get("components") or 0)
                 for r in records)
    cves = sorted({c for r in sca for c in ((r.get("sca") or {}).get("cves") or [])})

    lines = [
        "## 七、30 仓供应链组件风险 × 代码入口可达性对照（M145）",
        "",
        "这一节回答一个单看任一表都答不出的问题：**哪些仓既用了已知有漏洞的"
        "组件版本，又真有一条代码级 P0？**",
        "",
        "- 组件版本来自构建清单（Maven `pom.xml` + Python `requirements*.txt`/"
        "`requirements/*.txt`）。**不解析 `package.json`**：这 30 个仓里的 JS "
        "依赖基本是 hardhat / editormd 这类构建期工具，不在运行时链路上。",
        "- CVE 对照表是**人工维护的保守清单**（每条都带修复版本与编号），"
        "未收录的组件不计命中、也不算安全 —— 报告里如实标成「未收录」。",
        "- 「代码级 P0」列取同仓的**独立根因数**（去重后），"
        "与 `wild_hunt.json` 同一口径。",
        "",
        f"扫描组件 {n_comp} 个，命中已知 advisory 的仓库 "
        f"**{len(sca)} 个**，涉及 CVE：{('、'.join(cves) if cves else '（无）')}。",
        "",
        "| 仓库 | 语言 | 组件（版本） | CVE | 代码级 P0 根因 | 交叉结论 |",
        "|---|---|---|---|---|---|",
    ]

    def lang_of(rel: str) -> str:
        p = Path(rel)
        if p.suffix == ".sol" or "/contracts" in rel.replace("\\", "/"):
            return "Solidity"
        if not (ROOT / rel).exists():
            return "?"
        if any((ROOT / rel).rglob("pom.xml")):
            return "Java"
        if any((ROOT / rel).rglob("*.sol")):
            return "Solidity"
        if any((ROOT / rel).rglob("*.py")):
            return "Python"
        return "?"

    for r in dual + dep_only + code_only:
        hits = (r.get("sca") or {}).get("hits") or []
        # 同一组件命中多条 advisory 时只显示一次版本（CVE 列并列）——
        # 否则 `django 1.11.1、django 1.11.1` 这种重复会让人以为装了两次。
        comps: dict[tuple[str, str], list[str]] = {}
        for h in hits:
            comps.setdefault((h["component"], h["version"]), []).append(h["cve"])
        comp = "、".join(f"`{c}` {v}" for (c, v) in list(comps)[:3])
        if len(comps) > 3:
            comp += f" …+{len(comps) - 3}"
        cve = "、".join(sorted({h["cve"] for h in hits}))
        n = rootn(r)
        if hits and n:
            verdict = f"**双重实锤**（{len(comps)} 个组件 / {len(hits)} 条 advisory" \
                      f" + {n} 个代码根因）"
        elif hits:
            verdict = "仅组件（代码侧未发现 P0）"
        else:
            verdict = "仅代码（组件版本未命中已知 advisory）"
        lines.append(f"| {r['name']} | {lang_of(r['path'])} | {comp or '—'} | "
                     f"{cve or '—'} | {n} | {verdict} |")
    lines += [
        "",
        f"**双重实锤仓 {len(dual)} 个**："
        + ("、".join(r["name"] for r in dual) if dual else "（无）"),
        "",
        "> 口径说明：「仅组件」不等于「有漏洞可利用」—— 组件是否存在可达的"
        "危险入口要看同一行的代码列；「仅代码」也不是「组件没问题」，"
        "只是版本没落进维护清单里。两类都如实列出，不做合并。",
        "",
    ]
    return "\n".join(lines)


SCA_HEADING = "## 七、"


def splice_report(path: Path, section: str) -> str:
    """把第七节**替换**进报告（幂等）。返回动作描述。

    找到 `## 七、` 开头的那一段，替换到下一个 `## ` 之前；找不到就追加到
    文末。这样重复跑 `wild_hunt.py` 不会堆出多份第七节。
    """
    if not path.exists():
        return "报告不存在，跳过"
    text = path.read_text(encoding="utf-8")
    i = text.find(SCA_HEADING)
    if i < 0:
        new = text.rstrip() + "\n\n" + section
        path.write_text(new, encoding="utf-8")
        return "已追加第七节"
    j = text.find("\n## ", i + len(SCA_HEADING))
    tail = text[j + 1:] if j >= 0 else ""
    new = text[:i] + section + ("\n" + tail if tail else "")
    path.write_text(new, encoding="utf-8")
    return "已替换第七节"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-bench", action="store_true")
    ap.add_argument("--only", default=None, help="只跑一个仓库（显示名）")
    ap.add_argument("--advisory-dir", default=None,
                    help="M99：把全部确认根因导出成 GHSA 披露草稿（每仓一子目录）")
    ap.add_argument("--report", default=str(ROOT / "WILD_HUNT_REPORT.md"),
                    help="M145：把第七节（供应链 × 代码入口）写回该报告")
    ap.add_argument("--no-report", action="store_true",
                    help="只产 json，不改报告（试跑/冒烟用）")
    args = ap.parse_args()

    records = []
    for name, rel, key, extra in REPOS:
        if args.only and name != args.only:
            continue
        if not (ROOT / rel).exists():
            print(f"SKIP {name}（缺少 {rel}）")
            continue
        print(f"[scan] {name} ...", flush=True)
        rec = collect_scan(name, rel, args.advisory_dir)
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
    # M135：总量块。跨仓聚类门禁（`cross_repo_clusters.py --check`）要拿
    # "独立根因总数"与聚类结果的计数守恒做对账 —— 口径必须由采集端给出，
    # 不能让下游自己 sum（两处各 sum 一次就会漂）。字段是**加性**的：
    # 老的消费方只读 repos，不受影响。
    agg["totals"] = {
        "repos": len(records),
        "units": sum(int(r.get("summary", {}).get("total_units") or 0)
                     for r in records),
        "p0_route_level_hits": sum(int(r.get("p0_route_level_hits") or 0)
                                   for r in records),
        "unique_root_causes": sum(int(r.get("p0_unique_root_causes") or 0)
                                  for r in records),
        # M145：供应链侧的两个总量 —— 报告第七节与 run_all/doctor 都读这里
        "repos_with_dependency_cve": sum(
            1 for r in records if (r.get("sca") or {}).get("hits")),
        "dual_confirmed_repos": sum(
            1 for r in records
            if (r.get("sca") or {}).get("hits")
            and int(r.get("p0_unique_root_causes") or 0) > 0),
        "dependency_cves": sorted({
            c for r in records
            for c in ((r.get("sca") or {}).get("cves") or [])}),
    }
    if args.advisory_dir:
        adv = Path(args.advisory_dir)
        n_adv = sum(1 for _ in adv.rglob("GHSA-*.md")) if adv.exists() else 0
        n_repos_adv = (sum(1 for p in adv.iterdir() if p.is_dir())
                       if adv.exists() else 0)
        # M111：把 21 个仓的草稿汇总成**一个**总目录（每仓子目录里那份只覆盖
        # 本仓，跨仓检索没有入口）。索引从草稿正文读 CVSS，不重算。
        try:
            # 脚本以 `python benchmarks/wild_hunt.py` 运行时 sys.path[0] 是
            # benchmarks/，`core` 包不可见 —— 先把仓库根塞进去。
            if str(ROOT) not in sys.path:
                sys.path.insert(0, str(ROOT))
            from core.context.advisory_exporter import _write_index
            all_drafts = sorted(adv.rglob("GHSA-*.md"))
            _write_index(adv, all_drafts)
        except Exception as e:                               # noqa: BLE001
            print(f"  ! INDEX.md 生成失败：{type(e).__name__}: {e}")
        agg["advisories"] = {"dir": str(adv), "files": n_adv,
                             "repos": n_repos_adv,
                             "index": str(adv / "INDEX.md")}
        print(f"\n披露草稿：{n_adv} 份 / {n_repos_adv} 个仓 → {adv}"
              f"（总目录 INDEX.md）")
    if not args.only:
        AGG.write_text(json.dumps(agg, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(f"\n聚合结果：{AGG}")
        if not args.no_report:
            act = splice_report(Path(args.report), render_sca_section(records))
            print(f"报告第七节：{act} → {args.report}")
    return 0 if all(r["scan_rc"] == 0 and r.get("benchmark", {}).get("rc", 0) == 0
                    for r in records) else 1


if __name__ == "__main__":
    sys.exit(main())
