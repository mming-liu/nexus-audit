"""M236：跨次运行确定性重现守卫。

把 wild_hunt.json / cross_repo_clusters.json 里**非时间戳**的事实压成
canonical JSON 再 sha256：50 仓名、入口数、每仓根因（类别/代表/文件/行）、
聚类簇与多仓共现数。--write 写基线，--check 比对当前结果。
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
AGG = ROOT / "benchmarks" / "results" / "wild_hunt.json"
CLU = ROOT / "benchmarks" / "results" / "cross_repo_clusters.json"
BASELINE = ROOT / "benchmarks" / "results" / "repro_baseline.json"


def canonical() -> dict:
    d = json.loads(AGG.read_text(encoding="utf-8"))
    repos = []
    for r in d["repos"]:
        s = r.get("summary") or {}
        roots = sorted(
            [rc.get("category", ""), rc.get("representative", ""),
             Path(rc.get("file", "")).name, int(rc.get("line") or 0)]
            for rc in s.get("root_causes", []))
        repos.append([r["name"], int(s.get("total_units") or 0), roots])
    c = json.loads(CLU.read_text(encoding="utf-8")) if CLU.exists() else {}
    return {
        "repos": repos,
        "totals": {k: d["totals"][k] for k in
                   ("repos", "units", "unique_root_causes")},
        "clusters": {
            "roots": c.get("total_root_causes"),
            "count": c.get("cluster_count"),
            "multi": c.get("cross_repo_clusters"),
        },
    }


def current_digest() -> str:
    raw = json.dumps(canonical(), ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="跨次运行确定性重现守卫（M236）")
    ap.add_argument("--write", action="store_true", help="写入当前基线")
    ap.add_argument("--check", action="store_true", help="比对当前基线")
    a = ap.parse_args()
    digest = current_digest()
    if a.write:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps({"digest": digest}, ensure_ascii=False,
                                       indent=2), encoding="utf-8")
        print(f"REPRO BASELINE WRITTEN {digest[:16]} → {BASELINE.name}")
        return 0
    if not BASELINE.exists():
        print("REPRO CHECK FAIL 缺少 repro_baseline.json（先跑 --write）")
        return 1
    want = json.loads(BASELINE.read_text(encoding="utf-8"))["digest"]
    if want != digest:
        print(f"REPRO CHECK FAIL 期望 {want[:16]} 实际 {digest[:16]}")
        return 1
    print(f"REPRO CHECK PASS ✔（sha256 {digest[:16]}，50 仓根因/聚类/排序守恒）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
