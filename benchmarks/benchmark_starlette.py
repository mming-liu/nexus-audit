"""encode/starlette —— 第 50 仓（Python #15），M218。"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web_treesitter import WebTreeSitterSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "starlette"
_ANCHOR = '''@app.route("/x")
@admin_required
def x():
    return "ok"
'''

def main() -> int:
    ap = argparse.ArgumentParser(description="starlette 路由/权限边界基准（M218）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "starlette.json"))
    a = ap.parse_args(); repo = Path(a.target)
    if not repo.exists(): print(f"! 找不到 {repo}"); return 2
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    true_rows = [(u.unit_name, c) for u in units
                 for c in ("authz", "jndi_injection", "arbitrary_file_delete")
                 if R.verdict(c, u.source_code) is True]
    src = (repo / "starlette" / "routing.py").read_text(encoding="utf-8", errors="ignore")
    auth = (repo / "starlette" / "authentication.py").read_text(
        encoding="utf-8", errors="ignore")
    has_route = "class Route" in src and "requires" in auth
    anchor = R.verdict("authz", _ANCHOR)
    print(f"装饰器入口 {len(units)} / Route+requires {has_route} / True {len(true_rows)} / 锚点 {anchor}")
    bad = []
    if not has_route: bad.append("routing.py 缺少 Route/requires")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if anchor is not False: bad.append(f"锚点 {anchor}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "route_requires": has_route,
                               "true": len(true_rows), "anchor": anchor,
                               "fp": len(true_rows), "pass": not bad},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 装饰器入口 / Route+requires 就位 / 0 True）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
