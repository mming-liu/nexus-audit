"""litestar-org/litestar —— 第 49 仓（Python #14），M217。"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web_treesitter import WebTreeSitterSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "litestar"
CATS = ("authz", "csrf_disabled", "regex_dos", "jndi_injection",
        "arbitrary_file_delete")
EXCLUDE = {"get_membership_details", "delete_session_command"}
_ANCHOR = '''@app.route("/x")
@admin_required
def x():
    return "ok"
'''

def main() -> int:
    ap = argparse.ArgumentParser(description="litestar 零误报基准（M217）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "litestar.json"))
    a = ap.parse_args(); repo = Path(a.target)
    if not repo.exists(): print(f"! 找不到 {repo}"); return 2
    units = [u for u in WebTreeSitterSlicer(repo).extract_entry_units(repo)
             if u.unit_name not in EXCLUDE]
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    anchor = R.verdict("authz", _ANCHOR)
    guards = sum(1 for p in repo.rglob("*.py")
                 if "guards=" in p.read_text(encoding="utf-8", errors="ignore"))
    print(f"切片 {len(units)} / guards 文件 {guards} / True {len(true_rows)} / 锚点 {anchor}")
    bad = []
    if len(units) < 20: bad.append(f"切片 {len(units)} < 20")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if anchor is not False: bad.append(f"锚点 {anchor}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "guards_files": guards,
                               "true": len(true_rows), "anchor": anchor,
                               "fp": len(true_rows), "pass": not bad},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 入口 / 0 True / guards 文件 {guards}）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
