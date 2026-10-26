"""jazzband/django-oauth-toolkit —— 第 43 仓（Python #11），M199。"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web_treesitter import WebTreeSitterSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "django-oauth-toolkit"
CATS = ("authz", "csrf_disabled", "regex_dos", "xss", "sqli")
_CSRF = '''@csrf_exempt
def update(request):
    if request.method == "POST":
        save(request.POST.get("name"))
    return HttpResponse("ok")
'''
_LOGIN = '''@admin_required
def update(request):
    save(request.POST.get("name"))
    return HttpResponse("ok")
'''

def main() -> int:
    ap = argparse.ArgumentParser(description="django-oauth-toolkit 零误报基准（M199）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "django_oauth.json"))
    a = ap.parse_args(); repo = Path(a.target)
    if not repo.exists(): print(f"! 找不到 {repo}"); return 2
    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    true_rows = [(u.unit_name, c) for u in units for c in CATS
                 if R.verdict(c, u.source_code) is True]
    csrf_v = R.verdict("csrf_disabled", _CSRF)
    login_v = R.verdict("authz", _LOGIN)
    print(f"切片 {len(units)} / True {len(true_rows)} / csrf {csrf_v} / login {login_v}")
    bad = []
    if len(units) < 15: bad.append(f"切片 {len(units)} < 15")
    if true_rows: bad.append(f"True: {true_rows[:5]}")
    if csrf_v is not True: bad.append(f"csrf 锚点 {csrf_v}")
    if login_v is not False: bad.append(f"login 锚点 {login_v}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total_units": len(units), "true": len(true_rows),
                               "csrf_anchor": csrf_v, "login_anchor": login_v,
                               "fp": len(true_rows), "pass": not bad},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print(f"STRICT PASS ✔（{len(units)} 入口 / 0 True / csrf 锚点 True）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
