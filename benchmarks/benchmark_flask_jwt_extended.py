"""vimalloc/flask-jwt-extended —— 第 40 仓（Python #10），M184。

这是库仓，本身没有 Flask 路由（切片 0 入口）；它提供的是
@jwt_required / verify_jwt_in_request 装饰器语义。基准用一个最小 Flask
应用加载真实的 flask_jwt_extended 装饰器，验证：受保护路由 authz False、
fresh token 守卫 False、0 True；并核对库源码里的 verify_jwt_in_request。
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.agents import rule_detectors as R
from core.slicer.web_treesitter import WebTreeSitterSlicer
from core.text_utils import ensure_utf8_stdio
ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "flask-jwt-extended"
APP = '''from flask import Flask
from flask_jwt_extended import jwt_required, fresh_jwt_required
app = Flask(__name__)

@app.route("/me")
@jwt_required
def me():
    return "ok"

@app.route("/fresh")
@fresh_jwt_required
def fresh():
    return "ok"

@app.route("/admin")
@jwt_required
def admin():
    return "ok"
'''

def main() -> int:
    ap = argparse.ArgumentParser(description="flask-jwt-extended 装饰器基准（M184）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "flask_jwt_extended.json"))
    a = ap.parse_args()
    repo = Path(a.target)
    src = repo / "flask_jwt_extended" / "view_decorators.py"
    if not src.is_file():
        print(f"! 找不到 {src}"); return 2
    text = src.read_text(encoding="utf-8", errors="replace")
    has_verify = "verify_jwt_in_request" in text
    has_fresh = "fresh" in text
    # WebTreeSitter 需要路径：用工作区 .tmp（系统 %TEMP% 在沙箱下不可写）
    from uuid import uuid4
    d = ROOT / ".tmp" / f"jwt184_{uuid4().hex[:8]}"
    d.mkdir(parents=True, exist_ok=True)
    try:
        (d / "app.py").write_text(APP, encoding="utf-8")
        units = list(WebTreeSitterSlicer(d).extract_entry_units(d))
        vals = {u.unit_name: R.verdict("authz", u.source_code) for u in units}
        true_rows = [u.unit_name for u in units if R.verdict("authz", u.source_code) is True]
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    print(f"库源码 verify_jwt_in_request={has_verify} / fresh={has_fresh}")
    print(f"合成路由 {len(units)} / authz {vals} / True {len(true_rows)}")
    bad = []
    if not (has_verify and has_fresh): bad.append("库源码缺少 verify/fresh 证据")
    if len(units) != 3: bad.append(f"路由 {len(units)} != 3")
    if true_rows: bad.append(f"True: {true_rows}")
    if any(v is not False for v in vals.values()): bad.append(f"authz 非 False: {vals}")
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"library_verify": has_verify, "library_fresh": has_fresh,
                               "routes": len(units), "authz": vals,
                               "fp": len(true_rows), "pass": not bad},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    if bad: print("STRICT FAIL " + "；".join(bad)); return 1
    print("STRICT PASS ✔（3 路由 / jwt_required+fresh 全 False / 0 True）")
    return 0

if __name__ == "__main__":
    sys.exit(main())
