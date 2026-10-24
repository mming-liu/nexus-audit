"""Employee-Management-System（Thinal-Fernando，真实 Flask-SQLAlchemy 应用）
—— 第 25 个靶场，M72 首个性野生 Python 仓库。

## 为什么选它

不是漏洞靶场，没有 expectedresults：一个真实的小型 Flask CRUD 员工管理
系统（Flask + Flask-SQLAlchemy + Jinja2）。我们只做两件事：
  1. 对 4 条路由跑全类目规则普查；
  2. 对 `app.py` 做文件级 hardcoded_secret 普查（`app.secret_key = "123"`）。

人工核查后的真值只有两条：
  · `delete(id)` —— 无主体、无归属校验，任意 id 可删（CWE-639）；
  · `app.py` 文件级 `hardcoded_secret` —— Flask 会话签名密钥写死为 `"123"`
    （CWE-798 / 弱密钥）。
`insert` / `update` 同样缺少登录与权限控制，但这是"缺失认证"而非
对象级 authz，规则层不硬判 True；在输出里单列为人工复核面，不掺进真值。

## 门禁（--strict）

零误报（非真值单元不许判 True）+ 真值 2/2 命中 + secret 文件级命中。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer       # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "employee-management-system"
TRUTH = {("app.py", "delete"): "authz"}
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi")


def main() -> int:
    ap = argparse.ArgumentParser(description="Employee-Management-System Flask 野战基准")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="零误报 + 真值 2/2 + 文件级密钥命中")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "flaskcrud.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Thinal-Fernando/Employee-Management-System.git）")
        return 2

    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个（真值 2 条，人工核查）")

    fp = fn = 0
    rows = []
    for u in units:
        fname = Path(u.file_path).name
        meth = u.unit_name.split("#")[0]
        truth_cat = TRUTH.get((fname, meth))
        hit = [c for c in CATS if rule_verdict(c, u.source_code) is True]
        if truth_cat and truth_cat not in hit:
            fn += 1
            rows.append({"unit": meth, "file": fname, "truth": truth_cat,
                         "got": None})
        for c in hit:
            if c != truth_cat:
                fp += 1
                rows.append({"unit": meth, "file": fname, "truth": truth_cat,
                             "got": c})

    secret_text = (repo / "app.py").read_text(encoding="utf-8", errors="ignore")
    secret_ok = rule_verdict("hardcoded_secret", secret_text) is True
    if not secret_ok:
        fn += 1
        rows.append({"unit": "[secret-file] app.py", "file": "app.py",
                     "truth": "hardcoded_secret", "got": None})

    n_decided = sum(1 for u in units for c in CATS
                    if rule_verdict(c, u.source_code) is not None)
    if rule_verdict("hardcoded_secret", secret_text) is not None:
        n_decided += 1

    print("=" * 72)
    print("Employee-Management-System 结果（规则层，真实 Flask CRUD）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则确定性判定        ：{n_decided}")
    print(f"  真值命中              ：{2 - fn}/2")
    print(f"  误报                  ：{fp}")
    print(f"  漏报                  ：{fn}")
    print(f"  文件级硬编码密钥      ：{'True' if secret_ok else 'None/False'}")
    print("  人工复核面（不进真值）：insert / update 缺少登录与权限控制")
    for r in rows:
        print(f"    {r['file']}:{r['unit']} truth={r['truth']} got={r['got']}")

    ok = (fp == 0 and fn == 0 and secret_ok and len(units) >= 4)
    print(f"\n{'STRICT 门禁：通过 ✔（零误报 / 真值 2/2 / 密钥命中）' if ok else 'STRICT 门禁：FAIL ✘'}")
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "flaskcrud", "units": len(units), "decided": n_decided,
        "truth_n": 2, "fp": fp, "fn": fn, "secret_ok": secret_ok,
        "rows": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
