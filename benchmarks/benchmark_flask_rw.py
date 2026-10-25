"""gothinkster/flask-realworld-example-app —— 第 36 仓，M168。

RealWorld 三剑客里唯一用 Flask-JWT-Extended 的实现。鉴权主体是
current_user.profile.id，直接写进 filter_by 查询条件；favorite 则把
current_user.profile 传给 article.favourite(profile)。只认
current_user.id 的规则会把这些判成 True。

门禁（--strict）：26 个入口 / 全类目 0 True / 8 条 authz False /
反向锚点（去掉归属条件 -> True，有归属 -> False）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.agents.vuln_categories import CATEGORIES              # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer      # noqa: E402
from core.text_utils import ensure_utf8_stdio                   # noqa: E402

ensure_utf8_stdio()
DEFAULT_TARGET = ROOT / "reference_repos" / "flask-realworld"
MIN_UNITS = 20
AUTHZ_FALSE = ("update_article", "delete_article", "favorite_an_article",
               "unfavorite_an_article", "make_comment_on_article",
               "delete_comment_on_article", "follow_user", "get_profile")

_ANCHOR_VULN = '''@app.route("/articles/<int:id>", methods=["PUT"])
@jwt_required
def update_article(id):
    article = Article.query.filter_by(id=id).first()
    article.title = request.json["title"]
    db.session.commit()
    return article
'''
_ANCHOR_SAFE = '''@app.route("/articles/<int:id>", methods=["PUT"])
@jwt_required
def update_article(id):
    article = Article.query.filter_by(
        id=id, author_id=current_user.profile.id).first()
    article.title = request.json["title"]
    db.session.commit()
    return article
'''


def main() -> int:
    ap = argparse.ArgumentParser(description="flask-realworld 零误报基准（M168）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" /
                                            "flask_rw.json"))
    args = ap.parse_args()
    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    units = list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    by_name = {u.unit_name: u for u in units}
    true_rows = []
    decided = 0
    for u in units:
        for c in CATEGORIES:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((u.unit_name, c))

    authz = {n: R.verdict("authz", by_name[n].source_code)
             for n in AUTHZ_FALSE if n in by_name}
    anchor_v = R.verdict("authz", _ANCHOR_VULN)
    anchor_s = R.verdict("authz", _ANCHOR_SAFE)

    print("=" * 72)
    print("flask-realworld 结果（Flask-JWT-Extended 主体链）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    for n, c in true_rows[:10]:
        print(f"    [FP] {n} [{c}]")
    print(f"  authz 安全入口        ：{sum(1 for v in authz.values() if v is False)}"
          f"/{len(AUTHZ_FALSE)}")
    print(f"  反向锚点（去归属 -> True / 有归属 -> False）："
          f"{anchor_v} / {anchor_s}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if true_rows:
        bad.append(f"规则层出现 {len(true_rows)} 条 True：{true_rows[:5]}")
    missing = [n for n in AUTHZ_FALSE if authz.get(n) is not False]
    if missing:
        bad.append(f"authz 未判 False：{missing}")
    if anchor_v is not True or anchor_s is not False:
        bad.append(f"反向锚点失效：{anchor_v}/{anchor_s}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "target": str(repo), "total_units": len(units),
        "decided": decided, "true": len(true_rows),
        "authz": authz, "anchor_vuln": anchor_v, "anchor_safe": anchor_s,
        "fp": len(true_rows), "reverse_fn": 0,
        "pass": not bad,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if bad:
        print("\nSTRICT FAIL ✘ " + "；".join(bad))
        print(f"结果写入 {out}")
        return 1
    print(f"\nSTRICT PASS ✔（{len(units)} 入口 / 全类目 0 True / "
          f"8 条 authz False / 反向锚点生效）")
    print(f"结果写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
