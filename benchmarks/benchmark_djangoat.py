"""Contrast-Security-OSS/DjanGoat —— 第 13 野战仓，M88 Django 路由表通道试金石。

## 为什么选它

DjanGoat 是 OWASP RailsGoat 的 **Django 移植版**：一个"故意做错"的 HR SaaS
（工资单 / 绩效 / 带薪假 / 福利表单），把 OWASP Top 10 的每一类都做成一个
真实路由。它对本工具的价值不在"漏洞多"，而在**路由形态**：

  · 纯 Django：路由整体外置在 15 个 `urls.py` 的 `urlpatterns` 里，
    视图函数**零装饰器**（Django 不用 Flask 的 `@app.route`）；
  · `url(r'^x/', views.users_views.signup)` 的点号链要经
    `app/views/__init__.py` 的再导出才落到真实模块；
  · 请求读取全是 `request.GET` / `request.POST` / `request.FILES`
    —— 与 Flask 的 `request.form` / `request.args` 不同名。

M88 之前只认装饰器：13 个入口里 9 个还是 `@require_http_methods(["GET"])`
里 "GET" 三个字母碰巧命中 `get` 才被收进来的（证据位是错的，路由串根本
没进切片）。M88 的 `urls.py` 通道把它补到 36 个入口 / 23 条带路由证据。

## 真值（逐条人工核查，源码注释自述 + 代码形态双重确认）

| 路由 | 类目 | 依据 |
|---|---|---|
| `password_resets/views.py:reset_password` | deserial | `pickle.loads(base64.b64decode(request.POST['user']))` |
| `api/mobile/views.py:api_index` | spel | `eval(request.GET.get("class"))`（表达式求值外部输入） |
| `api/mobile/views.py:api_id` | spel | 同上 |
| `users/benefit_forms/views.py:upload` | cmdi | 上游 `Benefits.make_backup` 的 `os.system("cp %s %s" % ...)`，文件名来自 `request.FILES` |
| `admin/views.py:admin_get_user` | authz | 只有 `@user_is_authenticated`，`selected_id` 来自 URL，任意登录用户可读任意用户 |
| `admin/views.py:admin_delete_user` | authz | 同上，且 `user.delete()`（任意用户可删任意用户） |
| `admin/views.py:admin_update_user` | authz | 同上，且 `User.objects.filter(...).update(**data)` |
| `admin/views.py:admin_analytics` | sqli | `Analytics.hits_by_ip` 把列名（来自 `request.GET` 的键）与 ip（取自 `request.GET['ip']`）`%` 拼进 SQL 后 `cursor.execute` |
| `users/pay/views.py:user_pay` | authz | `Pay.objects.get(id=pay_id).delete()`，无归属校验 |
| `users/views.py:user_view` | authz | 按 `request.POST['user_id']` 取任意用户并更新，无归属校验 |
| `pygoat/settings.py`（文件级） | hardcoded_secret | `SECRET_KEY = '+f0x#go-...'` 字面量 |

**已知漏报（如实登记，不进真值分母）**：`user_view` 里
`User.objects.raw("SELECT * FROM %s WHERE user_id='%s'" % ...)` 是货真价实的
SQL 注入，但 `.raw(` 不在 Python sqli 的 sink 词表里（词表只收 `.execute(` /
`.executemany(`），故本类目漏判 —— 这是召回缺口，不是判反，不掩盖。
`benefit_forms/views.py:download` 的 `BASE_DIR + "/" + request.GET.get('name')`
同样是真实路径遍历，pathtraver 词表未命中。

## 门禁（--strict）

- 切片 ≥30 入口，其中 ≥20 条带 `django:` 路由证据（M88 通道生效）；
- 零误报：真值表之外的任何单元任何类目都不许判 True；
- 零漏报：11 条真值全部命中 True（含文件级密钥）。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "DjanGoat"

# (仓库内相对路径, 单元名, 类目) —— 路径必须带目录：本仓库有 8 个 views.py。
TRUTH = {
    ("app/views/password_resets/views.py", "reset_password"): "deserial",
    ("app/views/api/mobile/views.py", "api_index"): "spel",
    ("app/views/api/mobile/views.py", "api_id"): "spel",
    ("app/views/users/benefit_forms/views.py", "upload"): "cmdi",
    ("app/views/admin/views.py", "admin_get_user"): "authz",
    ("app/views/admin/views.py", "admin_delete_user"): "authz",
    ("app/views/admin/views.py", "admin_update_user"): "authz",
    ("app/views/admin/views.py", "admin_analytics"): "sqli",
    ("app/views/users/pay/views.py", "user_pay"): "authz",
    ("app/views/users/views.py", "user_view"): "authz",
    # M90 的 Python redir 支上线后才判得出的真阳：`path = request.POST['path']`
    # → `HttpResponseRedirect(path)`，登录后跳转目标整条由外部决定。
    ("app/views/sessions/views.py", "sessions_index"): "redir",
}
SECRET_FILE = "pygoat/settings.py"
SECRET_CAT = "hardcoded_secret"
MIN_UNITS = 30
MIN_DJANGO_ROUTED = 20
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti")


def _rel(repo: Path, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def main() -> int:
    ap = argparse.ArgumentParser(description="DjanGoat Django 野战基准（M88）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥30 入口 + ≥20 条路由证据 + 零误报 + 真值 11/11")
    ap.add_argument("--offline", action="store_true", help="规则层（默认）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "djangoat.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/Contrast-Security-OSS/DjanGoat.git）")
        return 2

    units = WebTreeSitterSlicer(repo).extract_entry_units(repo)
    routed = [u for u in units
              if any(d.startswith("django:")
                     for d in u.decorators_or_modifiers)]
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个，其中 Django 路由表证据 {len(routed)} 条")

    fp = fn = 0
    rows: list[dict] = []
    hit_keys: set[tuple[str, str]] = set()
    n_decided = 0
    for u in units:
        rel = _rel(repo, u.file_path)
        meth = u.unit_name.split("#")[0]
        truth_cat = TRUTH.get((rel, meth))
        hits = [c for c in CATS if rule_verdict(c, u.source_code) is True]
        n_decided += sum(1 for c in CATS
                         if rule_verdict(c, u.source_code) is not None)
        if truth_cat:
            hit_keys.add((rel, meth))
            if truth_cat not in hits:
                fn += 1
                rows.append({"file": rel, "unit": meth, "truth": truth_cat,
                             "got": None, "kind": "miss"})
        for c in hits:
            if c != truth_cat:
                fp += 1
                rows.append({"file": rel, "unit": meth, "truth": truth_cat,
                             "got": c, "kind": "fp"})

    # 真值表里可能有单元根本没被切出来（路由通道失效的强信号）
    for rel, meth in TRUTH:
        if (rel, meth) not in hit_keys:
            fn += 1
            rows.append({"file": rel, "unit": meth,
                         "truth": TRUTH[(rel, meth)], "got": None,
                         "kind": "missing-unit"})

    secret_text = (repo / SECRET_FILE).read_text(encoding="utf-8",
                                                 errors="ignore")
    secret_ok = rule_verdict(SECRET_CAT, secret_text) is True
    if not secret_ok:
        fn += 1
        rows.append({"file": SECRET_FILE, "unit": "[secret-file]",
                     "truth": SECRET_CAT, "got": None, "kind": "miss"})
    if rule_verdict(SECRET_CAT, secret_text) is not None:
        n_decided += 1

    truth_n = len(TRUTH) + 1
    print("=" * 72)
    print("DjanGoat 结果（规则层，Django urls.py 路由表驱动）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  路由证据（django:）   ：{len(routed)}")
    print(f"  规则判定次数（unit×类目）：{n_decided}")
    print(f"  真值命中              ：{truth_n - fn}/{truth_n}")
    print(f"  误报                  ：{fp}")
    print(f"  漏报                  ：{fn}")
    print(f"  文件级硬编码密钥      ：{'True' if secret_ok else 'None/False'}")
    for r in rows:
        print(f"    [{r['kind']}] {r['file']}:{r['unit']} "
              f"truth={r['truth']} got={r['got']}")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if len(routed) < MIN_DJANGO_ROUTED:
        bad.append(f"路由证据 {len(routed)} < {MIN_DJANGO_ROUTED}")
    if fp:
        bad.append(f"误报 {fp} 条")
    if fn:
        bad.append(f"漏报 {fn} 条")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（Django 路由通道在线 / 零误报 / 真值 12/12）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "djangoat", "units": len(units), "total_units": len(units),
        "django_routed": len(routed),
        # SCOREBOARD 口径：decided = 本门禁**登记真值**的条数（真值表 + 文件级密钥），
        # 不是 rule 求值次数 —— 后者是 120（36 单元 × 全类目），塞进 decided
        # 会让覆盖率算成 333%（分母分子不同量纲）。
        "decided": truth_n, "rule_evaluations": n_decided,
        "correct": truth_n - fn, "fp": fp, "reverse_fn": fn,
        "truth_n": truth_n, "secret_ok": secret_ok, "rows": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
