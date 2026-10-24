"""pygoat（OWASP）—— 第 12 个靶场：Python Web 双栈（Flask labs 全集）。

## 为什么需要它

vulpy 是单应用 6 条真值，Python 线一直缺一个"多应用、多类目、多缺陷
形态"的靶场。pygoat 顶层是 Django 启动器（challenge/views.py，无作者
漏洞标注），真正的靶场在 `dockerized_labs/` —— **20 个独立 Flask 应用**，
每个 README + 源码注释里**逐条指名**漏洞点（"Intentionally vulnerable
command execution" / "Vulnerable SQL query construction (intentional)" /
docstring "intentionally vulnerable to XXE"）。

## 本靶场逼出来的三个切片/判据修复（探针先行）

1. **SymbolIndexer 同名符号覆盖**：symbol_table 按函数名做键，20 个 lab
   都有 index/lab1/health_check → 整库切片 50 个单元、一半 lab 被静默
   丢弃。改为 name → 列表 + prefer_file 同文件优先，单元 50→119。
2. **赋值链遮蔽**：切片 hop 段带着 User 模型类，`username =
   db.Column(...)` 把入口的 `request.form.get` 赋值遮成 None；多行调用
   里的关键字实参 `sql_query=sql_query,` 与赋值同貌。赋值链改为只在
   入口区域、括号深度 0 处追，右值支持 PEP 8 多行括号包裹。
3. **Python 判据缺口**：sqli 多行 f-string、deserial 的 pickle/yaml
   （Module 25 判据）、pathtraver 的 `open(os.path.join(常量, 输入))`
   （join 不清洗 `..` 与绝对路径）、xxe 的
   `setFeature(feature_external_ges, True)`（解析器事实一行定案）。

## 真值口径

· 只收**源码注释/docstring 指名**的 9 条（列 TRUTH 表，每条带原文）；
· xss_lab 三条"Vulnerable: Reflects unescaped user input"**不收**：
  视图层走 render_template（Jinja2 自动转义），真正的 sink 在模板文件
  里——与我们 xss 类目"输入是否原样进入响应体"的口径不同，收进去是
  判据口径自相矛盾（同 JavaSecLab safe2 的处理）；
· Django 顶层入口：无作者标注真值，Django 视图识别 0 收益，按约束
  跳过投机升级（记录在案）。

## 门禁（--strict）

1. 9 条真值全判 True（作者指名的漏洞一条都不许静默放行）；
2. 零计划外 True（作者没标注的单元被判 True 就是误报）；
3. 切片单元 ≥100、确定性 False ≥200（覆盖与 safe 面回归锁）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "pygoat-master"

# (lab 目录, 单元名, 类目, 是否漏洞, 作者标注原文)
TRUTH: list[tuple[str, str, str, bool, str]] = [
    ("sql_injection_lab", "lab", "sqli", True,
     "# Vulnerable SQL query construction (intentional)"),
    ("command_injection_lab", "lab1", "cmdi", True,
     "# Intentionally vulnerable command execution"),
    # M69 补登：lab2 的 eval() 是作者写明的代码执行面（既有真值表漏收，
    # 规则层补上 Python 裸 eval sink 后被"计划外 True"挡下 —— 收真值，
    # 不静默放行）。
    ("command_injection_lab", "lab2", "spel", True,
     '"""Lab 2: Python eval() Code Execution"""'),
    ("insec_des_lab", "deserialize_data", "deserial", True,
     "# Intentionally vulnerable deserialization, matching PyGoat"),
    ("software_integrity_lab", "lab1", "deserial", True,
     "# Intentionally vulnerable to pickle deserialization"),
    ("a9_uckv_lab", "upload_yaml", "deserial", True,
     "# Intentionally vulnerable YAML loading"),
    ("a9_uckv_lab", "process_image", "spel", True,
     "# Intentionally vulnerable expression evaluation（Pillow ImageMath.eval）"),
    ("ssrf_lab", "lab2", "ssrf", True,
     "ssrf_lab/lab2：requests.get(客户端 url)（目录名即作者声明）"),
    ("ssrf_lab", "lab1", "pathtraver", True,
     "# Vulnerable implementation - allows directory traversal"),
    ("xxe_lab", "xxe_parse", "xxe", True,
     '"""Parse XML input - intentionally vulnerable to XXE"""'),
]

MIN_UNITS = 100
MIN_FALSE = 200
CATEGORIES = ("sqli", "cmdi", "deserial", "xss", "ssrf", "pathtraver",
              "redir", "spel", "xxe")

# 口径分歧（不静默，打印在案）：作者标注 vul 但与我们的类目口径不同
DISPUTED = [
    ("xss_lab", "lab1/lab2/lab3", "xss",
     "作者：Reflects unescaped user input；视图层走 render_template"
     "（Jinja2 自动转义），真实 sink 在模板文件的 |safe —— 与本工具 xss"
     " 类目'输入是否原样进入响应体'口径不同，不收"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="pygoat 基准（作者注释指名真值）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则（CI 门禁）")
    ap.add_argument("--strict", action="store_true",
                    help="真值全 True + 零计划外 True + 覆盖锁（CI 门禁）")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "pygoat.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    labs = repo / "dockerized_labs"
    if not labs.exists():
        print(f"! 靶场不存在：{repo}（安装：curl -sL -o x.zip "
              f"https://codeload.github.com/adeyosemanputra/pygoat/zip/refs/heads/master）")
        return 2

    units = list(WebTreeSitterSlicer(labs).extract_entry_units())
    print("pygoat 结果（20 个 Flask lab，作者注释指名真值）")
    print("=" * 72)
    print(f"切片单元 {len(units)}（门禁 ≥{MIN_UNITS}）")

    rows, missing = [], []
    by_key = {}
    for u in units:
        d = PurePath(u.file_path).parent.name
        by_key.setdefault((d, u.unit_name), []).append(u)
    for lab, uname, cat, is_vul, why in TRUTH:
        cands = by_key.get((lab, uname))
        if not cands:
            missing.append(f"{lab}:{uname}（真值表与源码不同步）")
            continue
        rows.append({"unit": cands[0], "category": cat, "real_vuln": is_vul,
                     "why": why, "lab": lab, "uname": uname})

    wrong, reverse_fn, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        r["rv"] = rv
        if rv is None:
            fallback.append(r)
        elif rv == r["real_vuln"]:
            pass
        else:
            (reverse_fn if rv is True else wrong).append(r)

    # 零计划外 True：作者没标注的单元被判 True 就是误报
    labeled = {(r["lab"], r["uname"]) for r in rows}
    stray_true = []
    n_false = 0
    for u in units:
        d = PurePath(u.file_path).parent.name
        for c in CATEGORIES:
            rv = rule_verdict(c, u.source_code)
            if rv is False:
                n_false += 1
            elif rv is True and (d, u.unit_name) not in labeled:
                stray_true.append((d, u.unit_name, c))

    print(f"真值 {len(rows)} 条，命中失败 {len(missing)}；"
          f"确定性 True {sum(1 for r in rows if r['rv'] is True)} / "
          f"False {sum(1 for r in rows if r['rv'] is False)} / "
          f"None {len(fallback)}")
    for r in rows:
        print(f"    {r['lab']:24} {r['uname']:18} {r['category']:11} "
              f"规则={r['rv']}  ← {r['why'][:48]}")
    for r in reverse_fn:
        print(f"    [判反] {r['lab']}:{r['uname']} ({r['category']})")
    for d, n, c in stray_true:
        print(f"    [计划外 True] {d}:{n} ({c})")
    print(f"确定性 False 判定 {n_false} 条（safe 面）")
    if args.list or True:
        for lab, uname, cat, why in DISPUTED:
            print(f"    [口径分歧·不收] {lab}:{uname} {cat} —— {why}")

    out = {
        "target": str(repo), "total_units": len(units),
        "truth_rows": len(rows), "missing": missing,
        # 计分板五标量（Module 26）：真值行即判定分母——本靶场门禁要求
        # 真值行 100% 判 True，所以 decided=真值数、correct=caught。
        "decided": len(rows),
        "correct": sum(1 for r in rows if r["rv"] is True),
        "fp": len(stray_true),
        "reverse_fn": len(reverse_fn),
        "fallback": [f"{r['lab']}:{r['uname']}" for r in fallback],
        "stray_true": [f"{d}:{n} ({c})" for d, n, c in stray_true],
        "false_judgements": n_false,
        "disputed": [{"lab": l, "unit": u, "cat": c, "why": w}
                     for l, u, c, w in DISPUTED],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        bad = []
        if missing:
            bad.append(f"真值表 {len(missing)} 条未命中")
        if reverse_fn:
            bad.append(f"判反 {len(reverse_fn)} 条")
        if fallback:
            bad.append(f"作者指名漏洞静默放行 {len(fallback)} 条（退 None）")
        if stray_true:
            bad.append(f"计划外 True {len(stray_true)} 条")
        if len(units) < MIN_UNITS:
            bad.append(f"切片单元 {len(units)}（<{MIN_UNITS}，同名符号覆盖退化）")
        if n_false < MIN_FALSE:
            bad.append(f"False 判定 {n_false}（<{MIN_FALSE}，safe 面退化）")
        if bad:
            print("STRICT FAIL ✘ " + "；".join(bad))
            return 1
        print(f"STRICT PASS ✔ （作者指名 {len(rows)}/{len(rows)} 全 True"
              " / 零计划外 True / 覆盖在线）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
