"""逐条诊断 OWASP 规则层误报（safe→True）的**机制归属**。

为什么单独一个脚本：`regress_owasp_rules.py` 只告诉你"哪几条错了"，
不告诉你"错在哪一层"。而本项目的教训是——先分清是「判据写窄」还是
「证据没进来」，再决定改哪一层。混在一起改必然打回归。

对每条样本打印：
  - 拼接右值（`sql = ...` / `fileName = ...`）与操作数变量
  - 每个操作数的 `_value_origin` 三态结果
  - 该变量的最后一次赋值右值、是否互斥控制流、容器推演结果
  - 是否存在 `_ambiguous_control_flow` 挡路

用法：
    python benchmarks/diag_owasp_fp_mechanism.py [样本号 ...]
    不给参数时诊断 regress_owasp_rules 报出的全部 B 方向样本。
"""
from __future__ import annotations

import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmarks.diag_owasp_sqli_fp import load_units   # noqa: E402
from core.agents import rule_detectors as R            # noqa: E402

REPO = os.path.join(ROOT, "reference_repos", "BenchmarkJava-master")


def load_truth() -> dict[str, tuple[str, bool]]:
    truth = {}
    path = os.path.join(REPO, "expectedresults-1.2.csv")
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.reader(line for line in f if not line.startswith("#")):
            if len(row) >= 3:
                truth[row[0].strip()] = (row[1].strip(), row[2].strip() == "true")
    return truth


def entry_body(src: str) -> str:
    """取入口方法体（与 verdict 内部同源）。"""
    return R.entry_body(src)


def diag_one(name: str, cat: str, src: str) -> None:
    body = entry_body(src)
    sib = R._sibling_methods(src)
    params = set(R._bare_params(R._entry_signature(src)))

    print(f"\n{'=' * 72}\n{name}  [{cat}]")
    verdict = R.verdict(cat, src)
    print(f"  verdict = {verdict}")

    # 找拼接赋值
    concat_lines = [ln.strip() for ln in body.splitlines()
                    if "=" in ln and re.search(r'"[^"]*"\s*\+|\+\s*"', ln)]
    for ln in concat_lines[:4]:
        print(f"  concat: {ln[:110]}")

    # 操作数三态
    for rhs in R._sql_rhs_iter(body):
        vars_ = R._operand_vars(rhs)
        print(f"  sql_rhs={rhs.strip()[:70]!r} operands={vars_}")
        for v in (vars_ or []):
            print(f"    {v}: last_rhs={R._last_assign_rhs(body, v)!r}")
            print(f"    {v}: ambiguous={R._ambiguous_control_flow(body, v)}"
                  f" container_lit={R._container_proven_lit(body, v)}"
                  f" origin={R._value_origin(body, v, sib, params)}")

    # pathtraver 的拼接形态：`x = prefix + bar`
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);", body):
        var, rhs = m.group(1), m.group(2)
        if "+" not in rhs:
            continue
        if not re.search(rf"(?:Paths\s*\.\s*get|new\s+File|FileInputStream)\s*\([^)]*\b{re.escape(var)}\b", body):
            continue
        print(f"  path_rhs: {var} = {rhs.strip()[:70]!r}")
        for part in R._STR_LIT_RE.sub('""', rhs).split("+"):
            p = R._strip_cast(part.strip())
            if not p or p == '""':
                continue
            if re.fullmatch(r"[A-Za-z_]\w*", p):
                print(f"    {p}: last_rhs={R._last_assign_rhs(body, p)!r}"
                      f" ambiguous={R._ambiguous_control_flow(body, p)}"
                      f" container_lit={R._container_proven_lit(body, p)}"
                      f" origin={R._value_origin(body, p, sib, params)}")
            else:
                print(f"    {p}: (非裸变量，字段/调用)")

    # 判定链上的每个闸门
    print(f"  gates: sql_concat_all_const={R._sql_concat_all_constant(body, sib)}"
          f" path_concat_all_const={R._path_concat_all_constant(body, sib)}"
          f" ambiguous(bar)={R._ambiguous_control_flow(body, 'bar')}")


def main() -> None:
    units = load_units(False)
    truth = load_truth()

    targets = sys.argv[1:]
    if targets:
        names = [f"BenchmarkTest{t.zfill(5)}" for t in targets]
    else:
        names = []
        for name, (cat, is_vul) in sorted(truth.items()):
            hit = [k for k in units if name in k]
            if not hit:
                continue
            if not is_vul and R.verdict(cat, units[hit[0]]) is True:
                names.append(name)

    for name in names:
        hit = [k for k in units if name in k]
        if not hit:
            print(f"{name}: 无切片")
            continue
        cat, is_vul = truth.get(name, ("?", False))
        diag_one(name, cat, units[hit[0]])


if __name__ == "__main__":
    main()
