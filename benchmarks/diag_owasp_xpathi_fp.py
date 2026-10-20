"""OWASP xpathi 规则层判定逐条核验（只跑规则层，不调模型）。

背景：xpathi 的 4 条 FP 全是 `missing_property`（模型投票抖动），规则层
"一条没错"只是没判错——没有 verdict 入口时规则只能返回 None，可证为
常量的 safe 样本照样送模型抽签。本脚本在接入 `xpathi_verdict` 前后
逐条核验：15 条 vul **绝不能**被短路成 False（方向性错误，比误报危险），
15 条 safe 里有几条能被拦下来。

切片很慢（OWASP 2740 个文件），复用 diag_owasp_sqli_fp.py 的 pickle 缓存。

用法：
    python benchmarks/diag_owasp_xpathi_fp.py
"""
from __future__ import annotations

import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmarks.diag_owasp_sqli_fp import load_units, pick_unit   # noqa: E402
from core.agents import rule_detectors as R            # noqa: E402

REPO = os.path.join(ROOT, "reference_repos", "BenchmarkJava-master")


def load_truth() -> dict[str, bool]:
    truth = {}
    path = os.path.join(REPO, "expectedresults-1.2.csv")
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.reader(line for line in f if not line.startswith("#")):
            if len(row) >= 3 and row[1].strip().lower() == "xpathi":
                truth[row[0].strip()] = row[2].strip() == "true"
    return truth


def main() -> None:
    units = load_units(False)
    truth = load_truth()
    print(f"xpathi 真值条数 {len(truth)}\n")

    v_f, v_t, v_n = [], [], []
    s_f, s_other = [], []
    for name, is_vul in sorted(truth.items()):
        key = pick_unit(units, name)
        if not key:
            print(f"{name}: 未找到入口（跳过）")
            continue
        src = units[key]
        verdict = R.xpathi_verdict(src)
        if is_vul:
            {"False": v_f, True: v_t, None: v_n}.get(
                "False" if verdict is False else verdict, v_n).append(name)
        else:
            (s_f if verdict is False else s_other).append(name)
        mark = {False: "False", True: "True ", None: "None "}[verdict]
        flag = ""
        if is_vul and verdict is False:
            flag = "  <<<< 方向性错误：真漏洞被判 safe"
        print(f"{name}  vul={str(is_vul):5}  verdict={mark}{flag}")

    print("\n===== 汇总 =====")
    print(f"vul 15 条：True={len(v_t)}  None={len(v_n)}  False(!!)={len(v_f)}  {v_f}")
    print(f"safe 15 条：False(拦下)={len(s_f)}  {s_f}")
    print(f"           其余交模型={len(s_other)}  {s_other}")


if __name__ == "__main__":
    main()
