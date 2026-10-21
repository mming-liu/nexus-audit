"""smartbugs-curated —— 第 8 个靶场，第一个**真实 Solidity** 基准。

## 为什么需要这个靶场

Solidity 规则（Module 6）此前只靠 [57] 合成夹具锁定。`smartbugs/smartbugs-curated`
是社区权威数据集：`dataset/reentrancy/`（31 个合约）与 `dataset/access_control/`
（18 个合约），官方 `vulnerabilities.json` 给出漏洞行号 —— 含漏洞行的函数为
vul，其余函数构成**真实 safe 分母**（合成夹具给不出负样本分布）。

## 真值来源

`vulnerabilities.json`：`{path, vulnerabilities: [{lines, category}]}`。
真值按行号映射到函数：函数 [start_line, end_line] 覆盖任一标注行 → vul，
同文件其余函数 → safe。映射脚本会打印全部三元组供抽查。

## DISPUTED（口径分歧，不计入指标）

`parity_wallet_bug_1.sol` 与 `parity_wallet_bug_2.sol` 的 `kill` 函数
**代码逐字相同**（`onlymanyowners` 多签保护 + `suicide(_to)`），官方真值
却一处不标、一处标注为漏洞 —— 同一函数不可能既是 safe 又是 vul。
不为分数改判据（记忆条 34），把两个 kill 都记入 DISPUTED 剔除计分；
规则对相同代码给出相同判定，这本身就是该有的性质。

## Module 13 修复记录（真实合约抓出的判据坑）

1. `_looks_solidity` 要求 pragma/contract 关键字 —— 函数级切片没有
   文件头，恒 False，全部静默退 None；
2. 老语法 `msg.sender.call.value(x)()`（0.4.x 主流）不在外部调用集合；
3. modifier 可以无参（`modifier onlyowner {`），带参正则漏掉整类；
4. modifier 保护必须看**实现体**里的 msg.sender 恒等检查；纯状态门
   （parity `only_uninitialized` 查 m_numOwners）不是身份检查，拿它
   判安全会把 initWallet 判反 —— 方向错误比退回恶劣；
5. 错名构造函数（Rubixi 的 `DynamicPyramid`）= 函数名 != 合约名却写
   owner 态 → True；同名才是构造函数，正常初始化不判。

## 门禁（--strict）

safe 负样本**零误报（FPR = 0）**，且判过方向的样本 FN = 0
（判据宁退 None 不判反）。退回 None 交模型，不阻塞门禁。
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.web3_slither import SoliditySlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "smartbugs-curated-main"

CATEGORIES = ["reentrancy", "access_control"]

# 口径分歧剔除表：(文件名, 函数名)。同一函数在官方数据集里真值相反。
DISPUTED = {
    ("parity_wallet_bug_1.sol", "kill"),
    ("parity_wallet_bug_2.sol", "kill"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="safe 负样本零误报 + 零判反（CI 门禁）")
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组供抽查")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "smartbugs.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    meta_file = repo / "vulnerabilities.json"
    if not meta_file.exists():
        print(f"! 找不到 {meta_file}")
        sys.exit(2)
    meta = {Path(x["path"]).name: x
            for x in json.loads(meta_file.read_text(encoding="utf-8"))}

    rows, disputed_rows = [], []
    total = 0
    slicer = SoliditySlicer(repo)
    for cat in CATEGORIES:
        units = slicer.extract_entry_units(repo / "dataset" / cat)
        for u in units:
            entry = meta.get(Path(u.file_path).name)
            if not entry:
                continue
            vul_lines = {l for v in entry["vulnerabilities"]
                         if v["category"] == cat for l in v["lines"]}
            if not vul_lines:
                continue
            total += 1
            truth = any(u.start_line <= l <= u.end_line for l in vul_lines)
            row = {"unit": u, "category": cat, "real_vuln": truth,
                   "file": Path(u.file_path).name}
            if (row["file"], u.unit_name) in DISPUTED:
                disputed_rows.append(row)
            else:
                rows.append(row)

    vul_n = sum(1 for r in rows if r["real_vuln"])
    print(f"靶场：{repo}")
    print(f"[1/2] 切出函数 {total} 个，登记 {len(rows)} 条"
          f"（vul {vul_n} / safe {len(rows) - vul_n}），"
          f"口径分歧剔除 {len(disputed_rows)} 条")
    if args.list:
        for r in disputed_rows:
            print(f"      [DISPUTED] {r['file']}:{r['unit'].unit_name}")

    print("[2/2] 规则层判定...")
    wrong, reverse_fn, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        if rv is None:
            fallback.append(r)
        elif rv is True and not r["real_vuln"]:
            wrong.append(r)                    # 误报
        elif rv is False and r["real_vuln"]:
            reverse_fn.append(r)               # 判反（比退回恶劣）
    judged = len(rows) - len(fallback)
    right = judged - len(wrong) - len(reverse_fn)
    safe_n = len(rows) - vul_n

    print()
    print("=" * 72)
    print("smartbugs-curated 结果（规则层，零改动）")
    print("=" * 72)
    for cat in CATEGORIES:
        sub = [r for r in rows if r["category"] == cat]
        sub_v = sum(1 for r in sub if r["real_vuln"])
        tp = sum(1 for r in sub if r not in fallback and r not in wrong
                 and r not in reverse_fn and r["real_vuln"] and
                 rule_verdict(cat, r["unit"].source_code) is True)
        print(f"  {cat:15} 登记 {len(sub):3}（vul {sub_v} / safe {len(sub) - sub_v}）")
    print(f"登记样本              ：{len(rows)}（safe 分母 {safe_n}）")
    print(f"规则确定性判定        ：{judged}/{len(rows)}（退回 {len(fallback)}）")
    print(f"判定正确              ：{right}/{judged}")
    if wrong:
        print("\n! 误报（safe 判 True）—— strict 门禁必须为 0：")
        for r in wrong:
            print(f"  {r['file']}:{r['unit'].unit_name}  {r['category']}")
    if reverse_fn:
        print("\n! 判反（vul 判 False）—— 比退回恶劣，必须为 0：")
        for r in reverse_fn:
            print(f"  {r['file']}:{r['unit'].unit_name}  {r['category']}")
    if disputed_rows:
        print(f"\n口径分歧剔除 {len(disputed_rows)} 条（不计入任何指标）：")
        for r in disputed_rows:
            print(f"  {r['file']}:{r['unit'].unit_name}  官方真值={r['real_vuln']}")

    out = {
        "target": str(repo),
        "total_functions": total,
        "registered": len(rows),
        "safe_denominator": safe_n,
        "decided": judged,
        "correct": right,
        "fp": len(wrong),
        "reverse_fn": len(reverse_fn),
        "fallback": len(fallback),
        "disputed": [{"file": r["file"], "unit": r["unit"].unit_name}
                     for r in disputed_rows],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        if wrong or reverse_fn:
            print("\nSTRICT 门禁：未通过 ✘")
            sys.exit(1)
        print("\nSTRICT 门禁：通过 ✔（safe 零误报 / 零判反）")


if __name__ == "__main__":
    main()
