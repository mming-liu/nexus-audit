"""vulpy —— 第 7 个靶场，第一个**真实外部 Python Web** 基准（bad/ vs good/ 双目录对照）。

## 为什么需要这个靶场

Python 赛道的规则（Module 5）此前只靠 [56] 合成夹具锁定 —— 合成探针的
形态永远只有作者想得到的那几种。`fportantier/vulpy` 是真实开源靶场：
`bad/` 是漏洞版（SQLi 用 `.format` 拼接），`good/` 是修复版（参数化 `?`），
文件同名、路由同构 —— 成对真值天然成立，不需要人工标注。

## 真值来源

**代码事实对比**（bad/good 逐文件 diff，比注释更硬）：

1. `bad/libuser.login`   : `"... username = '{}' ...".format(username, password)` → 拼接
   `good/libuser.login`  : `"... username = ?", (username,)`                      → 参数化
2. `bad/libuser.password_change`: `"UPDATE ... password = '{}' ...".format(...)` → 拼接
   `good/libuser.password_change`: 参数化
3. `bad/libapi.keygen` → `libuser.login(username, password)` 校验凭据
   —— SQL 拼接经两跳可达（key_create 链）

### 登记口径（机制内才登记，记忆条 51）

只登记 **sqli**（有确定性判据）。libsession 的会话管理差异、libapi 的
keyfile 路径拼接属其他机制，未实现判据前**不登记**（不表态 ≠ 判错，
混进分母会把"能力边界"污染成"FPR"）。

## 门禁（--strict）

登记样本必须**全部**确定性判定且方向正确：
  - 误报（good 判 True）= 0
  - 静默放行（bad 判 False）= 0
  - 退回 None = 0（登记机制内不允许"查不出"）
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
from core.slicer.web_treesitter import WebTreeSitterSlicer          # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "vulpy-master"

# 真值表：键 (side, unit_name)。unit_name 在 bad/good 两侧同构
# （good 的 do_chpasswd 拆成了 GET/POST 两个函数，分别登记）。
# 值: (类目, 真值, 依据)
TRUTH: dict[tuple[str, str], tuple[str, bool, str]] = {
    # ---- SQL 注入（bad：.format 拼接 / good：参数化 ?）----
    ("bad", "do_login"):       ("sqli", True,  "bad/libuser.login 用 .format 拼 SELECT"),
    ("good", "do_login"):      ("sqli", False, "good/libuser.login 参数化 ?"),
    ("bad", "do_chpasswd"):    ("sqli", True,  "bad/libuser.password_change .format 拼 UPDATE"),
    ("good", "do_chpasswd_post"): ("sqli", False, "good/libuser.password_change 参数化"),
    # keygen 先经 libuser.login 校验凭据再写 keyfile —— SQL 拼接两跳可达
    ("bad", "do_key_create"):  ("sqli", True,  "bad/libapi.keygen → libuser.login .format"),
    ("good", "do_key_create"): ("sqli", False, "good 同链路已参数化"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="登记样本必须全部确定性判定且零误报零静默放行（CI 门禁）")
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组供抽查")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "vulpy.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    print(f"靶场：{repo}")

    rows, unregistered = [], []
    total = 0
    for side in ("bad", "good"):
        d = repo / side
        if not d.exists():
            print(f"! 缺少 {d}（靶场结构应为 bad/ + good/ 双目录）")
            sys.exit(2)
        units = WebTreeSitterSlicer(d).extract_entry_units()
        total += len(units)
        for u in units:
            hit = TRUTH.get((side, u.unit_name))
            if hit:
                rows.append({"unit": u, "side": side, "category": hit[0],
                             "real_vuln": hit[1], "src": hit[2]})
            else:
                unregistered.append((side, u.unit_name))

    print(f"[1/2] 切出入口 {total} 个（bad+good），登记 {len(rows)} 条"
          f"（vul {sum(1 for r in rows if r['real_vuln'])} / "
          f"safe {sum(1 for r in rows if not r['real_vuln'])}），"
          f"机制外不登记 {len(unregistered)} 条")
    if args.list:
        for side, name in sorted(unregistered):
            print(f"      [不登记] {side}/{name}")
        for r in rows:
            print(f"      [{r['side']}] {r['unit'].unit_name:18} {r['category']:6} "
                  f"{'vul ' if r['real_vuln'] else 'safe'} 依据={r['src']}")

    print("[2/2] 规则层判定...")
    wrong, silent, fallback = [], [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        if rv is None:
            fallback.append(r)
        elif rv != r["real_vuln"]:
            (wrong if rv is not None else silent).append(r)
        if rv is False and r["real_vuln"]:
            silent.append(r)
        if rv is True and not r["real_vuln"]:
            wrong.append(r)

    n = len(rows)
    decided = n - len(fallback)
    right = sum(1 for r in rows
                if r not in fallback and r not in wrong and r not in silent)
    print()
    print("=" * 72)
    print("vulpy 成对真值结果（规则层，零改动）")
    print("=" * 72)
    print(f"登记样本              ：{n}（bad vul {sum(1 for r in rows if r['side']=='bad' and r['real_vuln'])}"
          f" / good safe {sum(1 for r in rows if r['side']=='good') and sum(1 for r in rows if r['side']=='good' and not r['real_vuln'])}）")
    print(f"规则确定性判定        ：{decided}/{n}（退回 {len(fallback)}）")
    print(f"判定正确              ：{right}/{decided}")
    if wrong:
        print("\n! 误报（good 判 True）—— 必须为 0：")
        for r in wrong:
            print(f"  [{r['side']}] {r['unit'].unit_name}  规则=True 真值={r['real_vuln']}")
    if silent:
        print("\n! 静默放行（bad 判 False）—— 必须为 0：")
        for r in silent:
            print(f"  [{r['side']}] {r['unit'].unit_name}  规则=False 真值={r['real_vuln']}")
    if fallback:
        print("\n退回 None（--strict 下记为失败）：")
        for r in fallback:
            print(f"  [{r['side']}] {r['unit'].unit_name}  {r['category']}")

    out = {
        "target": str(repo),
        "total_units": total,
        "registered": n,
        "decided": decided,
        "correct": right,
        "fp": len(wrong),
        "silent_fn": len(silent),
        "fallback": [{"side": r["side"], "unit": r["unit"].unit_name,
                      "category": r["category"]} for r in fallback],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")

    if args.strict:
        bad_gate = wrong or silent or fallback
        if bad_gate:
            print("\nSTRICT 门禁：未通过 ✘")
            sys.exit(1)
        print("\nSTRICT 门禁：通过 ✔（零误报 / 零静默放行 / 零退回）")


if __name__ == "__main__":
    main()
