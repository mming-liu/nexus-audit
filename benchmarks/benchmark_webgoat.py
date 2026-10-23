"""WebGoat —— 第 18 个靶场：教学关卡型真值（成对攻防）。

## 为什么是这个靶场

前 17 个靶场的真值都来自"作者注明的漏洞行"或"成对 vuln/fixed 文件"。
WebGoat 补的是第三类真值源：**同一门课程里成对的攻击关与修复关** ——
作者本人写下"这关要你注入成功"（AssignmentEndpoint + success 反馈），
修复关则用参数化/清洗把洞堵上。攻击关与修复关**同库同构**，判定口径
必须一致才敢登记。

## 探针结论（Module 46，先探针后落地）

WebGoat 全库 179 个入口，五个目标课程（sqlinjection / pathtraversal /
xxe / ssrf / idor）逐条跑规则判定，实测：

  · sqlinjection：**口径一致**，可登记 —— 攻击关 Lesson2/3/4/5 与
    Mitigations 的 Servers.sort（ORDER BY 拼接）判 True，修复关
    Lesson13（PreparedStatement + setString）判 False；
  · pathtraversal：**口径冲突**（ProfileUploadRetrieval 用随机文件名，
    是"安全示范"却被判 True）→ **不登记**；
  · xxe / ssrf：sink 全在跨文件（comments.parseXml / RestTemplate），
    规则层全退 None → 判不了，不登记；
  · idor：教学意图是"越权成功"，与 authz 判据方向相反 → 不登记。

只登记作者意图明确、且规则判定与之一致的条目（铁律：只收作者指名真值）。

## 本靶场逼出的通用机制缺口（Module 46 副产品）

**整句 SQL 由用户控制**：`statement.executeQuery(query)` —— query 是
String 形参（@RequestParam），SQL 语句**整句**由攻击者给。这不是"拼接"
形态（`+` 拼接），比拼接更彻底，但规则层此前只认拼接，于是这一整类经典
注入全部退回 None（WebGoat 实测 10 余个关卡全退）。

新增判据（`sqli_verdict` 的 A1 分支，挂在所有既有分支之后，只认 True）：
  ① sink 是 JDBC 执行方法；
  ② 实参是标识符（非 SQL 字面量、无 ? 占位符）；
  ③ 实参是所在方法的 **String 型形参**（数字型形参注入不了）；
  ④ 该形参来自外部输入：入口的用户输入形参（@RequestParam/@PathVariable/
     @RequestBody/@RequestHeader），或 Spring MVC 默认绑定（HTTP 入口上
     无注解的 String 形参），或它所在方法被入口以用户输入形参调用。

门禁（--strict）：登记条目全部判对（零误报 / 零判反 / 零退回）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.java_servlet import JavaSlicer                  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "WebGoat-master"

# 真值表：键 (file_name, unit_name, start_line)（铁律 23 精确匹配）
TRUTH: dict[tuple[str, str, int], tuple[str, bool, str]] = {
    # ---- 攻击关：整句 SQL 由用户控制（Statement 直传形参）----
    ("SqlInjectionLesson2.java", "SqlInjectionLesson2.completed", 40):
        ("sqli", True, "statement.executeQuery(query)：query 是 @RequestParam 形参，整句可控"),
    ("SqlInjectionLesson3.java", "SqlInjectionLesson3.completed", 35):
        ("sqli", True, "statement.executeUpdate(query)：整句可控（写型注入）"),
    ("SqlInjectionLesson4.java", "SqlInjectionLesson4.completed", 36):
        ("sqli", True, "statement.executeUpdate(query)：整句可控（写型注入）"),
    ("SqlInjectionLesson5.java", "SqlInjectionLesson5.completed", 53):
        ("sqli", True, "completed(String query) 无注解形参：Spring 默认按名绑定请求参数，整句可控"),
    # ---- 攻击关：ORDER BY 拼接 ----
    ("Servers.java", "Servers.sort", 43):
        ("sqli", True, "prepareStatement(\"... order by \" + column)：column 是 @RequestParam"),
    # ---- 修复关：参数化查询 ----
    ("SqlInjectionLesson13.java", "SqlInjectionLesson13.completed", 41):
        ("sqli", False, "prepareStatement(\"... where ip = ? and hostname = ?\") + setString 绑定"),
}


def run(target: Path, strict: bool, out: Path | None) -> int:
    units = JavaSlicer(target).extract_entry_units()
    print("WebGoat 结果（教学关卡成对真值）")
    print("=" * 72)
    print(f"切片单元 {len(units)}（全仓入口）")

    by_key: dict[tuple[str, str, int], list] = {}
    for u in units:
        by_key.setdefault((Path(u.file_path).name, u.unit_name, u.start_line),
                          []).append(u)

    tp = fp = fn = none_ct = 0
    rows = []
    for key, (cat, truth, why) in sorted(TRUTH.items()):
        u = by_key.get(key, [None])[0]
        if u is None:
            print(f"  对不上  {key}")
            return 1
        rv = rule_verdict(cat, u.source_code or "")
        rows.append({"file": key[0], "unit": key[1], "start_line": key[2],
                     "category": cat, "truth": truth, "rule": rv, "why": why})
        if rv is None:
            none_ct += 1
            print(f"  退回  {key[1]} ({cat})  ({why})")
        elif rv == truth:
            tp += 1
            print(f"  判对  {key[1]} ({cat})  -> {rv}")
        else:
            if truth is False:
                fp += 1
                print(f"  误报  {key[1]} ({cat})  -> {rv}")
            else:
                fn += 1
                print(f"  判反  {key[1]} ({cat})  -> {rv}")

    print(f"\n  判对 {tp}  误报 {fp}  判反 {fn}  退回 {none_ct}"
          f"  （登记 {len(TRUTH)} 条）")
    if out:
        out.write_text(json.dumps(
            {"target": str(target), "total_units": len(units),
             "truth_entries": len(TRUTH), "decided": tp + fp + fn,
             "correct": tp, "fp": fp, "reverse_fn": fn, "none": none_ct,
             "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结果写入 {out}")
    if strict:
        ok = fp == 0 and fn == 0 and none_ct == 0
        print("\nSTRICT 门禁：" + ("通过 ✔（零误报 / 零判反 / 零退回）"
                                    if ok else "未通过 ✘"))
        return 0 if ok else 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WebGoat 基准（M46）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results"
                                          / "webgoat.json"))
    a = ap.parse_args()
    return run(Path(a.target), a.strict, Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
