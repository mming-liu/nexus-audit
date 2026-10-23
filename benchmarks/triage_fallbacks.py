"""跨靶场退回池（rule_verdict is None）自动聚类体检器（Module 33，只读）。

对所有 SCOREBOARD 真值型靶场的切出单元 × 类目跑确定性规则，把每个 None
退回样本按五类原因分桶（按优先级取第一命中）：

  1. 缺 Sink          —— body 里没有该类目的任何汇点形态
  2. 缺 Source        —— 没有外部输入形态（request/参数注解/形参直传）
  3. 跨文件链路未闭合 —— 调了 Service/Mapper 但切片里没有 [Hop] 实现体
  4. 含未决 Helper    —— 调用了方法名，但切片里没有对应实现段
  5. 含未知安全包装   —— 汇点存在，结果经某函数返回后未再处理（疑似包装）

产出：--json / --md 两份剖析表，供后续迭代一眼识别哪一桶还有确定性规则
空间（Module 34 的榜首选择依据）。只读诊断，不写任何判定。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict  # noqa: E402
from core.agents.rule_detectors import _looks_solidity          # noqa: E402

BENCHES = {
    "RuoYi": ("java", ROOT / "reference_repos" / "RuoYi-master"),
    "eladmin-mp": ("java", ROOT / "reference_repos" / "eladmin-mp-master"),
    "vulpy": ("python", ROOT / "reference_repos" / "vulpy-master"),
    "pygoat": ("python", ROOT / "reference_repos" / "pygoat-master"),
    "smartbugs": ("solidity", ROOT / "reference_repos" / "smartbugs-curated-main"),
    "DeFiVulnLabs": ("solidity", ROOT / "reference_repos" / "DeFiVulnLabs-main"),
    "nssc": ("solidity", ROOT / "reference_repos" / "not-so-smart-contracts-master"),
}

CATEGORIES = ["sqli", "authz", "pathtraver", "xss", "cmdi", "deserial",
              "ssrf", "xxe", "reentrancy", "access_control"]

# 缺 Sink 判定：类目 → 汇点形态（与 rule_detectors 的门控同源的最小集）
SINK_RES = {
    "sqli": re.compile(r"execute(?:Query|Update)|prepareStatement|createStatement"
                       r"|JdbcTemplate|\$\{|\.apply\s*\(|\.last\s*\(", re.I),
    "authz": re.compile(r"(?:Service|Mapper|Dao|DAO)\s*\.\s*\w+\s*\("),
    "pathtraver": re.compile(r"new\s+File\s*\(|Paths\s*\.|FileInputStream|"
                             r"Files\s*\.\w+\s*\(|open\s*\(", re.I),
    "xss": re.compile(r"out\s*\.\s*print|println|write\s*\(|render_template", re.I),
    "cmdi": re.compile(r"Runtime\s*\.\s*getRuntime|exec\s*\(|subprocess|os\.system", re.I),
    "deserial": re.compile(r"readObject\s*\(|ObjectInputStream|loads\s*\(|load\s*\(", re.I),
    "ssrf": re.compile(r"openConnection|URLConnection|requests\.|urlopen|HttpClient", re.I),
    "xxe": re.compile(r"DocumentBuilder|parse\s*\(|fromstring|XMLReader|SAX", re.I),
    "reentrancy": re.compile(r"\.\s*call\s*(?:\{|\.|\()|\.\s*(?:send|transfer)\s*\("),
    "access_control": re.compile(r"selfdestruct|owner|msg\s*\.\s*sender|transfer|"
                                 r"transferFrom", re.I),
}
SOURCE_RE = re.compile(r"getParameter|@RequestBody|@PathVariable|@RequestParam|"
                       r"MultipartFile|request\s*\.\s*\w+|request\.form|request\.args|"
                       r"msg\s*\.\s*(?:sender|value|data)|tx\s*\.\s*origin|calldata", re.I)
HOP_MARK_RE = re.compile(r"//\s*(?:来自 |\[Hop \d+\]|跨文件证据)")
CALL_RE = re.compile(r"\b([a-z]\w*(?:Service|Mapper|Dao|DAO))\s*\.\s*(\w+)\s*\(")
HELPER_CALL_RE = re.compile(r"\b([a-z]\w+)\s*\(\s*[^)]{0,80}", re.I)


def _strip_comments(src: str) -> str:
    return re.sub(r"//[^\n]*", "", src)


def classify(category: str, src: str) -> str:
    """五桶分类：按优先级取第一命中（缺Sink > 缺Source > 链路未闭合 >
    未决Helper > 未知安全包装），全不命中归『其它未决』。"""
    body = src
    sink = SINK_RES.get(category)
    if sink is not None and not sink.search(body):
        return "缺 Sink"
    if not SOURCE_RE.search(body):
        return "缺 Source"
    stripped = _strip_comments(body)
    hops = HOP_MARK_RE.findall(body)
    calls = CALL_RE.findall(stripped)
    if calls and not hops:
        return "跨文件链路未闭合"
    if hops:
        # 有 Hop 段：看被调的方法名是否都有实现段覆盖
        called = {m.lower() for _, m in calls}
        impld = set(re.findall(r"// 来自 \S+?[ \[]?(\w+)\s*\(", body))
        impld |= set(re.findall(r"跨文件证据：\w+\(\)\s*的接口实现类方法体", body))
        if called and not called & {c.lower() for c in
                                    re.findall(r"public\s+\S+\s+(\w+)\s*\(", body)}:
            return "跨文件链路未闭合"
    # 函数式调用但无实现段
    for m in HELPER_CALL_RE.finditer(stripped):
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "return", "catch",
                    "require", "assert", "success", "error"):
            continue
        if name not in body.replace("(", "") and f"def {name}" not in body \
                and not re.search(rf"(public|private|protected|def)\s+\S+\s+{name}\s*\(", body):
            return "含未决 Helper"
    return "含未知安全包装" if sink is not None and sink.search(body) else "其它未决"


def iter_units(bench: str):
    kind, repo = BENCHES[bench]
    if kind == "java":
        from core.slicer.java_servlet import JavaSlicer
        yield from JavaSlicer(repo).extract_entry_units()
    elif kind == "python":
        from core.slicer.web_treesitter import WebTreeSitterSlicer
        yield from WebTreeSitterSlicer(repo).extract_entry_units()
    else:
        from core.slicer.web3_slither import SoliditySlicer
        yield from SoliditySlicer(repo).extract_entry_units(repo)


# Module 41：覆盖地板门禁。各真值靶场**确定性命中数**（rule_verdict 非
# None 的真值条目）的下限 —— 防止规则改动引入新的退回路径把覆盖率静默
# 打下来（"跑过"≠"绿着"：strict 只锁误报/判反，覆盖率下滑不拦截）。
# 基线取自 2026-10-23 全绿态 results/*.json 的 decided 字段。
FLOORS = {
    "defivulnlabs": 9,      # DeFiVulnLabs 9/9 满贯（M36）
    "nssc": 7,              # nssc 7/8（1 条真值按口径退模型）
    "smartbugs": 177,
    "vampi": 7,             # VAmPI 7/7（M37）
    "mall": 16,             # mall 16/16（M38）
    "vulpy": 6,
    "pygoat": 9,
    "ruoyi": 159,
    "eladminmp": 53,
}


def check_floor() -> int:
    """读各 results/*.json 的 decided，跌破 FLOORS 非零退出。

    判定挂文件不挂脚本：json 是各 benchmark 自己写的，门禁只看结果
    指标 —— 脚本内部实现怎么改都不影响门禁语义。"""
    print("覆盖地板门禁（--check-floor）：")
    bad = []
    for name, floor in sorted(FLOORS.items()):
        j = ROOT / "benchmarks" / "results" / f"{name}.json"
        if not j.exists():
            print(f"  SKIP  {name:14}（无 {name}.json）")
            continue
        d = json.loads(j.read_text(encoding="utf-8"))
        decided = d.get("decided")
        if not isinstance(decided, (int, float)):
            print(f"  SKIP  {name:14}（json 无 decided 字段）")
            continue
        status = "OK " if decided >= floor else "LOW"
        print(f"  {status}  {name:14} decided={decided}  地板={floor}")
        if decided < floor:
            bad.append((name, decided, floor))
    if bad:
        print(f"\n覆盖地板跌破 {len(bad)} 项：{bad}")
        print("覆盖率静默下滑 —— 查最近的规则/切片改动（铁律：退回 None")
        print("是'退回'不是漏报，但覆盖率暗降必须显式可见）。")
        return 1
    print(f"\n{len(FLOORS)} 项地板全部达标 ✔")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="退回池五分类剖析（只读）")
    ap.add_argument("--json", default=str(ROOT / "benchmarks" / "results" /
                                          "triage_fallbacks.json"))
    ap.add_argument("--md", default=str(ROOT / "benchmarks" / "results" /
                                        "triage_fallbacks.md"))
    ap.add_argument("--limit-samples", type=int, default=5)
    ap.add_argument("--check-floor", action="store_true",
                    help="覆盖地板门禁：确定性命中数跌破 FLOORS 即非零退出")
    args = ap.parse_args()

    if args.check_floor:
        return check_floor()

    out: dict = {}
    samples: dict = defaultdict(list)
    for bench in BENCHES:
        per_cat: Counter = Counter()
        for u in iter_units(bench):
            src = u.source_code or ""
            if not src:
                continue
            for cat in CATEGORIES:
                if rule_verdict(cat, src) is None:
                    if _looks_solidity(src) != (BENCHES[bench][0] == "solidity"):
                        continue
                    b = classify(cat, src)
                    per_cat[f"{cat}/{b}"] += 1
                    if len(samples[f"{bench}/{cat}/{b}"]) < args.limit_samples:
                        samples[f"{bench}/{cat}/{b}"].append(
                            f"{Path(u.file_path).name}:{u.unit_name}")
        out[bench] = dict(per_cat)
        print(f"{bench:14} 退回分桶：")
        for k, v in sorted(per_cat.items(), key=lambda kv: -kv[1]):
            print(f"    {k:34} {v}")
        print()

    # 榜单：全靶场合计按桶排序（Module 34 的选择依据）
    total: Counter = Counter()
    for d in out.values():
        total.update(d)
    lines = ["# 退回池五分类剖析（Module 33，只读诊断）", "",
             "| 靶场/类目/桶 | 样本数 |", "|---|---|"]
    for k, v in total.most_common():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## 样本示例", ""]
    for k in list(samples)[:40]:
        lines.append(f"- `{k}`：{'；'.join(samples[k])}")
    Path(args.md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.json).write_text(json.dumps(
        {"total": dict(total), "per_bench": out,
         "samples": dict(samples)}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"汇总 Top：")
    for k, v in total.most_common(10):
        print(f"    {k:34} {v}")
    print(f"\n写入 {args.md} 与 {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
