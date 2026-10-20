"""Hello-Java-Sec 零改动迁移盲测（Zero-Shot Transfer）。

## 这个脚本要回答的问题

java-sec-code 上的 63/63 是**在同源样本上做出来的**规则，过拟合风险一直悬着。
要检验规则到底是"识别通用安全事实"还是"记住了 JoyChou93 的写法"，
唯一的办法是换一个作者、换一套命名、换一批工具类，**一行正则都不改**再跑一遍。

因此本脚本有一条铁律：**不 import 任何被修改过的规则，也不改 rule_detectors**。
它只做三件事：
  1. 从靶场自己的标注里提取真值（不猜、不硬凑）
  2. 让现有规则直接判，统计"规则给出结论的比例"与"给出结论时的正确率"
  3. 规则未覆盖的交给模型，单独统计 —— 两部分不能混在一起算分

## 真值来源（两处独立标注，交叉确认）

Hello-Java-Sec 的作者标了两处：
  1. `@ApiOperation(value = "vul：XMLReader")` / `value = "safe：检测是否包含外部实体"`
     注意用的是**全角冒号**，半角写法也要兼容。
  2. 路由命名 `/vul` `/vul1` `/safe` `/safe2`，以及方法名里的 `Vul`/`Safe`。
两处冲突时以 @ApiOperation 为准（离方法更近，意图更明确），并在输出里计数，
冲突样本本身也说明靶场不规整 —— 这类样本要能看到，不能悄悄按某一方算。

判不出的（`/download`、`/list`、`/reflect` 这种既无注解也无命名标记的）
一律标 unknown 并**排除出计算**。宁可样本少，也不猜。

## 指标口径

- Fallback Rate = 规则返回 None 的条数 / 有人工真值的条数
- 规则判定正确率 = 规则给出结论的样本里判对的比例（这一项必须接近 100%，
  否则说明规则在别的项目上会批量误报，比覆盖不足严重得多）
- 模型部分单独统计 TPR/FPR，不与规则部分合并
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.models import base_unit_name                          # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "Hello-Java-Sec-master"

# 类名 -> 类目。只映射我们有确定性规则的类；其余（IDOR/CSRF/JWT/SSTI/
# 组件漏洞）没有对应类目或参考价值有限，整体排除。
CLASS_TO_CATEGORY = {
    "JDBC": "sqli",
    "MyBatis": "sqli",
    "Hibernate": "sqli",
    "XSS": "xss",
    "SSRF": "ssrf",
    "XXE": "xxe",
    "SpEL": "spel",
    "GroovyVul": "spel",       # Groovy shell 属于脚本引擎执行，归到 spel 一起看
    "LoadJsVul": "spel",
    "Deserialization": "deserial",
    "SnakeYamlVul": "deserial",
    "XMLDecoderVul": "deserial",
    "CORS": "cors",
    "Redirect": "redir",
    "Traversal": "pathtraver",
    "RuntimeVul": "cmdi",
    "ProcessBuilderVul": "cmdi",
    "ProcessImplVul": "cmdi",
}

# @ApiOperation(value = "vul：xxx") —— 全角/半角冒号都有
APIOP_RE = re.compile(r'@ApiOperation\s*\(\s*(?:value\s*=\s*)?"([^"]*)"')
APIOP_VUL = re.compile(r"^\s*vul", re.I)
APIOP_SAFE = re.compile(r"^\s*(?:safe|sec)\b|^\s*(?:safe|sec)\s*[：:]", re.I)

ROUTE_VUL = re.compile(r"(?:^|/)vul(?:n)?\d*(?:/|$)", re.I)
ROUTE_SAFE = re.compile(r"(?:^|/)(?:safe|sec)\d*(?:/|$)", re.I)
NAME_VUL = re.compile(r"vul", re.I)
NAME_SAFE = re.compile(r"(?:safe|sec)(?:\d|$)", re.I)

# ---------------- 真值存疑样本 ----------------
# 靶场自己标反了的样本。**不静默剔除**（静默剔除不利样本，和静默迎合错误真值
# 一样是让数字骗人），而是单列打印、从正确率分母里扣除，并把理由写在这里。
#
# XMLDecoderVul.safe 的构造是：
#     public void safe() { ... new ObjectInputStream(bis).readUnshared(); }
# 而同一个作者的 Deserialization.readUnshared 是：
#     @ApiOperation("vul：readUnshared反序列化")
#     public String readUnshared(String base64) { ... in.readUnshared(); }
# 同一个 API，一处标 vul、一处标 safe。readUnshared 只影响对象引用共享，
# 不做任何类型过滤，安全性质与 readObject 完全相同（CWE-502 同样适用），
# 两个标注不可能同时成立。规则判 True 与"vul"那一处一致，故视为真值存疑。
# 清单已集中到 `benchmarks/disputed_truth.py`（结构化：含行号级源码证据、
# 分歧类型、给外部的说明），这里只取 {unit: 理由} 兼容旧调用点。
# 想增删争议样本请改登记簿，不要在靶场脚本里加本地字典 —— 那样三份脚本
# 会各说各话，也没法导出成给维护者看的报告。
from benchmarks.disputed_truth import for_target as _for_target   # noqa: E402
DISPUTED_TRUTH = _for_target("Hello-Java-Sec")


def route_of(unit) -> str:
    for a in unit.decorators_or_modifiers or []:
        m = re.search(r'"([^"]*)"', a)
        if m:
            return m.group(1)
    return ""


def apiop_of(unit) -> str:
    """取方法上方的 `@ApiOperation(value = "...")`。

    不能从 `unit.decorators_or_modifiers` 里取 —— 切片器只保留**路由**注解
    （@GetMapping 之类），其余注解在构造 CodeUnit 时就被丢掉了。所以回读源文件。

    两个坑（都踩过）：
    1. `start_line` 指向**第一个注解行**，不是 `public` 声明行。用
       `lines[:start-1]` 做窗口会差一位，读到上一个方法的注解 —— 表现为
       一堆"路由写 /safe、注解写 vul"的假冲突。
    2. 不能固定回读 N 行：方法之间只隔空行时，窗口会跨过上一个方法。必须
       在遇到 `}`（上一个成员结束）或另一个成员声明时停下。
    """
    try:
        lines = Path(unit.file_path).read_text(
            encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    j = min(unit.start_line - 1, len(lines) - 1)
    for _ in range(16):
        if j < 0:
            break
        s = lines[j].strip()
        if s.startswith("@ApiOperation"):
            # 允许注解参数跨行：往下拼到括号闭合为止
            joined = lines[j]
            k = j
            while ")" not in joined and k + 1 < len(lines) and k - j < 3:
                k += 1
                joined += " " + lines[k].strip()
            m = APIOP_RE.search(joined)
            return m.group(1) if m else ""
        # 走到上一个成员就停，不许越界
        if s in ("}", "};") or re.match(r"(public|private|protected)\s", s) \
                or s.startswith("/*") or s.startswith("*"):
            break
        j -= 1
    return ""


async def _gather(fn, items):
    """并发跑 fn，异常就地转成 error 记录，不让一条失败拖垮整批。"""
    return await asyncio.gather(*(fn(x) for x in items))


def _truth(text: str) -> bool | None:
    if not text:
        return None
    if APIOP_VUL.search(text):
        return True
    if re.match(r"^\s*(?:safe|sec)", text, re.I):
        return False
    return None


def classify(unit) -> tuple[str, bool | None, str]:
    """返回 (类目, 真值或 None, 真值来源)。"""
    cls, meth = base_unit_name(unit.unit_name).split(".", 1)
    cat = CLASS_TO_CATEGORY.get(cls)
    if not cat:
        return "", None, ""

    route = route_of(unit)
    api = apiop_of(unit)

    from_api = _truth(api)
    from_route = None
    if ROUTE_VUL.search(route):
        from_route = True
    elif ROUTE_SAFE.search(route):
        from_route = False
    else:
        if NAME_VUL.search(meth):
            from_route = True
        elif NAME_SAFE.search(meth):
            from_route = False

    if from_api is not None and from_route is not None:
        return cat, from_api, "apiop" if from_api == from_route else "conflict"
    if from_api is not None:
        return cat, from_api, "apiop"
    if from_route is not None:
        return cat, from_route, "route"
    return cat, None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则，不调模型")
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "hellojavasec.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    print(f"靶场：{repo}")
    units = JavaSlicer(repo).extract_entry_units()
    print(f"[1/3] 切出入口 {len(units)} 个")

    rows, unknown = [], []
    for u in units:
        cat, truth, src = classify(u)
        if not cat:
            continue
        if truth is None:
            unknown.append((u, cat))
            continue
        rows.append({"unit": u, "category": cat, "real_vuln": truth, "src": src})

    src_stat = Counter(r["src"] for r in rows)
    print(f"[2/3] 有真值 {len(rows)} 条，无法判定 {len(unknown)} 条已排除")
    print(f"      真值来源：{dict(src_stat)}   （conflict=两处标注互相矛盾）")
    if src_stat.get("conflict"):
        print("      ! 冲突样本按 @ApiOperation 计入，下列为清单：")
        for r in rows:
            if r["src"] == "conflict":
                print(f"        {r['unit'].unit_name:34} route={route_of(r['unit']):26} "
                      f"apiop={apiop_of(r['unit'])[:30]}")
    by_cat = Counter(r["category"] for r in rows)
    print(f"      类目分布：{dict(sorted(by_cat.items()))}")

    print("[3/3] 规则零改动迁移（不修改任何正则）...")
    rule_dec, rule_none = [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        (rule_dec if rv is not None else rule_none).append((r, rv))

    print()
    print("=" * 72)
    print("零改动迁移结果")
    print("=" * 72)
    print(f"有人工真值样本        ：{len(rows)}")
    print(f"规则直接给出结论      ：{len(rule_dec)}  "
          f"（覆盖率 {len(rule_dec) / max(len(rows), 1) * 100:.1f}%）")
    print(f"规则返回 None（交模型）：{len(rule_none)}  "
          f"（退回率 {len(rule_none) / max(len(rows), 1) * 100:.1f}%）")

    if rule_dec:
        # 真值存疑的样本单列，不进正确率分母 —— 否则一条标反的真值会永久
        # 把规则正确率钉在 97%，让人误以为规则有缺陷。
        judged = [(r, rv) for r, rv in rule_dec
                  if r["unit"].unit_name not in DISPUTED_TRUTH]
        disputed = [(r, rv) for r, rv in rule_dec
                    if r["unit"].unit_name in DISPUTED_TRUTH]
        right = sum(1 for r, rv in judged if rv == r["real_vuln"])
        print(f"规则判定正确          ：{right}/{len(judged)} = "
              f"{right / max(len(judged), 1) * 100:.1f}%")
        if disputed:
            print(f"\n· 真值存疑（{len(disputed)} 条，不计入正确率）：")
            for r, rv in disputed:
                print(f"  {r['unit'].unit_name:26} {r['category']:11} "
                      f"标注={r['real_vuln']!s:5} 规则={rv!s:5}")
                print(f"    理由：{DISPUTED_TRUTH[r['unit'].unit_name]}")
        wrong = [(r, rv) for r, rv in judged if rv != r["real_vuln"]]
        if wrong:
            print("\n! 规则判错的样本（这部分必须为 0，否则是跨项目误报）：")
            for r, rv in wrong:
                print(f"  {r['unit'].unit_name:26} {r['category']:11} "
                      f"真值={r['real_vuln']!s:5} 规则={rv!s:5} route={route_of(r['unit'])}")

    per_cat = defaultdict(lambda: [0, 0, 0])   # 判定数, 正确数, 总数
    for r in rows:
        per_cat[r["category"]][2] += 1
    for r, rv in judged:
        per_cat[r["category"]][0] += 1
        per_cat[r["category"]][1] += int(rv == r["real_vuln"])
    print("\n逐类目（规则）：")
    print(f"  {'类目':<12}{'n':>4}{'规则判定':>10}{'正确':>8}{'退回率':>10}")
    for c, (d, ok, n) in sorted(per_cat.items()):
        print(f"  {c:<12}{n:>4}{d:>10}{ok:>8}{(n - d) / n * 100:>9.0f}%")

    if rule_none:
        print("\n退回模型的样本：")
        for r, _ in rule_none:
            print(f"  {r['unit'].unit_name:26} {r['category']:11} "
                  f"真值={r['real_vuln']!s:5} route={route_of(r['unit'])[:34]}")

    # ---------------- 模型侧：只跑规则退回的那批 ----------------
    model_rows = []
    if not args.offline and rule_none:
        from cli import load_dotenv
        load_dotenv(ROOT / ".env")
        from core.agents.router import OpenAICompatClient, TwoTierRouter
        from core.agents.scenario_matcher import ScenarioMatcher

        print(f"\n模型侧：{args.model} 判定 {len(rule_none)} 条退回样本"
              f"（带 evidence_line，并发 {args.concurrency}）...", flush=True)
        router = TwoTierRouter(tier1=OpenAICompatClient(model=args.model, timeout=180))
        matcher = ScenarioMatcher(router=router, max_concurrency=args.concurrency,
                                  code_language="java_web")
        sem = asyncio.Semaphore(args.concurrency)

        async def judge(r):
            async with sem:
                t0 = time.time()
                try:
                    hs = await matcher.audit_unit_for(r["unit"], [r["category"]], "java_web")
                except Exception as e:
                    return {**{k: r[k] for k in ("category", "real_vuln")},
                            "unit": r["unit"].unit_name, "flagged": None,
                            "stage": "error", "detail": str(e)[:160],
                            "elapsed_s": round(time.time() - t0, 1)}
                if not hs or "LLM 调用失败" in (hs[0].reasoning_summary or ""):
                    return {"unit": r["unit"].unit_name, "category": r["category"],
                            "real_vuln": r["real_vuln"], "flagged": None,
                            "stage": "error", "detail": "调用失败",
                            "elapsed_s": round(time.time() - t0, 1)}
                h = hs[0]
                flagged = bool(h.property_missing)
                if not h.scenario_hit:
                    stage = "no_sink"
                elif flagged:
                    stage = "missing_property"
                else:
                    stage = "protected"
                return {"unit": r["unit"].unit_name, "category": r["category"],
                        "real_vuln": r["real_vuln"], "flagged": flagged,
                        "stage": stage, "detail": (h.reasoning_summary or "")[:200],
                        "elapsed_s": round(time.time() - t0, 1)}

        model_rows = asyncio.run(_gather(judge, [r for r, _ in rule_none]))
        ok = [m for m in model_rows if m["flagged"] is not None]
        tp = sum(1 for m in ok if m["flagged"] and m["real_vuln"])
        fn = sum(1 for m in ok if not m["flagged"] and m["real_vuln"])
        fp = sum(1 for m in ok if m["flagged"] and not m["real_vuln"])
        tn = sum(1 for m in ok if not m["flagged"] and not m["real_vuln"])
        err = len(model_rows) - len(ok)
        print(f"\n模型侧结果（{len(ok)} 条有效，{err} 条调用失败已剔除，"
              f"不计为'无漏洞'）：")
        print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
        if tp + fn:
            print(f"  TPR = {tp}/{tp + fn} = {tp / (tp + fn) * 100:.1f}%")
        if fp + tn:
            print(f"  FPR = {fp}/{fp + tn} = {fp / (fp + tn) * 100:.1f}%")
        for m in model_rows:
            if m["flagged"] is None:
                continue
            mark = "OK " if m["flagged"] == m["real_vuln"] else "ERR"
            print(f"  {mark} {m['unit']:26} {m['category']:11} "
                  f"真值={m['real_vuln']!s:5} 模型={m['flagged']!s:5} {m['stage']}")

    result = {
        "target": str(repo),
        "units_total": len(units),
        "with_truth": len(rows),
        "unknown": len(unknown),
        "truth_src": dict(src_stat),
        "rule_decided": len(rule_dec),
        "rule_correct": sum(1 for r, rv in judged if rv == r["real_vuln"]),
        "rule_none": len(rule_none),
        "disputed_truth": [{"unit": r["unit"].unit_name, "category": r["category"],
                            "labeled": r["real_vuln"], "rule": rv,
                            "why": DISPUTED_TRUTH[r["unit"].unit_name]}
                           for r, rv in disputed],
        "per_category": {c: {"n": n, "decided": d, "correct": ok}
                         for c, (d, ok, n) in per_cat.items()},
        "rule_wrong": [{"unit": r["unit"].unit_name, "category": r["category"],
                        "real_vuln": r["real_vuln"], "rule": rv}
                       for r, rv in rule_dec if rv != r["real_vuln"]],
        "fallback": [{"unit": r["unit"].unit_name, "category": r["category"],
                      "real_vuln": r["real_vuln"], "route": route_of(r["unit"])}
                     for r, _ in rule_none],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")


if __name__ == "__main__":
    main()
