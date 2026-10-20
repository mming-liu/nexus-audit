"""JavaSecLab 零改动迁移（第三个异源靶场，目的：把 FPR 分母撑起来）。

## 为什么需要这第三个靶场

前两个靶场的 safe 样本加起来只有 11 条（java-sec-code 1 + Hello-Java-Sec 10），
FPR 的分母小到这个程度，任何结论都站不住 —— 上上轮吃过一次亏：
"longcat 57% vs beam-free 83%" 看着差 26 个百分点，算 Wilson 区间
[5%,48%] 与 [25%,84%]，大幅重叠，差别统计上不成立。

`whgojp/JavaSecLab` 的情况：227 个入口，路由标注 `/vul` 69 条、`/safe` 40 条，
**109 条真值，其中 40 条安全样本** —— 分母是前两个靶场加起来的 3.6 倍。
作者（whgojp）与 JoyChou93 / Threekiii 都不同，命名、工具类、框架版本全换，
是合格的第三个异源。

## 真值来源

这个靶场标注得很规整，只有一处：
  路由命名 `/vul` `/vul1` `/vul2` `/safe` `/safeGroovy` `/safe2`
没有 @ApiOperation 之类的第二标注，因此**不存在冲突样本**，也不需要
交叉确认逻辑 —— 好处是干净，坏处是没有第二来源可以校验，
所以脚本会打印全部被判定的 (类名, 路由, 真值) 三元组供人工抽查。

判不出的（`/internal/metadata`、`/redirect`、`/href`、`/jsp` 这种）一律排除。

## 类目映射

按「模块路径」+「类名」共同决定。只映射我们有确定性规则的类目，
其余（csrf / logic / loginconfront / mshell / infoleak / funny / test /
springboot / components）整块排除 —— 那些类目我们没有判据，
纳入只会污染覆盖率分母，不产生任何信息。

## 与 Hello-Java-Sec 脚本的关系

**不 import 任何规则常量，也不改 rule_detectors**，与上一个迁移脚本同一条铁律。
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

from benchmarks.disputed_truth import for_target as _for_target  # noqa: E402

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "JavaSecLab-main"

# 模块路径前缀 -> 类目（模块内所有 Controller 都归这一类）
MODULE_TO_CATEGORY = {
    "sqli": "sqli",
    "xss": "xss",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "spel": "spel",
    "ssti": "spel",              # 模板注入与脚本执行同属"表达式/代码执行"
    "rce/code": "spel",          # Groovy/JS 引擎执行
    "rce/command": "cmdi",       # 系统命令执行
    "file": "pathtraver",        # download / read / delete / upload 都是路径类
    "infoleak/dirtraversal": "pathtraver",
    "deserialize": "deserial",
    "crossorigin": "cors",
    "other/urlredirect": "redir",
    # 越权模块。此前**没有**这一项，于是 227 个入口里 idor 的 6 个整块被
    # 当成"无类目"排除 —— 这也是"with_truth 只有 59"的一部分原因。
    "logic/idor": "authz",
}

# 少数漏洞路由的名字里没有 `vul` 字样，真值取自靶场自己的页面标注。
#
# `logic/idor`：horizontal.html 第 161 行
#   common.formListenFun("vul-horizontal-button", "", "/logic/idor/horizontal/getUserInfo", ...)
# 与页面正文"越权入口"/"安全场景：验证Session"的对照 —— 前一个按钮是越权入口，
# 后一个（`/safe`）是安全场景。所以 `getUserInfo` 为 vul，`safe` 走 ROUTE_SAFE。
MODULE_VUL_ROUTES = {
    "logic/idor": {"getUserInfo"},
}

# 类名级覆盖（模块路径判不出时兜底）
CLASS_TO_CATEGORY = {
    "DirTraversalController": "pathtraver",
    "UrlRedirectController": "redir",
    "SPELController": "spel",
    "SSTIController": "spel",
    "CodeController": "spel",
    "CommandController": "cmdi",
    "XXEController": "xxe",
    "SsrfController": "ssrf",
    "CrossOriginController": "cors",
    "ReadObjectController": "deserial",
    "SnakeYamlController": "deserial",
    "XMLDecoderController": "deserial",
    "JdbcController": "sqli",
    "MyBatisController": "sqli",
    "HibernateController": "sqli",
    "JPAController": "sqli",
    "ReflectController": "xss",
    "StoreController": "xss",
    "DomController": "xss",
    "JsonpController": "xss",
    "OtherController": "xss",
    "UEditorController": "xss",
    "DownloadController": "pathtraver",
    "ReadController": "pathtraver",
    "DeleteController": "pathtraver",
    "UploadController": "pathtraver",
}

# 路由标记。/vul、/vul1、/vulGroovy、/vul2Upload 都算 vul；
# /safe、/safe2、/safeGroovy 都算 safe。注意必须整段匹配，
# 否则 `/vul2OtherTemplate` 里的 `vul` 会连带把 `safe` 也吞进去。
ROUTE_VUL = re.compile(r"(?:^|/)(?:vul|vulnerable)\w*$", re.I)
ROUTE_SAFE = re.compile(r"(?:^|/)(?:safe|sec)\w*$", re.I)

# ---------------- 真值存疑样本 ----------------
# 靶场自己标反（或至少标得不严）的样本。**不静默剔除** —— 静默剔除不利样本
# 与静默迎合错误真值一样是让数字骗人。单列打印、从正确率分母里扣除、写清理由。
#
# ReflectController.safe2：
#     response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'");
#     return payload;                      // 裸回显，没有做任何输出编码
#
# 作者在这条方法的 @ApiOperation notes 里**自己写着**：
#     "CSP 是由浏览器实施的额外防护层，可降低恶意脚本加载和执行风险，
#      但不能替代输出编码与安全模板/DOM用法"
# 同一文件里 safe1 的注释也写着"前端过滤后传递过来 后端未进行处理(同样存在安全问题)"。
#
# 也就是说，`return payload;` 是裸反射，CSP 只是纵深防御、不是修复。
# 靶场把它归入 safe 是想演示"CSP 的缓解效果"，而我们的类目口径是
# "输入是否原样进入响应体" —— 两个口径不同，不是规则判错。
# 按 vuln_categories 里 xss 的定义，规则判 True 与口径一致。
# 清单集中在 `benchmarks/disputed_truth.py`（结构化证据 + 分歧类型 + 导出）。
DISPUTED_TRUTH = _for_target("JavaSecLab")


def route_of(unit) -> str:
    for a in unit.decorators_or_modifiers or []:
        m = re.search(r'"([^"]*)"', a)
        if m:
            return m.group(1)
    return ""


def module_path_of(unit) -> str:
    """取 `modules/` 之后、文件名之前的**完整**目录串。

    不能写成 `r"/modules/(.+?)/"`（非贪婪只取第一段）：那样
    `modules/logic/idor/controller/X.java` 只会得到 `logic`，
    于是 `logic/idor` 这个键永远匹配不上，整个越权模块被静默排除。
    症状与切片缺证据同型 —— 不报错，只是数字里少了一块。
    """
    p = str(unit.file_path).replace("\\", "/")
    m = re.search(r"/modules/(.+)/[^/]+\.java$", p)
    return m.group(1) if m else ""


def classify(unit) -> tuple[str, bool | None, str]:
    """返回 (类目, 真值或 None, 真值来源)。"""
    cls = unit.unit_name.split(".", 1)[0]

    cat = ""
    mp = module_path_of(unit)
    # 先按模块路径判（更粗、更稳），再按类名兜底
    for key in sorted(MODULE_TO_CATEGORY, key=len, reverse=True):
        if mp == key or mp.startswith(key + "/"):
            cat = MODULE_TO_CATEGORY[key]
            break
    if not cat:
        cat = CLASS_TO_CATEGORY.get(cls, "")
    if not cat:
        return "", None, ""

    route = route_of(unit)
    if ROUTE_VUL.search(route):
        return cat, True, "route"
    if ROUTE_SAFE.search(route):
        return cat, False, "route"
    # 路由名里没有 vul/safe 时，退到靶场页面标注的漏洞入口清单
    tail = route.rsplit("/", 1)[-1]
    for mod, names in MODULE_VUL_ROUTES.items():
        if (mp == mod or mp.startswith(mod + "/")) and tail in names:
            return cat, True, "page"
    return cat, None, ""


async def _gather(fn, items):
    return await asyncio.gather(*(fn(x) for x in items))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则，不调模型")
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组供抽查")
    ap.add_argument("--output", default=str(ROOT / "benchmarks" / "results" / "javaseclab.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    print(f"靶场：{repo}")
    units = JavaSlicer(repo).extract_entry_units()
    print(f"[1/3] 切出入口 {len(units)} 个")

    rows, unknown, no_cat = [], [], 0
    for u in units:
        cat, truth, src = classify(u)
        if not cat:
            no_cat += 1
            continue
        if truth is None:
            unknown.append((u, cat))
            continue
        rows.append({"unit": u, "category": cat, "real_vuln": truth, "src": src})

    print(f"[2/3] 有真值 {len(rows)} 条（vul {sum(1 for r in rows if r['real_vuln'])} / "
          f"safe {sum(1 for r in rows if not r['real_vuln'])}），"
          f"类目内无标注 {len(unknown)} 条，无对应类目 {no_cat} 条，均已排除")
    by_cat = Counter(r["category"] for r in rows)
    print(f"      类目分布：{dict(sorted(by_cat.items()))}")

    if args.list:
        print("      ---- 判定三元组（供人工抽查真值）----")
        for r in sorted(rows, key=lambda x: x["unit"].unit_name):
            print(f"      {r['unit'].unit_name:38} {r['category']:11} "
                  f"{'vul ' if r['real_vuln'] else 'safe'} route={route_of(r['unit'])}")

    print("[3/3] 规则零改动迁移（不修改任何正则）...")
    rule_dec, rule_none = [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        (rule_dec if rv is not None else rule_none).append((r, rv))

    print()
    print("=" * 72)
    print("JavaSecLab 零改动迁移结果")
    print("=" * 72)
    n = len(rows)
    print(f"有人工真值样本        ：{n}")
    print(f"规则直接给出结论      ：{len(rule_dec)}  "
          f"（覆盖率 {len(rule_dec) / max(n, 1) * 100:.1f}%）")
    print(f"规则返回 None（交模型）：{len(rule_none)}  "
          f"（退回率 {len(rule_none) / max(n, 1) * 100:.1f}%）")

    judged = [(r, rv) for r, rv in rule_dec
              if r["unit"].unit_name not in DISPUTED_TRUTH]
    disputed = [(r, rv) for r, rv in rule_dec
                if r["unit"].unit_name in DISPUTED_TRUTH]
    right = sum(1 for r, rv in judged if rv == r["real_vuln"])
    if rule_dec:
        print(f"规则判定正确          ：{right}/{len(judged)} = "
              f"{right / max(len(judged), 1) * 100:.1f}%")
        if disputed:
            print(f"\n· 真值存疑（{len(disputed)} 条，不计入正确率）：")
            for r, rv in disputed:
                print(f"  {r['unit'].unit_name:38} {r['category']:11} "
                      f"标注={r['real_vuln']!s:5} 规则={rv!s:5}")
                print(f"    理由：{DISPUTED_TRUTH[r['unit'].unit_name]}")
        wrong = [(r, rv) for r, rv in judged if rv != r["real_vuln"]]
        if wrong:
            print("\n! 规则判错的样本（这一项必须为 0，否则是跨项目误报）：")
            for r, rv in wrong:
                print(f"  {r['unit'].unit_name:38} {r['category']:11} "
                      f"真值={r['real_vuln']!s:5} 规则={rv!s:5} route={route_of(r['unit'])}")
        # 分开报：vul 判对 / safe 判对。合成一个正确率会把
        # "不敢判 safe"（漏报）与"敢判 safe 但判错"（误报）混为一谈。
        safe_judged = [(r, rv) for r, rv in judged if not r["real_vuln"]]
        safe_right = sum(1 for r, rv in safe_judged if rv is False)
        vul_judged = [(r, rv) for r, rv in judged if r["real_vuln"]]
        vul_right = sum(1 for r, rv in vul_judged if rv is True)
        print(f"  ├ 其中 safe 样本 {len(safe_judged)} 条，判对 {safe_right} "
              f"（FPR = {(len(safe_judged) - safe_right) / max(len(safe_judged), 1) * 100:.1f}%）")
        print(f"  └ 其中 vul  样本 {len(vul_judged)} 条，判对 {vul_right} "
              f"（漏报率 = {(len(vul_judged) - vul_right) / max(len(vul_judged), 1) * 100:.1f}%）")

    per_cat = defaultdict(lambda: [0, 0, 0, 0])   # 判定数, 正确数, 总数, safe判定数
    for r in rows:
        per_cat[r["category"]][2] += 1
    for r, rv in judged:
        per_cat[r["category"]][0] += 1
        per_cat[r["category"]][1] += int(rv == r["real_vuln"])
        if not r["real_vuln"]:
            per_cat[r["category"]][3] += 1
    print("\n逐类目（规则）：")
    print(f"  {'类目':<12}{'n':>4}{'safe_n':>8}{'规则判定':>10}{'正确':>8}{'退回率':>10}")
    for c, (d, ok, tot, sn) in sorted(per_cat.items()):
        print(f"  {c:<12}{tot:>4}{sn:>8}{d:>10}{ok:>8}{(tot - d) / tot * 100:>9.0f}%")

    if rule_none:
        print("\n退回模型的样本：")
        for r, _ in rule_none:
            print(f"  {r['unit'].unit_name:38} {r['category']:11} "
                  f"真值={r['real_vuln']!s:5} route={route_of(r['unit'])[:30]}")

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
                    return {"unit": r["unit"].unit_name, "category": r["category"],
                            "real_vuln": r["real_vuln"], "flagged": None,
                            "stage": "error", "detail": str(e)[:160],
                            "elapsed_s": round(time.time() - t0, 1)}
                if not hs or "LLM 调用失败" in (hs[0].reasoning_summary or ""):
                    return {"unit": r["unit"].unit_name, "category": r["category"],
                            "real_vuln": r["real_vuln"], "flagged": None,
                            "stage": "error", "detail": "调用失败",
                            "elapsed_s": round(time.time() - t0, 1)}
                h = hs[0]
                flagged = bool(h.property_missing)
                stage = ("missing_property" if flagged else
                         ("no_sink" if not h.scenario_hit else "protected"))
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
        print(f"  有效 {len(ok)} 条，失败 {err} 条（失败样本剔除，不计为无漏洞）")
        if ok:
            print(f"  TPR = {tp}/{tp + fn} = {tp / max(tp + fn, 1) * 100:.1f}%")
            print(f"  FPR = {fp}/{fp + tn} = {fp / max(fp + tn, 1) * 100:.1f}%"
                  f"   （分母 {fp + tn} 条 safe）")

    out = {
        "target": str(repo),
        "total_units": len(units),
        "with_truth": n,
        "rule_covered": len(rule_dec),
        "rule_coverage": round(len(rule_dec) / max(n, 1), 4),
        "rule_correct": right,
        "rule_accuracy": round(right / max(len(judged), 1), 4),
        "per_category": {c: {"n": v[2], "safe_n": v[3], "decided": v[0], "correct": v[1]}
                         for c, v in per_cat.items()},
        "fallback": [{"unit": r["unit"].unit_name, "category": r["category"],
                      "real_vuln": r["real_vuln"], "route": route_of(r["unit"])}
                     for r, _ in rule_none],
        "model": model_rows,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")


if __name__ == "__main__":
    main()
