"""java-sec-code 真实项目评测（Spring Boot，非模板化靶场）。

与 OWASP Benchmark 的区别，也是本次评测的意义所在：
  - Benchmark 每个用例都是「取参数 → 拼接 → sink」的固定模板，路径极其规整
  - java-sec-code 是真实业务写法：Service 分层、MyBatis Mapper、工具类封装、
    注解传参、跨文件调用链，误报率通常远高于 Benchmark

真值（ground truth）怎么来的 —— 这是本脚本最需要交代清楚的部分：

  该项目是漏洞教学靶场，作者在**两个地方**标注了每个方法的性质：
    1. 路由命名：/vuln, /vuln01, /vuln/xxx -> 有漏洞；/sec, /sec01 -> 安全写法
    2. 方法紧邻的 Javadoc：「Vuln Code.」「Vuln Code.」 「safe Code.」
  第 2 条覆盖率更高：XSS.java 的路由是 /xss/reflect、/xss/safe，
  没有 vuln 字样，但注释明确写了「Vuln Code.」/「safe Code.」。

  两处都判不出的方法（如 /rce/runtime/exec、/ssrf/openStream、
  /cors/vuln/crossOrigin 这种只有方法体没有标注的），一律标 unknown 并
  **排除出计算**，不猜、不硬凑 —— 宁可样本少，也不污染指标。

类别映射：按控制器类名推断（SQLI->sqli, Rce->cmdi, XSS->xss, SSRF->ssrf ...）。
一个控制器只映射到一个类目，同一类目下再用方法名细分（如 Rce 里的
yarm 归到 deserial、jscmd 归到 spel），避免把 17 个 XXE 用例全挤进 xss。

结果按 OWASP 口径给出 Score = TPR - FPR。因为样本量远小于 Benchmark
（435 条），结论只作为「真实代码上的方向性验证」，不与 Benchmark 分数横向比较。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.router import OpenAICompatClient, TwoTierRouter   # noqa: E402
from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.agents.scenario_matcher import ScenarioMatcher             # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "java-sec-code"

# 控制器类 -> 默认漏洞类目
CLASS_TO_CATEGORY = {
    "SQLI": "sqli",
    "Rce": "cmdi",
    "CommandInject": "cmdi",
    "PathTraversal": "pathtraver",
    "XSS": "xss",
    "SSRF": "ssrf",
    "XXE": "xxe",
    "SpEL": "spel",
    "Deserialize": "deserial",
    "URLRedirect": "redir",
    "Cors": "cors",
}

# 同一控制器内按方法名细分：Rce 里的 yarm 是 YAML 反序列化，jscmd 是脚本引擎执行
METHOD_CATEGORY_OVERRIDE = {
    ("Rce", "yarm"): "deserial",
    ("Rce", "secYarm"): "deserial",
    ("Rce", "jsEngine"): "spel",
    ("Rce", "groovyshell"): "spel",
    ("Deserialize", "Jackson"): "spel",
}

# 无对应类目 / 无明确标注，整体排除
SKIP_CLASSES = {
    "Jsonp", "Cookies", "FileUpload", "Jwt", "CSRF", "CsrfToken", "Shiro",
    "Fastjson", "XStreamRce", "Log4j", "QLExpress", "SSTI", "IPForge",
    "ClassDataLoader", "WebSockets", "JNDI", "URLWhiteList", "GetRequestURI",
    "Index", "Login", "Jdbc", "CRLFInjection", "SpringBootActuator",
    "ooxmlXXE", "xlsxStreamerXXE", "othervulns",
}

# 路由里的 vuln/sec 标记（作者的第一处标注）
VULN_RE = re.compile(r"(?:^|/)vuln\d*(?:/|$)|(?:^|/)vuln_|_vul|/vul(?:/|$)", re.I)
SEC_RE = re.compile(r"(?:^|/)sec\d*(?:/|$)|(?:^|/)seccode|_sec|/safe(?:/|$)", re.I)

# 方法紧邻注释里的标注（作者的第二处标注）
DOC_VULN_RE = re.compile(r"\b(vuln(?:erable)?|unsafe|insecure)\s*(code|Code)?\.?", re.I)
DOC_SEC_RE = re.compile(r"\b(safe|security|secure|fixed)\s*(code|Code)?\.?", re.I)
DOC_STRONG_VULN = re.compile(r"^\s*\*?\s*(vuln|Vuln|VULN)\s*(code)?\s*\.?\s*$", re.M)
DOC_STRONG_SEC = re.compile(r"^\s*\*?\s*(safe|Safe|SAFE)\s*(code)?\s*\.?\s*$", re.M)


def _route_of(unit) -> str:
    route = unit.decorators_or_modifiers[0] if unit.decorators_or_modifiers else ""
    m = re.search(r'"([^"]*)"', route)
    if m:
        return m.group(1)
    return route


def _doc_block_of(unit) -> str:
    """取方法声明之前的 Javadoc / 行注释块。

    切片的第一行就是注解，注释块不在 source_code 里，必须回读源文件。
    """
    try:
        lines = Path(unit.file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    i = min(unit.start_line - 1, len(lines))
    out: list[str] = []
    j = i - 1
    while j >= 0 and len(out) < 18:
        s = lines[j].strip()
        if s.startswith("@") or s.startswith("public") or s.startswith("}"):
            break
        out.append(lines[j])
        if s.startswith("/**") or s.startswith("/*"):
            break
        j -= 1
    return "\n".join(reversed(out))


def _truth_from_text(text: str) -> bool | None:
    """在注释块里找作者标注。

    注意 "Vul Code." 是作者对 "Vuln Code." 的简写，必须一起认；
    但只认「注释行本身就是在给这个方法定性」的形态：
      * Vuln Code. / Vul Code. / safe Code. / security code.
    而 "Fix method: ..." 这类描述修复手段的句子不算标注。
    """
    if not text:
        return None
    v = bool(re.search(r"^\s*\*?\s*(vuln|vul|unsafe|insecure)\s+code\b", text, re.I | re.M))
    s = bool(re.search(r"^\s*\*?\s*(safe|security|secure|fixed)\s+code\b", text, re.I | re.M))
    if v and not s:
        return True
    if s and not v:
        return False
    return None


def classify(unit) -> tuple[str, bool | None, str]:
    """返回 (类别, 是否有漏洞或 None, 真值来源)。"""
    cls, meth = unit.unit_name.split(".", 1)
    if cls in SKIP_CLASSES:
        return "", None, ""
    cat = METHOD_CATEGORY_OVERRIDE.get((cls, meth)) or CLASS_TO_CATEGORY.get(cls)
    if not cat:
        return "", None, ""

    # 1) 路由命名（作者第一处标注）
    route = _route_of(unit)
    if VULN_RE.search(route):
        return cat, True, "route"
    if SEC_RE.search(route):
        return cat, False, "route"

    # 2) 紧邻 Javadoc（作者第二处标注）
    t = _truth_from_text(_doc_block_of(unit))
    if t is not None:
        return cat, t, "doc"

    return cat, None, ""


async def run(args):
    target = Path(args.target).resolve()
    print(f"[1/4] 切片 {target.name} ...", flush=True)
    t0 = time.time()
    units = JavaSlicer(target).extract_entry_units()
    print(f"      {len(units)} 个 Spring/Servlet 入口，耗时 {time.time() - t0:.1f}s", flush=True)

    cases, unknown = [], []
    for u in units:
        cat, truth, src = classify(u)
        if not cat:
            continue
        if truth is None:
            unknown.append(u)
            continue
        cases.append({"unit": u, "category": cat, "real_vuln": truth, "src": src})

    from collections import Counter
    per_cat = Counter(c["category"] for c in cases)
    src_stat = Counter(c["src"] for c in cases)
    print(f"[2/4] 可判定样本 {len(cases)} 条"
          f"（真漏洞 {sum(c['real_vuln'] for c in cases)}，"
          f"安全 {sum(not c['real_vuln'] for c in cases)}）", flush=True)
    print(f"      按类目：{dict(sorted(per_cat.items()))}", flush=True)
    print(f"      真值来源：{dict(src_stat)}（route=路由命名，doc=方法注释）", flush=True)
    print(f"      命名与注释均无法判定 {len(unknown)} 条已排除", flush=True)

    if not args.offline:
        from cli import load_dotenv
        load_dotenv(ROOT / ".env")
    router = None if args.offline else TwoTierRouter(
        tier1=OpenAICompatClient(model=args.model, timeout=180))
    if args.offline:
        # 离线基线：不做静态判定（那属于 LLM 层的能力），只保留确定性规则，
        # 用来度量「规则前置」本身贡献了多少判定，以及链路是否还跑得通。
        # 不能用 ScenarioMatcher —— 它在调用失败时会返回 scenario_hit=False 的
        # 假设对象而不抛异常，会被当成"正常判定为无漏洞"，静默污染指标。
        matcher = None
    else:
        matcher = ScenarioMatcher(router=router, max_concurrency=args.concurrency,
                                  code_language="java_web",
                                  scenario_votes=args.votes, property_votes=args.votes)

    print(f"[3/4] 判定中（并发 {args.concurrency}，"
          + ("离线规则基线，不调用模型"
             if args.offline else f"模型 {args.model}，每问 {args.votes} 票") + "）...",
          flush=True)
    out_jsonl = Path(args.output).with_suffix(".jsonl")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    out_jsonl.write_text("", encoding="utf-8")
    lock = asyncio.Lock()
    done = 0

    async def one(c):
        nonlocal done
        u = c["unit"]
        t = time.time()
        rv = None if args.no_rules else rule_verdict(c["category"], u.source_code)
        if rv is None and matcher is None:
            # 离线且规则未覆盖：没有判定手段，标 not_judged，不算"调用失败"也不算漏报
            rec = {"unit": u.unit_name, "route": _route_of(u)[:60],
                   "category": c["category"], "real_vuln": c["real_vuln"],
                   "truth_src": c["src"], "flagged": None, "stage": "not_judged",
                   "detail": "规则未覆盖（离线模式）",
                   "elapsed_s": round(time.time() - t, 1)}
            async with lock:
                with out_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                done += 1
            return rec
        if rv is not None:
            flagged, stage, detail = rv, "rule", "deterministic"
        else:
            try:
                hs = await matcher.audit_unit_for(u, [c["category"]], "java_web")
                err = ""
            except Exception as e:
                hs, err = [], str(e)[:200]
            if err or any("LLM 调用失败" in h.reasoning_summary for h in hs):
                rec = {"unit": u.unit_name, "route": _route_of(u)[:60],
                       "category": c["category"], "real_vuln": c["real_vuln"],
                       "truth_src": c["src"],
                       "flagged": None, "stage": "error", "detail": err,
                       "elapsed_s": round(time.time() - t, 1)}
                async with lock:
                    with out_jsonl.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    done += 1
                return rec
            flagged = any(h.property_missing for h in hs)
            if not hs or not hs[0].scenario_hit:
                stage, detail = "no_sink", "sink not reachable"
            elif not flagged:
                stage, detail = "protected", hs[0].reasoning_summary
            else:
                stage, detail = "missing_property", hs[0].reasoning_summary
        rec = {"unit": u.unit_name, "route": _route_of(u)[:60],
               "category": c["category"], "real_vuln": c["real_vuln"],
               "truth_src": c["src"],
               "flagged": flagged, "stage": stage, "detail": detail,
               "elapsed_s": round(time.time() - t, 1)}
        async with lock:
            with out_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            done += 1
            if done % 10 == 0 or done == len(cases):
                print(f"      进度 {done}/{len(cases)}", flush=True)
        return rec

    recs = [r for r in await asyncio.gather(*(one(c) for c in cases)) if r]
    scored = [r for r in recs if r["flagged"] is not None]
    errors = sum(1 for r in recs if r["stage"] == "error")
    not_judged = sum(1 for r in recs if r["stage"] == "not_judged")
    if errors:
        print(f"      ⚠ 剔除调用失败 {errors} 条（不计入指标，"
              f"否则会把限流伪装成低误报率）", flush=True)
    if not_judged:
        print(f"      ⚠ 规则未覆盖 {not_judged} 条（离线模式无 LLM 兜底，不计入指标）",
              flush=True)

    report(scored, out_jsonl)


def _tally(rs):
    tp = sum(1 for r in rs if r["real_vuln"] and r["flagged"])
    fn = sum(1 for r in rs if r["real_vuln"] and not r["flagged"])
    fp = sum(1 for r in rs if not r["real_vuln"] and r["flagged"])
    tn = sum(1 for r in rs if not r["real_vuln"] and not r["flagged"])
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "n": len(rs),
            "tpr": tp / (tp + fn) if tp + fn else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def report(rows, jsonl):
    by = defaultdict(list)
    for r in rows:
        by[r["category"]].append(r)
    print("\n" + "=" * 74)
    print(f"{'类目':<12}{'n':>4}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}"
          f"{'TPR':>7}{'FPR':>7}{'规则':>6}")
    print("-" * 74)
    for cat, rs in sorted(by.items()):
        s = _tally(rs)
        nrule = sum(1 for r in rs if r["stage"] == "rule")
        print(f"{cat:<12}{s['n']:>4}{s['tp']:>4}{s['fn']:>4}{s['fp']:>4}{s['tn']:>4}"
              f"{s['tpr']:>7.2f}{s['fpr']:>7.2f}{nrule:>6}")
    o = _tally(rows)
    print("-" * 74)
    print(f"{'OVERALL':<12}{o['n']:>4}{o['tp']:>4}{o['fn']:>4}{o['fp']:>4}{o['tn']:>4}"
          f"{o['tpr']:>7.2f}{o['fpr']:>7.2f}")
    print(f"Score = TPR - FPR = {o['tpr'] - o['fpr']:.3f}")
    print("=" * 74)
    print("（「规则」列 = 由确定性规则直接给出结论的样本数，不经模型）")

    fps = [r for r in rows if not r["real_vuln"] and r["flagged"]]
    if fps:
        print(f"\n误报明细 {len(fps)} 条（作者标注为安全写法，引擎判成漏洞）：")
        for r in fps:
            print(f"  [{r['category']:<9}] {r['unit']:<32}{r['route'][:34]}")
    fns = [r for r in rows if r["real_vuln"] and not r["flagged"]]
    if fns:
        print(f"\n漏报明细 {len(fns)} 条（作者标注有漏洞，引擎未命中）：")
        for r in fns:
            print(f"  [{r['category']:<9}] {r['unit']:<32}{r['route'][:34]}"
                  f"  ({r['stage']})")
    print(f"\n明细已写入 {jsonl}")


def main():
    ap = argparse.ArgumentParser(description="java-sec-code 真实项目评测")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--output", default=str(ROOT / "benchmarks/results/javaseccode.jsonl"))
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-rules", action="store_true")
    ap.add_argument("--votes", type=int, default=1,
                    help="每个问题问几次取多数（默认 1；实测 3 票不降抖动只增成本，见 REAL_PROJECT_REPORT.md）")
    args = ap.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
