"""micro_service_seclab 零改动迁移（第四个异源靶场，目的：用真实多层仓库锁死四跳切片）。

## 为什么需要这第四个靶场

前三个靶场（OWASP / java-sec-code / Hello-Java-Sec / JavaSecLab）的漏洞几乎都在
**入口方法的同一个文件里** —— 入口体本身就是 sink。这让"跨文件调用链展开"这项
能力长期没有真实阻力：把 `depth` 从 1 调到 4，跑分一分不动，因为靶场里根本没有
四跳链。

`l4yn3/micro_service_seclab` 不一样。它是标准 Spring Boot 分层：
    Controller(IndexController) -> Logic(IndexLogic) -> Db(IndexDb) -> JdbcTemplate
以及两条独立的持久层通道：
    Mapper 接口 + XML(`${name}`)          /  Mapper 注解(`@Select(... '${name}')`)
    Spring Data JPA 派生查询 + `@Query`

`/sqlinjection/one` 的 sink 在 `IndexDb.getStudent()` 第 41 行 —— 距入口两跳。
若切片器只展开 1 跳，模型拿到的是 `return indexLogic.getStudent(username);`
这样一行，看不到任何 SQL，必然判"无 sink"。**这个靶场就是为了让这条链断在明处。**

## 真值来源（三档，都要写明白）

1. **源码注释自述**（最硬）：靶场作者在入口上方直接写了
   `// 这并不是一个注入，如果SAST扫描器将这个报为SQL注入漏洞，那么这是一个误报问题`
   （`/longin`、`/objectint`）。这是**作者声明的误报陷阱**，不是我们的推测。
2. **README 的漏洞种类表**：SQL 注入 11 种写法、RCE 2 种、SSRF 5 种、XXE 1 种、
   FastJson 1 种，逐项对应到方法。
3. **代码事实**：`longin` 的形参是 `List<Long>`、`objectint` 走 `getStudentById(Integer)`、
   `jpaone` 走 `JpaRepository` 派生查询 —— 这三条即使不读注释也能从类型上核对。

与 JavaSecLab 不同，**这个靶场没有 `/vul` `/safe` 路由命名**，所以真值只能显式
列表维护。好处是逼着把每条真值的依据写下来；坏处是加样本必须手工改表。
没有第二标注来源的地方，脚本会打印全部三元组供抽查。

## 类目口径

只映射我们**有确定性判据**的五个类目：sqli / cmdi / ssrf / xxe / deserial。
`MyBatsTest`、`MicroServiceSeclabApplication`、`data/*` 不是入口，天然不入分母。

## 与其它脚本的关系

**不 import 任何规则常量，也不改 rule_detectors**，与三个迁移脚本同一条铁律。
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
from core.models import base_unit_name                          # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "micro_service_seclab-main"

CLASS_TO_CATEGORY = {
    "IndexController": "sqli",
    "RceController": "cmdi",
    "SSRFController": "ssrf",
    "XXEController": "xxe",
    "FastJsonController": "deserial",
}

# ---------------- 真值表 ----------------
# 键：(类名, 路由)。路由取自 @RequestMapping/@PostMapping 的 value，
# 类级前缀拼在前面（`value = "one"` 少了前导 `/`，Spring 照样拼成 `/rce/one`）。
#
# 值：(类目, 真值, 依据)
#   依据 tag：
#     "comment"  —— 源码注释自述（作者明写是/不是漏洞）
#     "readme"   —— README 漏洞种类表
#     "type"     —— 从形参/返回类型可核对的事实
TRUTH: dict[tuple[str, str], tuple[str, bool, str]] = {
    # ---- SQL 注入：11 种写法 ----
    # String source：Controller -> Logic -> Db 两跳，Db 里字符串拼接进 jdbcTemplate.query
    ("IndexController", "/sqlinjection/one"): ("sqli", True, "readme"),
    # List<String> source：Joiner.on("','").join(name_list) 拼进 in (...)
    ("IndexController", "/sqlinjection/in"): ("sqli", True, "readme"),
    # List<Long>：**误报陷阱**。作者注释："这并不是一个注入，如果SAST扫描器将
    # 这个报为SQL注入漏洞，那么这是一个误报问题"。Long 元素承载不了引号，
    # 反序列化阶段非法值直接抛异常 —— 拼接形态与 /in 一模一样，但污点值不存在。
    ("IndexController", "/sqlinjection/longin"): ("sqli", False, "comment"),
    # Object source：user.getUsername() 是 String
    ("IndexController", "/sqlinjection/object"): ("sqli", True, "readme"),
    # Object + int 字段：**误报陷阱**，同 longin 的注释。
    # getStudentById(Integer id) 里 String.valueOf(id) 已把值域锁死在整数
    ("IndexController", "/sqlinjection/objectint"): ("sqli", False, "comment"),
    # Lombok @Data 生成 getter，字段 name 是 String
    ("IndexController", "/sqlinjection/object_lombok"): ("sqli", True, "readme"),
    # Optional<String>：username.get() 解包后仍是 String
    ("IndexController", "/sqlinjection/optinal_like"): ("sqli", True, "readme"),
    # MyBatis XML：IStudentMapper.xml 第 7 行 `username ='${name}'` —— 字符串替换
    ("IndexController", "/sqlinjection/myBatis"): ("sqli", True, "readme"),
    # MyBatis 注解：@Select("... username ='${name}'")
    ("IndexController", "/sqlinjection/myBatisWithAnnotations"): ("sqli", True, "readme"),
    # JPA 派生查询：findPersonByUsername 由方法名派生，Spring 生成参数化 SQL
    ("IndexController", "/sqlinjection/jpaone"): ("sqli", False, "comment"),
    # @Query("... nickname = '?1'")：占位符绑定（作者把 ?1 包进单引号是笔误，
    # 结果恒为空集，但无论如何不构成注入）
    ("IndexController", "/sqlinjection/jpaWithAnnotations"): ("sqli", False, "comment"),
    # ---- RCE ----
    ("RceController", "/rce/one"): ("cmdi", True, "readme"),
    ("RceController", "/rce/two"): ("cmdi", True, "readme"),
    # ---- SSRF：五种客户端 ----
    ("SSRFController", "/ssrf/one"): ("ssrf", True, "readme"),      # url.openConnection
    ("SSRFController", "/ssrf/two"): ("ssrf", True, "readme"),      # Request.Get (fluent-hc)
    ("SSRFController", "/ssrf/three"): ("ssrf", True, "readme"),    # OkHttpClient
    ("SSRFController", "/ssrf/four"): ("ssrf", True, "readme"),     # DefaultHttpClient
    ("SSRFController", "/ssrf/five"): ("ssrf", True, "readme"),     # url.openStream
    # ---- XXE ----
    # 注意 XXEController 的 @RestController(value = "/xxe") 写错了（value 是 bean name，
    # 不是路径前缀），实际路由只有 `/one`。不影响真值。
    ("XXEController", "/one"): ("xxe", True, "readme"),
    # ---- FastJson ----
    # 1.2.31 + parseObject(applyData, Teacher.class)：parse 阶段仍处理 @type
    ("FastJsonController", "/fastjson/create"): ("deserial", True, "readme"),
}

DISPUTED_TRUTH = _for_target("micro_service_seclab")


def route_of(unit) -> str:
    """拼出完整路由：类级 @RequestMapping 前缀 + 方法级 value。"""
    cls = unit.unit_name.split(".", 1)[0]
    path = str(unit.file_path).replace("\\", "/")
    prefix = ""
    try:
        src = Path(unit.file_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        src = ""
    m = re.search(
        r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?\"([^\"]*)\"\s*\)\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
        r"public\s+class\s+" + re.escape(cls),
        src,
    )
    if m:
        prefix = m.group(1).rstrip("/")
    tail = ""
    for a in unit.decorators_or_modifiers or []:
        mm = re.search(r'"([^"]*)"', a)
        if mm:
            tail = mm.group(1)
            break
    if not tail:
        return prefix
    if not tail.startswith("/"):
        tail = "/" + tail
    return prefix + tail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--offline", action="store_true", help="只跑确定性规则，不调模型")
    ap.add_argument("--model", default="longcat-2.5-preview-free")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组供抽查")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "msseclab.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    print(f"靶场：{repo}")
    units = JavaSlicer(repo).extract_entry_units()
    print(f"[1/3] 切出入口 {len(units)} 个")

    rows, unknown, no_cat = [], [], 0
    for u in units:
        cls = u.unit_name.split(".", 1)[0]
        key = (cls, route_of(u))
        hit = TRUTH.get(key)
        if not hit:
            # 路由拼接可能因注解写法差异而不同，退到「类名 + 方法名」匹配
            tail = base_unit_name(u.unit_name)
            alt = [k for k in TRUTH if k[0] == cls and tail.endswith("." + k[1].rsplit("/", 1)[-1])]
            hit = TRUTH[alt[0]] if len(alt) == 1 else None
        if not hit:
            if cls in CLASS_TO_CATEGORY:
                unknown.append((u, CLASS_TO_CATEGORY[cls]))
            else:
                no_cat += 1
            continue
        rows.append({"unit": u, "category": hit[0], "real_vuln": hit[1],
                     "src": hit[2], "route": route_of(u)})

    print(f"[2/3] 有真值 {len(rows)} 条（vul {sum(1 for r in rows if r['real_vuln'])} / "
          f"safe {sum(1 for r in rows if not r['real_vuln'])}），"
          f"类目内无标注 {len(unknown)} 条，无对应类目 {no_cat} 条，均已排除")
    by_cat = Counter(r["category"] for r in rows)
    print(f"      类目分布：{dict(sorted(by_cat.items()))}")
    if no_cat or unknown:
        print(f"      ! 有 {no_cat + len(unknown)} 条入口没落进真值表 —— "
              f"先确认是真值表漏了，还是靶场多了入口")

    if args.list:
        print("      ---- 判定三元组（供人工抽查真值）----")
        for r in sorted(rows, key=lambda x: x["unit"].unit_name):
            print(f"      {r['unit'].unit_name:38} {r['category']:9} "
                  f"{'vul ' if r['real_vuln'] else 'safe'} "
                  f"src={r['src']:8} route={r['route']}")

    print("[3/3] 规则零改动迁移（不修改任何正则）...")
    rule_dec, rule_none = [], []
    for r in rows:
        rv = rule_verdict(r["category"], r["unit"].source_code)
        (rule_dec if rv is not None else rule_none).append((r, rv))

    print()
    print("=" * 72)
    print("micro_service_seclab 零改动迁移结果")
    print("=" * 72)
    n = len(rows)
    print(f"有人工真值样本        ：{n}")
    print(f"规则直接给出结论      ：{len(rule_dec)}  "
          f"（覆盖率 {len(rule_dec) / max(n, 1) * 100:.1f}%）")
    print(f"规则返回 None（交模型）：{len(rule_none)}  "
          f"（退回率 {len(rule_none) / max(n, 1) * 100:.1f}%）")

    judged = [(r, rv) for r, rv in rule_dec if r["unit"].unit_name not in DISPUTED_TRUTH]
    disputed = [(r, rv) for r, rv in rule_dec if r["unit"].unit_name in DISPUTED_TRUTH]
    right = sum(1 for r, rv in judged if rv == r["real_vuln"])
    if rule_dec:
        print(f"规则判定正确          ：{right}/{len(judged)} = "
              f"{right / max(len(judged), 1) * 100:.1f}%")
        if disputed:
            print(f"\n· 真值存疑（{len(disputed)} 条，不计入正确率）：")
            for r, rv in disputed:
                print(f"  {r['unit'].unit_name:38} {r['category']:9} "
                      f"标注={r['real_vuln']!s:5} 规则={rv!s:5}")
        wrong = [(r, rv) for r, rv in judged if rv != r["real_vuln"]]
        if wrong:
            print("\n! 规则判错的样本（这一项必须为 0，否则是跨项目误报）：")
            for r, rv in wrong:
                print(f"  {r['unit'].unit_name:38} {r['category']:9} "
                      f"真值={r['real_vuln']!s:5} 规则={rv!s:5} route={r['route']}")
        safe_judged = [(r, rv) for r, rv in judged if not r["real_vuln"]]
        safe_right = sum(1 for r, rv in safe_judged if rv is False)
        vul_judged = [(r, rv) for r, rv in judged if r["real_vuln"]]
        vul_right = sum(1 for r, rv in vul_judged if rv is True)
        print(f"  ├ safe 样本 {len(safe_judged)} 条，判对 {safe_right} "
              f"（FPR = {(len(safe_judged) - safe_right) / max(len(safe_judged), 1) * 100:.1f}%）")
        print(f"  └ vul  样本 {len(vul_judged)} 条，判对 {vul_right} "
              f"（漏报率 = {(len(vul_judged) - vul_right) / max(len(vul_judged), 1) * 100:.1f}%）")

    per_cat = defaultdict(lambda: [0, 0, 0, 0])
    for r in rows:
        per_cat[r["category"]][2] += 1
        if not r["real_vuln"]:
            per_cat[r["category"]][3] += 1
    for r, rv in judged:
        per_cat[r["category"]][0] += 1
        per_cat[r["category"]][1] += int(rv == r["real_vuln"])
    print("\n逐类目（规则）：")
    print(f"  {'类目':<12}{'n':>4}{'safe_n':>8}{'规则判定':>10}{'正确':>8}{'退回率':>10}")
    for c, (d, ok, tot, sn) in sorted(per_cat.items()):
        print(f"  {c:<12}{tot:>4}{sn:>8}{d:>10}{ok:>8}{(tot - d) / tot * 100:>9.0f}%")

    if rule_none:
        print("\n退回模型的样本：")
        for r, _ in rule_none:
            print(f"  {r['unit'].unit_name:38} {r['category']:9} "
                  f"真值={r['real_vuln']!s:5} 依据={r['src']:8} route={r['route']}")

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
                      "real_vuln": r["real_vuln"], "route": r["route"],
                      "truth_src": r["src"]} for r, _ in rule_none],
        "model": model_rows,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")


async def _gather(fn, items):
    return await asyncio.gather(*(fn(x) for x in items))


if __name__ == "__main__":
    main()
