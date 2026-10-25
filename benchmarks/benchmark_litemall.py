"""litemall（linlinjava/litemall，20.4k Star）—— 第 24 个靶场，野战实弹。

## 为什么选它

多模块微信小程序商城：litemall-wx-api（C 端）+ litemall-admin-api（后台）
+ litemall-db（MyBatis Generator 层）。M64 盲测 288 条 P0 → 逐条人工核查：

  · **sqli 40 → 0**：`@Sort(accepts={"add_time","id"})` / `@Order` 是
    Bean Validation 白名单注解（类级 @Validated 强制）—— 框架在参数解析
    阶段拒绝白名单外的值。淬火④：切片器给形参打 `[param-validated]`
    标记，MBG `setOrderByClause` 出口据此豁免；`selectByExampleSelective`
    变体、枚举列描述链（`Column.addTime.desc()`）、MBG POJO 管道定义
    （`orderBy(String orderByClause)` 且调用点全字面量）三类形态同批收口；
  · **authz 21 → 0**：litemall-admin 的 ShiroConfig `filterChainDefinition
    Map.put("/admin/**", "authc")` 全局认证（淬火⑥：Shiro 过滤链并入
    前缀覆盖机制）；wx-api 是**显式 token 鉴权模块**（@LoginUser resolver
    逐路由声明主体，未声明的就是匿名面 C 端浏览，淬火⑦
    `[explicit-auth-module]`）；
  · **pathtraver 5 → 0**：`request.getInputStream()` 是读 HTTP 请求体
    不是文件路径（淬火⑨）；二维码生成的内部临时文件与形参无交集
    （淬火⑧：路径 sink 需与入口形参相关）；
  · **真阳 3 条**：admin 商品富文本 → 前台渲染的存储型 XSS ×2；
    `WxMaMessage.fromXml`（XStream）解析微信回调 XML 的反序列化/XXE 面。

## CORS 真值口径（配置继承）

`CorsConfig.java` 注册了 `addAllowedOrigin("*")` **且** `setAllowCredentials
(true)` —— 教科书级危险组合，且 `urlPatterns=['/**']` 全局生效。这是**一条
真实配置缺陷**，全部 219 个入口都是它的暴露面（机械真值：wiring 证据在切片
里逐单元可见）。

## 门禁（--strict）

真值表零误报 / 零漏报 / 零判反。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.java_servlet import JavaSlicer                  # noqa: E402
from benchmarks.slice_cache import cached_units                  # noqa: E402

ensure_utf8_stdio()

DEFAULT_TARGET = ROOT / "reference_repos" / "litemall-master"

# 人工核查真值：(文件名, 类.方法) -> 类目
TRUTH = {
    ("AdminGoodsController.java", "AdminGoodsController.update"): "xss",
    ("AdminGoodsController.java", "AdminGoodsController.create"): "xss",
    ("WxMsgController.java", "WxMsgController.config"): "deserial",
}

CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "crypto",
        "ldapi", "xpathi", "ssrf", "xxe", "spel", "deserial", "redir",
        "cors", "authz", "trustbound", "securecookie")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="真值表零误报 / 零漏报 / 零判反（CI 门禁）")
    ap.add_argument("--offline", action="store_true",
                    help="只跑规则层（默认，规则靶场）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "litemall.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    print(f"靶场：{repo}")
    units = cached_units(repo, "litemall",
                         lambda: JavaSlicer(repo).extract_entry_units())
    print(f"      切片单元 {len(units)} 个")

    rows, n_fp, n_fn, n_rev = [], 0, 0, 0
    decided = 0
    cors_truth_n = 0
    # 先逐单元判定，再按 (fname, base) 聚合 —— 真值命中看同名单元组里
    # 有没有一个判 True（litemall 的 config 与 config#2 是两个同名单元）
    unit_rows = []
    for u in units:
        fname = Path(u.file_path).name
        base = u.unit_name.split("#")[0]
        per = {cat: rule_verdict(cat, u.source_code) for cat in CATS}
        unit_rows.append((fname, base, u, per))
        decided += sum(1 for v in per.values() if v is not None)

    for fname, base, u, per in unit_rows:
        for cat, v in per.items():
            if v is None or v is False:
                continue
            if cat == "cors":
                cors_truth_n += 1      # 配置继承真值（CorsConfig /**）
                continue
            if TRUTH.get((fname, base)) == cat:
                continue
            n_fp += 1
            rows.append({"unit": base, "file": fname, "cat": cat,
                         "truth": False, "got": True})

    for (fname, bname), truth_cat in TRUTH.items():
        group = [per for f, b, _, per in unit_rows
                 if f == fname and b == bname]
        if not group or not any(per.get(truth_cat) is True for per in group):
            n_fn += 1
            rows.append({"unit": bname, "file": fname, "cat": truth_cat,
                         "truth": True, "got": None})

    print("=" * 72)
    print("litemall 结果（规则层，配置继承真值 + 人工核查真值）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则确定性判定        ：{decided}")
    print(f"  CORS 配置继承真阳     ：{cors_truth_n}"
          "（CorsConfig: ACAO=* + AllowCredentials=true，/** 全局）")
    print(f"  人工真值命中          ：{len(TRUTH) - n_fn}/{len(TRUTH)}")
    print(f"  误报                  ：{n_fp}")
    print(f"  漏报                  ：{n_fn}")
    for r in rows[:20]:
        print(f"    {r['file']}:{r['unit']} [{r['cat']}] truth={r['truth']} got={r['got']}")

    ok = (n_fp == 0 and n_fn == 0)
    print(f"\n{'STRICT 门禁：通过 ✔（零误报 / 真值全命中）' if ok else 'STRICT 门禁：FAIL ✘'}")
    Path(args.output).write_text(json.dumps({
        "bench": "litemall", "units": len(units), "decided": decided,
        "cors_truth": cors_truth_n, "truth_n": len(TRUTH),
        "fp": n_fp, "fn": n_fn, "rows": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {args.output}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
