"""mall —— 第 17 个靶场，第一个**整体安全的生产级多模块项目** 对照面。

## 为什么需要这个靶场

macrozheng/mall 是 70k+ star 的生产级电商系统（Spring Boot + MyBatis
Generator + Spring Security）。它不是漏洞靶场 —— 真值面**全 safe**，
价值与 eladmin-mp 同类：门禁锁"零误报"。它逼出三块此前没有靶场覆盖的
机制（Module 38）：

1. **仓库级全局鉴权豁免**：mall-admin 的 controller 全部没有方法级
   注解，但 JwtAuthenticationTokenFilter 经 addFilterBefore 统一拦截
   认证 —— "入口体没鉴权就判漏洞"是铁律 4 的高频陷阱，过滤器是仓库
   级事实，单文件视角看不到。切片头打机器标记 [global-authz]，
   authz 判定降 None。
2. **Spring Security 服务端主体链**（mall-portal 形态）：
   `memberService.getCurrentMember().getId()` 直接作 Service 实参 ——
   资源主键来自服务端会话，没有可越权的他人资源键 → False（2g-2）。
3. **MyBatis Generator Example 参数化**（sqli C2b）：
   `selectByExample(new XxxExample())` 全部 #{} 绑定，唯一字符串替换
   出口是 XML 的 `${orderByClause}` —— setOrderByClause 实参全字面量
   → False，非字面量 → True。

顺带修复铁律 24 同构坑：`_interface_index` setdefault 首见即占，
mall 的 `getList` 被 OmsOrderDao 抢占后 PmsProductCategoryService 的
同名方法永远进不了索引（name → 列表 + 同 Maven 模块优先）；`_pick_impl`
补后缀匹配（productCategoryService ↔ PmsProductCategoryServiceImpl，
pms 前缀包不误配 PmsProductAttributeCategoryServiceImpl）。

## 真值来源

代码事实（README 未标注漏洞；mall 是维护中的生产项目）：
- authz False：getCurrentMember().getId() 参与 Service 资源定位（6 条）
- sqli False：ServiceImpl 段 selectByExample + setOrderByClause 字面量
  （抽 10 条代表，跨 mall-portal / mall-admin / mall-demo 三模块）

门禁（--strict）：登记条目全部判 False 判对 + **全库 246 单元零 True**
（安全项目的任何 True 都是误报）。
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

DEFAULT_TARGET = ROOT / "reference_repos" / "mall-main"

# 真值表：键 (file_name, unit_name, start_line)（铁律 23 精确匹配）。
TRUTH: dict[tuple[str, str, int], tuple[str, bool, str]] = {
    # ---- authz：Spring Security 服务端主体链（getCurrentMember）----
    ("OmsCartItemController.java", "OmsCartItemController.list", 41):
        ("authz", False, "cartItemService.list(getCurrentMember().getId())"),
    ("OmsCartItemController.java", "OmsCartItemController.listPromotion", 49):
        ("authz", False, "listPromotion(getCurrentMember().getId(), cartIds)"),
    ("OmsCartItemController.java", "OmsCartItemController.updateQuantity", 57):
        ("authz", False, "updateQuantity(id, getCurrentMember().getId(), q)"),
    ("OmsCartItemController.java", "OmsCartItemController.delete", 88):
        ("authz", False, "delete(getCurrentMember().getId(), ids)"),
    ("OmsCartItemController.java", "OmsCartItemController.clear", 99):
        ("authz", False, "clear(getCurrentMember().getId())"),
    ("UmsMemberCouponController.java", "UmsMemberCouponController.listCart", 68):
        ("authz", False, "listCart(getCurrentMember().getId())"),
    # ---- sqli：MBG Example 参数化（orderByClause 全字面量）----
    ("HomeController.java", "HomeController.recommendProductList", 36):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("HomeController.java", "HomeController.getProductCateList", 45):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("PmsProductCategoryController.java", "PmsProductCategoryController.getList", 55):
        ("sqli", False, "selectByExample + orderByClause 字面量（跨模块 Hop）"),
    ("PmsBrandController.java", "PmsBrandController.getList", 28):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("PmsProductAttributeController.java", "PmsProductAttributeController.getList", 32):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("OmsPortalOrderController.java", "OmsPortalOrderController.list", 75):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("PmsPortalProductController.java", "PmsPortalProductController.search", 35):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("UmsAdminController.java", "UmsAdminController.getItem", 125):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("SmsCouponController.java", "SmsCouponController.getItem", 71):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
    ("OmsOrderController.java", "OmsOrderController.detail", 70):
        ("sqli", False, "selectByExample + orderByClause 字面量"),
}


def run(target: Path, strict: bool, out: Path | None) -> int:
    units = JavaSlicer(target).extract_entry_units()
    print("mall 结果（生产级项目对照面：零误报门禁）")
    print("=" * 72)
    print(f"切片单元 {len(units)}（多模块跨文件 Hop）")

    by_key = {}
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

    # 安全项目全库断言：任何 True 都是误报
    n_true = 0
    true_rows = []
    for u in units:
        for cat in ("sqli", "authz"):
            if rule_verdict(cat, u.source_code or "") is True:
                n_true += 1
                true_rows.append(f"{Path(u.file_path).name}:{u.unit_name}[{cat}]")
    print(f"\n  判对 {tp}  误报 {fp}  判反 {fn}  退回 {none_ct}"
          f"  （登记 {len(TRUTH)} 条）")
    print(f"  全库 True（安全项目应恒为 0）：{n_true}"
          + (f"  {true_rows[:5]}" if true_rows else ""))
    if out:
        out.write_text(json.dumps(
            {"total_units": len(units), "decided": tp + fp + fn,
             "correct": tp, "fp": fp, "reverse_fn": fn, "none": none_ct,
             "global_true": n_true, "rows": rows},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结果写入 {out}")
    if strict:
        ok = fp == 0 and fn == 0 and none_ct == 0 and n_true == 0
        print("\nSTRICT 门禁：" + ("通过 ✔（登记全判对 / 全库零 True / 零退回）"
                                    if ok else "未通过 ✘"))
        return 0 if ok else 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="mall 基准（M38）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results"
                                          / "mall.json"))
    a = ap.parse_args()
    return run(Path(a.target), a.strict, Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
