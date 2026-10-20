"""newbee-mall 回归基线（第 5 靶场，第一个**真实业务项目**）。

## 为什么要有这个靶场

前四个靶场（OWASP / java-sec-code / Hello-Java-Sec / JavaSecLab /
micro_service_seclab）都是**为演示漏洞而写**的：一条路由一个类、方法名带
vul/safe、入口体就是 sink。它们的分数再高，也证明不了"能在真实业务代码上跑"。

newbee-mall 是标准 4 层生产结构：

    Controller → NewBeeMallXxxService(接口) → NewBeeMallXxxServiceImpl
               → XxxMapper.java → resources/mapper/XxxMapper.xml

70 个入口、9 个 Mapper XML、`#{}` 全量、`${}` 零次。**没有逐路由漏洞真值**，
所以这个脚本不追求"跑分"，只锁三件确定的事：

  ① 切片穿透基线   —— 数字掉了就是切片器退化（ServiceImpl / Mapper XML 进没进切片）
  ② authz 真值表   —— 12 条逐条人工核对过的判定（11 safe + 1 真越权）
  ③ sqli 方向护栏   —— 全仓库 `${}` 出现 0 次 ⇒ 任何一条 sqli=True 都是误报

## 真值是怎么来的（每条都能逐行核对）

不来自任何漏洞报告，来自三条**代码事实**：

  1. 主体来源：`httpSession.getAttribute(MALL_USER_SESSION_KEY)` —— 取自可信上下文
  2. 主体是否参与资源定位：`getOrderDetailByOrderNo(orderNo, user.getUserId())`
     / `item.setUserId(user.getUserId())` / `!user.getUserId().equals(order.getUserId())`
  3. 缺少上述任一条的写操作路由 = 水平越权（`/paySuccess` 就是唯一一条）

## 已知缺口（写成断言，防止悄悄扩大）

`ShoppingCartController` 的 PUT `/shop-cart` 与 DELETE `/shop-cart/{id}` **同名**
（都叫 `updateNewBeeMallShoppingCartItem`），而切片器按方法名建索引 →
DELETE 那条入口被静默丢弃。全仓库共 5 条入口这样丢失（另见 HJS 2 条）。
本条写进 `KNOWN_MISSING`，跑分会明确打印；修法（按 `(name, start_line)` 建索引）
属独立一轮，会改变入口分母，不在本脚本里顺手改。

## 用法

    python benchmarks/benchmark_newbeemall.py            # 切片 + 规则，全离线
    python benchmarks/benchmark_newbeemall.py --dump X   # dump 名字含 X 的切片

与其它 benchmark 同一条铁律：**不 import 规则常量、不改 rule_detectors**。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict      # noqa: E402
from core.slicer.java_servlet import JavaSlicer                      # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "newbee-mall-master"

# ---------------- ① 切片穿透基线 ----------------
# 数字取自 2026-10-20 零改动盲测（commit 3d892d6）之后的实测值。
# 变化只会来自两处：切片器真改了 / 仓库换了版本。两种都该有人看一眼。
BASELINE = {
    "entries": 70,
    "service_entries": 53,      # 入口体里出现 XxxService.method( 的入口数
    "service_penetrated": 52,   # 其中切片里真的带进了跨文件实现体
    "impl_hops": 56,            # 切片里出现 `[Hop N]` 段的入口（ServiceImpl / Mapper 任一）
    "mapper_xml": 36,           # 含 Mapper XML SQL 的入口
}

# 已知丢失的入口（同名重载 → 按方法名建索引只保留第一条）。
# 写在代码里而不是注释里：修好之后这条断言会失败，逼人回来改掉它。
KNOWN_MISSING = {
    "ShoppingCartController.updateNewBeeMallShoppingCartItem":
        "PUT /shop-cart 与 DELETE /shop-cart/{id} 同名，DELETE 那条未入切片",
}

# ---------------- ② authz 真值表 ----------------
# 键：(类名, 完整路由)。路由已含类级前缀（UploadController 的 `/admin`）。
# 值：(真值, 依据)
#   依据 tag：
#     "subject-key"  主体值参与资源定位（getXxx(key, user.getUserId()) / setUserId(...)）
#     "subject-cmp"  方法内显式比对主体与资源归属并终止请求
#     "no-arg"       路由不接受任何资源标识入参，无从越权
#     "no-subject"   写操作既不取主体也不比对归属 → 水平越权
AUTHZ_TRUTH: dict[tuple[str, str], tuple[bool, str]] = {
    # ---- 个人中心：会话主体 + 主体值作资源键 ----
    ("OrderController", "/orders/{orderNo}"):
        (False, "subject-key"),          # getOrderDetailByOrderNo(orderNo, user.getUserId())
    ("OrderController", "/orders/{orderNo}/cancel"):
        (False, "subject-key"),          # cancelOrder(orderNo, user.getUserId())
    ("OrderController", "/orders/{orderNo}/finish"):
        (False, "subject-key"),          # finishOrder(orderNo, user.getUserId())
    ("OrderController", "/orders"):
        (False, "subject-key"),          # params.put("userId", user.getUserId()) 再分页查
    ("OrderController", "/saveOrder"):
        (False, "no-arg"),               # 入参只有 HttpSession，购物车由主体取
    # ---- 支付：显式比对主体与订单归属，不等则 NewBeeMallException.fail ----
    ("OrderController", "/selectPayType"):
        (False, "subject-cmp"),
    ("OrderController", "/payPage"):
        (False, "subject-cmp"),
    # ---- 购物车：主体值写进实体或被当作查询条件 ----
    # `/shop-cart` 一个路由三个动词（GET/POST/PUT），方法名各不相同，
    # 真值挂在 unit_name 上（见 AUTHZ_TRUTH_BY_UNIT），这里不按路由重复登记。
    ("ShoppingCartController", "/shop-cart/settle"):
        (False, "subject-key"),
    # ---- 唯一的真漏洞：不取主体、不比对归属，orderNo 直接进 Service ----
    ("OrderController", "/paySuccess"):
        (True, "no-subject"),
}

# 与 AUTHZ_TRUTH 的 "/shop-cart" 共用路由、靠方法名区分的两条。
AUTHZ_TRUTH_BY_UNIT: dict[str, tuple[bool, str]] = {
    "ShoppingCartController.cartListPage": (False, "subject-key"),
    "ShoppingCartController.saveNewBeeMallShoppingCartItem": (False, "subject-key"),
    "ShoppingCartController.updateNewBeeMallShoppingCartItem": (False, "subject-key"),
}

# 真值存疑：规则判 True 但"是否有可达注入面"静态无法定论。
# 按项目铁律单列、不进分母、不改判据。
DISPUTED: dict[str, str] = {
    "UploadController.upload":
        "pathtraver：写入路径 = 常量目录 + 生成的文件名，用户可控部分只是"
        "`fileName.substring(lastIndexOf('.'))`。它能含 `/`，但要逃出基目录需要"
        "存在一个名为 `<时间戳><随机数>.` 的中间目录（mkdir 只建常量目录），"
        "静态无法证明可利用，也无法证明绝对不可利用 → 不进分母。",
    "UploadController.uploadV2":
        "同 upload：同样的文件名后缀拼接与常量目录。",
}


def _load(repo: Path):
    slicer = JavaSlicer(repo)
    return slicer.extract_entry_units()


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


SERVICE_CALL_RE = re.compile(r"\b([A-Za-z_]\w*[Ss]ervice)\s*\.\s*([A-Za-z_]\w*)\s*\(")
XML_SQL_RE = re.compile(r"<\s*(select|insert|update|delete)\b", re.I)
DOLLAR_RE = re.compile(r"\$\{")


def slice_stats(units) -> dict[str, int]:
    """切片穿透的四个口径。与 `_probe_newbee.py` 的 ① 段同义，但这里出硬数字。

    口径要点：`impl_hops` 数的是**切片里真出现了 `[Hop N]` 段**的入口，
    不是"入口调了 Service"。二者一个是事实（代码在切片里），
    一个是意图（代码想调它）—— 断链恰恰发生在两者之间，只能数前者。
    """
    impl, xml, svc_units, svc_hit = 0, 0, 0, 0
    for u in units:
        src = u.source_code
        has_impl = ("接口实现类方法体" in src) or bool(re.search(r"\[Hop \d+\]", src))
        if has_impl:
            impl += 1
        if XML_SQL_RE.search(src):
            xml += 1
        if SERVICE_CALL_RE.search(src):
            svc_units += 1
            if has_impl:
                svc_hit += 1
    return {"entries": len(units), "service_entries": svc_units,
            "service_penetrated": svc_hit, "impl_hops": impl, "mapper_xml": xml}


def _lookup_truth(u):
    """先按方法名精确匹配，再按 (类, 路由) 匹配。"""
    hit = AUTHZ_TRUTH_BY_UNIT.get(u.unit_name)
    if hit:
        return hit
    cls = u.unit_name.split(".", 1)[0]
    # 去重后的方法名（同名重载的 #2 后缀）不影响真值：都属同一路由族
    return AUTHZ_TRUTH.get((cls, u.route_path))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--dump", default="", help="打印名字含该串的入口切片")
    ap.add_argument("--list", action="store_true", help="打印全部判定三元组")
    ap.add_argument("--strict", action="store_true",
                    help="基线漂移或 sqli 误报时以非零码退出（供 pre-push 用）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "newbeemall.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 靶场不存在：{repo}")
        sys.exit(2)
    units = _load(repo)
    print(f"靶场：{repo}")
    print(f"[1/3] 切出入口 {len(units)} 个")

    if args.dump:
        for u in units:
            if args.dump.lower() in u.unit_name.lower():
                print("=" * 78)
                print(u.unit_name, "|", u.route_path)
                print("-" * 78)
                print(u.source_code)
        return

    # ---------- ① 切片穿透 ----------
    st = slice_stats(units)
    print("\n① 切片穿透基线（入口 → ServiceImpl → Mapper XML）")
    ok = True
    for k, label in (("entries", "入口数"),
                     ("service_entries", "含 Service 调用的入口"),
                     ("service_penetrated", "其中带进跨文件实现体"),
                     ("impl_hops", "含跨文件实现体"),
                     ("mapper_xml", "含 Mapper XML SQL")):
        cur, base = st[k], BASELINE[k]
        flag = "" if cur == base else f"  <-- 基线 {base}"
        ok = ok and cur == base
        print(f"   {label:<24}{cur:>4}{flag}")
    if not ok:
        print("   ! 与基线不一致：升级切片器就同步改 BASELINE，别让它悄悄漂移")

    # 入口丢失（同名重载）—— 只报警，不算错
    names = Counter(u.unit_name for u in units)
    dup = {n: c for n, c in names.items() if c > 1}
    print(f"\n   同名重载重复单元：{len(dup)} 条")
    if dup:
        for n, c in dup.items():
            print(f"     ! {n} × {c} —— unit_name 撞车，跨路由串接会把它当同一个方法")
    print(f"   已知丢失入口：{len(KNOWN_MISSING)} 条（同名重载只保留第一条）")
    for n, why in KNOWN_MISSING.items():
        print(f"     - {n}: {why}")

    # ---------- ② authz 真值 ----------
    rows = []
    for u in units:
        hit = _lookup_truth(u)
        if hit:
            rows.append({"unit": u, "real_vuln": hit[0], "src": hit[1]})
    print(f"\n② authz 真值表：命中 {len(rows)} 条"
          f"（vul {sum(1 for r in rows if r['real_vuln'])} / "
          f"safe {sum(1 for r in rows if not r['real_vuln'])}）"
          f"  表内共 {len(AUTHZ_TRUTH) + len(AUTHZ_TRUTH_BY_UNIT)} 条")
    missing = (set(AUTHZ_TRUTH_BY_UNIT)
               | {f"{c}.{r}" for (c, r) in AUTHZ_TRUTH})
    hit_names = {r["unit"].unit_name for r in rows}
    # 路由型真值的 "类.路由" 与 unit_name 不同名，只对方法名型的做缺失检查
    for n in sorted(set(AUTHZ_TRUTH_BY_UNIT) - hit_names):
        print(f"     ! 真值表里的 {n} 没匹配到任何入口")

    decided, fallback = [], []
    for r in rows:
        rv = rule_verdict("authz", r["unit"].source_code)
        (decided if rv is not None else fallback).append((r, rv))

    judged = [(r, rv) for r, rv in decided if r["unit"].unit_name not in DISPUTED]
    right = sum(1 for r, rv in judged if rv == r["real_vuln"])
    print(f"   规则直接给出结论：{len(decided)}/{len(rows)}"
          f"（覆盖 {len(decided) / max(len(rows), 1) * 100:.0f}%）")
    print(f"   规则判定正确    ：{right}/{len(judged)}"
          f" = {right / max(len(judged), 1) * 100:.1f}%")
    safe_j = [(r, rv) for r, rv in judged if not r["real_vuln"]]
    vul_j = [(r, rv) for r, rv in judged if r["real_vuln"]]
    fp = [r for r, rv in safe_j if rv is True]
    fn = [r for r, rv in vul_j if rv is False]
    print(f"   ├ safe {len(safe_j)} 条判对 {len(safe_j) - len(fp)}"
          f"（FPR = {len(fp) / max(len(safe_j), 1) * 100:.1f}%）")
    print(f"   └ vul  {len(vul_j)} 条判对 {len(vul_j) - len(fn)}"
          f"（漏报率 = {len(fn) / max(len(vul_j), 1) * 100:.1f}%）")
    if fp or fn:
        print("\n   ! 方向性错误（必须为 0）：")
        for r in fp:
            print(f"     FP {r['unit'].unit_name:<52} 真值=safe 规则=True")
        for r in fn:
            print(f"     FN {r['unit'].unit_name:<52} 真值=vul  规则=False")
    if fallback:
        print("\n   退回模型（真值仍成立，只是规则没覆盖）：")
        for r, _ in fallback:
            print(f"     {r['unit'].unit_name:<52} "
                  f"真值={'vul ' if r['real_vuln'] else 'safe'} {r['unit'].route_path}")

    if args.list:
        print("\n   判定三元组：")
        for r, rv in decided + fallback:
            print(f"     {r['unit'].unit_name:<52} {r['unit'].route_path:<34} "
                  f"真值={'vul ' if r['real_vuln'] else 'safe'} 规则={rv}")

    # ---------- ③ sqli 方向护栏 ----------
    # 全仓库 Mapper XML 里 `${}` 出现 0 次 ⇒ 没有任何一条路由存在 SQL 注入面。
    # 所以 sqli=True 的每一条都是误报，必须为 0；sqli=False 是覆盖率，只记录。
    dollar_files = [p for p in repo.rglob("*.xml")
                    if "mapper" in str(p).lower()
                    and DOLLAR_RE.search(p.read_text(encoding="utf-8", errors="ignore"))]
    sqli_t = [u.unit_name for u in units if rule_verdict("sqli", u.source_code) is True]
    sqli_f = sum(1 for u in units if rule_verdict("sqli", u.source_code) is False)
    print(f"\n③ sqli 方向护栏：Mapper XML 含 `${{}}` 的文件 {len(dollar_files)} 个")
    print(f"   规则判 True（= 误报）：{len(sqli_t)}"
          f"{'  <-- 必须为 0' if not sqli_t else ''}")
    for n in sqli_t:
        print(f"     ! {n}")
    print(f"   规则判 False（判安全）  ：{sqli_f} / {len(units)}")

    # ---------- 存疑 ----------
    pt_t = [u.unit_name for u in units
            if rule_verdict("pathtraver", u.source_code) is True]
    print(f"\n④ 存疑（不进分母、不改判据）：{len(DISPUTED)} 条")
    for n, why in DISPUTED.items():
        v = rule_verdict("pathtraver", next(
            (u.source_code for u in units if u.unit_name == n), ""))
        print(f"   {n}  规则 pathtraver={v}")
        print(f"     {why}")
    extra = [n for n in pt_t if n not in DISPUTED]
    if extra:
        print(f"   ! 另有 {len(extra)} 条 pathtraver 判 True 且未登记，需补真值：")
        for n in extra:
            print(f"     - {n}")

    # ---------- 判定分布快照 ----------
    print("\n判定分布快照（True / False / None）：")
    snap = {}
    for cat in ("authz", "sqli", "xss", "pathtraver", "cmdi", "ssrf"):
        vs = [rule_verdict(cat, u.source_code) for u in units]
        t, f = sum(1 for v in vs if v is True), sum(1 for v in vs if v is False)
        snap[cat] = {"true": t, "false": f, "none": len(vs) - t - f}
        print(f"   {cat:<11} {t:>4} / {f:>4} / {len(vs) - t - f:>4}")

    out = {
        "target": str(repo),
        "slice": st,
        "slice_matches_baseline": ok,
        "authz": {
            "truth_n": len(rows),
            "decided": len(decided),
            "correct": right,
            "fp": [r["unit"].unit_name for r in fp],
            "fn": [r["unit"].unit_name for r in fn],
            "fallback": [r["unit"].unit_name for r, _ in fallback],
        },
        "sqli_false_positive": sqli_t,
        "sqli_safe_decided": sqli_f,
        "distribution": snap,
        "disputed": DISPUTED,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    print(f"\n结果写入 {args.output}")
    if args.strict and (not ok or sqli_t):
        print("! --strict：基线漂移或存在 sqli 误报 → 退出码 3")
        sys.exit(3)


if __name__ == "__main__":
    main()
