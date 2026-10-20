"""newbee-mall 零改动探针：只看切片器与规则层在真实分层项目上的事实，不改任何代码。

三步（对应盲测计划）：
  ① 切片：切出多少入口，其中多少把 ServiceImpl 方法体 / Mapper XML 带进来了
  ② 断链：`<include refid>` 有没有展开；Map<String,Object> 封装传参丢在哪一跳
  ③ authz：订单 / 收货地址 / 购物车控制器判出几条 True，逐条打印依据

用法：
  python benchmarks/_probe_newbee.py [--units] [--unit NAME] [--authz]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.slicer.java_servlet import JavaSlicer  # noqa: E402

REPO = Path("reference_repos/newbee-mall-master")
SRC = REPO / "src/main/java/ltd/newbee/mall"

HOP_RE = re.compile(r"\[Hop (\d+)\]")
XML_SQL_RE = re.compile(r"<\s*(select|insert|update|delete)\b", re.I)
INCLUDE_RE = re.compile(r"<include\s+refid\s*=\s*\"(\w+)\"", re.I)
SQLFRAG_RE = re.compile(r"<sql\s+id\s*=\s*\"(\w+)\"")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _impl_method_body(iface: str, method: str) -> str:
    """在 `service/impl/<iface>Impl.java` 里截出方法体，用于判断是否进了切片。"""
    p = SRC / "service/impl" / f"{iface}Impl.java"
    if not p.exists():
        # 接口名形如 NewBeeMallGoodsService -> Impl 名同前缀
        cands = list((SRC / "service/impl").glob("*.java"))
        p = next((c for c in cands if c.stem == iface + "Impl"), None)
        if p is None:
            return ""
    txt = p.read_text(encoding="utf-8", errors="ignore")
    m = re.search(rf"\b{re.escape(method)}\s*\([^)]*\)\s*\{{", txt)
    if not m:
        return ""
    i = txt.find("{", m.start())
    depth = 0
    for j in range(i, len(txt)):
        if txt[j] == "{":
            depth += 1
        elif txt[j] == "}":
            depth -= 1
            if depth == 0:
                return txt[i:j + 1]
    return ""


def _service_calls(body: str) -> list[tuple[str, str]]:
    out = []
    for m in re.finditer(r"\b([A-Za-z_]\w*[Ss]ervice)\s*\.\s*([A-Za-z_]\w*)\s*\(", body):
        out.append((m.group(1), m.group(2)))
    return out


def _field_types(text: str) -> dict[str, str]:
    """字段名 → 类型：`private NewBeeMallGoodsService newBeeMallGoodsService;`"""
    return {m.group(2): m.group(1) for m in
            re.finditer(r"(?:private|protected|public)\s+(?:final\s+)?(\w+)\s+(\w+)\s*;", text)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--units", action="store_true")
    ap.add_argument("--unit", default="")
    ap.add_argument("--authz", action="store_true")
    args = ap.parse_args()

    units = JavaSlicer(REPO).extract_entry_units()
    print(f"入口总数：{len(units)}")

    if args.units:
        for u in units:
            print("  ", u.unit_name, "|", Path(u.file_path).name if u.file_path else "?")

    stats = {"hop_any": 0, "impl": 0, "xml": 0, "xml_raw": 0, "include_left": 0}
    rows = []
    for u in units:
        src = u.source_code
        hops = [int(x) for x in HOP_RE.findall(src)]
        body = src
        calls = _service_calls(body)
        # 字段声明在**入口方法之外**，切片里没有（`_entry_only` 只留方法体），
        # 必须回源文件取，否则接口名永远为空、探针会误报"impl 没进来"。
        try:
            ftypes = _field_types(Path(u.file_path).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            ftypes = {}
        impl_hit = []
        for var, meth in calls:
            iface = ftypes.get(var, "")
            if not iface.endswith("Service"):
                continue
            b = _impl_method_body(iface, meth)
            if b and _norm(b)[:60] in _norm(src):
                impl_hit.append(f"{iface}.{meth}")
        has_xml = bool(XML_SQL_RE.search(src))
        inc = INCLUDE_RE.findall(src)
        # include 是否**只剩字面量**（未展开）：切片里出现 <include 且没有对应 <sql id=...>
        unexpanded = [r for r in inc if f'<sql id="{r}"' not in src]
        if hops:
            stats["hop_any"] += 1
        if impl_hit:
            stats["impl"] += 1
        if has_xml:
            stats["xml"] += 1
        if inc:
            stats["xml_raw"] += 1
        if unexpanded:
            stats["include_left"] += 1
        rows.append((u.unit_name, len(hops), len(calls), len(impl_hit), len(inc), unexpanded))
        if args.unit and args.unit in u.unit_name:
            print("=" * 78)
            print(u.unit_name)
            print("-" * 78)
            print(src)

    print()
    print("① 切片穿透（n=%d）" % len(units))
    print(f"   有跨文件 Hop 段        : {stats['hop_any']}")
    print(f"   ServiceImpl 方法体在内 : {stats['impl']}")
    print(f"   Mapper XML SQL 在内    : {stats['xml']}")
    print(f"   含 <include refid>      : {stats['xml_raw']}")
    print(f"   其中 refid 未展开       : {stats['include_left']}")
    print()
    print("② 逐入口明细（hops / service 调用数 / impl 命中 / include 数 / 未展开 refid）")
    for name, h, c, i, n, un in rows:
        flag = ""
        if c and not i:
            flag = "  <-- Service 调了但 impl 没进来"
        if un:
            flag += "  <-- include 未展开: " + ",".join(un)
        print(f"   {name:<46} {h} / {c} / {i} / {n}{flag}")

    if args.authz:
        from core.agents.rule_detectors import authz_verdict
        print()
        print("③ authz 判定")
        for u in units:
            if not any(k in u.unit_name for k in ("Order", "Address", "Cart", "User", "Personal")):
                continue
            v = authz_verdict(u.source_code)
            print(f"   {u.unit_name:<46} {v}")


if __name__ == "__main__":
    main()
