"""VAmPI —— 第 16 个靶场，第一个 **Connexion/OpenAPI 路由** 基准。

## 为什么需要这个靶场

erev0s/VAmPI 是 OWASP API Top 10 专门靶场（Flask + Connexion，路由声明
在 openapi3.yml 的 operationId 里）。它补了两块此前没有任何靶场覆盖的
机制面：

1. **OpenAPI 路由通道**（M37 切片层）：函数本体零装饰器，`@app.route`
   家族的识别器全部空转 —— 入口必须从 yml 的
   `operationId: api_views.users.get_by_username` 对回符号表。
2. **JWT 主体链第二形态**（M37 判据层）：主体经
   `User.decode_auth_token(token)` 解出 claim 再取 `resp['sub']` 作查询
   键 —— 机制与 `get_jwt_identity` 同类（"是谁"由 token 决定）。

## 真值来源

**README「List of Vulnerabilities」指名 + 作者代码注释指名**
（铁律 23：只收作者指名的漏洞；`vuln` 开关按 Docker 默认 vulnerable=1
口径，vuln/fixed 双形态同函数时按作者注释指名的 vuln 分支收）：

- `users.get_by_username`  : True  —— README 指名 BOLA（无任何 token
  校验，URL username 直查返回全量用户数据）
- `books.get_by_title`     : True  —— 作者注释
  `# Broken Object Level Authorization`（vuln 分支
  filter_by(book_title=形参) 绕过主体归属，secret 任意读）
- `users.update_password`  : True  —— README 指名 Unauthorized Password
  Change（vuln 分支 filter_by(username=URL形参) 写他人密码）
- `users.me`               : False —— 主体链 resp['sub'] 查自己
- `users.update_email`     : False —— 主体链 resp['sub'] 定位，形参未参与
- `users.delete_user`      : False —— 主体链 + user.admin 门
- `books.add_new_book`     : False —— 主体链，user_id=user.id 落自己

不登记（无确定性判据，混进分母会把能力边界污染成 FPR）：
register_user（Mass Assignment）、login_user（枚举）、debug（信息泄露）、
update_email 的 ReDoS、JWT 弱密钥（需要密钥强度判定）。

## 门禁（--strict）

登记样本全部确定性判定且方向正确：误报 0 / 判反 0 / 退回 None = 0。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.web_treesitter import WebTreeSitterSlicer       # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "VAmPI-main"

# 真值表：键 (file_name, unit_name, start_line)（铁律 23 精确匹配）。
TRUTH: dict[tuple[str, str, int], tuple[str, bool, str]] = {
    ("users.py", "get_by_username", 45): ("authz", True,
        "README 指名 BOLA：无 token 校验，URL username 直查"),
    ("books.py", "get_by_title", 45): ("authz", True,
        "作者注释 # Broken Object Level Authorization（vuln 分支形参定位）"),
    ("users.py", "update_password", 179): ("authz", True,
        "README 指名 Unauthorized Password Change（vuln 分支写他人密码）"),
    ("users.py", "me", 28): ("authz", False,
        "主体链 resp['sub'] 查自己"),
    ("users.py", "update_email", 132): ("authz", False,
        "主体链 resp['sub'] 定位，URL 形参未参与目标定位"),
    ("users.py", "delete_user", 206): ("authz", False,
        "主体链 + user.admin 门"),
    ("books.py", "add_new_book", 17): ("authz", False,
        "主体链，user_id=user.id 落自己"),
}


def run(target: Path, strict: bool, offline: bool, out: Path | None) -> int:
    units = WebTreeSitterSlicer(target).extract_entry_units()
    print(f"VAmPI 结果（Connexion/OpenAPI 路由 + JWT 主体链）")
    print("=" * 72)
    print(f"切片单元 {len(units)}（OpenAPI operationId 通道）")

    # (file, start_line) 精确对位
    by_key = {}
    for u in units:
        by_key.setdefault((Path(u.file_path).name, u.unit_name, u.start_line),
                          []).append(u)
    missing = [k for k in TRUTH if k not in by_key]
    if missing:
        print(f"真值表对不上切片: {missing}")
        return 1

    tp = fp = fn = none_ct = 0
    rows = []
    for key, (cat, truth, why) in sorted(TRUTH.items()):
        u = by_key[key][0]
        rv = rule_verdict(cat, u.source_code or "")
        rows.append({"file": key[0], "unit": key[1], "start_line": key[2],
                     "category": cat, "truth": truth, "rule": rv, "why": why})
        if rv is None:
            none_ct += 1
            print(f"  退回  {key[0]}:{key[1]}  ({why})")
        elif rv == truth:
            tp += 1
            print(f"  判对  {key[0]}:{key[1]}  -> {rv}")
        elif truth is False:
            fp += 1
            print(f"  误报  {key[0]}:{key[1]}  -> {rv} 真值 {truth}")
        else:
            fn += 1
            print(f"  判反  {key[0]}:{key[1]}  -> {rv} 真值 {truth}")

    print(f"\n  判对 {tp}  误报 {fp}  判反 {fn}  退回 {none_ct}"
          f"  （登记 {len(TRUTH)} 条）")
    if out:
        out.write_text(json.dumps(
            {"total_units": len(units), "decided": tp + fp + fn,
             "correct": tp, "fp": fp, "reverse_fn": fn,
             "none": none_ct, "rows": rows},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结果写入 {out}")
    if strict:
        ok = fp == 0 and fn == 0 and none_ct == 0
        print("\nSTRICT 门禁：" + ("通过 ✔（零误报 / 零判反 / 零退回）"
                                    if ok else "未通过 ✘"))
        return 0 if ok else 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="VAmPI 基准（M37）")
    ap.add_argument("--target", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results"
                                          / "vampi.json"))
    a = ap.parse_args()
    return run(Path(a.target), a.strict, a.offline, Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
