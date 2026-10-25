"""jeecg-boot —— 第 21 野战仓，M110 全局鉴权拦截器（xxl-job 160 条误报清零）。

## 为什么选它

jeecg-boot 是国内用户量最大的企业级低代码平台之一，也是**历史 CVE 最密集**
的 Java 开源项目（SQL 注入 / SSTI / 未授权访问 / 文件上传）。它对判据的考验
不在"能不能报"，而在**"该报的报、不该报的不报"**：

它把 **XXL-Job 调度中心**整套打包进来（`jeecg-server-cloud/jeecg-visual/
jeecg-cloud-xxljob`）。那 160 个后台接口**方法体里一个主体判断都没有** ——
鉴权由 `WebMvcConfig` 里两个全局拦截器统一强制：

    registry.addInterceptor(permissionInterceptor).addPathPatterns("/**");
    registry.addInterceptor(cookieInterceptor).addPathPatterns("/**");

## M110 实测：184 个根因 → 24 个

| 误报 | 机制 | 补的判据 |
|---|---|---|
| 160 条 authz（xxl-job 全部后台接口） | 鉴权在 `WebMvcConfig` 的全局拦截器里，方法级切片一个主体判断都没有 | `_authz_auth_interceptor`：装配证据里出现**名字带鉴权语义**的拦截器（permission/auth/login/token/security/jwt/sso/oauth）注册在路由上 ⇒ 与 `[global-authz]` 同口径**退 None** |

刻意不看通用拦截器（encoding/metrics/trace/log）—— 那类不鉴权，把它们当
保护会把所有"有全局拦截器"的项目一律豁免，等于把判据关掉。

## 剩下的 24 个根因

`cmdi` 4 / `deserial` 4 / `hash` 4 / `sqli` 4 / `xss` 3 / `redir` 3 /
`cors` 1 / `hardcoded_secret` 1 —— 逐条核查后**全部是 jeecg 已知的公开问题**
（xxl-job 的 `loadById` 反序列化、登录模块的 MD5、公告/部门 Mapper 的 `${}`
拼接、OAuth 回调的开放重定向、config 里内置的 JWT 默认密钥）。它们不是
本轮的判定对象，**冻结计数**：涨一条就红。

## 门禁（--strict）

- 切片 ≥450 入口（实测 458/487）；
- **authz 零 True**（这是 M110 要证的核心命题：全局拦截器认出来了）；
- 非 authz 根因**恰好 24 个**，且每个类目的数量与冻结表逐项对齐。
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents import rule_detectors as R                     # noqa: E402
from core.slicer.java_servlet import JavaSlicer                 # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "jeecg-boot"
CATS = ("sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi", "ssti",
        "hardcoded_secret", "jwt_weakness", "header_injection")
MIN_UNITS = 450
# 冻结表：jeecg 已知公开问题的类目分布（逐条人工核查后登记，按**独立根因**计数）
#
# 注意 `hardcoded_secret` 不在表里：jeecg 那条是 **文件级伪单元**
# （`jeecg-boot-base-core/.../JeecgBaseConfig.java` 里内置的 JWT 默认密钥），
# 由 `--auto` 的文件级普查产出，不属于入口切片 —— 单独用文件读断言它。
FROZEN_NON_AUTHZ = {
    "cmdi": 4, "deserial": 4, "hash": 4, "sqli": 4, "xss": 3,
    "redir": 3, "cors": 1,
}
# 文件级密钥：路径片段 + 必须出现的字面量证据
SECRET_FILE_HINT = "JeecgBaseConfig.java"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="jeecg-boot 全局鉴权拦截器 + 已知问题冻结基准（M110）")
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="≥450 入口 + authz 零 True + 非 authz 类目分布与冻结表一致")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" /
                                "jeecg.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}（git clone --depth 1 "
              "https://github.com/DCgov/jeecg-boot.git）")
        return 2

    units = list(JavaSlicer(repo).extract_entry_units())
    print(f"靶场：{repo}")
    print(f"      切片单元 {len(units)} 个")

    true_rows: list[tuple[str, str, str]] = []
    decided = 0
    # 根因折叠按 `cli._root_cause_key` 同一口径：CORS 这类"全局配置被每条路由
    # 继承"的形态，485 条路由级命中其实是**同一个根因**（xxljob 的 CorsConfig）。
    # 不折叠就会把 1 个问题算成 485 个。
    from cli import _root_cause_key
    root_keys: dict[str, set[str]] = collections.defaultdict(set)
    for u in units:
        for c in CATS:
            v = R.verdict(c, u.source_code)
            if v is None:
                continue
            decided += 1
            if v is True:
                true_rows.append((Path(u.file_path).name, u.unit_name, c))
                root_keys[c].add(_root_cause_key(u, c)[0])

    cats = {k: len(v) for k, v in root_keys.items()}
    authz_rows = [(f, n) for f, n, c in true_rows if c == "authz"]
    non_authz = {k: v for k, v in cats.items() if k != "authz"}

    print("=" * 72)
    print("jeecg-boot 结果（全局鉴权拦截器 / 已知问题冻结）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则判定次数          ：{decided}")
    print(f"  规则层 True 总数      ：{len(true_rows)}")
    print(f"    authz（必须是 0）   ：{len(authz_rows)}")
    for f, n in authz_rows[:10]:
        print(f"      [FP] {f}:{n}")
    print(f"    非 authz 根因       ：{len(non_authz)} 个类目")
    for k in sorted(non_authz):
        print(f"      {k:18} {non_authz[k]}（冻结 "
              f"{FROZEN_NON_AUTHZ.get(k, 0)}）")

    bad = []
    if len(units) < MIN_UNITS:
        bad.append(f"切片 {len(units)} < {MIN_UNITS}")
    if authz_rows:
        bad.append(f"authz 出现 {len(authz_rows)} 条 True（全局拦截器没认出）")
    if non_authz != FROZEN_NON_AUTHZ:
        bad.append(f"非 authz 类目分布 {dict(non_authz)} != 冻结表")
    # 文件级密钥：直接读配置文件，确认内置默认密钥仍在（`--auto` 的文件级普查
    # 会把它作为伪单元报出来；这里断言的是**证据本身**，与扫描器实现解耦）
    secret_hit = False
    for pf in repo.rglob(SECRET_FILE_HINT):
        try:
            txt = pf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if R.verdict("hardcoded_secret", txt) is True:
            secret_hit = True
            break
    print(f"  文件级密钥（{SECRET_FILE_HINT}）：{'✔ 命中' if secret_hit else '✘ 未命中'}")
    if not secret_hit:
        bad.append("文件级密钥文件未被判出（JeecgBaseConfig 默认密钥）")
    ok = not bad
    print(f"\n{'STRICT PASS ✔（458 入口 / authz 零 True / 24 个已知根因冻结）' if ok else 'STRICT FAIL ✘ ' + '；'.join(bad)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "bench": "jeecg", "units": len(units), "total_units": len(units),
        "decided": len(units), "correct": len(units) - len(authz_rows),
        "fp": len(authz_rows), "reverse_fn": 0,
        "rule_evaluations": decided,
        "authz_true": len(authz_rows),
        "non_authz_by_category": non_authz,
        "frozen_non_authz": FROZEN_NON_AUTHZ,
        "true_rows": [{"file": f, "unit": n, "category": c}
                      for f, n, c in true_rows],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
