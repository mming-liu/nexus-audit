"""跨仓库同源缺陷聚类（M126）。

## 要回答的问题

25 个真实仓库跑出 84 个独立根因之后，一个自然的问题：**这 84 个里有多少是
同一个缺陷模板的多次出现？** 比如"Spring 全局 CORS 通配 + 携带凭证"在
`waynboot-mall` / `mall4j` / `eladmin` / `eladmin-mp` 各出现一次 —— 对使用者
来说那是**一个**知识点，不是一个新问题。

## 聚类键怎么选（这是本模块的全部难度）

不能用"类目"当键 —— 那样 `sqli` 一个大类全归一堆，信息量归零。
不能用"文件名 + 方法名"当键 —— 跨仓库文件名必然不同。
用**规范化后的 sink 形态**：把类目与该根因的引擎证据（签名 kind +
证据文件名归一化）合起来。具体：

    key = (category, root_kind, normalized_engine_evidence)

其中 `normalized_engine_evidence` 从根因的 `file` 里取**框架组件名**：
`MobileSaTokenConfiguration.java` → `CorsConfiguration`（配置类）；
`AuthConfig.java` → `AuthConfig`；`EncryptUtils.java` → `EncryptUtils`。

于是"跨 4 仓共现：CORS 通配配置"就自然聚成一类，而"某业务 Controller 的
一次拼写错误"不会跟别人混在一起。

## 输出

`benchmarks/results/cross_repo_clusters.json` + 一段可直接贴进白皮书的
markdown 表格。**计数守恒**：各簇的仓库数之和必须等于参与聚类的根因总数
（每个根因只归一个簇），这是冒烟 `[163]` 的断言点。
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# M150：`--check` 的判定行带 `✔/✘`，写侧钉 UTF-8
from core.text_utils import ensure_utf8_stdio        # noqa: E402
ensure_utf8_stdio()

AGG = ROOT / "benchmarks" / "results" / "wild_hunt.json"
OUT = ROOT / "benchmarks" / "results" / "cross_repo_clusters.json"
# M135：多仓共现簇的**下界**。低于这个数，聚类就已经退化成一仓一簇，
# "跨仓同源"的结论不成立 —— 门禁必须拦住这种"数字好看但信息量为零"的状态。
MIN_MULTI_REPO = 8

# 框架组件归一化：把"某个项目的具体类名"映射到"它扮演的框架角色"。
# 只收**角色明确**的组件；收不进来的保持原名（宁可少聚，不可乱聚）。
_ROLE_PATTERNS = (
    (r"(?i)cors", "CorsConfiguration"),
    (r"^AuthConfig$|^SecurityConfig$|^WebSecurityConfig$", "SecurityConfig"),
    (r"^(?:Encrypt|Crypto|Aes|Des)\w*", "CryptoUtils"),
    (r"^(?:Jwt|JWT|Token)\w*(?:Util|Utils|Config)$", "JwtUtils"),
    (r"^(?:File|Upload)\w*(?:Util|Utils)$", "FileUtils"),
    (r"^settings\.py$", "DjangoSettings"),
    (r"^application[\w.-]*\.(?:yml|yaml|properties)$", "AppConfig"),
)


def _component_name(path: str) -> str:
    name = Path(path).name
    # 先去扩展名再匹配 —— 否则 ^AuthConfig$ 永远命中不了 AuthConfig.java
    stem = Path(path).stem
    for pat, role in _ROLE_PATTERNS:
        if re.search(pat, stem) or re.search(pat, name):
            return role
    return name


def cluster(agg_path: Path = AGG) -> dict:
    """把 wild_hunt.json 里的全部根因聚成"跨仓同源"簇。"""
    data = json.loads(Path(agg_path).read_text(encoding="utf-8"))
    members: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)
    counts: dict[tuple[str, str, str], int] = collections.defaultdict(int)
    total = 0
    for repo in data.get("repos", []):
        name = repo.get("name", "?")
        for rc in (repo.get("summary") or {}).get("root_causes") or []:
            total += 1
            # global-config 根因的 ile 是**代表入口**，不是配置类 ——
            # 用签名（= 配置体哈希）当组件，同一份配置文本才会跨仓合并。
            _kind = rc.get("kind", "")
            _comp = (rc.get("signature", "") if _kind == "global-config"
                     else _component_name(rc.get("file", "")))
            key = (rc.get("category", ""), _kind, _comp)
            members[key].add(name)
            counts[key] += 1
    clusters = []
    for (cat, kind, comp), repos in members.items():
        clusters.append({
            "category": cat, "root_kind": kind, "component": comp,
            "repo_count": len(repos), "root_count": counts[(cat, kind, comp)],
            "repos": sorted(repos),
        })
    clusters.sort(key=lambda c: (-c["repo_count"], c["category"],
                                 c["component"]))
    cross = [c for c in clusters if c["repo_count"] > 1]
    return {
        "total_root_causes": total,
        "cluster_count": len(clusters),
        "cross_repo_clusters": len(cross),
        "conservation_ok": sum(c["root_count"] for c in clusters) == total,
        "clusters": clusters,
    }


def render_markdown(res: dict) -> str:
    lines = [
        "## 跨仓库同源缺陷聚类",
        "",
        f"对 {res['total_root_causes']} 个独立根因按"
        f"「类目 + 根因类型 + 框架组件」聚类，得到 **{res['cluster_count']}** 个簇，"
        f"其中 **{res['cross_repo_clusters']}** 个跨仓库共现。",
        "",
        "| 出现仓数 | 类目 | 根因类型 | 框架组件 | 仓库 |",
        "|---|---|---|---|---|",
    ]
    for c in res["clusters"]:
        if c["repo_count"] < 2:
            continue
        lines.append(f"| {c['repo_count']} | {c['category']} | "
                     f"{c['root_kind']} | `{c['component']}` | "
                     f"{', '.join(c['repos'][:6])}"
                     f"{' …' if len(c['repos']) > 6 else ''} |")
    return "\n".join(lines)


def _agg_root_total(agg: dict) -> tuple[int, int]:
    """从 wild_hunt.json 读「独立根因总数」与「仓数」。

    M135：优先读采集端自己算的 `totals.unique_root_causes`（单一口径）；
    老产物没有 totals 时回落到逐仓求和 —— 两条路必须给出同一个数，
    否则说明 `--only` 局部采集把某仓漏了。
    """
    totals = agg.get("totals") or {}
    n = totals.get("unique_root_causes")
    repos = totals.get("repos")
    if not isinstance(n, int):
        n = sum(int((r.get("summary") or {}).get("p0_unique_root_causes") or 0)
                for r in agg.get("repos", []))
    if not isinstance(repos, int):
        repos = len(agg.get("repos", []))
    return n, repos


def check(agg_path: Path = AGG, out_path: Path = OUT,
          min_multi: int = MIN_MULTI_REPO) -> int:
    """`--check` 门禁（M135）：聚类产物与采集产物**必须对得上账**。

    两条断言，缺一不可：

      ① **计数守恒**：各簇根因数之和 == wild_hunt 的独立根因总数。
         少一个说明有根因没归簇（聚类漏了），多一个说明重复计数
         （同一根因进了两个簇）。
      ② **多仓共现簇 ≥ 8**：低于 8 说明聚类退化成"一仓一簇"，
         跨仓同源的结论就不成立了 —— 数字好看但信息量为零。

    返回 0（通过）/ 1（不通过）；缺文件也算不通过（门禁不能因为
    "还没跑"而静默通过）。
    """
    if not agg_path.exists():
        print(f"! [FAIL] 缺 {agg_path}（先跑 benchmarks/wild_hunt.py）")
        return 1
    if not out_path.exists():
        print(f"! [FAIL] 缺 {out_path}（先跑 cross_repo_clusters.py）")
        return 1
    agg = json.loads(Path(agg_path).read_text(encoding="utf-8"))
    res = json.loads(Path(out_path).read_text(encoding="utf-8"))
    roots, repos = _agg_root_total(agg)
    clusters = res.get("clusters") or []
    # 字段名两种都认：`root_count`（本脚本口径）与旧文档里的 `count`
    counted = sum(int(c.get("root_count", c.get("count", 0)))
                  for c in clusters)
    multi = sum(1 for c in clusters if int(c.get("repo_count", 0)) >= 2)
    stored_total = res.get("total_root_causes")
    print(f"  采集：{repos} 仓 / 独立根因 {roots}")
    print(f"  聚类：{len(clusters)} 簇 / 簇内根因合计 {counted}"
          f" / 多仓共现 {multi}")
    ok = True
    if counted != roots:
        print(f"  [FAIL] 计数不守恒：簇内合计 {counted} != 采集总数 {roots}")
        ok = False
    else:
        print("  [OK] 计数守恒（每个根因恰好归一个簇）")
    if stored_total is not None and int(stored_total) != roots:
        print(f"  [FAIL] 聚类产物的 total_root_causes={stored_total}"
              f" 与采集 {roots} 不一致（产物是旧的，需重跑聚类）")
        ok = False
    if multi < min_multi:
        print(f"  [FAIL] 多仓共现簇 {multi} < {min_multi}"
              "（聚类退化成了一仓一簇）")
        ok = False
    else:
        print(f"  [OK] 多仓共现簇 {multi} ≥ {min_multi}")
    return 0 if ok else 1


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="跨仓库同源缺陷聚类（M126 建，M135 加 --check 门禁）")
    ap.add_argument("--check", action="store_true",
                    help="只校验产物与 wild_hunt.json 的计数守恒 + 多仓簇下界")
    ap.add_argument("--min-multi-repo", type=int, default=MIN_MULTI_REPO,
                    help=f"多仓共现簇下界（默认 {MIN_MULTI_REPO}）")
    ap.add_argument("--agg", default=str(AGG))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--no-write", action="store_true",
                    help="只打印聚类结果，不写 json（冒烟/试跑用）")
    args = ap.parse_args()
    agg_path, out_path = Path(args.agg), Path(args.out)

    if args.check:
        return check(agg_path, out_path, args.min_multi_repo)

    if not agg_path.exists():
        print(f"! 缺 {agg_path}（先跑 benchmarks/wild_hunt.py）")
        return 2
    res = cluster(agg_path)
    if not args.no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    print(f"根因 {res['total_root_causes']} 个 → 簇 {res['cluster_count']} 个"
          f"（跨仓共现 {res['cross_repo_clusters']} 个）"
          f" ｜ 计数守恒={'✔' if res['conservation_ok'] else '✘'}")
    print(render_markdown(res))
    if not args.no_write:
        print(f"\n结果写入 {out_path}")
    return 0 if res["conservation_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
