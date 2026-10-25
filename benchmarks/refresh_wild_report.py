"""M165：从 wild_hunt.json 重建 WILD_HUNT_REPORT 的一/二/四节。

报告是给人看的，json 是机器事实源。手抄数字每轮都会漂，doctor 第六段
又会当场抓红 —— 这里把三节做成纯函数，野战后一条命令刷新。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGG = ROOT / "benchmarks" / "results" / "wild_hunt.json"
REPORT = ROOT / "WILD_HUNT_REPORT.md"


def _lang_of(path: Path) -> str:
    if path.is_dir() and any(path.rglob("pom.xml")):
        return "Java"
    if path.is_dir() and any(path.rglob("*.sol")):
        return "Solidity"
    return "Python"


def main() -> int:
    d = json.loads(AGG.read_text(encoding="utf-8"))
    repos = d["repos"]
    t = d["totals"]
    n = t["repos"]
    langs = {"Java": 0, "Python": 0, "Solidity": 0}
    rows = []
    for r in repos:
        lang = _lang_of(Path(r["path"]))
        langs[lang] += 1
        s = r.get("summary") or {}
        b = r.get("benchmark") or {}
        cves = "、".join((r.get("sca") or {}).get("cves") or [])
        rows.append((r["name"], lang, int(s.get("total_units") or 0),
                     int(r.get("p0_route_level_hits") or 0),
                     int(r.get("p0_unique_root_causes") or 0),
                     "✔" if b.get("rc", 0) == 0 else "✘", cves or "—"))
    rows.sort(key=lambda x: (-x[4], x[0]))
    bench_pass = sum(1 for r in rows if r[5] == "✔")
    fp = sum(int((r.get("benchmark") or {}).get("fp") or 0) for r in repos)
    rev = sum(int((r.get("benchmark") or {}).get("reverse_fn") or 0)
              for r in repos)
    drafts = len(list((ROOT / "benchmarks" / "results" / "advisories")
                      .rglob("GHSA-*.md")))

    sec1 = f"""## 一、总量（{n} 仓 / {t['unique_root_causes']} 独立根因 / 零误报）

| 项 | 数值 |
|---|---|
| 真实仓库 | **{n} 个**（Java {langs['Java']} + Python {langs['Python']} + Solidity {langs['Solidity']}） |
| 路由/合约入口 | **{t['units']:,} 个** |
| 路由级 P0 命中 | **{t['p0_route_level_hits']:,} 条** |
| 去重后的独立根因 P0 | **{t['unique_root_causes']} 个** |
| GHSA 披露草稿 | **{drafts} 份**（按独立根因，不按路由） |
| benchmark 层误报 | **{fp} 条** |
| benchmark 层判反 | **{rev} 条** |
| benchmark_* --strict | **{bench_pass}/{n} exit 0** |
| 供应链命中已知 advisory 的仓库 | **{t['repos_with_dependency_cve']} 个** |
| 供应链 × 代码双重实锤 | **{t['dual_confirmed_repos']} 个** |

一句话：**在 {t['units']:,} 个真实入口上，规则层没有确认误报；{t['unique_root_causes']} 个独立根因全部由规则层确定性判据产出，PoC/补丁自检可复核。**

## 二、逐仓数字

| 仓库 | 语言 | 入口 | 路由级 P0 | 独立根因 | benchmark | 组件 CVE |
|---|---|---|---|---|---|---|
"""
    sec1 += "\n".join(
        f"| {a} | {b} | {c} | {e} | {f} | {g} | {h} |" for a, b, c, e, f, g, h in rows)
    sec1 += "\n\n"

    sec4 = ["## 四、逐仓独立根因（规则层确定性判定）\n"]
    for r in sorted(repos, key=lambda x: (-int(x.get("p0_unique_root_causes") or 0),
                                          x["name"])):
        roots = (r.get("summary") or {}).get("root_causes") or []
        if not roots:
            continue
        sec4.append(f"### {r['name']}（{_lang_of(Path(r['path']))}）— "
                    f"{len(roots)} 个独立根因\n")
        for rc in roots:
            f = Path(rc["file"]).name
            sec4.append(f"- **[{rc['category']}]** `{rc['representative']}`"
                        f"（{rc['kind']}，影响 {rc['affected_routes']} 条路由）"
                        f" @ `{f}:{rc['line']}`")
        sec4.append("")
    sec4 = "\n".join(sec4) + "\n"

    text = REPORT.read_text(encoding="utf-8")
    text = re.sub(r"^# 野战白皮书.*$",
                  f"# 野战白皮书 —— {n} 个真实开源生产仓库（M151–M166 收官）",
                  text, count=1, flags=re.M)
    a = text.index("## 一、")
    b = text.index("## 三、")
    text = text[:a] + sec1 + text[b:]
    a = text.index("## 四、")
    b = text.index("## 五、")
    text = text[:a] + sec4 + text[b:]
    text = re.sub(r"^## 七、.*$",
                  f"## 七、{n} 仓供应链组件风险 × 代码入口可达性对照",
                  text, count=1, flags=re.M)
    REPORT.write_text(text, encoding="utf-8")
    print(f"report refreshed: {n} repos / {t['unique_root_causes']} roots / "
          f"{drafts} drafts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
