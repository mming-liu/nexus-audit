"""M160/M259：Top-10 真实仓库交单包（纯生产仓严选）。

选择口径（M259，全部由 wild_hunt.json + LLM 复核台账现算）：

1. 只收 repo_role != "educational_demo" 的仓库（清出 spring-boot-demo / DjanGoat /
   Employee-Management-System）；
2. 剔除纯 CORS 配置类根因（全局 CORS 是一个配置缺陷，不是一条可独立交单的
   业务入口）；
3. 同一函数的多规则命中合并成一条，取 CVSS 最高者，manifest 里记录合并类目；
4. 每仓最多 2 条根因，按 CVSS / 受影响路由数排序；
5. 若 benchmarks/results/llm_root_triage.json 存在，剔除 LIKELY_FP_GUARDED，
   并把 CONFIRMED_TP 排在 NEEDS_HUMAN 前面（LLM 复核只用于排序/降噪，不是
   人工核验）；
6. 逐条尝试确定性补丁器；补丁自检 True -> False 不通过就跳过，顺延下一条。
   目标 10 条；若剩余候选都过不了自检，允许交付 9 条并如实标注，
   **绝不拿未验证补丁伪造第 10 条**。

每包四件套：

    ADVISORY.md             —— GHSA 草稿（CVSS / 机制 / 污点图 / PoC / diff）
    poc_test.*              —— 可离线运行的 PoC 骨架
    fix.patch               —— 已验证的 unified diff
    SUBMISSION_CHECKLIST.md —— GitHub 私密提交 + CVE 申请流程单

用法：

    python benchmarks/first_blood_packs.py            # 重新选包并生成
    python benchmarks/first_blood_packs.py --check    # 只校验四件套 + 选择口径
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.context.advisory_exporter import export_advisories   # noqa: E402
from core.context import watchtower as W                        # noqa: E402

ensure_utf8_stdio()

OUT = ROOT / "benchmarks" / "results" / "first_blood_packs"
WILD = ROOT / "benchmarks" / "results" / "wild_hunt.json"
TRIAGE = ROOT / "benchmarks" / "results" / "llm_root_triage.json"
LIVE = ROOT / "benchmarks" / "results" / "live_hunt.json"
SELECTION = OUT / "SELECTION.json"
REQUIRED = ("ADVISORY.md", "fix.patch", "SUBMISSION_CHECKLIST.md")
TOP_N = 10
MIN_VERIFIED = 9
MAX_PER_REPO = 2

# 嵌套在工作区里的参考仓没有独立 .git（根仓 remote 是 nexus-audit），
# 这些用人工核对的 GitHub slug 补齐；其余仓从 .git/config 的 origin 推导。
SLUG_OVERRIDES = {
    "newbee-mall": "newbee-ltd/newbee-mall",
    "newbee-mall-api": "newbee-ltd/newbee-mall-api",
    "RuoYi": "yangzongzhuan/RuoYi",
    "eladmin-mp": "elunez/eladmin",
    "mall": "macrozheng/mall",
    "My-Blog": "ZHENFENG13/My-Blog",
    "litemall": "linlinjava/litemall",
    "flaskr": "pallets/flask",
}
_SLUG_CACHE: dict[str, str] = {}


def _live_index() -> dict[tuple[str, str, str], dict]:
    """活水大盘里的 (repo, category, unit) -> 记录；无则空。"""
    if not LIVE.is_file():
        return {}
    try:
        data = json.loads(LIVE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    out = {}
    for r in data.get("records") or []:
        out[(r.get("repo", ""), r.get("category", ""),
             r.get("unit", ""))] = r
    return out


def _origin(live: dict, repo: str, cat: str, unit: str) -> str:
    rec = live.get((repo, cat, unit), {})
    status = rec.get("status")
    if status == "ZERO_RECORD_FRESH":
        return "ZERO_RECORD_FRESH"
    if status in ("DUPLICATE_CVE", "DUPLICATE_ISSUE_OR_GHSA",
                  "PATCHED_UPSTREAM"):
        return "KNOWN_CVE_BENCHMARK"
    return "UNVERIFIED"


def _triage_index() -> dict[tuple[str, str, str], str]:
    """(repo, category, representative) -> CONFIRMED_TP / ...；无台账则空。"""
    if not TRIAGE.is_file():
        return {}
    try:
        data = json.loads(TRIAGE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {(r.get("repo", ""), r.get("category", ""),
             r.get("representative", "")): r.get("verdict", "")
            for r in data.get("roots", [])}


def _candidate_rows(data: dict, triage: dict) -> list[dict]:
    """从 50 仓根因里算候选：剔教学仓/CORS、合并同函数、每仓限 2。"""
    from core.context.cvss import compute_cvss31

    patcher_cats = set(W._cli().MATRIX_FIX_MAP)
    live = _live_index()
    groups: dict[tuple[str, str], list[dict]] = {}
    for repo in data.get("repos", []):
        if repo.get("repo_role") == "educational_demo":
            continue
        repo_name = repo.get("name", "")
        for rc in repo.get("summary", {}).get("root_causes") or []:
            cat = rc.get("category", "")
            if cat == "cors" or cat not in patcher_cats:
                continue
            tv = triage.get((repo_name, cat,
                             rc.get("representative", "")), "")
            if tv == "LIKELY_FP_GUARDED":
                continue
            try:
                cv = compute_cvss31(cat, rc.get("representative", ""), False)
                score = float(cv.get("score") or 0.0)
            except Exception:                                # noqa: BLE001
                score = 0.0
            key = (repo_name, rc.get("representative", ""))
            groups.setdefault(key, []).append({
                "repo": repo_name, "repo_role": repo.get("repo_role", "production"),
                "repo_path": repo.get("path", ""),
                "category": cat, "representative": rc.get("representative", ""),
                "file": rc.get("file", ""), "line": int(rc.get("line") or 0),
                "affected_routes": int(rc.get("affected_routes") or 0),
                "kind": rc.get("kind", ""),
                "score": score, "triage": tv,
                "origin": _origin(live, repo_name, cat,
                                  rc.get("representative", "")),
                "rc": rc,
            })

    merged: list[dict] = []
    for key, group in groups.items():
        group.sort(key=lambda x: (-x["score"], -x["affected_routes"]))
        best = dict(group[0])
        best["merged_categories"] = sorted({g["category"] for g in group})
        best["triage_by_cat"] = {g["category"]: g["triage"] for g in group}
        merged.append(best)

    def triage_rank(c: dict) -> int:
        return (0 if c["triage"] == "CONFIRMED_TP" else
                2 if c["triage"] == "NEEDS_HUMAN" else 1)

    merged.sort(key=lambda c: (triage_rank(c), -c["score"],
                               -c["affected_routes"], c["repo"]))
    picked: list[dict] = []
    per_repo: dict[str, int] = {}
    for c in merged:
        if per_repo.get(c["repo"], 0) >= MAX_PER_REPO:
            continue
        picked.append(c)
        per_repo[c["repo"]] = per_repo.get(c["repo"], 0) + 1
    return picked


def _checklist(repo_name: str, slug: str, rc: dict, has_patch: bool) -> str:
    cwe = rc.get("cwe") or "CWE"
    return f"""# 交单流程单（{repo_name} / {rc['category']} / {rc['unit_name']}）

## 0. 事实核对

- 仓库：https://github.com/{slug}
- 根因：{rc['category']}（{cwe}）
- 位置：{Path(rc['file']).name}:{rc['line']}
- 受影响路由：{rc['affected_routes']} 条（同一独立根因）
- 补丁：{'已验证 True -> False，见 fix.patch' if has_patch else '需人工编写'}

## 1. 私密报告（不要先开公开 issue）

- [ ] 打开 https://github.com/{slug}/security/advisories/new
- [ ] 标题：{cwe} in {rc['unit_name']}
- [ ] 正文粘贴 ADVISORY.md（删掉本流程单）
- [ ] 附上 poc_test.* 与 fix.patch
- [ ] 受影响版本：以当前默认分支 HEAD 为准，再用 git tag --contains 确认区间

## 2. 复现

- [ ] 在仓库内执行 git apply --check fix.patch
- [ ] 按 ADVISORY.md 的 Quick Reproduction 离线复核
- [ ] PoC 只证明"代码路径成立"；线上是否可达由维护者确认部署形态

## 3. CVE / 披露

- [ ] advisory 内点 Request CVE（GitHub 是 CNA），或走 MITRE 表单
- [ ] 附 CWE、CVSS 向量、补丁、复现步骤
- [ ] 默认 90 天协调披露；修复发布后再 published

> 规则层能证明"这条代码路径确定性成立"，证明不了"线上版本一定受影响"。
> 提交前请人工核对版本区间与路由可达性。
"""


def _git_slug(path: Path) -> str:
    import subprocess
    for q in [path, *path.parents]:
        if (q / ".git").is_dir():
            try:
                url = subprocess.run(
                    ["git", "-C", str(q), "remote", "get-url", "origin"],
                    capture_output=True, text=True, timeout=10).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return ""
            m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
            if m and "nexus-audit" not in m.group(1):
                return m.group(1)
            return ""
    return ""


def _slug_lookup(data: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in data.get("repos", []):
        name = r.get("name", "")
        if name in _SLUG_CACHE:
            out[name] = _SLUG_CACHE[name]
            continue
        slug = SLUG_OVERRIDES.get(name) or _git_slug(Path(r.get("path", "")))
        _SLUG_CACHE[name] = slug
        out[name] = slug
    return out


def _file_level_unit(cand: dict):
    """文件级根因（硬编码密钥）没有路由单元，造一个 file_level 伪单元。

    补丁器 _fix_hardcoded_secret 对 file_level 单元走"全文重跑规则"的自检
    分支，正是为这类配置/工具类准备的；没有它，最高危的密钥根因永远进不了
    交单包。
    """
    from core.models import CodeUnit, Language
    path = Path(cand["file"])
    text = path.read_text(encoding="utf-8", errors="replace")
    lang = (Language.PYTHON_WEB if path.suffix == ".py" else
            Language.SOLIDITY_WEB3 if path.suffix == ".sol" else
            Language.JAVA_WEB)
    unit = CodeUnit(file_path=str(path), language=lang,
                    unit_name=cand["representative"], start_line=1,
                    end_line=max(1, len(text.splitlines())),
                    source_code=text, own_body=text)
    unit.file_level = True
    return unit


def _rewrite_pack_metadata(pack: Path, slug: str) -> None:
    """把 GitHub slug 补进 manifest / checklist / advisory（幂等）。

    嵌套参考仓没有独立 .git 时 slug 会暂时为空；生成后用本函数回填，
    避免交单流程单里出现 https://github.com/ 这种断链。
    """
    if not slug:
        return
    mf = pack / "manifest.json"
    if mf.is_file():
        m = json.loads(mf.read_text(encoding="utf-8"))
        m["github"] = slug
        mf.write_text(json.dumps(m, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    ck = pack / "SUBMISSION_CHECKLIST.md"
    if ck.is_file():
        text = ck.read_text(encoding="utf-8")
        text = re.sub(r"- 仓库：https://github\.com/\S*",
                      f"- 仓库：https://github.com/{slug}", text, count=1)
        text = re.sub(
            r"https://github\.com/[^/\s]*/security/advisories/new",
            f"https://github.com/{slug}/security/advisories/new", text, count=1)
        text = text.replace("https://github.com//security/advisories/new",
                            f"https://github.com/{slug}/security/advisories/new")
        ck.write_text(text, encoding="utf-8")
    adv = pack / "ADVISORY.md"
    if adv.is_file():
        text = adv.read_text(encoding="utf-8")
        text = re.sub(r"- Repository: .*",
                      f"- Repository: https://github.com/{slug}", text, count=1)
        adv.write_text(text, encoding="utf-8")


def refresh_metadata() -> int:
    if not SELECTION.is_file():
        print("! 缺 SELECTION.json（先生成一次）")
        return 1
    data = json.loads(WILD.read_text(encoding="utf-8"))
    slugs = _slug_lookup(data)
    live = _live_index()
    sel = json.loads(SELECTION.read_text(encoding="utf-8"))
    missing: list[str] = []
    for i, t in enumerate(sel.get("targets", []), 1):
        t["rank"] = i
        slug = slugs.get(t["repo"], "")
        if not slug:
            missing.append(t["repo"])
        t["github"] = slug
        t["origin"] = _origin(live, t["repo"], t["category"], t["unit"])
        pack = OUT / t["pack"]
        _rewrite_pack_metadata(pack, slug)
        mf = pack / "manifest.json"
        if mf.is_file():
            m = json.loads(mf.read_text(encoding="utf-8"))
            m["origin"] = t["origin"]
            mf.write_text(json.dumps(m, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    SELECTION.write_text(json.dumps(sel, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    print(f"[first-blood] 回填 GitHub slug：{len(sel.get('targets', []))} 个包"
          + (f"；缺 slug：{missing}" if missing else "，全部命中"))
    return 0 if not missing else 1


def _build_one(data: dict, cand: dict, units: list) -> dict | None:
    repo = Path(cand["repo_path"])
    u = next((x for x in units if x.unit_name == cand["representative"]), None)
    if u is None and (cand.get("kind") == "file-level"
                      or cand["representative"].startswith("[secret-file]")):
        u = _file_level_unit(cand)
        print(f"  [file-level] {cand['repo']}/{cand['representative']}")
    if u is None:
        print(f"! 切片里找不到 {cand['repo']}/{cand['representative']}")
        return None
    from core.agents.vuln_categories import CATEGORIES
    rc = dict(cand["rc"])
    rc.setdefault("unit_name", rc.get("representative", ""))
    rc["cwe"] = getattr(CATEGORIES.get(cand["category"]), "cwe", "")
    rc["representative"] = u
    cat = cand["category"]
    poc = W._poc(u, cat)
    diff, _report, patch_ok = W._try_patch(repo, u, cat)
    if not diff or not patch_ok:
        print(f"! {cand['repo']}/{u.unit_name} [{cat}] 补丁未通过自检，顺延")
        return None
    pack_name = f"{cand['repo']}_{cat}_{u.unit_name.split('.')[-1]}"
    pack = OUT / pack_name
    pack.mkdir(parents=True, exist_ok=True)
    fix_text = (f"## [{cat}] {u.unit_name}\n"
                "\x60\x60\x60diff\n" + diff + "\x60\x60\x60\n")
    tmp = pack / ".adv_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    written = export_advisories([rc], repo, tmp, fix_text)
    adv_src = next((p for p in written if p.suffix == ".md"), None)
    if adv_src is None:
        print(f"! {cand['repo']} 未能生成 advisory")
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    (pack / "ADVISORY.md").write_text(
        adv_src.read_text(encoding="utf-8"), encoding="utf-8")
    shutil.rmtree(tmp, ignore_errors=True)
    if poc is not None and poc.content:
        (pack / (poc.path or "poc_test.txt")).write_text(poc.content,
                                                         encoding="utf-8")
    (pack / "fix.patch").write_text(diff, encoding="utf-8")
    (pack / "SUBMISSION_CHECKLIST.md").write_text(
        _checklist(cand["repo"], _slug_lookup(data).get(cand["repo"], ""),
                   rc, True), encoding="utf-8")
    (pack / "manifest.json").write_text(json.dumps({
        "repo": cand["repo"], "repo_role": cand["repo_role"],
        "github": _slug_lookup(data).get(cand["repo"], ""), "category": cat,
        "unit": u.unit_name, "file": Path(cand["file"]).name,
        "line": cand["line"], "affected_routes": cand["affected_routes"],
        "cvss": cand["score"], "triage": cand["triage"],
        "origin": cand.get("origin", "UNVERIFIED"),
        "merged_categories": cand["merged_categories"],
        "patch_verified": True,
        "poc_ok": bool(poc and poc.self_check_ok),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [OK] {pack.name}  CVSS {cand['score']:.1f} / "
          f"triage={cand['triage'] or 'unreviewed'} / "
          f"PoC {'✓' if poc and poc.self_check_ok else '—'} / 补丁 ✓")
    return {"rank": 0, "repo": cand["repo"], "repo_role": cand["repo_role"],
            "category": cat, "unit": u.unit_name, "file": cand["file"],
            "line": cand["line"], "affected_routes": cand["affected_routes"],
            "cvss": cand["score"], "triage": cand["triage"],
            "origin": cand.get("origin", "UNVERIFIED"),
            "merged_categories": cand["merged_categories"],
            "pack": pack_name}


def _existing_packs() -> dict[tuple[str, str, str], tuple[str, dict]]:
    """已生成的完整包（四件套齐全）按 (repo, cat, unit) 索引，重跑时复用。"""
    out: dict[tuple[str, str, str], tuple[str, dict]] = {}
    if not OUT.is_dir():
        return out
    for d in OUT.iterdir():
        mf = d / "manifest.json"
        if not (d.is_dir() and mf.is_file()):
            continue
        if not all((d / f).is_file() for f in REQUIRED):
            continue
        if (d / "fix.patch").stat().st_size <= 0:
            continue
        if "[Auto-Fix Verified]" not in (d / "ADVISORY.md").read_text(
                encoding="utf-8", errors="replace"):
            continue
        try:
            m = json.loads(mf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        out[(m.get("repo", ""), m.get("category", ""),
             m.get("unit", ""))] = (d.name, m)
    return out


def generate() -> int:
    if not WILD.exists():
        print(f"! 缺 {WILD}（先跑 wild_hunt）")
        return 2
    data = json.loads(WILD.read_text(encoding="utf-8"))
    cands = _candidate_rows(data, _triage_index())
    print(f"候选 {len(cands)} 条（已剔教学仓/CORS、合并同函数、每仓≤2）")
    OUT.mkdir(parents=True, exist_ok=True)
    slugs = _slug_lookup(data)
    existing = _existing_packs()
    units_cache: dict[str, list] = {}
    selected: list[dict] = []
    for cand in cands:
        if len(selected) >= TOP_N:
            break
        key = (cand["repo"], cand["category"], cand["representative"])
        if key in existing:
            pack_name, m = existing[key]
            _rewrite_pack_metadata(OUT / pack_name, slugs.get(cand["repo"], ""))
            m.update({
                "repo_role": cand["repo_role"],
                "github": slugs.get(cand["repo"], ""),
                "cvss": cand["score"], "triage": cand["triage"],
                "origin": cand.get("origin", "UNVERIFIED"),
                "merged_categories": cand["merged_categories"],
                "affected_routes": cand["affected_routes"],
            })
            (OUT / pack_name / "manifest.json").write_text(
                json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
            selected.append({
                "rank": 0, "repo": cand["repo"],
                "repo_role": cand["repo_role"], "category": cand["category"],
                "unit": cand["representative"], "file": cand["file"],
                "line": cand["line"], "affected_routes": cand["affected_routes"],
                "cvss": cand["score"], "triage": cand["triage"],
                "origin": cand.get("origin", "UNVERIFIED"),
                "merged_categories": cand["merged_categories"],
                "pack": pack_name,
            })
            print(f"  [reuse] {pack_name}  CVSS {cand['score']:.1f} / "
                  f"triage={cand['triage'] or 'unreviewed'}")
            continue
        key = cand["repo_path"]
        if key not in units_cache:
            print(f"[slice] {cand['repo']} ...", flush=True)
            units_cache[key] = W._slice_all(Path(key))
        try:
            got = _build_one(data, cand, units_cache[key])
        except Exception as e:                                # noqa: BLE001
            print(f"! {cand['repo']}/{cand['representative']} 生成异常："
                  f"{type(e).__name__}: {e}")
            got = None
        if got is None:
            continue
        got["rank"] = len(selected) + 1
        selected.append(got)

    for i, t in enumerate(selected, 1):
        t["rank"] = i
    if len(selected) < TOP_N:
        print(f"! 目标 {TOP_N}，实测 {len(selected)} 条通过补丁自检；"
              "不拿未验证补丁凑数")
    names = {s["pack"] for s in selected}
    removed = 0
    for d in sorted(OUT.iterdir()):
        if d.is_dir() and d.name not in names:
            shutil.rmtree(d)
            removed += 1
    SELECTION.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "human_verified": False,
        "rule": "production only; no cors; merge same function; max 2 per repo; "
                "drop LLM-flagged LIKELY_FP_GUARDED; patch self-check required",
        "targets": selected,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"交单包 {len(selected)} 个 → {OUT}（清理旧包 {removed} 个）")
    return 0 if len(selected) >= MIN_VERIFIED else 1


def check() -> int:
    if not SELECTION.is_file():
        print(f"! 缺 {SELECTION}（先生成一次）")
        return 1
    data = json.loads(WILD.read_text(encoding="utf-8"))
    sel = json.loads(SELECTION.read_text(encoding="utf-8"))
    targets = sel.get("targets") or []
    bad: list[str] = []
    if not (MIN_VERIFIED <= len(targets) <= TOP_N):
        bad.append(f"选择清单 {len(targets)} 条（应 {MIN_VERIFIED}–{TOP_N}）")
    if len(targets) < TOP_N:
        print(f"  [note] Top-{TOP_N} 目标实测 {len(targets)} 条："
              "其余候选补丁自检未过，未拿未验证补丁凑数")
    per_repo: dict[str, int] = {}
    for t in targets:
        per_repo[t["repo"]] = per_repo.get(t["repo"], 0) + 1
        if t.get("repo_role") == "educational_demo":
            bad.append(f"{t['repo']}: 教学仓混入 Top-10")
        if t.get("category") == "cors":
            bad.append(f"{t['repo']}: 纯 CORS 混入 Top-10")
        if t.get("triage") == "LIKELY_FP_GUARDED":
            bad.append(f"{t['repo']}/{t['unit']}: LLM 已判 FP 仍入 Top-10")
        pack = OUT / t["pack"]
        missing = [f for f in REQUIRED if not (pack / f).is_file()]
        has_patch = (pack / "fix.patch").is_file() and \
            (pack / "fix.patch").stat().st_size > 0
        adv = ((pack / "ADVISORY.md").read_text(encoding="utf-8")
               if (pack / "ADVISORY.md").is_file() else "")
        ok = not missing and has_patch and "[Auto-Fix Verified]" in adv
        print(f"  [{'OK' if ok else 'FAIL'}] {t['pack']}"
              f"{' 缺 ' + str(missing) if missing else ''}"
              f"{' 无补丁' if not has_patch else ''}"
              f"{' 缺标记' if '[Auto-Fix Verified]' not in adv else ''}")
        if not ok:
            bad.append(t["pack"])
    for repo, n in per_repo.items():
        if n > MAX_PER_REPO:
            bad.append(f"{repo}: 单仓 {n} 条（上限 {MAX_PER_REPO}）")
    # 目录里不允许残留旧包（否则 INDEX/冒烟会多算）
    dirs = {d.name for d in OUT.iterdir() if d.is_dir()}
    extra = sorted(dirs - {t["pack"] for t in targets})
    if extra:
        bad.append(f"残留旧包：{extra}")
    if bad:
        for b in bad[:10]:
            print(f"[first-blood][FAIL] {b}")
        return 1
    print(f"[first-blood][OK] {len(targets)} 包，"
          f"{len(per_repo)} 个生产仓，每仓 ≤{MAX_PER_REPO} 条")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="生成/校验 Top-10 交单包（M160/M259）")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--refresh-metadata", action="store_true",
                    help="只回填 GitHub slug（不重扫/不重打补丁）")
    args = ap.parse_args()
    if args.check:
        return check()
    if args.refresh_metadata:
        return refresh_metadata()
    return generate()


if __name__ == "__main__":
    sys.exit(main())
