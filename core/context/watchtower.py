"""M152：白盒增量首杀监控（Watchtower）。

为什么需要它：全量野战回答"这个仓库现在有没有洞"，而真实交单节奏问的是
"这次提交有没有新引入洞"。两者口径不同 —— 全量扫出 200 条存量命中，
对赏金/CVE 交单几乎没有价值（维护者会说"这不是本次改动引入的"）；增量
扫描把注意力收窄到本次 diff 改动的方法及其反向调用方，命中才值得立刻
写披露包。

状态机（watch_state.json）：

    {
      "version": 1,
      "repos": {
        "<abs repo path>": {"last_sha": "<40 hex>", "last_run": "<iso8601>",
                             "last_findings": 3}
      }
    }

首跑没有 last_sha 时回看 HEAD~1..HEAD 一个提交，而不是直接记基线跳过：
"第一次挂上监控"本身就应该给出一次结果，否则用户要等下一次提交才知道
它到底工不工作。没有父提交的仓库（单提交）记基线并明确打印"无父提交"。

增量口径：

  1. git diff --name-only <last_sha> HEAD 取变更文件；
  2. 只切三语言入口（Java / Python / Solidity），用与 pr-scan 同一套
     "变更行 -> 所属方法" 反查（直接复用 cli 的实现，避免两套口径漂移）；
  3. hot = 变更方法本身对应的入口；dependent = 调用了变更方法的入口，
     外加框架装配层（Filter/Interceptor）覆盖到的路由；
  4. 规则层 verdict 判 True 的命中，再与 last_sha 的 worktree 基线比对：
     基线已 True 的标 pre-existing 并默认不产包（不是本次引入的）；
  5. 每个新命中产出一个四件套目录：
        ADVISORY.md / poc_test.* / fix.patch / SUBMISSION_CHECKLIST.md
     另有 manifest.json 供 doctor / 冒烟做机器对账。

诚实边界（写进产物，不藏）：

  · watch 只跑规则层，不调用 LLM。规则层判不出的逻辑缺陷不会出现在
    增量结果里 —— 它的定位是"首杀警报器"，不是"完整审计"。
  · fix.patch 只在该类目有确定性补丁器、且补丁器自检 True->False 时生成；
    没有补丁器的类目明确写"需人工修复"，不拿空 diff 冒充。
  · 基线比对按 (仓库相对路径, 单元名) 对齐；重命名文件会退化成"新命中"，
    宁可多报一次也不漏掉真正的新增。
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.agents.vuln_categories import CATEGORIES
from core.context.cvss import compute_cvss31
from core.context.taint_graph import build_taint_graph
from core.models import base_unit_name
from core.sandbox.poc_synthesizer import PocSynthesizer

# 与 CATEGORIES 同源，另外补上检测器专有键（有判据/有补丁器，没有 LLM 问句）。
WATCH_CATEGORIES: list[str] = sorted(CATEGORIES) + ["unchecked_low_level_calls"]

FENCE = chr(96) * 3


@dataclass
class WatchHit:
    """一条增量命中（未落盘前的内存形态）。"""
    repo: Path
    category: str
    unit: object
    origin: str                  # hot / dependent / wiring
    introduced: bool = True      # False = 基线已存在
    baseline: str = "unknown"    # new / pre-existing / unknown
    bundle: Path | None = None
    patch_verified: bool = False
    poc_ok: bool = False

    @property
    def rel_file(self) -> str:
        try:
            return Path(self.unit.file_path).resolve().relative_to(
                self.repo.resolve()).as_posix()
        except (ValueError, OSError):
            return Path(self.unit.file_path).as_posix()


@dataclass
class RepoWatchResult:
    repo: Path
    base: str
    head: str
    changed_files: int = 0
    units: int = 0
    hot: int = 0
    dependent: int = 0
    hits: list[WatchHit] = field(default_factory=list)
    skipped: str = ""
    error: str = ""


# ---------------------------------------------------------------- git 工具

def _git(repo: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout)


def _head_sha(repo: Path) -> str:
    r = _git(repo, "rev-parse", "HEAD")
    return r.stdout.strip() if r.returncode == 0 else ""


def _has_parent(repo: Path) -> bool:
    r = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD~1")
    return r.returncode == 0


def _changed_files(repo: Path, base: str, head: str = "HEAD") -> list[str]:
    r = _git(repo, "diff", "--name-only", base, head)
    if r.returncode != 0:
        return []
    exts = (".py", ".java", ".kt", ".sol", ".xml")
    return [x.strip() for x in r.stdout.splitlines()
            if x.strip() and x.strip().endswith(exts)]


# ---------------------------------------------------------------- 切片 / 影响面

def _slice_all(repo: Path) -> list:
    """三语言入口切片，单语言失败不影响其它语言。"""
    units: list = []
    try:
        from core.slicer.java_servlet import JavaSlicer
        units += list(JavaSlicer(repo).extract_entry_units())
    except Exception:                                        # noqa: BLE001
        pass
    try:
        from core.slicer.web_treesitter import WebTreeSitterSlicer
        units += list(WebTreeSitterSlicer(repo).extract_entry_units(repo))
    except Exception:                                        # noqa: BLE001
        pass
    try:
        from core.slicer.web3_slither import SoliditySlicer
        units += list(SoliditySlicer(repo).extract_entry_units(repo))
    except Exception:                                        # noqa: BLE001
        pass
    seen, out = set(), []
    for u in units:
        key = (str(Path(u.file_path).resolve()), u.unit_name)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def _cli():
    """拿到 cli 模块：作为 __main__ 运行时直接复用，避免二次加载。"""
    mod = sys.modules.get("cli")
    if mod is not None:
        return mod
    main = sys.modules.get("__main__")
    if main is not None and str(getattr(main, "__file__", "")).replace(
            "\\", "/").endswith("/cli.py"):
        return main
    return importlib.import_module("cli")


def _affected(repo: Path, base: str, changed: list[str],
              units: list) -> tuple[list, list, list]:
    """返回 (hot, dependent, wiring) —— 与 pr-scan 同一口径。"""
    cli = _cli()
    changed_methods = cli._changed_methods_of(repo, base, changed)
    funcs = cli._changed_symbols(repo, base, changed)
    changed_funcs: set[str] = set(funcs)
    for names in changed_methods.values():
        changed_funcs |= (names or set())

    hot, dependent = [], []
    changed_set = {str(Path(f).as_posix()) for f in changed}
    for u in units:
        up = str(u.file_path).replace("\\", "/")
        match = next((c for c in changed_set
                      if up.endswith(c) or c.endswith(up)), None)
        if match:
            meths = changed_methods.get(match)
            if meths is None:
                hot.append(u)
            elif base_unit_name(u.unit_name).split(".")[-1] in meths:
                hot.append(u)
            continue
        called = (set(getattr(u, "called_symbols", []) or [])
                  | set(cli._java_called_names(u.source_code)))
        called.discard(base_unit_name(u.unit_name).split(".")[-1])
        if changed_funcs and called & changed_funcs:
            dependent.append(u)

    already = {u.unit_name for u in hot + dependent}
    wiring = cli._wiring_dependents(repo, changed_funcs, units, already)
    return hot, dependent, wiring


# ---------------------------------------------------------------- 基线（worktree）

def _baseline_index(repo: Path, base: str) -> dict[tuple[str, str], set[str]]:
    """在 base 的临时 worktree 上跑一遍规则，得到"改之前就已 True"的集合。

    为什么要 worktree 而不是 git show base:file：Java 切片要跨文件解析
    实现体，单文件回放会让证据段缺一半，基线结论直接失真。worktree 与
    主工作树共享对象库，代价只有一次 checkout。
    """
    from core.agents.rule_detectors import verdict as rule_verdict
    out: dict[tuple[str, str], set[str]] = {}
    tmp = tempfile.mkdtemp(prefix="nexus-watch-base-")
    wt = Path(tmp) / "wt"
    try:
        r = _git(repo, "worktree", "add", "--detach", str(wt), base)
        if r.returncode != 0:
            return out
        for u in _slice_all(wt):
            try:
                rel = Path(u.file_path).resolve().relative_to(
                    wt.resolve()).as_posix()
            except (ValueError, OSError):
                continue
            key = (rel, base_unit_name(u.unit_name))
            for cat in WATCH_CATEGORIES:
                try:
                    if rule_verdict(cat, u.source_code) is True:
                        out.setdefault(key, set()).add(cat)
                except Exception:                            # noqa: BLE001
                    continue
    finally:
        try:
            _git(repo, "worktree", "remove", "--force", str(wt))
        except Exception:                                    # noqa: BLE001
            pass
        try:
            Path(tmp).rmdir()
        except OSError:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
    return out


# ---------------------------------------------------------------- 补丁

def _extract_diff(report: str) -> str:
    m = re.search(re.escape(FENCE) + r"diff\n(.*?)" + re.escape(FENCE),
                  report or "", re.S)
    return m.group(1).strip() + "\n" if m else ""


def _restore_new_changes(repo: Path, before: set[str]):
    """把补丁器遗留的**新增**改动还原；用户原有改动一个字节都不碰。

    补丁器按约定在 finally 里还原，但异常路径可能漏。只对"调用前是干净的、
    调用后变脏的"文件做 git checkout —— 调用前就脏的文件说明是用户改动，
    绝不能用 checkout 覆盖。
    """
    after = {x.strip() for x in _git(repo, "diff", "--name-only").stdout.splitlines()
             if x.strip()}
    for f in sorted(after - before):
        try:
            _git(repo, "checkout", "--", f)
        except Exception:                                    # noqa: BLE001
            pass
    from core.context.java_impl_resolver import _FILE_CACHE
    _FILE_CACHE.clear()


def _try_patch(repo: Path, unit, category: str) -> tuple[str, str, bool]:
    """调确定性补丁器并抓取已验证 diff。返回 (diff, report, verified)。"""
    cli = _cli()
    names = cli.MATRIX_FIX_MAP.get(category, ())
    if not names:
        return "", "", False
    try:
        f = Path(unit.file_path)
        backup = {str(f): f.read_bytes()} if f.is_file() else {}
    except OSError:
        backup = {}
    before = {x.strip() for x in _git(repo, "diff", "--name-only").stdout.splitlines()
              if x.strip()}
    reports: list[str] = []
    for name in names:
        fn = getattr(cli, name, None)
        if not callable(fn):
            continue
        lines: list[str] = []
        try:
            n = fn(repo, [unit], lines)
        except Exception as exc:                             # noqa: BLE001
            lines.append(f"补丁器 {name} 异常：{type(exc).__name__}: {exc}")
            n = 0
        finally:
            for path, data in backup.items():
                try:
                    Path(path).write_bytes(data)
                except OSError:
                    pass
            _restore_new_changes(repo, before)
        report = "\n".join(lines)
        if report:
            reports.append(report)
        diff = _extract_diff(report)
        if n and diff:
            return diff, report, True
    return "", "\n\n".join(reports), False


# ---------------------------------------------------------------- 产物

def _slug(s: str, limit: int = 40) -> str:
    s = re.sub(r"[^0-9A-Za-z._-]+", "-", s or "unit").strip("-")
    return (s or "unit")[:limit]


def _ghsa(repo: Path, hit: WatchHit) -> str:
    sig = f"{repo.resolve()}|{hit.unit.unit_name}|{hit.category}|{hit.unit.start_line}"
    h = hashlib.sha256(sig.encode("utf-8")).hexdigest().upper()
    return f"GHSA-{h[0:4]}-{h[4:8]}-{h[8:12]}"


def _poc(unit, category: str):
    try:
        return PocSynthesizer().synthesize(unit, category)
    except Exception:                                        # noqa: BLE001
        return None


def _advisory(repo: Path, hit: WatchHit, sha: str, poc, patch: str) -> str:
    cat = hit.category
    meta = CATEGORIES.get(cat)
    cwe = meta.cwe if meta else "CWE-000"
    display = meta.display if meta else cat
    cvss = compute_cvss31(cat, hit.unit.unit_name, False)
    graph = build_taint_graph(hit.unit, cat) or (
        FENCE + "mermaid\nflowchart LR\n"
        f'  R["入口 {hit.unit.unit_name}"] --> S["Sink: {cat}"]\n' + FENCE)
    if poc is not None and poc.self_check_ok:
        poc_block = f"{FENCE}{poc.language}\n{poc.content}\n{FENCE}"
        poc_note = f"自检通过：{poc.self_check_msg}"
    elif poc is not None:
        poc_block = f"（PoC 合成自检未通过：{poc.self_check_msg}）"
        poc_note = "需手工补全"
    else:
        poc_block, poc_note = "（未生成 PoC）", "该类目没有合成模板"
    patch_block = (f"{FENCE}diff\n{patch}{FENCE}"
                   if patch else "（该类目没有确定性补丁器，需人工修复）")
    badge = "**[Auto-Fix Verified]**" if patch else ""
    return f"""# {cwe} · {display} in {Path(hit.unit.file_path).name} {badge}

**{_ghsa(repo, hit)}** ｜ 规则层增量 P0 ｜ {hit.origin} ｜ 基线：{hit.baseline}
**CVSS v3.1：{cvss['score']:.1f} {cvss['severity']}** ｜ {cvss['vector']}

## Affected Component

- Repository: {repo}
- Commit: {sha}
- File: {hit.rel_file}:{hit.unit.start_line}
- Representative entry: {hit.unit.unit_name}
- Introduced by this change: **{hit.introduced}**

## Vulnerability Mechanism

类目 {cat}（{cwe}）。该入口在本次 diff 的受影响面内（{hit.origin}），
规则层给出确定性 True；基线 worktree 上同一入口的结论为 {hit.baseline}。

## Taint Flow

{graph}

## PoC Harness

{poc_block}

> {poc_note}

## Verified Patch

{patch_block}

## Quick Reproduction Command

{FENCE}bash
python cli.py watch {repo} --since {sha}~1
{FENCE}

## References

- CWE: https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html
- Generated by nexus-audit cli.py watch
"""


def _checklist(hit: WatchHit, sha: str, patch_ok: bool) -> str:
    patch_line = ("fix.patch 已实测 True->False，可直接附上" if patch_ok
                  else "该类目无确定性补丁器，需人工给出修复建议")
    poc_line = "通过" if hit.poc_ok else "未通过，需手工补全"
    return f"""# 交单流程单（{hit.category} / {hit.unit.unit_name}）

- [ ] **1. 私密报告**：在 GitHub 仓库 Security -> Advisories -> New draft
      security advisory 创建私密草稿（不要先开公开 issue）。
- [ ] **2. 影响面确认**：受影响版本以 {sha} 为准；确认该入口在
      {hit.rel_file} 的路由确实可达（{hit.unit.unit_name}）。
- [ ] **3. 复现**：按 ADVISORY.md 的 Quick Reproduction 命令离线复核；
      PoC 自检：{poc_line}。
- [ ] **4. 补丁**：{patch_line}；
      在仓库内 git apply --check fix.patch 后再跑全量测试。
- [ ] **5. 版本区间**：用 git tag --contains {sha} 或发布记录确认
      受影响版本区间与修复版本号。
- [ ] **6. CVE 申请**：通过 GitHub CNA（Security advisory 内 Request CVE）
      或 MITRE 表单提交；附 CWE、CVSS 向量、补丁与复现步骤。
- [ ] **7. 披露节奏**：默认 90 天协调披露；维护者确认修复后更新 advisory
      为 published，并同步 GHSA ID。

> 本清单由 nexus-audit 自动生成；勾选前请逐条人工核对，尤其是影响面与
> 版本区间 —— 规则层能证明"代码路径成立"，证明不了"线上版本受影响"。
"""


def _write_bundle(repo: Path, hit: WatchHit, sha: str, bundle_dir: Path) -> Path:
    name = (f"{_slug(repo.name, 24)}_{sha[:8]}_{_slug(hit.category, 24)}_"
            f"{_slug(base_unit_name(hit.unit.unit_name).replace('.', '_'), 32)}")
    out = bundle_dir / name
    out.mkdir(parents=True, exist_ok=True)
    poc = _poc(hit.unit, hit.category)
    patch, report, patch_ok = _try_patch(repo, hit.unit, hit.category)
    hit.patch_verified = patch_ok
    hit.poc_ok = bool(poc is not None and poc.self_check_ok)
    (out / "ADVISORY.md").write_text(
        _advisory(repo, hit, sha, poc, patch), encoding="utf-8")
    if poc is not None and poc.content:
        fname = poc.path or f"poc_{_slug(hit.category)}.txt"
        (out / fname).write_text(poc.content, encoding="utf-8")
    if patch:
        (out / "fix.patch").write_text(patch, encoding="utf-8")
    (out / "SUBMISSION_CHECKLIST.md").write_text(
        _checklist(hit, sha, patch_ok), encoding="utf-8")
    (out / "fix_report.md").write_text(report or "（无补丁报告）", encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps({
        "repo": str(repo), "commit": sha, "category": hit.category,
        "unit": hit.unit.unit_name, "file": hit.rel_file,
        "line": hit.unit.start_line, "origin": hit.origin,
        "introduced": hit.introduced, "baseline": hit.baseline,
        "poc_ok": hit.poc_ok, "patch_verified": patch_ok,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    hit.bundle = out
    return out


# ---------------------------------------------------------------- 状态

def _load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("repos"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "repos": {}}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- 主入口

def run_watch(repos: list[str | Path], since: str | None = None,
              state_file: str | Path = ".watch_state.json",
              bundle_dir: str | Path = "watch_bundles",
              categories: list[str] | None = None,
              check_baseline: bool = True,
              include_existing: bool = False,
              dry_run: bool = False) -> dict:
    """对一组本地 Git 仓库做一次增量首杀监控。

    返回机器可读摘要（供 cli --json / 冒烟断言）：
        {"repos": [...], "hits": [...], "bundle_count": N}
    """
    from core.agents.rule_detectors import verdict as rule_verdict

    cats = list(categories or WATCH_CATEGORIES)
    state_path = Path(state_file)
    state = _load_state(state_path)
    bundle_root = Path(bundle_dir)
    results: list[RepoWatchResult] = []

    for raw in repos:
        repo = Path(raw).expanduser().resolve()
        res = RepoWatchResult(repo=repo, base="", head="")
        if not (repo / ".git").exists() and not (repo / ".git").is_file():
            res.error = "不是 git 仓库"
            results.append(res)
            continue
        head = _head_sha(repo)
        res.head = head
        if not head:
            res.error = "仓库没有提交"
            results.append(res)
            continue
        base = since or (state["repos"].get(str(repo), {}) or {}).get("last_sha", "")
        if not base:
            if _has_parent(repo):
                base = "HEAD~1"
                print(f"[watch] {repo.name}: 首跑，回看 HEAD~1..HEAD")
            else:
                res.skipped = "首跑且无父提交，已记基线"
                state["repos"][str(repo)] = {
                    "last_sha": head,
                    "last_run": datetime.now(timezone.utc).isoformat(),
                    "last_findings": 0}
                results.append(res)
                continue
        res.base = base
        changed = _changed_files(repo, base, head)
        res.changed_files = len(changed)
        if not changed:
            print(f"[watch] {repo.name}: {base}..{head} 无代码变更")
            state["repos"][str(repo)] = {
                "last_sha": head,
                "last_run": datetime.now(timezone.utc).isoformat(),
                "last_findings": 0}
            results.append(res)
            continue
        print(f"[watch] {repo.name}: {len(changed)} 个代码文件变更（{base}..{head}）")
        try:
            units = _slice_all(repo)
            res.units = len(units)
            hot, dependent, wiring = _affected(repo, base, changed, units)
            res.hot, res.dependent = len(hot), len(dependent)
            print(f"[watch]   入口 {len(units)} / 变更入口 {len(hot)} / "
                  f"反向依赖 {len(dependent)} / 装配级 {len(wiring)}")
            baseline = _baseline_index(repo, base) if check_baseline else {}

            seen: set[tuple[str, str]] = set()
            for origin, group in (("hot", hot), ("dependent", dependent),
                                  ("wiring", wiring)):
                for u in group:
                    key = (str(Path(u.file_path).resolve()), u.unit_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    for cat in cats:
                        try:
                            if rule_verdict(cat, u.source_code) is not True:
                                continue
                        except Exception:                    # noqa: BLE001
                            continue
                        try:
                            rel = Path(u.file_path).resolve().relative_to(
                                repo.resolve()).as_posix()
                        except (ValueError, OSError):
                            rel = Path(u.file_path).as_posix()
                        pre = cat in baseline.get(
                            (rel, base_unit_name(u.unit_name)), set())
                        if pre and not include_existing:
                            continue
                        res.hits.append(WatchHit(
                            repo=repo, category=cat, unit=u, origin=origin,
                            introduced=not pre,
                            baseline="pre-existing" if pre
                            else ("new" if check_baseline else "unknown")))
            if not dry_run:
                for hit in res.hits:
                    _write_bundle(repo, hit, head, bundle_root)
            print(f"[watch]   新命中 {len(res.hits)} 条，"
                  f"产物 {sum(1 for h in res.hits if h.bundle)} 个")
        except Exception as exc:                             # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
            print(f"[watch]   [!] {res.error}")
            results.append(res)
            continue
        state["repos"][str(repo)] = {
            "last_sha": head,
            "last_run": datetime.now(timezone.utc).isoformat(),
            "last_findings": len(res.hits)}
        results.append(res)

    if not dry_run:
        _save_state(state_path, state)
    payload = {
        "repos": [{
            "repo": str(r.repo), "base": r.base, "head": r.head,
            "changed_files": r.changed_files, "units": r.units,
            "hot": r.hot, "dependent": r.dependent,
            "hits": len(r.hits), "skipped": r.skipped, "error": r.error,
            "bundles": [str(h.bundle) for h in r.hits if h.bundle],
        } for r in results],
        "hits": [{
            "repo": str(h.repo), "category": h.category,
            "unit": h.unit.unit_name, "file": h.rel_file,
            "line": h.unit.start_line, "origin": h.origin,
            "introduced": h.introduced, "baseline": h.baseline,
            "patch_verified": h.patch_verified, "poc_ok": h.poc_ok,
        } for r in results for h in r.hits],
        "bundle_count": sum(1 for r in results for h in r.hits if h.bundle),
        "state_file": str(state_path),
    }
    return payload
