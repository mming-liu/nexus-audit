"""M267：远端默认分支 HEAD 同步与“目标方法是否仍存活”校验。

活水首杀的第一道闸门不是“本地扫到了”，而是“远端最新 HEAD 上这个方法
还存在、且没有被修复注释停用”。本模块只做只读的 git 操作：

  · 远端仓浅克隆/fetch 到 .cache/upstream/（绝不改目标仓工作树）
  · 解析默认分支（main/master/其它）
  · 从 HEAD 读取目标文件，定位方法；被注释、被删除、上下文带 GHSA/CVE
    修复标记 → PATCHED_UPSTREAM
  · 返回 head_sha + 行号，供报告生成“永久链接”（禁止用分支名）

失败时一律返回 UNKNOWN，绝不把“没拉到”当成“还活着”。
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE_ROOT = ROOT / ".cache" / "upstream"

_SLUG_RE = re.compile(r"github\.com[:/]+([^/]+)/([^/#?]+?)(?:\.git)?$", re.I)
_REPAIR_MARK_RE = re.compile(r"\b(?:GHSA-[0-9A-Za-z-]{8,}|CVE-\d{4}-\d{4,})\b")


def _git(args: list[str], cwd: Path | None = None,
         timeout: int = 120) -> tuple[int, str]:
    try:
        env = {**os.environ, "GIT_SSL_BACKEND": "openssl",
               "GIT_TERMINAL_PROMPT": "0"}
        p = subprocess.run(["git", "-c", "http.sslBackend=openssl", *args],
                           cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"


def normalize_slug(value: str) -> str | None:
    """把 https URL / git@ URL / owner/repo 统一成 owner/repo。"""
    if not value:
        return None
    v = value.strip()
    m = _SLUG_RE.search(v)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", v):
        return v
    return None


def remote_url(slug: str) -> str:
    return f"https://github.com/{slug}.git"


def safe_dirname(slug: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", slug)


def default_branch(slug: str, timeout: int = 60) -> str:
    rc, out = _git(["ls-remote", "--symref", remote_url(slug), "HEAD"],
                   timeout=timeout)
    if rc == 0:
        m = re.search(r"ref:\s+refs/heads/([^\s]+)\s+HEAD", out)
        if m:
            return m.group(1)
    for branch in ("main", "master"):
        rc, _ = _git(["ls-remote", "--exit-code", "--heads",
                      remote_url(slug), branch], timeout=timeout)
        if rc == 0:
            return branch
    return "main"


def sync_repo(slug: str, dest_root: Path = CACHE_ROOT,
              depth: int = 50) -> dict:
    """浅克隆/fetch 到缓存目录；返回 head_sha / branch / path。"""
    dest_root.mkdir(parents=True, exist_ok=True)
    dest = dest_root / safe_dirname(slug)
    branch = default_branch(slug)
    if (dest / ".git").is_dir():
        rc, out = _git(["fetch", "--depth", str(depth), "origin",
                        f"refs/heads/{branch}"], cwd=dest, timeout=180)
        if rc != 0:
            return {"status": "UNKNOWN", "reason": f"fetch_failed: {out[-300:]}",
                    "slug": slug, "branch": branch, "path": str(dest)}
        rc, out = _git(["reset", "--hard", "FETCH_HEAD"], cwd=dest, timeout=60)
        if rc != 0:
            return {"status": "UNKNOWN", "reason": f"reset_failed: {out[-300:]}",
                    "slug": slug, "branch": branch, "path": str(dest)}
    else:
        rc, out = _git(["clone", "--depth", str(depth), "--branch", branch,
                        remote_url(slug), str(dest)], timeout=300)
        if rc != 0:
            return {"status": "UNKNOWN", "reason": f"clone_failed: {out[-300:]}",
                    "slug": slug, "branch": branch, "path": str(dest)}
    rc, sha = _git(["rev-parse", "HEAD"], cwd=dest, timeout=30)
    if rc != 0:
        return {"status": "UNKNOWN", "reason": "rev_parse_failed",
                "slug": slug, "branch": branch, "path": str(dest)}
    return {"status": "OK", "slug": slug, "branch": branch,
            "head_sha": sha.strip(), "path": str(dest)}


def local_head(repo: Path) -> dict:
    """本地仓 HEAD（用于 reference_repos 或客户仓）。"""
    repo = Path(repo).resolve()
    if not (repo / ".git").exists():
        return {"status": "UNKNOWN", "reason": "not_a_git_repo",
                "path": str(repo)}
    rc, sha = _git(["rev-parse", "HEAD"], cwd=repo, timeout=30)
    rc2, branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo,
                       timeout=30)
    if rc != 0:
        return {"status": "UNKNOWN", "reason": "rev_parse_failed",
                "path": str(repo)}
    return {"status": "OK", "head_sha": sha.strip(),
            "branch": branch.strip() if rc2 == 0 else "",
            "path": str(repo)}


def read_at_head(repo: Path, rel_path: str, head_sha: str | None = None) -> str:
    repo = Path(repo)
    sha = head_sha or "HEAD"
    rel = rel_path.replace("\\", "/").lstrip("/")
    rc, out = _git(["show", f"{sha}:{rel}"], cwd=repo, timeout=60)
    return out if rc == 0 else ""


def _comment_flags(lines: list[str]) -> list[bool]:
    """每行是否处在 // 或 /* */ 注释中（含行尾注释）。"""
    out: list[bool] = []
    in_block = False
    for ln in lines:
        s = ln.strip()
        if in_block:
            out.append(True)
            if "*/" in s:
                in_block = False
            continue
        if s.startswith("//"):
            out.append(True)
            continue
        if s.startswith("/*"):
            out.append(True)
            if "*/" not in s:
                in_block = True
            continue
        # 行尾 // 不影响“这一行是否被整行注释”
        out.append(False)
    return out


def _method_span(lines: list[str], name: str) -> tuple[int, int] | None:
    """在 HEAD 文本里定位方法；返回 0-based (start,end)。"""
    pat = re.compile(rf"\b{re.escape(name)}\s*\(")
    for i, ln in enumerate(lines):
        if not pat.search(ln):
            continue
        # 必须像方法声明，不能是调用：行首有修饰符/返回类型，或以 function/def 开头
        s = ln.strip()
        if not (re.match(r"(?:public|protected|private|static|final|synchronized|"
                         r"abstract|native|default|function|def|async|constructor|"
                         r"modifier)\b", s)
                or "{" in s):
            continue
        start = i
        # 向上带注解
        j = start
        while j > 0 and (lines[j - 1].strip().startswith("@")
                         or lines[j - 1].strip().startswith("///")
                         or lines[j - 1].strip().startswith("//")):
            j -= 1
        # 向下找配对花括号（最多 200 行）
        depth = 0
        seen = False
        end = start
        for k in range(start, min(len(lines), start + 220)):
            depth += lines[k].count("{") - lines[k].count("}")
            if "{" in lines[k]:
                seen = True
            if seen and depth <= 0:
                end = k
                break
            end = k
        return max(0, j), end
    return None


def verify_unit_alive_on_head(repo: Path, rel_path: str, unit_name: str,
                              head_sha: str | None = None) -> dict:
    """判定目标方法在 HEAD 上是否仍可达。

    返回 status: ALIVE / PATCHED_UPSTREAM / UNKNOWN；附带 reason / line /
    head_sha / evidence。任何不确定都走 UNKNOWN，不冒充“活着”。
    """
    repo = Path(repo)
    head = head_sha or local_head(repo).get("head_sha")
    if not head:
        return {"status": "UNKNOWN", "reason": "no_head_sha",
                "head_sha": "", "line": 0}
    text = read_at_head(repo, rel_path, head)
    if not text:
        return {"status": "PATCHED_UPSTREAM", "reason": "file_missing_on_head",
                "head_sha": head, "line": 0}
    lines = text.splitlines()
    name = unit_name.split(".")[-1].split("#")[0].strip()
    span = _method_span(lines, name)
    if span is None:
        return {"status": "PATCHED_UPSTREAM",
                "reason": "unit_not_found_on_head", "head_sha": head,
                "line": 0}
    start, end = span
    flags = _comment_flags(lines)
    # 方法声明行 / 方法体是否整体被注释
    body = lines[start:end + 1]
    if flags[start] and all(flags[i] for i in range(start, end + 1)
                            if lines[i].strip()):
        return {"status": "PATCHED_UPSTREAM",
                "reason": "method_commented_out_on_head", "head_sha": head,
                "line": start + 1}
    # 方法体为空/只有注释
    body_text = "\n".join(ln for i, ln in enumerate(body, start)
                          if not flags[i]).strip()
    if body_text.count("{") <= 1 and re.search(r"\{\s*\}\s*$", body_text):
        return {"status": "PATCHED_UPSTREAM",
                "reason": "empty_method_body_on_head", "head_sha": head,
                "line": start + 1}
    # 修复标记：方法上下文 ±8 行，或文件头 80 行
    context = "\n".join(lines[max(0, start - 8): min(len(lines), end + 9)])
    header = "\n".join(lines[:80])
    m = _REPAIR_MARK_RE.search(context) or _REPAIR_MARK_RE.search(header)
    if m:
        return {"status": "PATCHED_UPSTREAM",
                "reason": f"repair_marker_on_head: {m.group(0)}",
                "head_sha": head, "line": start + 1,
                "evidence": m.group(0)}
    return {"status": "ALIVE", "reason": "method_present_on_head",
            "head_sha": head, "line": start + 1, "evidence": ""}


def head_permalink(slug: str, head_sha: str, rel_path: str,
                   start_line: int, end_line: int | None = None) -> str:
    """GitHub HEAD 永久链接：必须带 commit SHA，禁止分支名。"""
    rel = rel_path.replace("\\", "/").lstrip("/")
    frag = f"#L{start_line}" + (f"-L{end_line}" if end_line and
                                end_line != start_line else "")
    return f"https://github.com/{slug}/blob/{head_sha}/{rel}{frag}"
