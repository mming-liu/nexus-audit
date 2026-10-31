"""M287：陌生野仓板块 A 降噪（三条可核对规则，不做语义猜测）。

  · DEMO_CONTROLLER          —— 路径/入口带 demo 的示例 Controller，非生产代码
  · PUBLIC_READONLY_ENDPOINT —— /app-api/ /public/ 下的 get*List / get*Page
                                 等公开只读接口（仅 authz 类：公开只读本来就是
                                 设计意图，不是越权）
  · AUTHZ_SIBLING_GUARD      —— **反向**规则：同文件其它写接口都带
                                 @PreAuthorize / @RequiresPermissions /
                                 @SaCheckPermission，唯独当前写接口没加
                                 → 高置信度真洞，提拔到板块 A 顶部（不拦截）

M294 追加：
  · LOCAL_UNIX_SOCKET_SERVER —— 绑定 AF_UNIX + 0700/0600 + SO_PEERCRED 的
                                 本地控制通道（ssh-agent / docker.sock 同类），
                                 本来就不可从网络到达，压进板块 B
  · Python 版兄弟守卫         —— Depends(get_current_*) / Security(...) /
                                 @login_required / @jwt_required / IsAuthenticated

M302 追加：
  · NO_SQL_SINK              —— Python sqli 但入口文件里一个
                                 .execute/.executemany/.executescript 都没有：
                                 根因来自切片里未被入口调用的辅助函数
                                 （跨跳污染），压进板块 B 等人工复核
"""
from __future__ import annotations

import re
from pathlib import Path

DEMO_CONTROLLER = "DEMO_CONTROLLER"
PUBLIC_READONLY_ENDPOINT = "PUBLIC_READONLY_ENDPOINT"
AUTHZ_SIBLING_GUARD = "AUTHZ_SIBLING_GUARD"
LOCAL_UNIX_SOCKET_SERVER = "LOCAL_UNIX_SOCKET_SERVER"
UNVERIFIED_WILD_AUTHZ = "UNVERIFIED_WILD_AUTHZ"
ZERO_ENTRY_LIB = "ZERO_ENTRY_LIB"
RULE_LANGUAGE_MISMATCH = "RULE_LANGUAGE_MISMATCH"
# M302：入口文件里根本没有 SQL 执行语句，sqli 根因一定来自切片里
# 未被入口调用的辅助函数（跨跳污染）。宁可进 B 等人工复核，不进 A。
NO_SQL_SINK = "NO_SQL_SINK"

_PY_SQL_SINK_RE = re.compile(r"\.\s*(?:execute|executemany|executescript)\s*\(")

# M297：只在 Solidity 里成立的类目；落到 .py/.java 入口一定是判据串了语言。
SOLIDITY_ONLY = frozenset({"reentrancy", "unchecked_low_level_calls",
                           "tx_origin", "delegatecall_untrusted"})

PUBLIC_PREFIXES = ("/app-api/", "/public/", "/open-api/")

_READONLY_VERB = re.compile(
    r"^(?:get|list|query|page|search|find|select|fetch|count|export|download|"
    r"view|show|load|detail|info)[A-Z_0-9]")
_WRITE_VERB = re.compile(
    r"^(?:save|create|add|insert|update|edit|modify|delete|remove|batch|submit|"
    r"upload|import|pay|refund|transfer|approve|audit|publish|cancel|reset|"
    r"bind|grant|assign|set|do|handle|confirm)[A-Z_0-9]")

GUARD_ANNOTATIONS = ("@PreAuthorize", "@RequiresPermissions",
                     "@SaCheckPermission", "@RequiresRoles", "@SaCheckRole",
                     "@CrmPermission")

_METHOD_DECL = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?"
    r"(?:synchronized\s+)?(?:[\w<>\[\],.?]+\s+)+(\w+)\s*\(")


def _norm(value: str) -> str:
    return str(value or "").replace("\\", "/").lower()


def _read(repo_root: Path | None, rel: str) -> str:
    if not rel or repo_root is None:
        return ""
    try:
        path = Path(repo_root) / rel
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_local_socket(text: str) -> bool:
    """AF_UNIX + 对端凭据/套接字路径 → 本地 IPC，不是网络服务。"""
    if not text:
        return False
    if not any(h in text for h in ("AF_UNIX", "SO_PEERCRED", "LOCAL_PEERCRED")):
        return False
    return any(h in text for h in ("SO_PEERCRED", "LOCAL_PEERCRED",
                                   "socket_path", "uds=", ".bind("))


def classify(record: dict, repo_root: Path | None = None) -> dict:
    """判定一条 FRESH 根因是否属于“陌生野仓噪音”。

    返回 {"blocked": bool, "code": str, "reason": str}；blocked=True 的
    记录由调用方改判 UNKNOWN 并压进板块 B。
    """
    unit = str(record.get("unit") or "")
    file = _norm(record.get("file"))
    if "demo" in file or "demo" in unit.lower():
        return {"blocked": True, "code": DEMO_CONTROLLER,
                "reason": "demo/示例入口（非生产代码）"}

    if str(record.get("category") or "") in SOLIDITY_ONLY and not file.endswith(
            ".sol"):
        return {"blocked": True, "code": RULE_LANGUAGE_MISMATCH,
                "reason": (f"{record.get('category')} 是 Solidity 类目，"
                           f"入口文件是 {Path(file).suffix or '未知类型'}")}

    if looks_local_socket(_read(repo_root, str(record.get("file") or ""))):
        return {"blocked": True, "code": LOCAL_UNIX_SOCKET_SERVER,
                "reason": ("AF_UNIX 本地控制通道（0700/0600 + 对端 UID 校验），"
                           "设计上不可从网络到达")}

    if record.get("category") == "sqli" and file.endswith(".py"):
        raw = str(record.get("file") or "")
        src = _read(repo_root, raw)
        if src and not _PY_SQL_SINK_RE.search(src):
            return {"blocked": True, "code": NO_SQL_SINK,
                    "reason": ("入口文件无任何 SQL 执行语句"
                               "（.execute/.executemany/.executescript），"
                               "sqli 来自切片里未被入口调用的辅助函数")}

    if record.get("category") == "authz":
        path = "/" + file.lstrip("/")
        meth = unit.rsplit(".", 1)[-1]
        if any(p in path for p in PUBLIC_PREFIXES) and _READONLY_VERB.match(meth):
            return {"blocked": True, "code": PUBLIC_READONLY_ENDPOINT,
                    "reason": f"公开只读接口 {meth}（{'/'.join(PUBLIC_PREFIXES)}）"}
    return {"blocked": False, "code": "", "reason": ""}


def _class_span(lines: list[str], cls: str) -> tuple[int, int] | None:
    pat = re.compile(rf"\bclass\s+{re.escape(cls)}\b")
    for i, line in enumerate(lines):
        if not pat.search(line):
            continue
        depth = 0
        seen = False
        for k in range(i, len(lines)):
            depth += lines[k].count("{") - lines[k].count("}")
            if "{" in lines[k]:
                seen = True
            if seen and depth <= 0:
                return i, k
        return i, len(lines) - 1
    return None


def _methods(lines: list[str], start: int, end: int) -> list[dict]:
    out: list[dict] = []
    for i in range(start, end + 1):
        m = _METHOD_DECL.match(lines[i])
        if not m:
            continue
        name = m.group(1)
        annotations: list[str] = []
        j = i - 1
        blanks = 0
        while j >= start and i - j <= 12:
            s = lines[j].strip()
            if not s:
                blanks += 1
                if blanks > 2:
                    break
                j -= 1
                continue
            if s.startswith("@"):
                annotations.append(s.split("(")[0].strip())
                j -= 1
                continue
            if s.startswith((")", ",")) or s.endswith("),"):
                j -= 1
                continue
            break
        guarded = any(a in GUARD_ANNOTATIONS or a.startswith(tuple(GUARD_ANNOTATIONS))
                      for a in annotations)
        out.append({"name": name, "line": i + 1, "annotations": annotations,
                    "guarded": guarded})
    return out


_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
_PY_GUARD = ("Depends(get_current", "Depends(require", "Depends(verify",
             "Depends(auth", "Security(", "@login_required", "@jwt_required",
             "IsAuthenticated", "permission_required", "@requires_auth",
             "LoginRequiredMixin")
_PY_WRITE_DECOR = re.compile(r"@\w[\w.]*\.(?:post|put|patch|delete)\s*\(", re.I)


def _py_functions(lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(lines):
        m = _PY_DEF.match(line)
        if not m:
            continue
        decos: list[str] = []
        j = i - 1
        while j >= 0:
            s = lines[j].strip()
            if s.startswith("@"):
                decos.append(s)
                j -= 1
                continue
            if not s:
                j -= 1
                continue
            break
        block = "\n".join(decos + [line] + lines[i + 1:i + 4])
        out.append({"name": m.group(1), "line": i + 1,
                    "guarded": any(g in block for g in _PY_GUARD),
                    "write": bool(_PY_WRITE_DECOR.search("\n".join(decos)))})
    return out


def _python_promote(path: Path, lines: list[str], meth: str) -> dict:
    funcs = _py_functions(lines)
    target = next((f for f in funcs if f["name"] == meth), None)
    if target is None or target["guarded"] or not target["write"]:
        return {"level": "", "code": "", "evidence": ""}
    guarded = [f for f in funcs if f["guarded"] and f["name"] != meth]
    if not guarded:
        return {"level": "", "code": "", "evidence": ""}
    return {"level": "HIGH", "code": AUTHZ_SIBLING_GUARD,
            "evidence": (f"同文件 {len(guarded)} 个入口带鉴权依赖"
                         f"（Depends/Security/login_required），"
                         f"唯 {meth} 无（{path.name}:{target['line']}）")}


def promote(record: dict, repo_root: Path | None = None) -> dict:
    """authz 高置信度提拔：同文件其它写接口都被注解守卫，唯独当前写接口漏加。"""
    if record.get("category") != "authz" or repo_root is None:
        return {"level": "", "code": "", "evidence": ""}
    unit = str(record.get("unit") or "")
    cls, _, meth = unit.rpartition(".")
    if not cls or not meth:
        return {"level": "", "code": "", "evidence": ""}
    path = Path(repo_root) / str(record.get("file") or "")
    if not path.is_file():
        return {"level": "", "code": "", "evidence": ""}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {"level": "", "code": "", "evidence": ""}
    if path.suffix.lower() == ".py":
        return _python_promote(path, lines, meth)
    if not _WRITE_VERB.match(meth):
        return {"level": "", "code": "", "evidence": ""}
    span = _class_span(lines, cls.split(".")[-1])
    start, end = span if span else (0, len(lines) - 1)
    methods = _methods(lines, start, end)
    target = next((m for m in methods if m["name"] == meth), None)
    if target is None or target["guarded"]:
        return {"level": "", "code": "", "evidence": ""}
    guarded = [m for m in methods if m["guarded"] and m["name"] != meth]
    if not guarded:
        return {"level": "", "code": "", "evidence": ""}
    names = sorted({a for m in guarded for a in m["annotations"]
                    if a in GUARD_ANNOTATIONS})
    return {"level": "HIGH", "code": AUTHZ_SIBLING_GUARD,
            "evidence": (f"同文件 {len(guarded)} 个接口带 {'/'.join(names)}，"
                         f"唯 {meth} 无鉴权注解（{path.name}:{target['line']}）")}
