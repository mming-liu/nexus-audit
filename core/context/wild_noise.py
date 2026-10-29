"""M287：陌生野仓板块 A 降噪（三条可核对规则，不做语义猜测）。

  · DEMO_CONTROLLER          —— 路径/入口带 demo 的示例 Controller，非生产代码
  · PUBLIC_READONLY_ENDPOINT —— /app-api/ /public/ 下的 get*List / get*Page
                                 等公开只读接口（仅 authz 类：公开只读本来就是
                                 设计意图，不是越权）
  · AUTHZ_SIBLING_GUARD      —— **反向**规则：同文件其它写接口都带
                                 @PreAuthorize / @RequiresPermissions /
                                 @SaCheckPermission，唯独当前写接口没加
                                 → 高置信度真洞，提拔到板块 A 顶部（不拦截）
"""
from __future__ import annotations

import re
from pathlib import Path

DEMO_CONTROLLER = "DEMO_CONTROLLER"
PUBLIC_READONLY_ENDPOINT = "PUBLIC_READONLY_ENDPOINT"
AUTHZ_SIBLING_GUARD = "AUTHZ_SIBLING_GUARD"

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


def promote(record: dict, repo_root: Path | None = None) -> dict:
    """authz 高置信度提拔：同文件其它写接口都被注解守卫，唯独当前写接口漏加。"""
    if record.get("category") != "authz" or repo_root is None:
        return {"level": "", "code": "", "evidence": ""}
    unit = str(record.get("unit") or "")
    cls, _, meth = unit.rpartition(".")
    if not cls or not meth or not _WRITE_VERB.match(meth):
        return {"level": "", "code": "", "evidence": ""}
    path = Path(repo_root) / str(record.get("file") or "")
    if not path.is_file():
        return {"level": "", "code": "", "evidence": ""}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
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
