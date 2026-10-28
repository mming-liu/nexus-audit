"""服务层鉴权守卫识别：Controller 没写 @PreAuthorize 不等于无鉴权。

ruoyi-vue-pro 的 CRM 模块把权限放在 ServiceImpl 的 @CrmPermission 上；
只在 Controller 找注解会把“已守卫”误报成“未授权”。本模块做一次
保守的服务层核对：注解或方法体里的 hasPermission() 任一命中即判 guarded。
"""
from __future__ import annotations

import re
from pathlib import Path

_ANNOTATIONS = ("@CrmPermission", "@PreAuthorize", "@SaCheckPermission",
                "@RequiresPermissions")


def _method_names(lines: list[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if any(a in line for a in _ANNOTATIONS):
            for j in range(i + 1, min(i + 7, len(lines))):
                m = re.search(r"\b(\w+)\s*\(", lines[j])
                if m:
                    out.append((i + 1, m.group(1)))
                    break
    return out


def verify_service_guard(repo: Path, unit: str, file: str = "") -> dict:
    cls, _, meth = unit.partition(".")
    if not meth:
        return {"guarded": False, "evidence": "", "method": ""}
    stem = cls[:-len("Controller")] if cls.endswith("Controller") else cls
    repo = Path(repo)
    candidates = list(repo.rglob(f"{stem}ServiceImpl.java"))
    if not candidates:
        candidates = [p for p in repo.rglob("*ServiceImpl.java")
                      if stem.split(".")[-1] in p.name][:20]
    for path in candidates[:20]:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, name in _method_names(lines):
            if name == meth or name.startswith(meth) or meth in name:
                return {"guarded": True,
                        "evidence": f"{path.name}:{line_no}",
                        "method": name}
        for i, line in enumerate(lines):
            if re.search(rf"\b{re.escape(meth)}\w*\s*\(", line):
                body = "\n".join(lines[i:i + 25])
                if "hasPermission(" in body:
                    return {"guarded": True,
                            "evidence": f"{path.name}:{i + 1} hasPermission",
                            "method": meth}
    return {"guarded": False, "evidence": "", "method": ""}
