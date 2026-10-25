"""GitLab SAST 报告导出（M127）—— `gl-sast-report.json` v15.

## 为什么要有第二个 SAST 格式

GitHub 用 SARIF，GitLab 用自家 schema（`gl-sast-report.json`）。国内很多
企业在 GitLab Ultimate / 极狐上做安全门禁，只认后者；把 SARIF 硬塞进去
GitLab 解析不了。

## schema 硬要求（v15.0.0，缺一项 GitLab 直接拒收）

    {
      "version": "15.0.0",
      "scan": {"analyzer": {...}, "scanner": {...}, "type": "sast",
               "start_time": ..., "end_time": ..., "status": "success"},
      "vulnerabilities": [{
        "id": "<uuid>",                  # 同一 (位置,类目) 必须稳定
        "category": "sast",
        "name": "...", "message": "...",
        "description": "...",
        "severity": "Critical|High|Medium|Low|Info|Unknown",
        "confidence": "High|Medium|Low|Unknown",
        "scanner": {"id": "nexus_audit", "name": "nexus-audit"},
        "location": {"file": "<相对路径>", "start_line": N, "end_line": N},
        "identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89",
                         "url": "..."}]
      }]
    }

三个容易踩的点，本模块都按"错就拒收"处理：

1. **`severity` 必须是 GitLab 的六个枚举值之一** —— 我们内部用
   CRITICAL/HIGH/…（大写），直接照搬会被判 schema 违规；
2. **`file` 必须是相对仓库根的路径**，绝对路径 / 盘符路径 GitLab 无法定位；
3. **`id` 必须稳定**：同一处漏洞每次扫描的 uuid 要一样，否则 GitLab 会把它
   当成"新漏洞"重复计数（去重彻底失效）。这里用
   `sha1(relative_path|start_line|category)` 生成确定性 uuid。
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

SAST_VERSION = "15.0.0"
# 内部严重级 → GitLab 枚举（大小写敏感，GitLab 只认这一套）
_SEV_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}
_ALLOWED_SEVERITY = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}

_CWE_URL = "https://cwe.mitre.org/data/definitions/{n}.html"


def _rel_posix(path: str, repo: Path) -> str | None:
    try:
        rel = Path(path).resolve().relative_to(Path(repo).resolve())
    except (ValueError, OSError):
        return None
    s = rel.as_posix()
    if s.startswith("/") or "\\" in s or ":" in s:
        return None
    return s


def _stable_id(rel: str, line: int, category: str) -> str:
    """确定性 uuid：同一 (路径, 行, 类目) 每次都一样（GitLab 去重的前提）。"""
    key = f"{rel}|{line}|{category}".encode()
    h = hashlib.sha1(key).hexdigest()
    return str(uuid.UUID(h[:32]))


def _identifiers(category: str, cwe: str) -> list[dict]:
    out = [{"type": "nexus_audit_category", "name": category,
            "value": category}]
    m = cwe.upper().replace("CWE-", "").strip()
    if m.isdigit():
        out.append({"type": "cwe", "name": f"CWE-{m}", "value": m,
                    "url": _CWE_URL.format(n=m)})
    return out


def build_sast_report(findings: list[dict], repo: Path,
                      *, start_time: str | None = None,
                      end_time: str | None = None) -> dict:
    """把命中列表转成 GitLab SAST v15 报告。

    `findings` 每项：`{file, line, end_line?, category, severity, cwe,
    message?, description?}`。
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vulns: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for f in findings:
        rel = _rel_posix(f.get("file", ""), repo)
        if not rel:
            continue
        line = int(f.get("line") or 0)
        if line < 1:
            continue
        cat = f.get("category", "")
        if (rel, line, cat) in seen:
            continue                      # 同一处只报一次
        seen.add((rel, line, cat))
        sev = _SEV_MAP.get(str(f.get("severity", "MEDIUM")).upper(), "Unknown")
        if sev not in _ALLOWED_SEVERITY:  # 兜底，永不输出非法枚举
            sev = "Unknown"
        end_line = int(f.get("end_line") or line)
        name = f.get("name") or f"{cat} at {rel}:{line}"
        vulns.append({
            "id": _stable_id(rel, line, cat),
            "category": "sast",
            "name": name,
            "message": f.get("message") or name,
            "description": f.get("description")
            or f"nexus-audit 规则层确定性命中：类目 `{cat}`。",
            "severity": sev,
            "confidence": "High",         # 规则层命中都是确定性结论
            "scanner": {"id": "nexus_audit", "name": "nexus-audit"},
            "location": {"file": rel, "start_line": line,
                         "end_line": max(line, end_line)},
            "identifiers": _identifiers(cat, f.get("cwe", "")),
        })
    return {
        "version": SAST_VERSION,
        "scan": {
            "analyzer": {"id": "nexus_audit", "name": "nexus-audit",
                         "vendor": {"name": "nexus-audit"},
                         "version": "1.0.0"},
            "scanner": {"id": "nexus_audit", "name": "nexus-audit",
                        "vendor": {"name": "nexus-audit"},
                        "version": "1.0.0"},
            "type": "sast",
            "start_time": start_time or now,
            "end_time": end_time or now,
            "status": "success",
        },
        "vulnerabilities": vulns,
    }


def validate_sast_report(doc: dict) -> list[str]:
    """按 GitLab v15 的**必填字段**做本地校验（doctor / 冒烟复用）。"""
    errs: list[str] = []
    if doc.get("version") != SAST_VERSION:
        errs.append(f"version 必须是 {SAST_VERSION}")
    scan = doc.get("scan") or {}
    for k in ("analyzer", "scanner", "type", "start_time", "end_time",
              "status"):
        if k not in scan:
            errs.append(f"scan 缺字段 {k}")
    if scan.get("type") != "sast":
        errs.append("scan.type 必须是 sast")
    if scan.get("status") not in ("success", "failure"):
        errs.append("scan.status 非法")
    for i, v in enumerate(doc.get("vulnerabilities") or []):
        p = f"vulnerabilities[{i}]"
        for k in ("id", "category", "name", "message", "description",
                  "severity", "confidence", "scanner", "location",
                  "identifiers"):
            if k not in v:
                errs.append(f"{p} 缺 {k}")
        if v.get("category") != "sast":
            errs.append(f"{p}.category 必须是 sast")
        if v.get("severity") not in _ALLOWED_SEVERITY:
            errs.append(f"{p}.severity 非法：{v.get('severity')}")
        loc = v.get("location") or {}
        f = str(loc.get("file", ""))
        if not f or f.startswith("/") or "\\" in f or ":" in f:
            errs.append(f"{p}.location.file 必须是相对 POSIX 路径")
        if int(loc.get("start_line") or 0) < 1:
            errs.append(f"{p}.location.start_line 必须 ≥1")
        try:
            uuid.UUID(str(v.get("id")))
        except (ValueError, TypeError, AttributeError):
            errs.append(f"{p}.id 不是合法 uuid")
    return errs


def write_sast_report(path: str | Path, doc: dict) -> Path:
    import json
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return out
