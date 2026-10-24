"""SARIF 2.1.0 严格合规校验器（Module 92）。

## 为什么需要它

我们把 SARIF 上传到 GitHub Code Scanning 时，**格式错一个字段整次上传就
被拒**，而且拒绝信息往往只说"invalid SARIF"——排查一轮要十几分钟。更糟的是
这类错误本地复现不出来：`build_sarif()` 生成的文档"看起来对"，直到 CI 上
才炸。

所以把 GitHub Code Scanning 的硬性要求固化成一组**可离线执行的断言**，
在 `cli.py doctor` 里常驻自检：

  1. `version == "2.1.0"`（字符串精确匹配，不是 2.1）
  2. `runs` 非空，每条 run 的 `tool.driver.name` 非空
  3. `rules[].id` 全局（run 内）唯一 —— 重复 ID 会让结果无法归属
  4. `results[].ruleId` 必须能在 rules 里找到（GitHub 不接受悬空引用）
  5. `results[].message.text` 非空
  6. `artifactLocation.uri` 必须是**相对 POSIX 路径**：
     不含 `\\`、不含盘符（`C:`）、不以 `/` 开头
  7. `region.startLine >= 1`；有 `endLine` 时 `endLine >= startLine`
  8. `level`（若有）∈ {none, note, warning, error}
  9. `security-severity`（若有）必须是 0–10 的浮点**字符串**
     （GitHub 用它做严重度排序；写成数字或写 6 都会静默失效）

## 用法

    from core.context.sarif_validator import validate_sarif, validate_sarif_file
    errs = validate_sarif_file("out.sarif")
    if errs:
        raise SystemExit("SARIF 不合规：\\n" + "\\n".join(errs))

返回**错误消息列表**，空列表即合规。每条消息都带 `位置: 说明` 前缀，
便于直接贴进 CI 日志。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SARIF_VERSION = "2.1.0"
ALLOWED_LEVELS = frozenset({"none", "note", "warning", "error"})

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _is_relative_posix_uri(uri: str) -> tuple[bool, str]:
    """uri 是否为 GitHub 接受的相对 POSIX 路径。返回 (是否合规, 原因)。"""
    if not isinstance(uri, str) or not uri:
        return False, "uri 为空或不是字符串"
    if "\\" in uri:
        return False, "含反斜杠（必须是 POSIX 分隔符）"
    if _DRIVE_RE.match(uri):
        return False, "含盘符（必须是相对路径）"
    if uri.startswith("/"):
        return False, "以 / 开头（GitHub 要求相对仓库根的路径）"
    if uri.startswith("file:"):
        return False, "是 file: URI，不是相对路径"
    return True, ""


def _check_severity(value, where: str, errs: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        errs.append(f"{where}.security-severity: 必须是**字符串**，"
                    f"实际 {type(value).__name__}（写成数字会被 GitHub 忽略）")
        return
    try:
        score = float(value)
    except (TypeError, ValueError):
        errs.append(f"{where}.security-severity: 不是合法浮点字符串：{value!r}")
        return
    if not 0.0 <= score <= 10.0:
        errs.append(f"{where}.security-severity: {score} 超出 0–10 范围")


def validate_sarif(doc: object) -> list[str]:
    """校验 SARIF 文档。返回错误列表（空 = 合规）。"""
    errs: list[str] = []
    if not isinstance(doc, dict):
        return [f"root: SARIF 根必须是 JSON 对象，实际 {type(doc).__name__}"]

    ver = doc.get("version")
    if ver != SARIF_VERSION:
        errs.append(f'version: 必须是 {SARIF_VERSION!r}，实际 {ver!r}')

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        errs.append("runs: 必须是非空数组")
        return errs

    for ri, run in enumerate(runs):
        rp = f"runs[{ri}]"
        if not isinstance(run, dict):
            errs.append(f"{rp}: 必须是对象")
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if not isinstance(driver, dict):
            errs.append(f"{rp}.tool.driver: 缺失或不是对象")
            driver = {}
        if not str(driver.get("name") or "").strip():
            errs.append(f"{rp}.tool.driver.name: 不能为空")

        rule_ids: list[str] = []
        for ki, rule in enumerate(driver.get("rules") or []):
            kp = f"{rp}.tool.driver.rules[{ki}]"
            if not isinstance(rule, dict):
                errs.append(f"{kp}: 必须是对象")
                continue
            rid = rule.get("id")
            if not str(rid or "").strip():
                errs.append(f"{kp}.id: 不能为空")
                continue
            rule_ids.append(str(rid))
            props = rule.get("properties")
            if isinstance(props, dict):
                _check_severity(props.get("security-severity"),
                                f"{kp}.properties", errs)
        dupes = sorted({x for x in rule_ids if rule_ids.count(x) > 1})
        if dupes:
            errs.append(f"{rp}.tool.driver.rules: 规则 ID 重复 {dupes}")

        results = run.get("results") or []
        if not isinstance(results, list):
            errs.append(f"{rp}.results: 必须是数组")
            continue
        for xi, res in enumerate(results):
            xp = f"{rp}.results[{xi}]"
            if not isinstance(res, dict):
                errs.append(f"{xp}: 必须是对象")
                continue
            rid = res.get("ruleId")
            if not str(rid or "").strip():
                errs.append(f"{xp}.ruleId: 不能为空"
                            "（GitHub 不接受悬空结果）")
            elif rule_ids and str(rid) not in rule_ids:
                errs.append(f"{xp}.ruleId: {rid!r} 不在 rules 里")
            msg = res.get("message")
            if not isinstance(msg, dict) or not str(msg.get("text") or "").strip():
                errs.append(f"{xp}.message.text: 不能为空")
            lvl = res.get("level")
            if lvl is not None and lvl not in ALLOWED_LEVELS:
                errs.append(f"{xp}.level: {lvl!r} 不在 "
                            f"{sorted(ALLOWED_LEVELS)} 内")
            props = res.get("properties")
            if isinstance(props, dict):
                _check_severity(props.get("security-severity"),
                                f"{xp}.properties", errs)
            locs = res.get("locations")
            if locs is None:
                continue
            if not isinstance(locs, list) or not locs:
                errs.append(f"{xp}.locations: 若有则必须是非空数组")
                continue
            for li, loc in enumerate(locs):
                lp = f"{xp}.locations[{li}]"
                phys = (loc or {}).get("physicalLocation") if isinstance(loc, dict) else None
                if not isinstance(phys, dict):
                    errs.append(f"{lp}.physicalLocation: 缺失或不是对象")
                    continue
                art = phys.get("artifactLocation")
                if not isinstance(art, dict):
                    errs.append(f"{lp}.artifactLocation: 缺失或不是对象")
                    continue
                ok, why = _is_relative_posix_uri(art.get("uri"))
                if not ok:
                    errs.append(f"{lp}.artifactLocation.uri: {why}"
                                f"（实际 {art.get('uri')!r}）")
                region = phys.get("region")
                if region is None:
                    continue
                if not isinstance(region, dict):
                    errs.append(f"{lp}.region: 必须是对象")
                    continue
                sl = region.get("startLine")
                if not isinstance(sl, int) or isinstance(sl, bool) or sl < 1:
                    errs.append(f"{lp}.region.startLine: 必须是 ≥1 的整数，"
                                f"实际 {sl!r}")
                el = region.get("endLine")
                if el is not None:
                    if not isinstance(el, int) or isinstance(el, bool):
                        errs.append(f"{lp}.region.endLine: 必须是整数，"
                                    f"实际 {el!r}")
                    elif isinstance(sl, int) and el < sl:
                        errs.append(f"{lp}.region.endLine: {el} < "
                                    f"startLine {sl}")
    return errs


def validate_sarif_file(path: str | Path) -> list[str]:
    """读文件并校验；文件不存在/不是 JSON 也归入错误列表（不抛异常）。"""
    p = Path(path)
    if not p.is_file():
        return [f"文件不存在：{p}"]
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        return [f"JSON 解析失败：{e}"]
    return validate_sarif(doc)
