"""GitHub Pull Request 行级 Review 载荷导出（M112）。

## 为什么要有这个模块

`pr-scan` 已经能算出"这次 diff 影响了哪些路由、其中哪些有 P0"，但产物是
一份 markdown 报告 —— 评审的人还得自己把结论搬到 PR 的行级评论里。
GitHub 的 `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` 接受一个
结构化 `comments` 数组，**每条都带 path + line + body**，这才是能直接用的
形态；带 ```suggestion 代码块时，作者在 PR 页面点一下按钮就能应用补丁。

## 载荷契约（GitHub REST API）

    {
      "body": "<汇总>",
      "event": "COMMENT",                    # 只评论，不 approve/request changes
      "comments": [
        {"path": "src/Foo.java", "line": 42, "side": "RIGHT", "body": "..."}
      ]
    }

三条硬约束（写错 GitHub 直接 422）：

1. `path` 必须是**相对仓库根**的 POSIX 路径，不能是绝对路径、不能用反斜杠；
2. `line` 是**新文件**里的行号（`side=RIGHT`），必须 ≥1；
3. 同一个 `(path, line)` 只能有一条评论 —— 重复会让整个 review 提交失败。
   多条命中同一行时合并成一条（按类目列出），不是丢弃。
"""
from __future__ import annotations

import json
from pathlib import Path

# 严重级 → emoji，只为可读性；不影响判定
_SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟩"}


def _rel_posix(path: str, repo: Path) -> str | None:
    """把绝对路径转成相对仓库根的 POSIX 路径（不合法就返回 None）。"""
    try:
        p = Path(path).resolve()
        rel = p.relative_to(Path(repo).resolve())
    except (ValueError, OSError):
        return None
    s = rel.as_posix()
    if s.startswith("/") or "\\" in s or s.startswith("../"):
        return None
    return s


def _suggestion_block(diff_text: str, rel_path: str) -> str:
    """从统一 diff 里抽本文件的**新增行**，拼成 ```suggestion 块。

    只在一个 hunk 恰好"删 1 行 / 加 N 行"且替换语境干净时才给建议 ——
    GitHub 的 suggestion 是**整段替换**目标行，行数对不上会直接把文件改坏。
    判断不了就返回空串（宁可不给建议，也不给坏建议）。
    """
    if not diff_text:
        return ""
    cur_file = ""
    adds: list[str] = []
    dels = 0
    hunks = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            cur_file = line[4:].strip()
            if cur_file.startswith("b/"):
                cur_file = cur_file[2:]
            continue
        if line.startswith("@@ "):
            hunks += 1
            if hunks > 1:
                return ""              # 多 hunk：无法安全映射到单行建议
            continue
        if cur_file != rel_path:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            adds.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            dels += 1
    if not adds or dels > 1:
        return ""
    body = "\n".join(adds)
    if "```" in body:
        return ""
    return f"```suggestion\n{body}\n```"


def build_review_payload(findings: list[dict], repo: Path,
                         fix_text: str = "", *, max_comments: int = 50,
                         summary: str = "") -> dict:
    """把命中列表转成 GitHub PR review 载荷。

    `findings` 每项：`{file, line, category, severity, cwe, message?}`。
    返回可直接 `json.dumps` 后 POST 的 dict。
    """
    by_key: dict[tuple[str, int], dict] = {}
    for f in findings:
        rel = _rel_posix(f.get("file", ""), repo)
        if not rel:
            continue
        line = int(f.get("line") or 0)
        if line < 1:
            continue
        cat = f.get("category", "")
        sev = f.get("severity", "MEDIUM")
        cwe = f.get("cwe", "")
        msg = f.get("message", "")
        key = (rel, line)
        icon = _SEV_ICON.get(sev, "⬜")
        item = (f"{icon} **{sev}** · `{cat}`"
                + (f" · {cwe}" if cwe else "")
                + (f"\n\n{msg}" if msg else ""))
        if key not in by_key:
            by_key[key] = {"path": rel, "line": line, "side": "RIGHT",
                           "_items": [item]}
        else:
            by_key[key]["_items"].append(item)

    comments: list[dict] = []
    for (rel, line), entry in sorted(by_key.items(),
                                     key=lambda kv: (kv[0][0], kv[0][1])):
        items = entry.pop("_items")
        body = "\n\n".join(items)
        sug = _suggestion_block(fix_text, rel)
        if sug:
            body += "\n\n" + sug
        entry["body"] = body
        comments.append(entry)
        if len(comments) >= max_comments:
            break

    n_fix = sum(1 for c in comments if "```suggestion" in c["body"])
    head = summary or (f"nexus-audit 在本次 diff 上发现 **{len(comments)}** "
                       f"处规则层确定性命中（P0）；其中 **{n_fix}** 处附"
                       f"可直接采纳的修复建议。")
    return {"body": head, "event": "COMMENT", "comments": comments}


def write_review_payload(path: str | Path, payload: dict) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return out
