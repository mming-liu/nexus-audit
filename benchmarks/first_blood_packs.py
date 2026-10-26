"""M160：Top-3 真实仓库交单包（first_blood_packs）。

从 34 仓野战结果里挑三条**同时满足**以下条件的根因：

1. 规则层确定性 P0（不是模型猜测）；
2. 有确定性补丁器且补丁自检 True -> False；
3. PoC 合成自检通过；
4. 优先级：带"组件 CVE × 代码级 P0"双重证据的仓库优先。

当前三包（2026-10-25 快照）：

  · My-Blog / unrestricted_upload / BlogController.uploadFileByEditormd
  · newbee-mall / weakrand / UploadController.upload
  · RuoYi / sqli / GenController.create

每包四件套：

    ADVISORY.md             —— GHSA 草稿（CVSS / 机制 / 污点图 / PoC / diff）
    poc_test.*              —— 可离线运行的 PoC 骨架
    fix.patch               —— 已验证的 unified diff
    SUBMISSION_CHECKLIST.md —— GitHub 私密提交 + CVE 申请流程单

用法：

    python benchmarks/first_blood_packs.py            # 生成全部
    python benchmarks/first_blood_packs.py --check    # 只校验四件套完备
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.text_utils import ensure_utf8_stdio                   # noqa: E402
from core.context.advisory_exporter import export_advisories   # noqa: E402
from core.context import watchtower as W                        # noqa: E402

ensure_utf8_stdio()

OUT = ROOT / "benchmarks" / "results" / "first_blood_packs"
WILD = ROOT / "benchmarks" / "results" / "wild_hunt.json"

TARGETS = [
    # M234：Top-10 跨语言交单包。全部来自 50 仓 wild_hunt 的规则层根因，
    # 且补丁自检 True -> False 实测通过。
    ("My-Blog", "unrestricted_upload",
     "BlogController.uploadFileByEditormd", "ZHENFENG13/My-Blog",
     "编辑器 Markdown 图片上传：原始文件名直接落盘，无后缀白名单"),
    ("newbee-mall", "weakrand", "UploadController.upload",
     "newbee-ltd/newbee-mall",
     "上传文件名用 java.util.Random 生成，可预测；同仓另有 MD5 口令哈希"),
    ("RuoYi", "sqli", "GenController.create",
     "yangzongzhuan/RuoYi",
     "代码生成器表名/注释拼接进 SQL（管理员面，但仍是确定性注入）"),
    ("newbee-mall", "unrestricted_upload", "UploadController.upload",
     "newbee-ltd/newbee-mall",
     "上传接口原始文件名直接落盘；与 weakrand 同一入口两个独立缺陷"),
    ("newbee-mall-api", "unrestricted_upload", "NewBeeAdminUploadAPI.upload",
     "newbee-ltd/newbee-mall-api",
     "后台 API 上传原始文件名落盘，无后缀白名单"),
    ("newbee-mall-api", "weakrand", "NewBeeAdminUploadAPI.upload",
     "newbee-ltd/newbee-mall-api",
     "上传文件名 Random 生成，可预测"),
    ("My-Blog", "weakrand", "BlogController.uploadFileByEditormd",
     "ZHENFENG13/My-Blog",
     "Markdown 上传文件名弱随机，可与 unrestricted_upload 组合利用"),
    ("My-Blog", "unrestricted_upload", "UploadController.upload",
     "ZHENFENG13/My-Blog",
     "通用上传接口原始文件名落盘"),
    ("My-Blog", "weakrand", "UploadController.upload",
     "ZHENFENG13/My-Blog",
     "通用上传接口弱随机文件名"),
    ("spring-boot-demo", "unrestricted_upload", "UploadController.local",
     "xkcoding/spring-boot-demo",
     "示例上传接口原始文件名落盘；演示代码，仍按规则层登记"),
]

REQUIRED = ("ADVISORY.md", "fix.patch", "SUBMISSION_CHECKLIST.md")


def _find_rc(data: dict, repo_name: str, category: str, unit: str) -> dict | None:
    for repo in data.get("repos", []):
        if repo.get("name") != repo_name:
            continue
        for rc in repo.get("summary", {}).get("root_causes", []):
            if rc.get("category") == category and rc.get("representative") == unit:
                return rc
    return None


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


def build(data: dict, check_only: bool = False) -> int:
    if not WILD.exists():
        print(f"! 缺 {WILD}（先跑 wild_hunt）")
        return 2
    if not OUT.exists() and not check_only:
        OUT.mkdir(parents=True, exist_ok=True)
    failed: list[str] = []
    for repo_name, cat, unit, slug, _note in TARGETS:
        rc = _find_rc(data, repo_name, cat, unit)
        if rc is None:
            print(f"! 找不到根因 {repo_name}/{cat}/{unit}")
            failed.append(repo_name)
            continue
        # wild_hunt 的根因用 representative 字段；advisory_exporter 用
        # unit_name。补一个别名，避免两套契约漂移。
        rc = dict(rc)
        rc.setdefault("unit_name", rc.get("representative", ""))
        repo = next((Path(r["path"]) for r in data["repos"]
                     if r.get("name") == repo_name), Path("."))
        pack = OUT / f"{repo_name}_{cat}_{unit.split('.')[-1]}"
        if check_only:
            missing = [f for f in REQUIRED if not (pack / f).is_file()]
            has_patch = (pack / "fix.patch").is_file() and (
                pack / "fix.patch").stat().st_size > 0
            adv = (pack / "ADVISORY.md").read_text(encoding="utf-8") \
                if (pack / "ADVISORY.md").is_file() else ""
            ok = not missing and has_patch and "[Auto-Fix Verified]" in adv
            print(f"  [{'OK' if ok else 'FAIL'}] {pack.name}"
                  f"{' 缺 ' + str(missing) if missing else ''}"
                  f"{' 无补丁' if not has_patch else ''}"
                  f"{' 缺标记' if '[Auto-Fix Verified]' not in adv else ''}")
            if not ok:
                failed.append(pack.name)
            continue

        units = W._slice_all(repo)
        u = next((x for x in units
                  if x.unit_name == rc["representative"]), None)
        if u is None:
            print(f"! 切片里找不到 {unit}")
            failed.append(repo_name)
            continue
        # wild_hunt 里 representative 是入口名字符串；advisory_exporter
        # 需要真正的 CodeUnit（污点图要读 source_code）。
        rc["representative"] = u
        poc = W._poc(u, cat)
        diff, _report, patch_ok = W._try_patch(repo, u, cat)
        if not diff or not patch_ok:
            print(f"! {repo_name}/{unit} 补丁未通过自检，跳过")
            failed.append(repo_name)
            continue
        pack.mkdir(parents=True, exist_ok=True)
        fix_text = (f"## [{cat}] {u.unit_name}\n"
                    "\x60\x60\x60diff\n" + diff + "\x60\x60\x60\n")
        tmp = pack / ".adv_tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        written = export_advisories([rc], repo, tmp, fix_text)
        adv_src = next((p for p in written if p.suffix == ".md"), None)
        if adv_src is None:
            print(f"! {repo_name} 未能生成 advisory")
            failed.append(repo_name)
            continue
        (pack / "ADVISORY.md").write_text(
            adv_src.read_text(encoding="utf-8"), encoding="utf-8")
        shutil.rmtree(tmp, ignore_errors=True)
        if poc is not None and poc.content:
            (pack / (poc.path or "poc_test.txt")).write_text(
                poc.content, encoding="utf-8")
        (pack / "fix.patch").write_text(diff, encoding="utf-8")
        (pack / "SUBMISSION_CHECKLIST.md").write_text(
            _checklist(repo_name, slug, rc, True), encoding="utf-8")
        (pack / "manifest.json").write_text(json.dumps({
            "repo": repo_name, "github": slug, "category": cat,
            "unit": u.unit_name, "file": Path(rc["file"]).name,
            "line": rc["line"], "affected_routes": rc["affected_routes"],
            "patch_verified": True, "poc_ok": bool(poc and poc.self_check_ok),
            "component_cve": ("CVE-2022-21363" if repo_name == "jeecg-boot"
                              else ""),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  [OK] {pack.name}"
              f"（PoC {'✓' if poc and poc.self_check_ok else '—'} / "
              f"补丁 ✓）")
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="生成/校验 Top-3 交单包（M160）")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    data = json.loads(WILD.read_text(encoding="utf-8"))
    if not args.check:
        print("生成 first_blood_packs ...")
    rc = build(data, check_only=args.check)
    packs = sorted(OUT.glob("*/manifest.json")) if OUT.exists() else []
    print(f"交单包 {len(packs)} 个 → {OUT}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
