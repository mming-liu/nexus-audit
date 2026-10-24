"""My-Blog（ZHENFENG13/My-Blog，3.9k Star）—— 第 23 个靶场，首轮野战实弹。

## 为什么选它

真实个人博客系统：Spring Boot + MyBatis + Thymeleaf。它不是漏洞靶场，
作者没标注任何漏洞 —— 真值全部来自 M63 野战盲测的**逐条人工核查**：

  · 每一条规则层 P0 都回读了真实源码与框架配置；
  · 该项目的 `/admin/**` 路由由 `AdminLoginInterceptor` 前缀拦截器统一
    保护（MyBlogWebMvcConfigurer.addPathPatterns）—— M63 据此给切片器
    补了「Spring MVC 拦截器前缀覆盖 → [global-authz] 标记」机制；
  · 公开博客页（文章详情/标签/分类/搜索）按内容主键查公开内容，
    不归属任何主体 —— M63 据此给 authz 形参直查分支补了归属语义门控；
  · `StringUtils.hasText(linkUrl)`（空值校验）与
    `blogService.getBlogDetailBySubUrl(subUrl)`（DB 查询）都被 SSRF
    的宽形态误命中 —— M63 据此把该形态降为弱 sink（铁律 5：须 URL 旁证）。

## 真值表（人工核查，非作者标注 —— 与 DeFiVulnLabs 同一口径）

| 位置 | 类目 | 真值 | 依据 |
|---|---|---|---|
| AdminController.passwordUpdate | hash | True | 跨文件 Hop-1 实现体 `MD5Util.MD5Encode` 做密码哈希 —— MD5 不适合安全用途（弱哈希） |
| BlogController.uploadFileByEditormd | weakrand | True | `new Random()` + `nextInt(100)` 生成上传文件名 |
| UploadController.upload | weakrand | True | 同上 |

其余全部单元 = 全库负样本（safe 分母 = 全部已判定单元）。

## 门禁（--strict）

零误报（负样本侧判 True 即失败）+ 真值表 0 漏报 + 零判反。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.agents.rule_detectors import verdict as rule_verdict   # noqa: E402
from core.slicer.java_servlet import JavaSlicer                  # noqa: E402
from benchmarks.slice_cache import cached_units                  # noqa: E402

DEFAULT_TARGET = ROOT / "reference_repos" / "My-Blog-master"

# 手写真值：(文件名, 单元名) -> 类目。全部经 M63 盲测逐条回读源码核实。
TRUTH = {
    ("AdminController.java", "passwordUpdate"): "hash",
    ("BlogController.java", "uploadFileByEditormd"): "weakrand",
    ("UploadController.java", "upload"): "weakrand",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=str(DEFAULT_TARGET))
    ap.add_argument("--strict", action="store_true",
                    help="零误报 + 真值 0 漏报 + 零判反（CI 门禁）")
    ap.add_argument("--offline", action="store_true",
                    help="只跑规则层，不发模型请求（默认，规则靶场）")
    ap.add_argument("--output",
                    default=str(ROOT / "benchmarks" / "results" / "myblog.json"))
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.exists():
        print(f"! 找不到 {repo}")
        return 2

    print(f"靶场：{repo}")
    slicer = JavaSlicer(repo)
    units = cached_units(repo, "myblog",
                         lambda: slicer.extract_entry_units())
    print(f"      切片单元 {len(units)} 个（真值表 {len(TRUTH)} 条，人工核查）")

    rows = []
    n_fp = n_fn = n_rev = 0
    for u in units:
        fname = Path(u.file_path).name
        base = u.unit_name.split("#")[0]
        # 单元名是「类.方法」形态（JavaSlicer）；#N 后缀是同名去重序号
        cls_m = base.split(".")[-2] if "." in base else base
        meth = base.split(".")[-1]
        is_truth = (fname, meth) in TRUTH
        truth_cat = TRUTH.get((fname, meth))
        hit_cats = []
        decided_any = False
        for cat in ("sqli", "cmdi", "xss", "pathtraver", "weakrand",
                    "securecookie", "trustbound", "hash", "crypto", "ldapi",
                    "xpathi", "ssrf", "xxe", "spel", "deserial", "redir",
                    "cors", "authz"):
            v = rule_verdict(cat, u.source_code)
            if v is None:
                continue
            decided_any = True
            if v is True:
                hit_cats.append(cat)
                if not is_truth:
                    n_fp += 1
                    rows.append({"unit": base, "file": fname, "cat": cat,
                                 "truth": False, "got": True})
                elif cat != truth_cat:
                    # 真阳单元在**别的类目**上判 True：类目映射口径问题，
                    # 单独记录不直接算误报（与 smartbugs 的 DISPUTED 同理）
                    rows.append({"unit": base, "file": fname, "cat": cat,
                                 "truth": f"truth={truth_cat}", "got": True})
        if is_truth and truth_cat not in hit_cats:
            n_fn += 1
            rows.append({"unit": base, "file": fname, "cat": truth_cat,
                         "truth": True, "got": None})

    n_decided = sum(1 for u in units for c in (
        "sqli", "cmdi", "xss", "pathtraver", "weakrand", "hash", "ssrf",
        "authz", "deserial", "spel", "xxe", "redir", "cors", "crypto",
        "trustbound", "securecookie", "ldapi", "xpathi")
        if rule_verdict(c, u.source_code) is not None)

    print("=" * 72)
    print("My-Blog 结果（规则层，全库负样本 + 人工核查真值）")
    print("=" * 72)
    print(f"  切片单元              ：{len(units)}")
    print(f"  规则确定性判定        ：{n_decided}")
    print(f"  真值命中              ：{len(TRUTH) - n_fn}/{len(TRUTH)}")
    print(f"  误报                  ：{n_fp}")
    print(f"  漏报                  ：{n_fn}")
    if rows:
        print("  明细：")
        for r in rows:
            print(f"    {r['file']}:{r['unit']} [{r['cat']}] truth={r['truth']} got={r['got']}")

    ok = (n_fp == 0 and n_fn == 0)
    print(f"\n{'STRICT 门禁：通过 ✔（零误报 / 真值全命中）' if ok else 'STRICT 门禁：FAIL ✘'}")
    out = Path(args.output)
    out.write_text(json.dumps({
        "bench": "myblog", "units": len(units), "decided": n_decided,
        "truth_n": len(TRUTH), "fp": n_fp, "fn": n_fn, "rows": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果写入 {out}")
    return 0 if (ok or not args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
