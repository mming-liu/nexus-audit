# STAGE REPORT · v1.3.6（M307 → M309）

> 日期：2026-10-31 ｜ 基线：v1.3.5（019207a）
> 结论：cmdi 跨跳误归属与上传白名单"只认 ALLOWED 常量"两个根因已修；
> 今日 A=7 里剩下的 5 条逐条过堂，**没有干净的第 3 单**。

## 一、剩余 5 条候选核验（源码级）

| 候选 | 源码事实 | 结论 |
| --- | --- | --- |
| dramaclaw pathtraver `export_zip` (`generation.py:5996`) | 路径来自 `_resolve_generation_project(project, user, required_role="viewer")` 解析出的 `project_dir`，`episode_num: int`；ZIP 内条目由项目目录派生 | 规则层跨跳误归因（请求串没有直达 sink），FP-leaning，留待复核 |
| dramaclaw pathtraver `sketch_grid_preview` (`generation.py:5823`) | `output_dir = Path(resolved.output_dir)`，路径为 `output_dir/"grids"/f"ep{episode_num:03d}"` + 内部 pool index 的 `img.cell_path` | 同上；`_safe_grids_file` 另有 resolve 前缀校验 |
| xianyu `arbitrary_file_delete` `delete_face_verification_screenshot` (`face_verification.py:415`) | `pattern = STATIC_ROOT/uploads/face/face_verify_{account_id}_*.jpg` → `glob` → `os.remove`；前置 `_is_admin` + `account.owner_id == current_user.id` 校验 | **约束型真实风险**：`account_id` 含 `/` 时可绕出目录，但需命中 DB 里已有账号且目标文件以 `_*.jpg` 结尾 —— 不构成可直接交单的干净首杀 |
| xianyu `arbitrary_file_delete` `send_image` (`chat_new_image.py:45`) | `tempfile.mkstemp()` 生成临时文件，`finally: os.remove(temp_path)` 删自己刚建的临时文件 | **假阳**（删除目标不是外部输入）；规则未改，列入下一批（识别 mkstemp/NamedTemporaryFile 来源） |
| xianyu `unrestricted_upload` `send_image` (`chat_new_image.py:45`) | `Image.open(temp_path)` 是**读**文件；真正写入是 `os.fdopen(fd,"wb")`；随后上传 CDN 并删除临时文件 | **假阳**，已由 M308 的 sink 收紧（`Image.open` 不再算上传 sink）修掉，现判 None |

## 二、M307：cmdi 两个根因

| 根因 | 修法 |
| --- | --- |
| 跨跳未归属 | `python_cmdi_verdict` 每个 sink 先过 `_py_sink_reachable()`；另外把 `run/execute/start/handle...` 等通用动词列入 `_GENERIC_HOP_NAMES`：入口只有 `service.run(...)` 时，不再绑定到跨模块的 `def run(cmd)` |
| `nat is None` 兜底 | 删除 `elif nat is None and _py_func_params(source): tainted = True`；只认 `nat is True`，None 保持 None |
| 模块自测块 | `if __name__ == "__main__":` 之后的 sink 整体排除（不属于任何路由） |
| 兜底降噪 | `wild_noise.NO_CMD_SINK`：Python cmdi 但入口文件无任何 `os.system/subprocess/asyncio.create_subprocess` → 板块 B |

实码回归：codex-lb `run_cache_isolation_probe` 由 **True → None**。

## 三、M308：上传白名单按机制识别

| 旧行为 | 新行为 |
| --- | --- |
| 只认 `ALLOWED_*` 常量 | 认内联后缀集合：`if ext not in {".png", ".jpg"}` / `[...]` / `(...)` |
| if 下一行必须 raise/return | 允许 1–3 行日志/赋值后再中止 |
| 不认"非法后缀回落固定值" | `if ext not in [...]: ext = ".png"` 算防护（`_UPLOAD_PY_COERCE_RE`） |
| 只看入口体 | 守卫、`.filename`、sink 的检测范围扩展到入口**可达的 Hop 1** 函数体 |
| `Image.open(...)` 算落盘 sink | 排除属性形式的 `.open(`，只认裸 `open(`（读文件不再算上传） |

实码回归：xianyu `upload_qrcode` **True → False**、`send_image` upload **True → None**。

## 四、M309：路径守卫补 Python 形态

`PATH_SAFE_RE` 增加 `os.path.realpath(p).startswith(base)` 与
`Path(p).resolve().is_relative_to(root)`（旧词表只有 Java 的 getCanonicalPath/toRealPath）。

## 五、门禁

| 项 | 结果 |
| --- | --- |
| `smoke_test_chains.py` | PASS ✔ **1,757 项**（新增 [293] cmdi 6 项 / [294] upload+path 8 项） |
| `cli.py doctor` | PASS（12 段全绿） |
| 回归抽查 | vulpy / pygoat / djangoat / fastapi_rw / flaskr `--strict` 全 PASS；vulpy 多跳 cmdi 仍 True |

## 六、遗留

1. `send_image` 的 `arbitrary_file_delete` 判据未修（临时文件来源未识别），下一批补 `mkstemp/NamedTemporaryFile` 豁免。
2. dramaclaw 两条 pathtraver 需要把 `_safe_grids_file` 这类 resolve 前缀辅助函数的"返回值可信"传播进 sink 归属，单独一批做。
3. 本轮改了判据，但 `LIVE_HUNT_REPORT.md` 保留 15:34 的 v1.3.5 快照，未按新判据回填重算。
