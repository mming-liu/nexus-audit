# STAGE REPORT · v1.3.8（M310：dramaclaw 复核与 pathtraver 收口）

> 日期：2026-10-31 ｜ 基线：v1.3.7（2987229）
> 结论：dramaclaw 两条 pathtraver **均为规则层假阳**，已收口；
> xianyu advisory 按决策**归档冷冻**；LIVE_HUNT_REPORT.md 不单独重跑。

## 一、dramaclaw 稀疏检出复核（HEAD b1a424b1）

~~~bash
git clone --depth 1 --filter=blob:none --sparse ... .cache/upstream/dramaclaw_sparse
git sparse-checkout set src/novelvideo/api/routes src/novelvideo/utils
~~~

切片得到 377 个入口，两条候选的实际源码如下。

### 1) sketch_grid_preview（generation.py:5823）

~~~python
5837  resolved = await _resolve_generation_project(project, user, required_role="viewer")
5838  output_dir = Path(resolved.output_dir)
5839  ep_grids_dir = output_dir / "grids" / f"ep{episode_num:03d}"
5848  paths = build_beat_sketch_paths(ep_grids_dir, beat_numbers)
5858  cell_path = ep_grids_dir / img.cell_path      # img 来自内部 pool index
5865  paths = {**{beat: path for beat, (_g, path) in latest_pool_paths.items()}, **paths}
~~~

**病灶**：paths.get(beat_num) 是 dict 取值，但 PATH_SINK_RE 里的
Paths\.get\( 带了 re.I，把全小写的 paths.get( 当成了 Java 的
Paths.get(...) 文件 API。路径本身来自 resolved.output_dir + 整数集号 +
内部 pool index，没有外部字符串直达。

### 2) export_zip（generation.py:5996）

~~~python
6007  resolved = await _resolve_generation_project(project, user, required_role="viewer")
6018  paths = PathResolver(str(project_dir), episode_num)
6025  audio_path = paths.audio(beat_num)          # beat_num 来自 DB
6051  def build_zip_file() -> str:
6054      tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
6057      with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_STORED) as zf:
6058          for file_path, arc_name in files_to_pack:
6059              zf.write(file_path, arc_name)
~~~

**病灶**：zipfile.ZipFile(tmp_path, "w") 是**写**临时包，被 ZipFile\( 当成
Java 的读包/路径 API；tmp_path 来自 NamedTemporaryFile，files_to_pack 来自
PathResolver(project_dir) 与 project_dir/frames|grids。

## 二、收口

| 旧行为 | 新行为 |
| --- | --- |
| Paths 的 get 调用带 re.I，命中 paths.get( | (?-i:\bPaths\s*\.\s*get\s*\()，只认大写 Java 形态 |
| ZipFile\( 命中 zipfile.ZipFile(..., "w") | 改为 new\s+ZipFile\s*\(，只认 Java 读包；写包属 zip_slip 类目 |

实码回归：export_zip **True → None**、sketch_grid_preview **True → None**。

## 三、按决策执行的两件事

1. **xianyu advisory 归档冷冻**：.cache/advisories/xianyu-auto-reply/ 保留草稿，
   不提交；理由（低危约束型 + 小众仓）已写入 REPORT_STATUS.md。
2. **LIVE_HUNT_REPORT.md 不单独重跑**：避免消耗 60 次/小时的核心 API 配额，
   等下一次定时巡猎统一收敛。

## 四、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,769 项**（新增 [296] 6 项） |
| cli.py doctor | PASS（12 段全绿） |
| 回归 | 稀疏检出前后同一份切片：两条由 True 变 None，无其他入口判据变化 |

## 五、遗留

- 本轮只动了 PATH_SINK_RE 的两个分支；zip_slip 类目仍由独立判据覆盖，未受影响。
- delete_face_verification_screenshot 仍留在 A 板块（约束型真实风险，已冷冻待决）。
