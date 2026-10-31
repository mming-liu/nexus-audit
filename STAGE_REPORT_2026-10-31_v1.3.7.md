# STAGE REPORT · v1.3.7（M309 收尾）

> 日期：2026-10-31 ｜ 基线：v1.3.6（1d88ddf）
> 结论：补上 v1.3.6 遗留的两处误报边界（临时文件删除、上传面过宽），
> 并为 xianyu 的约束型路径穿越删除生成英文 advisory 草稿。

## 一、修了什么

| 项 | 问题 | 修法 |
| --- | --- | --- |
| 临时文件删除 | `send_image` 的 `finally: os.remove(temp_path)` 被报 `arbitrary_file_delete`，但 `temp_path` 是 `tempfile.mkstemp()` 刚建的 | `_TEMP_FILE_ORIGIN_RE` + 取 sink 前**最后一次**赋值判断来源；`temp_path=None` 再 `mkstemp` 的写法也覆盖 |
| 上传面过宽 | M308 把"所有可达辅助体"纳入 sink/守卫范围，`uploader.upload_image(temp_path)` 的下游 `img.save/open` 被算成上传 sink，`send_image` 又变回 True | 新增 `_py_upload_helper_bodies()`：只跟进"实参里出现上传对象"的调用；上传对象 = 入口读 `.filename` 的变量，或 `UploadFile/FileStorage` 注解形参 |
| 路径守卫 | Python 的 `realpath().startswith` / `resolve().is_relative_to` 不认（v1.3.6 已补） | `PATH_SAFE_RE` 已覆盖 |

实码回归（xianyu-auto-reply @ 3dbe45ba）：

| 单元 | v1.3.6 | v1.3.7 |
| --- | --- | --- |
| `send_image` upload | True | **None** |
| `send_image` delete | True | **False** |
| `delete_face_verification_screenshot` delete | True | True（保留，约束型真实风险） |
| `upload_qrcode` upload | False | False |

## 二、advisory 草稿（xianyu 约束型路径穿越删除）

- 路径：`.cache/advisories/xianyu-auto-reply/ADVISORY.md`（英文，5.5 KB）
  + `REPORT_STATUS.md`（中文状态与提交前检查）
- 接口：`DELETE /api/v1/face-verification/screenshot/{account_id}`
- CWE-22 / CWE-73，估算 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L`（~4.2）
- 关键事实：`account_id` 由客户端在创建账号时自选，`AccountService.create_account`
  只做唯一性校验、无格式校验；因此"带 `/` 的账号 ID"普通登录用户可造，
  剩余门槛是账号创建成功（需要可用凭据）
- 状态：**未提交**；`.cache/` 被 .gitignore 忽略，不进版本库

## 三、门禁

| 项 | 结果 |
| --- | --- |
| `smoke_test_chains.py` | PASS ✔ **1,763 项**（新增 [295] 5 项） |
| `cli.py doctor` | PASS（12 段全绿） |
| 回归抽查 | vulpy / pygoat `--strict` PASS（v1.3.6 已跑，本轮改动只涉及 delete/upload 判据） |

## 四、遗留

1. dramaclaw 两条 `pathtraver`：仓库 712 MB，未整体克隆；需要 `--filter=blob:none` 的
   稀疏检出才能复现整份切片，暂按"路径来自 resolved dir + 内部索引"记录为待复核。
2. `delete_face_verification_screenshot` 的真实风险取决于账号创建链路是否还有
   上游格式约束（已写入 advisory 的 Reachability 段）。
