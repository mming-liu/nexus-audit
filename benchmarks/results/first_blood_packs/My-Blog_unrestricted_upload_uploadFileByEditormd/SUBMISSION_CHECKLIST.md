# 交单流程单（My-Blog / unrestricted_upload / BlogController.uploadFileByEditormd）

## 0. 事实核对

- 仓库：https://github.com/ZHENFENG13/My-Blog
- 根因：unrestricted_upload（CWE）
- 位置：BlogController.java:185
- 受影响路由：1 条（同一独立根因）
- 补丁：已验证 True -> False，见 fix.patch

## 1. 私密报告（不要先开公开 issue）

- [ ] 打开 https://github.com/ZHENFENG13/My-Blog/security/advisories/new
- [ ] 标题：CWE in BlogController.uploadFileByEditormd
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
