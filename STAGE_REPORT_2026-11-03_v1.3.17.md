# STAGE REPORT · v1.3.17（M321：Django 响应回显 XSS）

> 日期：2026-11-03 ｜ 基线：v1.3.16（8ae0a6a）
> 结论：`VoIPWebHook.get` 的 zd_echo 回显**被 Django 默认 nosniff 缓解**，
> 不构成可利用 XSS；另发现两处 staff-only 开放重定向（同 CVE-2026-71240 类）。

## 一、zd_echo 复核（实证）

代码：`return HttpResponse(request.GET.get('zd_echo'), '')`，路由 `/voip/zd/` 免登录。
Django 6.0.8 实测第二参是 content_type，空串 → `Content-Type: ''`，正文不转义。

headless Chrome 实测：

| Content-Type | nosniff | 脚本执行 |
| --- | --- | --- |
| text/html | 无 | 是（对照） |
| 空 | 无 | **是** |
| 空 | 有 | **否**（渲染为文本） |
| text/plain | 任意 | 否 |

Django 默认 `SECURE_CONTENT_TYPE_NOSNIFF=True`（本项目未覆盖）→ 空类型 + nosniff
下不嗅探、不执行。结论：**不是可利用 XSS**，属纵深防御缺陷（建议
`HttpResponse(escape(echo), content_type="text/plain")`）。

## 二、其它重定向线索

- `common/views/select_emails_import.py:127`：`HttpResponseRedirect(request.GET['next'])`
  未调 `secure_url`，但路由 `staff_member_required`；
- `tasks/site/tasksbasemodeladmin.py:379/391`：`next_url` 重定向，仅 admin 可达；
- 与已公开 CVE-2026-71240 同类（该单已用 secure_url），不建议重复交单。

## 三、Mestudy 4 条 sqli 的 SQL 行（规则精度）

~~~java
// NetPortalRepository.userWhere()
where.append(" and name like ?");
parameters.add("%" + name.trim() + "%");
...
PreparedStatement statement = connection.prepareStatement(sql);
bind(statement, parameters);
~~~

`findPolicies` / `countPolicies` 同为 `like ?`；`connectionStats` 的 format 只来自
`"yyyy"/"yyyy-MM"/"yyyy-dd"` 三个硬编码分支。→ 4 条全是参数化，规则误报
（根因：SQL 变量由 `"..." + where` 拼接，规则未识别 where 里全是占位符）。

## 四、M321 落地

| 项 | 内容 |
| --- | --- |
| 判据 | `_py_echo_xss()`：`HttpResponse / make_response` 首参可控 + 未 escape + 非 text/plain/json → True；空 content_type → None |
| 冒烟 | [305]：可控 True、text/plain False、escape False、空类型 None、make_response True |

## 五、DjanGoat 新发现（规则精度）

M321 上线后 DjanGoat 报出 5 条"计划外 True"，逐条核实**全是真反射型 XSS**：

~~~python
def dashboard_view(request, dashboard_id):
    return HttpResponse("Dashboard " + str(dashboard_id))   # text/html，未转义
~~~

同形态还有 users.account_settings、paid_time_off.index、user_view、user_pay
（后两者原本只有 authz 真值）。已把 DjanGoat 基准改成多标签真值
（authz + xss），SCOREBOARD 从 12/12 更新为 15/15、0 误报。

pygoat 侧则把 make_response(render_template(...)) 识别为安全（Jinja 已转义），
避免把文件模板渲染当成回显。

## 六、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,835 项**（新增 [305] 6 项） |
| cli.py doctor | PASS（12 段全绿） |
