# STAGE REPORT · v1.3.16（M320：DjangoCRM 复核 + 粘连练习仓过滤）

> 日期：2026-11-03 ｜ 基线：v1.3.15（b04f78b）
> 结论：DjangoCRM 两条候选**均有防护，不是第 3 单**；Mestudy 是 JAX-RS 真入口，
> 但属练习/外包备份仓，按约定不交单，只补过滤规则。

## 一、DjangoCRM 两条候选（FP）

### 1) VoIPWebHook.post（SSRF，voipwebhook.py:29）

~~~python
@method_decorator(csrf_exempt, name='dispatch')
class VoIPWebHook(View):
    @staticmethod
    def post(request):
        ...
        if is_authenticated(request, data):
            ...
            if not any((contact, lead, deal)) and settings.VOIP_FORWARD_DATA:
                url = settings.VOIP_FORWARD_URL          # 配置值，不是请求入参
                headers = {'Signature': request.headers['Signature']}
                requests.post(url, data=request.POST, headers=headers)
~~~

- 目标 URL 来自 `settings.VOIP_FORWARD_URL`，请求体只作为 POST data；
- `is_authenticated()` 先校验来源 IP（`backend['IP']` / `VOIP_FORWARDING_IP`）
  + HMAC-SHA1 签名，不通过直接返回空响应。
- → 不是 SSRF。规则是把 `requests.post(` 当成 sink、把 `request.POST` 当成
  taint 拼出来的假阳。

### 2) email_subtask_completion（Open Redirect，create_completed_subtask.py:61）

~~~python
def email_subtask_completion(request, token, object_id):
    redirect_url = check_subtasks(object_id, request)
    if redirect_url:
        return HttpResponseRedirect(redirect_url)
    ...
~~~

~~~python
def check_subtasks(object_id, request):
    ...
    url = reverse('site:tasks_task_changelist')      # 固定路由
    redirect_url = f"{url}?task__id__exact={object_id}&responsible={request.user.username}"
~~~

- 跳转目标永远是 `reverse('site:tasks_task_changelist')`，参数是 int 与
  当前登录用户名，进的是 query string 而不是 host；
- 没有 `next` / `url` 之类的用户可控跳转参数。
- → 不是开放重定向。规则把 `HttpResponseRedirect(变量)` 直接判 True 过宽。

## 二、Mestudy（不交单）

- `NetUserInfoApplication` 带 JAX-RS `@Path("/npmanagement/netUserInfo")` +
  `@GET @Path("/queryNetUserInfoList")` —— 是**真入口**，切片没切错；
- `DraftsController.getPersonMessage` 的 `JSON.parse(ps)` 里 `ps` 来自
  配置的内网地址 `PERSONFILENUMBER` 的响应，不是用户输入 → deserial 属误报；
- 仓库是个人练习/政企外包备份（包名 `com.tecsun.sisp`、无版本发布），
  按约定不作为 CVE 标的。

## 三、M320 落地

| 项 | 内容 |
| --- | --- |
| 过滤 | `_GLUED_STUDY_RE`：`(?:^|my|me|java|py|web|test|code)(?:study|learn|practice|homework)$`，只匹配仓库名 |
| 不误杀 | `case-study` / `spring-boot-erp` 仍为 False |
| 种子 | DjangoCRM CVE-2026-90806 / 71240 / 71239 / 71238，共 46 条 |
| 冒烟 | [304]：Mestudy/javastudy 判练习仓、case-study 不误杀、DjangoCRM 拦为 DUPLICATE_CVE |
| ssrf 守卫 | 请求目标来自 settings.* / config.*（含局部变量上溯一层）判 False |
| redir 守卫 | HttpResponseRedirect(reverse(...)) / redirect(reverse(...)) 判 False |

## 四、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,829 项**（新增 [304] 7 项） |
| cli.py doctor | PASS（12 段全绿） |

## 五、今日 A=7 报告

坑位：django-crm 2 条（本轮证伪）、Mestudy 5 条（不交单）。报告已随本提交入库。
