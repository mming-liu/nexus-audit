# STAGE REPORT · v1.3.18（M322：三靶联查 + 两条判据收口）

> 日期：2026-11-04 ｜ 基线：v1.3.17（0526b8f）
> 结论：三靶均无新真洞；M322 收掉 Mestudy 的动态 ? 占位符假阳，并补上同包鉴权基线。

## 一、靶标 A：DjangoCRM ConnectionView

~~~python
class ConnectionView(FormView):
    def get(self, request, *args, **kwargs):
        connections = self.get_connections(request)      # owner=request.user, active=True
        to_number = request.GET.get('number')
        ...
        message = get_callback(connection, to_number)    # 走 provider SDK
        return HttpResponse(message)

    @staticmethod
    def get_connections(request):
        return Connection.objects.filter(owner=request.user, active=True)
~~~

- 连接严格按 `owner=request.user` 取，无对象越权；
- `to_number` 只是拨号目标，交给 Zadarma SDK，不是服务端发起任意 URL；
- 路由未加 login_required，但匿名用户取不到连接（owner 为匿名）。
→ 无新洞。

## 二、靶标 B：novel-plus AiAssistantController（FP）

每个方法先 `checkAuthor(request)`（JWT → queryAuthor，未登录/异常 401/403），
服务层 `loadOwnedPlan(authorId, planId)`、`selectByIdAndAuthor(taskId, authorId)`
按 author_id 隔离；没有 `@RequiresPermissions` 是因为走作者身份体系。

## 三、靶标 C：ujcms 两个 remove（FP）

- `api/CommentController.remove`：`bean.getUserId().equals(user.getId())` 否则 404；
- `api/ContributeController.remove` → `ContributeService.delete` → `requireOwn(site, user, id)`。

## 四、M322 落地

| 项 | 内容 |
| --- | --- |
| sqli | `_sql_builder_placeholder_only()`：builder 的所有 append 都是含 `?` 的字面量 + 参数绑定 → False；append 里拼变量仍 True |
| authz | `AUTHZ_PACKAGE_GUARD`：同文件无反差时，同目录 ≥2 个 Controller 有鉴权注解、当前类整类无注解且无身份校验 → HIGH 提拔 |
| 反假阳 | 当前文件出现 `getUserDetails/checkAuthor/getLoginUser/StpUtil/@login_required` 时不提拔 |

## 五、门禁

| 项 | 结果 |
| --- | --- |
| smoke_test_chains.py | PASS ✔ **1,840 项**（新增 [306] 5 项） |
| cli.py doctor | PASS（12 段全绿） |
