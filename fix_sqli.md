# sqli 补丁自检（`${}` → `#{}`）

## DemoController.list（`DemoMapper.xml`）
```diff
--- a/DemoMapper.xml
+++ b/DemoMapper.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <mapper namespace="demo.DemoMapper">
   <select id="list" resultType="map">
-    select * from demo_user where name = '${name}'
+    select * from demo_user where name = '#{name}'
   </select>
 </mapper>
```

> 自检通过：重切片 + 重跑 sqli 规则 → False。
> 注意 `${}`→`#{}` 把值改为绑定参数；order by / 列名等
> **标识符拼接**场景不能这样修，应改白名单 —— 需人工确认。
