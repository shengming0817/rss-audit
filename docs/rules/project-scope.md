# 项目范围

rss-audit 拥有可嵌入审计记录协议、组件 PostgreSQL schema/adapter 和租户内 HTTP adapter。
core 只拥有 provider-free 值类型、规范编码、ledger 组合和错误边界。

来源产品拥有事件含义与真实性、动作词汇、业务授权和产生时机。宿主持有认证授权、密钥、
保留/hold、迁移执行、数据库角色与生命周期。组件不创建或替换宿主连接池。

业务同事务 append 与可靠 Outbox 投影是两种不同保证，不能以异步集中化替换前者。

不建设动态插件注册、中央事件总线、全局 assembly、跨租户全局读、WORM/透明日志、历史导入、
通用多数据库框架或产品级 T3。MDM、Identity 和 Web 的迁移由各自后续任务持有。
