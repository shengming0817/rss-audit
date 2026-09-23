# 验证范围

- T1：值类型、规范编码、错误闭集、ledger 身份绑定、golden/边界/compile-fail 和独立消费。
- T2：真实 PostgreSQL 原子性、RLS、commit unknown、冲突、损坏恢复和 adapter 事务接缝；由 #2497 起拥有。
- T3：产品 binary/image/config、认证授权、密钥、保留、迁移和生产运行；由消费产品独立拥有。

本仓 `make ci` 执行 locked fmt/check/clippy/test、依赖来源、许可证/公告和隔离 source consumer。
固定 Git consumer 必须绑定完整 revision，在仓库祖先之外生成 workspace、lock 与 target，并实际运行。
`make test-postgres` 通过 testkit launcher 管理真实 TLS PostgreSQL fixture；`make coverage` 汇总 T1/T2
instrumentation，行覆盖率至少 80%。独立 consumer 验证 core 与四种 PostgreSQL feature 组合，
以及独立真实 TCP Axum 宿主，不以 workspace feature unification 代替 feature 隔离证据。
HTTP T2 复用现有 provider suite：租户授权、固定上界分页、必需查询审计、错误/取消与未确认连接隔离。
源码与固定 Git HTTP consumer 使用同一模板；不将测试用认证当作产品认证或 T3。
源码消费、固定候选消费和 registry 发布是不同事实，不得互相替代。
