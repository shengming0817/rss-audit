# 验证范围

- T1：值类型、规范编码、错误闭集、ledger 身份绑定、golden/边界/compile-fail 和独立消费。
- T2：真实 PostgreSQL 原子性、RLS、commit unknown、冲突、损坏恢复和 adapter 事务接缝；由 #2497 起拥有。
- T3：产品 binary/image/config、认证授权、密钥、保留、迁移和生产运行；由消费产品独立拥有。

本仓 `make ci` 执行 locked fmt/check/clippy/test、依赖来源、许可证/公告和隔离 source consumer。
固定 Git consumer 必须绑定完整 revision，在仓库祖先之外生成 workspace、lock 与 target，并实际运行。
源码消费、固定候选消费和 registry 发布是不同事实，不得互相替代。
