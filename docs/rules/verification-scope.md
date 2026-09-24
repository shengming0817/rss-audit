# 验证范围

- T1：值类型、规范编码、错误闭集、ledger 身份绑定和 golden/边界/compile-fail。
- T2：真实 PostgreSQL 原子性、RLS、commit unknown、冲突、损坏恢复和 adapter 事务接缝；由 #2497 起拥有。
- T3：产品 binary/image/config、认证授权、密钥、保留、迁移和生产运行；由消费产品独立拥有。

日常开发和 PR 收尾选择受影响构建、静态检查、业务测试及必要集成；已有缓存和有效结果可复用。
修复后只复验失败项与受影响行为，不因提交、文档修改或流程阶段变化重复全量验证。
`make ci` 保留为 develop CI 与显式完整检查入口，执行 fmt、locked check/clippy/test、覆盖率及
cargo-deny 的来源、许可证和公告检查。依赖版本和来源由 Cargo manifest/lock 持有，
不额外维护 commit、package 或 feature 清单副本。

`make test-postgres` 通过现有 testkit launcher 管理真实 TLS PostgreSQL fixture。
HTTP T2 复用 provider suite，覆盖租户授权、固定上界分页、普通查询与必需查询审计、错误/取消
及未确认连接隔离。`make coverage` 汇总 T1/T2 instrumentation，完整检查的行覆盖率至少 80%。

内部拆包不产生独立发布验收要求。不建设模拟 consumer、packed consumer、独立 workspace/target
消费证明或 artifact/commit 来源证明，也不保留其手动入口；正常 Git、manifest/lock 和构建记录保留。
真实 MDM/Identity 的 API/协议接入由对应产品验证，不将测试用认证当作产品认证或 T3。
RSS 主仓基础库的发布验证由主仓持有，不传递为本仓开发门槛。

容量、压力和长跑测试不进入普通开发、CI 或收尾；专项性能测试仅在有已确认目标时按需运行。
保留真实功能的短小资源边界测试，以及认证授权、内容完整性、事务、幂等和恢复行为测试。
