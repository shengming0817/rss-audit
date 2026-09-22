# #2497 PostgreSQL 原子审计与账本组合

状态：采纳；补充 [#2495 边界](202609220001-2495-embedded-audit.md)，不改变 V1 wire。

## 决定

一个 `PgAudit` owner，构造必须明确 `Integrity::Plain` 或 `Integrity::Ledger(auth)`。
账本故障不降级。已存记录保存实际模式及账本坐标；同 ID 重试不得换模式，但新事件可以选择
不同模式，不增加永久 tenant-mode gate。Audit 分页位置与 ledger sequence 分开，密码协议不复制。

独立路径由 Audit 持有 SQLx Transaction 和最终结算。账本只借用该 Transaction；消息路径则借用
原 `PgTransaction`，继承 tenant、剩余预算、Inbox 结算和 fencing，Audit 不改 GUC、不再开事务。
两种路径共用 Audit 记录仓储和 schema 检查，不建立通用 transaction/provider 平台或错误旁路。

录制前用 PostgreSQL 时间生成 `PreparedAuditV1`。调用方保存其精确字节，commit unknown 时原样
恢复并重试，不能重建 recorded_at。`Committed` 只能在 COMMIT ACK 后构造；staged 值没有 ACK 权限。
未确认连接退役。借用 SQL 是可信基础设施接口，不是沙箱；生命周期 SQL、tenant 修改及吞错均禁止。

Fresh schema 通过固定 definer 函数追加，runtime 只有 SELECT/EXECUTE，不直接 DML。两表 FORCE RLS；
构造和操作入口验证实际连接、角色、可继承/切换权限、列/约束、RLS、函数内容及 search_path。
稳定文本 ID 使用 C collation。按 Audit → ledger → business/outbox 顺序加锁，避免循环等待。

普通页按独立 Cursor 返回结构校验记录；SQL 在返回 payload 前检查整页行数及 canonical 字节预算。
账本页使用独立 Sequence/编码字节预算，包含 predecessor 开销，并组合 core 窗口验证。两个结果
不共用 cursor 或完整性声明。窗口认证不代表全部 Audit 历史、未截尾、外部 checkpoint 或来源真实性。

## 明确不做

不迁移旧 Audit、兼容旧表或重写 decoder，不增加双写、legacy feature、第二个 Audit runtime、
memory provider、HTTP 或来源产品改造。MDM #2498、Identity #2499、HTTP #2500 及产品 T3 独立持有。
宿主继续持有迁移执行、TLS、密钥、保留/hold、业务授权及连接池生命周期。

## 验证边界

本仓 T2 使用真实 TLS PostgreSQL，覆盖独立与消息事务、RLS/权限漂移、同 ID 并发、原字节恢复、
真实提交后的 ACK 丢失、后端终止、损坏和有界读取。source 与固定 Git consumer 在仓库祖先之外
创建 workspace/lock/target，分别执行 core、plain PG、ledger、messaging、ledger+messaging。
固定候选依赖验证不是 registry 发布证明；本仓验证不是产品 T3。

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
