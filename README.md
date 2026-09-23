# rss-audit

面向 RSS 产品的可嵌入审计组件。提供 provider-free 的 `rss-audit-core` V1 和
`rss-audit-postgres` 原子持久化、可选账本组合。以及 `rss-audit-http-axum` 租户内只读查询。来源投影由后续工作项实现。

- [架构决定](docs/architecture/adr/202609220001-2495-embedded-audit.md)
- [项目范围](docs/rules/project-scope.md)
- [验证范围](docs/rules/verification-scope.md)
- [开发规则](AGENTS.md)
- [HTTP 接入与合同](crates/audit-http-axum/README.md)
- [PostgreSQL 接入与边界](crates/audit-postgres/README.md)

本仓不提供应用装配、认证授权、密钥托管、保留策略或生产迁移。
