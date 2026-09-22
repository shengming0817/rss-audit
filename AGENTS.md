# RSS Audit 协作说明

rss-audit 提供可嵌入 Rust 产品的审计记录协议及后续 PostgreSQL、HTTP 适配。当前边界见
[#2495 ADR](docs/architecture/adr/202609220001-2495-embedded-audit.md)。

## 工作方式

- 默认中文沟通；使用系统 Git `/usr/bin/git`，集成分支为 `develop`。
- 修改前读取目标文件和 `docs/rules/*.md`，用 `rg` 搜索已有实现；提交采用 Conventional Commits。
- 行为变化同步更新所属文档，只修改当前需求需要的内容。
- RSS 依赖只允许同一仓库 URL与固定完整 commit；禁止跨仓 path、浮动 branch/tag、源码复制或双来源。
- 本地 worktree、临时 consumer 和验证产物使用 `.git/info/exclude` 或仓库外目录，不强制加入 Git。

## 安全与范围

- 来源产品拥有事件含义、actor/source 真实性与业务授权；宿主持有密钥、保留/hold、迁移和生命周期。
- core 的结构校验、规范编码或 ledger 验证都不是持久提交、未截尾或来源真实性证明。
- 默认考虑多租户、MDM 与零信任边界；不得恢复跨租户全局读、中央事件总线或通用 provider 平台。

## 验证

本仓检查入口为 `make ci`。独立 consumer 必须使用仓库祖先之外的 workspace、lock 和 target。
PostgreSQL T2 与产品 T3 只能由其对应后续任务声明。
