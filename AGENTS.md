# RSS Audit 协作说明

rss-audit 提供可嵌入 Rust 产品的审计记录协议、PostgreSQL 持久化与租户内 HTTP 适配。当前边界见
[#2495 ADR](docs/architecture/adr/202609220001-2495-embedded-audit.md)。

## 工作方式

- 默认中文沟通；使用系统 Git `/usr/bin/git`，集成分支为 `develop`。
- 修改前读取目标文件和 `docs/rules/*.md`，用 `rg` 搜索已有实现；提交采用 Conventional Commits。
- 行为变化同步更新所属文档，只修改当前需求需要的内容。
- RSS 依赖只允许同一仓库 URL与固定完整 commit；禁止跨仓 path、浮动 branch/tag、源码复制或双来源。
- 本地 worktree 和验证产物使用 `.git/info/exclude` 或仓库外目录，不强制加入 Git。

## 安全与范围

- 来源产品拥有事件含义、actor/source 真实性与业务授权；宿主持有密钥、保留/hold、迁移和生命周期。
- core 的结构校验、规范编码或 ledger 验证都不是持久提交、未截尾或来源真实性证明。
- 默认考虑多租户、MDM 与零信任边界；不得恢复跨租户全局读、中央事件总线或通用 provider 平台。

## 验证

日常开发与 PR 收尾按[验证范围](docs/rules/verification-scope.md)运行受影响检查和必要集成，复用缓存与
有效结果，修复后只复验失败项及受影响行为；不因提交或流程阶段变化重复全量验证。
`make ci` 保留为完整检查入口。依赖通过 Cargo manifest/lock、locked 构建及 cargo-deny 管理。
不建设内部拆包的独立 consumer、artifact 或 commit 来源证明，不默认运行容量压测。
PostgreSQL T2 由本仓 provider 集成测试验证；真实 MDM/Identity 接入及产品 T3 由消费产品持有。
