# 来源证据

- RSS 历史基线：tag `baseline/pre-community-core-20260902`，commit
  `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`。只提取失效案例，不复制旧 Audit 模型。
- RSS ledger：commit `c3fbd187b8d97ff25cc5968243062d1521714fb7`。
- CloudEvents spec：commit `2ed3806b4ad8fda35813263cfefb2d73098b7655`。
- Kubernetes apiserver audit types：commit `9a0d57c34dbee902b4683b0494050cd7955fe606`。

- Axum 0.8.9：[request Extension](https://github.com/tokio-rs/axum/blob/axum-v0.8.9/axum/src/extension.rs#L70-L98)，复用请求扩展和 router state；不复制默认 rejection 或认证机制。
