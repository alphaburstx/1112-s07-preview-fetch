# S-07 本地资源预览修复

从 `src/preview.mjs` 作者基线开始修复。锁定需求见 `AUTHOR-CONTRACT.md`，环境约束见 `ENVIRONMENT.md`。

正常资源示例（HTTP 与带临时 CA 的 HTTPS；会核对服务端 Host/SNI）：

```sh
node lab/smoke.mjs
```

此示例在未修复基线上也应通过，它只证明环境和正常路径可运行，不表示安全回归完整。fixture 提供 IPv4/IPv6 同端口、跳转、延迟、持续响应、压缩及损坏压缩体端点，可据此编写自己的回归。证书和私钥在运行时生成于系统临时目录，关闭后清理，不应复制进交付。
