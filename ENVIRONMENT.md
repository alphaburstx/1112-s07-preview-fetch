仅本地靶场。Node.js 固定为 22.18.0，使用 PATH 中的 `node` 命令；TLS 夹具使用 PATH 中的 `openssl` 命令。运行前用 `node --version` 和 `openssl version` 核对环境，确保 Node 版本正确。

loopback IPv4/IPv6 与同端口 TLS 能力已在作者环境验证。证书 CA 仅通过客户端选项提供，不安装到系统信任库。不要调用浏览器或真实 URL，不修改 hosts、路由或系统代理。
