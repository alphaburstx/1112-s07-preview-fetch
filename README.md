# S-07 本地资源预览修复

从 `src/preview.mjs` 作者基线开始修复。锁定需求见 `AUTHOR-CONTRACT.md`，环境约束见 `ENVIRONMENT.md`。

## 运行

环境核对（需 Node 22.18.0 与 PATH 中的 openssl）：

```sh
node --version && openssl version
```

正常资源示例（HTTP 与带临时 CA 的 HTTPS；会核对服务端 Host/SNI）：

```sh
node lab/smoke.mjs
```

安全回归（31 项，全部只走 127.0.0.1/::1 回环与注入解析）：

```sh
node test/regression.mjs
```

## 修复要点

- 每一跳（初始 URL 与每次跳转）先完整授权再连接：主机规则、显式端口、**完整**解析结果集全部命中策略才放行；解析为空、条目非法、family 与数值地址不符、任一地址未授权，整跳拒绝且不发请求。
- socket 只连接本跳已核验的数值地址（`hostname` 直接给已核验 IP，不装 `lookup` 钩子、不二次解析、不跨请求复用地址）；IP 字面量跳过 DNS 但同样做地址授权。
- 固定地址的 HTTPS 仍以 URL 的 DNS 名发 SNI 并校验证书身份与链（`rejectUnauthorized` 保持开启）；IP 字面量按 IP 身份校验、不伪造 SNI；Host 头保留端口与 IPv6 方括号。
- 跳转按当前 URL 解析相对 `Location`，每跳重新核验；`maxRedirects` 为可跟随跳数上限，超限拒绝。
- `timeoutMs` 为进入函数到解码完成的总期限，覆盖解析、连接、所有跳转与读取；取消与超时同样覆盖未完成的解析器，迟到的解析结果不会触发连接。
- body 支持 identity/gzip/deflate/br，其他或叠加编码拒绝；`maxWireBytes`/`maxDecodedBytes` 按实际读取计数（不信 Content-Length），恰好等于上限成功、超出拒绝；每次 fetch 的计时器、计数器、地址与取消处理相互独立。

## 平台限制与未完成项

- 已在 macOS（Darwin 27）+ Node 22.18.0 + OpenSSL 4.1.0 验证，IPv4/IPv6 回环与同端口 TLS 均可用；未在其他平台运行。
- 从已核验集合选取地址时固定取首个，不做故障自动重试（契约允许）。
- 跳转响应体立即关闭、不计入字节预算（契约允许）；`identity` 之外的编码清单外的值一律拒绝。
- 证书与私钥仅运行时生成于系统临时目录并在结束时删除，未复制进交付；未改动 hosts/路由/代理/信任库，未访问真实站点。

