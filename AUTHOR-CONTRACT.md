# 作者接口与本地预算附件

本题为作者合成的防御性本地靶场。`src/preview.mjs` 是有意保留缺陷的起点，不是可用于生产的抓取器；不依赖真实站点、生产域名或历史模型答案。请在此源码基础上修复并交付自己的回归。

## 兼容接口

```js
import { makePreviewClient } from './src/preview.mjs';
const client = makePreviewClient(policy, { resolveAll, ca });
const result = await client.fetchPreview(url, { signal });
// result = { url: 最终URL字符串, status: HTTP状态整数, body: Buffer }
```

`resolveAll(host)` 是可注入的异步解析器，返回完整数组 `[{address, family:4|6}, …]`；默认实现仍可用 Node DNS。测试只会注入 `.test` 名称和回环地址。`ca` 是可选的 PEM 测试 CA，不安装到系统信任库。`signal` 是可选 AbortSignal。保留上述导出和返回结构；可增添内部模块及自己的测试，无需新增服务或 UI。

```js
const policy = {
  hosts: {
    'preview.test': {
      ports: [8080],
      addresses: [{ address: '127.0.0.1', family: 4 }]
    }
  },
  limits: {
    timeoutMs: 1000,
    maxRedirects: 3,
    maxWireBytes: 65536,
    maxDecodedBytes: 131072
  }
};
```

`policy` 来自可信配置，不能由 URL、响应或调用参数扩权。主机按 WHATWG URL 解析，DNS 名小写；IPv6 字面量去掉方括号后作为 hosts 键，地址用数值 IP 等价关系比较。端口必须明确授权；省略端口按 HTTP 80/HTTPS 443。仅允许 HTTP/HTTPS；含用户名或密码的 URL 应拒绝。未配置主机、端口或地址均拒绝；不得采用通配主机或失败后回退到系统解析。

## 地址与连接

每一跳先验证目标和完整解析结果，再建立连接。解析为空、格式不合法、family 与数值地址不一致，或任一地址未获该主机授权时，整跳拒绝且不能发 HTTP 请求。不能只验证首个结果。每个实际 socket 只能连接该跳已核验的地址；不能另行解析、使用先前抓取或其他并发请求留下的地址。允许从已核验集合选地址，不要求故障自动重试。IP 字面量无需 DNS，但仍须检查同样的地址授权。

请求保持原 URL 的路径、查询、Host（包含必要端口及 IPv6 方括号）。HTTPS 连接固定数值地址时，仍以 URL 中的 DNS 主机名发送 SNI 并验证证书身份和链；IP 字面量按 IP 身份验证，不伪造 DNS SNI。不得关闭 `rejectUnauthorized`，也不得用“连接的是允许 IP”代替证书校验。

301/302/303/307/308 的 Location 按当前 URL 解析相对路径。每次跳转重新核验主机、端口、完整地址集和连接绑定；最终返回最终 URL。无 Location 的响应作为终态返回。非跳转 HTTP 状态码可照常返回。

## 预算、解码与生命周期

上述 limits 缺省时使用示例中的值。提供时 timeoutMs 必须是正整数，其余为非负整数；配置错误应明确拒绝。`maxRedirects` 是最多可跟随的跳数，0 表示不跟随。一个 fetch 的 timeoutMs 是从进入函数到完成解码的总期限，涵盖解析、连接、所有跳转和读取，不是每跳或空闲超时。

body 返回完整解码后的 Buffer。支持 identity、gzip、deflate、br；其他或叠加 Content-Encoding 可拒绝。maxWireBytes 限制实际读取的线上传输体字节（即解码前响应体字节，不含 HTTP 头/分块帧）；maxDecodedBytes 限制解码后的字节。它们按一次 fetch 累计，对实际读取的跳转体同样计数；允许立即关闭跳转响应，不要求为计数读完整体。恰好等于上限应成功，超出则拒绝；不能仅信 Content-Length。解码损坏、取消、超时、超限均不能把截断内容作为成功结果返回。

每次 fetch 的计时器、计数、地址和取消处理独立。取消与总期限也必须覆盖仍在等待的解析器；不要求取消自定义 Promise 内部工作，但它后来返回的结果不得触发连接。结束或失败后清理本次请求、响应、解码流和监听器。错误应拒绝为 Error，文本/自定义 code 不作固定匹配。

## 运行条件与安全边界

使用 ENVIRONMENT.md 指定 Node 22.18.0；不需第三方依赖。`lab/smoke.mjs` 是正常资源示例，不是完整验收。`lab/fixture.mjs` 仅在 127.0.0.1/::1 开启临时端口；`lab/tls.mjs` 在系统临时目录生成专用 CA/服务端证书和私钥，结束后删除。不得公开私钥、修改 hosts/路由/代理/信任库或访问真实网站。若平台缺少 IPv6 或 OpenSSL，应明确报告，不能把未运行当通过。
