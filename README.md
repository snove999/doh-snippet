# doh-snippet：Cloudflare Snippets 多上游 DoH 转发


## 端点

以 `https://doh.example.com` 为例：

| 路径 | 上游 | JSON 查询方式 |
|---|---|---|
| `/` | 首页：选择提供商、复制链接、在线测试 | — |
| `/cloudflare`、`/dns-query` | cloudflare-dns.com/dns-query | 原生 |
| `/ali` | dns.alidns.com/dns-query | 原生（/resolve） |
| `/tencent` | sm2.doh.pub/dns-query | 原生（/resolve） |
| `/360` | doh.360.cn/dns-query | 原生（/resolve） |
| `/google` | dns.google/dns-query | 原生（/resolve） |
| `/adguard` | dns.adguard-dns.com/dns-query | 原生（/resolve） |
| `/dnssb` | doh.dns.sb/dns-query | 脚本转换 |
| `/nextdns` | dns.nextdns.io/ | 脚本转换 |
| `/rethink` | basic.rethinkdns.com/ | 脚本转换 |
| `/vrecipes` | v.recipes/dns-query | 脚本转换 |
| `/appliedprivacy` | doh.applied-privacy.net/query | 脚本转换 |
| `/cznic` | odvr.nic.cz/doh | 脚本转换 |
| `/onedns` | doh.onedns.net/dns-query | 脚本转换 |

每个 DoH 路径都支持以下三种请求：

- RFC 8484 GET：`/google?dns=<base64url>`
- RFC 8484 POST：`Content-Type: application/dns-message`
- JSON：`/google?name=example.com&type=A`，可选参数 `cd`、`do`、`edns_client_subnet`

浏览器、系统或路由器的 DoH 设置里，直接填 `https://doh.example.com/google` 这类地址即可。

## 部署

前提：`example.com` 已作为 zone 托管在 Cloudflare。Snippets 仅 **Pro 及以上套餐**可用，Free 套餐不可用。

1. **创建 Snippet**：进入「Rules → Snippets → Create snippet」，名称例如 `doh`，把 `snippet.js` 的全部内容粘贴进去。
2. **触发规则**：选择「Custom filter expression」，表达式填：
   ```
   (http.host eq "doh.example.com")
   ```
4. 保存并部署。打开 `https://doh.example.com` 即可看到首页。

## 验证

```bash
curl -H "accept: application/dns-json" "https://doh.example.com/google?name=example.com&type=A"
curl -s -H "accept: application/dns-message" "https://doh.example.com/cloudflare?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" | xxd
# 查看上游实际收到的 ECS
curl "https://doh.example.com/google?name=o-o.myaddr.l.google.com&type=TXT"
```


## 修改提供商

编辑 `snippet.js` 顶部的 `PROVIDERS` 数组即可，首页会自动同步：

- `id`：路径名
- `doh`：RFC 8484 地址
- `json`（可选）：原生 JSON 接口
- `ecs: 1`（可选）：该 JSON 接口支持 `edns_client_subnet` 参数

默认上游由 `DEFAULT_ID` 指定（`/dns-query` 指向它）。
