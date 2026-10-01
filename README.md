# VM 公网 IP 流量监控

面向 KVM 宿主机的公网 IP 监控系统。VM 内不安装软件；每台宿主机运行一个 Go Agent。Laravel 13 负责采集、分析和探测 API；管理后台已迁移至 BuildAdmin（ThinkPHP 8 + Vue 3）。

`admin/` 基于 [BuildAdmin v2.3.8](https://github.com/build-admin/buildadmin) 定制，保留其 Apache-2.0 许可证；新装和升级步骤见 [部署教程](docs/DEPLOYMENT.md)。Laravel 仅承担接收和分析 API，不提供管理登录页面。

## 当前实现

- IPv4／IPv6 CIDR 过滤，同一 CIDR 可配置到多个节点。
- 公网 IP 独立资产，保留多个观察节点；不推断 VM 身份，不把多节点流量直接相加。
- Linux AF_PACKET 被动采集，支持 Ethernet、双层 VLAN、IPv4、IPv6 基础扩展头、TCP／UDP 统计。
- 非标准端口 HTTP Host、TLS ClientHello SNI 线索与有界 TCP 顺序重组。
- 横向扫描、端口扫描、认证服务重复连接、单目标高频连接、TCP 连接突增及出站 Mbps 阈值告警。
- WireGuard、部分 OpenVPN UDP 和 IKEv2 双向握手结构识别，保留独立窗口证据；不把加密流量特征误报为具体翻墙协议。
- SS、SSR、VMess、Trojan/Trojan-Go、Hysteria、VLESS、AnyTLS 等加密代理的疑似流量线索：按可见传输外观、多对端双向会话和 VM 多目标出站行为关联，低级别告警；候选名称不代表协议确认。
- 节点凭据、CIDR 越界校验、持久化接收队列、幂等重传、断网有界缓存。
- 有界自动 Web 验证、独立 Chromium 截图、疑似有害内容的待复核标记与人工分类修正。
- 站点详细分析报告：标题、描述、业务类型、复核理由、命中原文、观察时间和截图；可导出单站 JSON 报告。
- 多目标连接按握手回复比例分级，目标级连接／载荷样本、可见 HTTP 路径与参数名辅助复核；不以连接次数推断 HTTP 请求次数。
- 响应式中文后台：节点、公网 IP、网站、告警、规则、白名单、流量窗口、协议观察、探测任务、审计；筛选与分页在服务端完成，告警显示准确总数，批量处理只提交所选 ID，详情和截图按需读取。
- 管理员／只读角色、CSV 导出、可选 SMTP 告警。
- 默认 Agent 工作预算 2 GiB、服务硬限额 4 GiB、目录预算 2 GiB；可配置。
- Agent、服务端和截图工作进程的持续数据均支持 `/home` 自定义目录。

## 快速入口

1. [服务端与节点部署教程](docs/DEPLOYMENT.md)
2. [采集位置与网络可见性](docs/NETWORK.md)
3. [资源配置、数据协议与运维](docs/OPERATIONS.md)
4. [验证报告与能力边界](docs/VALIDATION.md)

目录：`server/` Laravel 采集与分析 API；`admin/` BuildAdmin 管理后台；`agent/` Go Agent；`worker/` 网站工作服务；`deploy/` 部署；`docs/` 教程。

## 本地验证

```sh
cd agent
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/vm-agent-linux-amd64 ./cmd/vm-agent

cd ../server
composer install
cp .env.example .env
php artisan key:generate
php vendor/phpunit/phpunit/phpunit

cd ../worker
npm ci
npm test
```

实际采集需要 Linux 和 `CAP_NET_RAW`。Windows 可运行解析测试、PCAP 回放及 Linux 交叉编译。

## 部署边界

这是一套可运行的初始版本，并非已在真实 500 VM 宿主机上完成性能认证的产品。生产上线前，必须按教程分别验证 OVS、Linux bridge、公网 IP 可见性、真实包速率下的丢包和资源消耗。

本版本不读取 VM 内进程／配置，不确认加密协议的认证失败，不解密 ECH，不支持 QUIC 网站识别或 IP 分片重组。域名线索必须主动验证；规则分类不能代替人工定性。详细边界见验证报告。
