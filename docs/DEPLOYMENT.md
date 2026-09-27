# 部署教程

## 1. 拓扑与准备

管理端部署到仍受支持的 Linux 系统，建议 Debian 13。宿主机支持目标为 CentOS 7、CentOS Stream 8、Debian 13，实际兼容性需要对应机器验证。CentOS 7 和 Stream 8 已停止官方维护。

管理端需要 Docker Engine、Compose v2、Python 3。项目提供可选的 Caddy HTTPS 入口，也可使用已有的反向代理。宿主机需要 systemd、Python 2.7+ 或 3、CA 证书；不需要 PHP、Docker、Node.js、libpcap 或 VM 内 Agent。

起步测试管理机可用 4–8 核、16 GiB 内存、SSD；这是试点起点，不是几十台宿主机的容量承诺。截图工作进程可迁到独立机器。容量按事件量与保留期压测。

不要在存放生产 VM 镜像的分区随意改变 Docker 全局配置。若要求容器镜像、构建缓存也全部存 `/home`，在专用管理机部署前，将 Docker 的 `data-root` 配置到 `/home/docker`；已有 Docker 的数据迁移需要单独规划。应用挂载目录不能控制 Docker 自身镜像存储位置。

## 2. 初始化服务端

把整个项目复制到管理机，例如 `/home/vm-monitor-src`：

```sh
cd /home/vm-monitor-src/deploy
bash prepare.sh
```

脚本创建 `.env`、生成 APP_KEY、数据库密码及工作进程凭据，不输出密钥。编辑 `.env`：

```dotenv
MONITOR_DATA_DIR=/home/vm-monitor-server
APP_URL=https://monitor.your-domain.example
MONITOR_DOMAIN=monitor.your-domain.example
MONITOR_AUTO_PROBE=false
```

不要在生产使用默认示例域名。第一次建议关闭自动探测，验证采集范围之后再开启。

准备目录：

```sh
sudo mkdir -p /home/vm-monitor-server/{storage,postgres,redis,worker,nginx-logs}
sudo mkdir -p /home/vm-monitor-server/worker/tmp
sudo chown -R 1000:1000 /home/vm-monitor-server/worker
docker compose build app web
docker compose up -d postgres redis app web
docker compose ps app
docker compose exec app php artisan migrate --force
docker compose exec app php artisan db:seed --class=MonitorSeeder --force
docker compose exec app php artisan monitor:admin admin@your-domain.example
docker compose up -d queue scheduler
```

密码通过交互输入，至少 12 位。没有内置默认管理员密码。

初始化不会自动添加节点、不会自动改变宿主机网络、不会向第三方发通知。

`app` 应保持 `Up`。若它反复重启，查看默认数据目录中的 `/home/vm-monitor-server/storage/logs/php-fpm.log`；自定义 `MONITOR_DATA_DIR` 时使用对应路径。容器日志驱动已关闭，因此 `docker compose logs app` 不显示此日志。

## 3. HTTPS

Compose 只将 Web 绑定到管理机 `127.0.0.1:8080`，数据库、Redis 和 PHP-FPM 不对公网发布。确认域名 A／AAAA 记录指向管理机，并在云平台安全组和主机防火墙开放 TCP 80、443。可以使用项目自带的 Caddy 入口自动申请并续期证书：

```sh
cd /home/vm-monitor-src/deploy
sudo mkdir -p /home/vm-monitor-server/caddy/{data,config}
docker compose --profile https up -d https
docker compose ps https
curl -I https://monitor.your-domain.example/admin/login
```

将示例域名替换为 `.env` 中的实际 `MONITOR_DOMAIN`。Caddy 的证书、配置及有界运行日志都保存在 `${MONITOR_DATA_DIR}/caddy`；证书申请失败时查看 `caddy/data/caddy-runtime.log`。若在容器启动之后才修改 `APP_URL`，执行 `docker compose up -d --no-deps --force-recreate app web queue scheduler` 使环境变量生效，然后启动 HTTPS 入口。

已有 Nginx/Caddy 时，不启动 `https` 配置组，而是在同一管理机终止 HTTPS 并转发到 `127.0.0.1:8080`。下面是 Nginx 的核心配置片段，证书路径使用你已有的实际证书：

```nginx
server {
    listen 443 ssl;
    server_name monitor.your-domain.example;
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    client_max_body_size 9m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 130s;
    }
}
```

访问 `https://你的域名/admin`。应用生成 HTTPS 链接，生产 Session Cookie 仅通过 HTTPS 发送。Agent 强制验证 HTTPS 证书；不要关闭校验来解决证书问题。

## 4. 截图工作服务

```sh
docker compose --profile screenshots build worker
docker compose --profile screenshots up -d worker
```

默认并发 1，容器内存上限 2 GiB，Chromium 以非 root 用户、沙箱和上游 seccomp 配置运行。使用额外网络隔离限制工作机到管理内网和云元数据地址的访问。

浏览器请求经任务专用代理，只能访问登记的目标 IP、协议、端口及 Host。浏览器不继承管理端凭据。第三方资源、跨站跳转、WebSocket、下载和表单提交默认阻止。某些网站因此只能得到不完整截图；这是明确的限制。

工作进程日志：`/home/vm-monitor-server/worker/worker.log`，按大小滚动。后台“网站探测任务”显示任务状态和失败原因。

**IPv6 站点验证要求工作进程本身具有 IPv6 出口。** Docker 默认网络不一定具备该能力，宿主机能够访问 IPv6 不代表容器也能。按你的 Docker／路由环境配置 IPv6 网络后，从 worker 容器验证连通性；也可在专用且具备 IPv6 出口的工作机部署 worker。IPv6 不可达会显示探测失败，不能解释为站点不存在。被动 IPv6 流量采集不依赖管理端的 IPv6 出口。

## 5. 创建节点并获取配置

后台进入“采集节点”，新增节点：

- CIDR 输入可能出现的公网范围，允许多个节点填相同范围。
- 采集接口填写经过网络验证的接口，例如 OVS 专用镜像接口。
- 数据目录默认 `/home/vm-monitor`。
- 默认工作内存 2048 MiB，服务硬限额 4096 MiB，磁盘预算 2048 MiB。

点击“下载接入配置”。每次下载会生成新凭据并撤销旧凭据。将 `agent.json` 以安全方式复制到宿主机。

**后台修改 CIDR 后，服务端授权范围立即更新；本版本不会自动远程改写 Agent 配置。** 更新接口、CIDR 或资源参数后，需要重新部署相应配置。生成新配置会轮换凭据，因此应及时部署。

只轮换凭据也可使用：

```sh
docker compose exec app php artisan monitor:node-token 节点UUID
```

此命令仅打印一次密钥，不要将输出放入工单、公共日志或代码仓库。

## 6. 编译与安装 Agent

开发机使用 Go 1.24 或更新且支持目标内核的版本：

```sh
bash deploy/agent/build.sh
```

将 `agent/bin/vm-agent-linux-amd64`、`agent/bin/SHA256SUMS`、`deploy/agent/install.sh` 和配置复制到宿主机。先核对二进制校验值，再安装：

```sh
sha256sum -c SHA256SUMS
chmod 700 vm-agent-linux-amd64
chmod 600 agent.json
sudo bash install.sh ./agent.json ./vm-agent-linux-amd64
```

安装器不会改防火墙、路由、网桥或 OVS。默认以 root 身份运行，但能力集限制为 `CAP_NET_RAW`，不保留 `CAP_NET_ADMIN`。所有应用文件写入指定目录，小型 systemd 单元放 `/etc/systemd/system`。

CentOS 7 的旧 systemd 使用 `MemoryLimit`，新版本使用 `MemoryMax`。安装器根据版本选择。不要禁用 SELinux；如访问 `/home` 或包套接字受到限制，检查 AVC 记录并按本机策略给予精确权限。

如果 `/home` 挂载为 `noexec`，目录中的二进制不能执行。可将整个数据目录配置到允许执行的大分区路径；不要为安装程序随意取消生产分区的安全选项。

## 7. 验证接入

```sh
systemctl status vm-monitor-agent --no-pager
tail -n 50 /home/vm-monitor/logs/agent.log
systemctl show vm-monitor-agent -p MemoryCurrent -p MemoryLimit -p MemoryMax
du -sh /home/vm-monitor
```

大约一个采集窗口后，后台应出现节点上报时间和健康指标；稍后调度器处理数据。旧缓存补传会更新“最近上报”，但不会把旧健康窗口覆盖到新健康窗口上。

几十台节点接入时，根据“待分析批次”的积压情况增加分析工作进程，例如 `docker compose up -d --scale queue=3 queue`。同一节点的分析串行，不同节点可并行；不要未经压测就把进程数量等同于容量保证。

以可控 VM 验证：向公网发起正常连接、通过非标准端口访问测试站点、分别检查 IPv4 与 IPv6。确认后台显示的是正确公网 IP。不能因为节点在线就认定它看到了全部 VM 流量。

## 8. 主动发现无访问的网站

使用已配置节点范围，对单个 IP 或小 IPv4 CIDR 排队：

```sh
docker compose exec app php artisan monitor:discover 节点UUID 实际公网IP --ports=80,443,8080,8443,18080 --scheme=both
docker compose exec app php artisan monitor:discover 节点UUID 实际IPv4网段/24 --ports=80,443
```

一次最多 128 个端口、2048 个 IP/端口组合、IPv4 范围不超过 /24。IPv6 必须给具体地址。每个协议是独立验证任务，未知服务会显示候选或失败，不会冒充“已经部署的网站”。

任意 TCP Web 端口可以分批指定；不提供对大网段高频全端口扫描。后台可对已发现 IP 手动添加域名及端口，再验证虚拟主机站点。

## 9. 通知、升级与卸载

SMTP 通知：在 `.env` 配置 `MONITOR_ALERT_EMAIL`、`MAIL_MAILER=smtp` 及真实 SMTP 参数，再重建相关容器。首次出现的合并告警会排队发送邮件；重试采用至少一次语义，极端故障时可能重复投递。未配置收件人时不会发送。

升级前备份数据库、`.env` 和 storage。升级服务端后执行迁移，重启队列与调度器。不要在生产使用 `migrate:fresh`。

Agent 升级重新运行安装器，保留一个 `vm-agent.previous`。回滚时停止服务，将该文件恢复为 `vm-agent`，核对兼容配置后启动。内存硬限额变更也需要重新运行安装器。

卸载：

```sh
sudo bash deploy/agent/uninstall.sh
```

卸载保留数据、凭据及人工配置的 OVS 镜像，供你检查后自行清理；到后台禁用节点或轮换其凭据。
