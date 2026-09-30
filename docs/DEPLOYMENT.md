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

不要在生产使用默认示例域名。第一次建议关闭自动探测，验证采集范围之后再开启。新部署的 `.env.example` 默认开启自动验证；试点时可以显式设为 `false`。

试点确认公网 IP 范围、截图工作服务和内网隔离后，将现有 `.env` 的 `MONITOR_AUTO_PROBE` 改为 `true`，执行 `docker compose up -d --no-deps --force-recreate app queue scheduler`。开启后，后台每 5 分钟最多为 50 个尚未验证或超过 24 小时未验证的网站排队，同时待处理任务最多 1000 个。未启动截图 worker 时任务会排队，但不会生成截图。

准备目录：

```sh
sudo mkdir -p /home/vm-monitor-server/{storage,postgres,redis,worker,nginx-logs}
sudo mkdir -p /home/vm-monitor-server/worker/tmp
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

## 4. 完整切换到 BuildAdmin 管理后台

BuildAdmin 承担登录、账号权限、首页及全部监控管理页面。原 Laravel 服务仍接收 Agent 数据并处理分析与截图任务，因此切换后台不会改变宿主机 Agent 的上报地址。BuildAdmin 使用独立 MySQL 保存账号和菜单，直接读取现有 PostgreSQL 监控数据；MySQL 数据默认保存在 `${MONITOR_DATA_DIR}/buildadmin/mysql`。

先更新项目代码，然后在管理服务器的 `deploy` 目录执行：

```sh
cd /home/vm-monitor-src/deploy
bash prepare.sh
sudo mkdir -p /home/vm-monitor-server/buildadmin/{mysql,runtime,uploads}
docker compose -f compose.yml -f compose.buildadmin.yml build buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml up -d buildadmin-db buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php tools/import-monitor-users.php
curl -I http://127.0.0.1:8081/
```

若使用自定义 `MONITOR_DATA_DIR`，目录创建命令也改为该路径。`prepare.sh` 会为旧 `.env` 补充 BuildAdmin 数据库密码和令牌密钥，不会重置现有密钥。迁移命令只初始化 BuildAdmin 的 MySQL 表，监控记录仍留在 PostgreSQL。账号导入程序复制原 Laravel 管理员及只读用户的邮箱、密码散列和权限；再次运行不会覆盖在新后台修改过的密码。BuildAdmin 上游自带的空密码演示管理员会被禁用。

`agent-builder` 在主控服务器编译 Linux amd64 Agent，产物、安装脚本及 `SHA256SUMS` 放在 `${MONITOR_DATA_DIR}/agent-dist`（默认 `/home/vm-monitor-server/agent-dist`）。后台“采集节点”可下载节点专属 `agent.json` 并复制安装命令；先通过可信通道将配置文件传到目标宿主机 `/home/vm-monitor-install/agent.json`，再在宿主机以 root 粘贴命令。命令从本站 HTTPS 下载编译产物并校验哈希，不含长期节点令牌。生成新配置会轮换旧凭据，务必及时安装。更新 Agent 源码后重新运行上面的 `agent-builder` 两条命令即可刷新下载文件。

在切换公网入口前，先通过本机端口打开 `http://127.0.0.1:8081/#/admin/login` 验证旧管理员邮箱及密码。若从远程电脑测试，可以通过现有可信的 SSH 隧道转发本机端口；不要把 8081 直接暴露到公网。确认采集节点、告警、网站、规则、详情和账号页面正常后，再切换 Caddy：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d --no-deps --force-recreate https
curl -I https://你的域名/
```

访问 `https://你的域名/#/admin/login`。公网 `/api/v1/*` 仍送到原 Laravel 服务供 Agent 与截图 worker 使用；BuildAdmin 的 `/api/common/*` 接收验证码和令牌刷新请求。其他页面由 BuildAdmin 提供。旧 Laravel 管理 UI 不再由公网入口提供。告警中心显示筛选后的准确总数，单页可选 10、25、50、100、200、500 条；列表仅返回概要字段，详情与截图在点击时单独读取。

如果输入账号后又回到登录页，先检查登录接口是否真正到达后台控制器：

```sh
curl -fsS -H 'server: true' https://你的域名/admin/Index/login
```

正常 JSON 的 `data` 中应有布尔值 `captcha`。如果返回的是 `site`、`menus` 等首页字段，说明运行中的 `buildadmin-web` 使用了旧版 Nginx 配置；更新代码后执行 `docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --build --force-recreate buildadmin-web`，再运行上面的检查。此操作不重置数据库或账号。不要将密码放进诊断命令。

若登录弹窗报错 `/api/common/clickCaptcha`，需要同时重建 `buildadmin-web` 并重启 `https` 服务，确保 Nginx 与 Caddy 都加载了新版路由。检查 `curl -fsS -H 'server: true' 'https://你的域名/api/common/clickCaptcha?id=smoke-check'`，正常 JSON 中的 `data.base64` 应以 `data:image/` 开头。验证码图像内容不必贴出。

如果切换后发现问题，可立即恢复旧公网入口，原有 PostgreSQL 和 Agent 无需回滚：

```sh
docker compose -f compose.yml --profile https up -d --no-deps --force-recreate https
```

回退后仍用原 Laravel 后台的账号信息登录；在 BuildAdmin 中变更的邮箱或密码不会自动同步回 Laravel。验证完成后才考虑停用旧管理登录入口，采集 API 仍需要 Laravel 服务运行。

## 5. 截图工作服务

```sh
docker compose --profile screenshots build worker
worker_uid=$(docker compose --profile screenshots run --rm --no-deps --entrypoint id worker -u)
worker_gid=$(docker compose --profile screenshots run --rm --no-deps --entrypoint id worker -g)
sudo chown -R "$worker_uid:$worker_gid" /home/vm-monitor-server/worker
docker compose --profile screenshots up -d worker
```

工作容器以镜像内的 `pwuser` 运行，UID/GID 随基础镜像而定，因此先查询实际编号再授权数据目录；自定义 `MONITOR_DATA_DIR` 时替换上述路径。若容器启动前就退出，可在 `deploy` 目录运行 `docker compose --profile screenshots run --rm --no-deps worker` 查看直接错误。

默认同时探测 2 个任务，可通过 `WORKER_CONCURRENCY=1..4` 调节。每个并发任务启动独立 Chromium；容器内存上限 2 GiB，增加并发前应观察内存和失败率，资源紧张时设为 1。升级已有部署时 `.env` 会保留原来的值，需要手动将 `WORKER_CONCURRENCY` 设为 2 后重建 worker 容器。Chromium 以非 root 用户、沙箱和上游 seccomp 配置运行。使用额外网络隔离限制工作机到管理内网和云元数据地址的访问。

浏览器请求经任务专用代理，只能访问登记的目标 IP、协议、端口及 Host。浏览器不继承管理端凭据。第三方资源、跨站跳转、WebSocket、下载和表单提交默认阻止。某些网站因此只能得到不完整截图；这是明确的限制。

工作进程日志：`/home/vm-monitor-server/worker/worker.log`，按大小滚动。后台“网站探测任务”显示任务状态和失败原因。

**IPv6 站点验证要求工作进程本身具有 IPv6 出口。** Docker 默认网络不一定具备该能力，宿主机能够访问 IPv6 不代表容器也能。按你的 Docker／路由环境配置 IPv6 网络后，从 worker 容器验证连通性；也可在专用且具备 IPv6 出口的工作机部署 worker。IPv6 不可达会显示探测失败，不能解释为站点不存在。被动 IPv6 流量采集不依赖管理端的 IPv6 出口。

## 6. 创建节点并获取配置

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

## 7. 编译与安装 Agent

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

## 8. 验证接入

```sh
systemctl status vm-monitor-agent --no-pager
tail -n 50 /home/vm-monitor/logs/agent.log
systemctl show vm-monitor-agent -p MemoryCurrent -p MemoryLimit -p MemoryMax
du -sh /home/vm-monitor
```

大约一个采集窗口后，后台应出现节点上报时间和健康指标；稍后调度器处理数据。旧缓存补传会更新“最近上报”，但不会把旧健康窗口覆盖到新健康窗口上。

几十台节点接入时，根据“待分析批次”的积压情况增加分析工作进程，例如 `docker compose up -d --scale queue=3 queue`。同一节点的分析串行，不同节点可并行；不要未经压测就把进程数量等同于容量保证。

以可控 VM 验证：向公网发起正常连接、通过非标准端口访问测试站点、分别检查 IPv4 与 IPv6。确认后台显示的是正确公网 IP。不能因为节点在线就认定它看到了全部 VM 流量。

## 9. 主动发现无访问的网站

使用已配置节点范围，对单个 IP 或小 IPv4 CIDR 排队：

```sh
docker compose exec app php artisan monitor:discover 节点UUID 实际公网IP --ports=80,443,8080,8443,18080 --scheme=both
docker compose exec app php artisan monitor:discover 节点UUID 实际IPv4网段/24 --ports=80,443
```

一次最多 128 个端口、2048 个 IP/端口组合、IPv4 范围不超过 /24。IPv6 必须给具体地址。每个协议是独立验证任务，未知服务会显示候选或失败，不会冒充“已经部署的网站”。

任意 TCP Web 端口可以分批指定；不提供对大网段高频全端口扫描。后台可对已发现 IP 手动添加域名及端口，再验证虚拟主机站点。

## 10. 通知、升级与卸载

SMTP 通知：在 `.env` 配置 `MONITOR_ALERT_EMAIL`、`MAIL_MAILER=smtp` 及真实 SMTP 参数，再重建相关容器。首次出现的合并告警会排队发送邮件；重试采用至少一次语义，极端故障时可能重复投递。未配置收件人时不会发送。

升级前备份数据库、`.env` 和 storage。升级服务端后执行迁移，重启队列与调度器。不要在生产使用 `migrate:fresh`。

新版疑似加密代理线索检测的升级示例：

```sh
cd /home/vm-monitor-src
git pull
cd deploy
# 若需要默认双任务并发，请在现有 .env 中设置 WORKER_CONCURRENCY=2
docker compose --profile screenshots build app web worker
docker compose run --rm --no-deps app php artisan migrate --force
docker compose run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose up -d --no-deps --force-recreate app web queue scheduler
docker compose --profile screenshots up -d --no-deps --force-recreate worker
```

迁移命令使用新镜像中的一次性应用容器，此时原有数据库与 Redis 服务应保持运行。已有索引迁移在大表上可能占用 I/O 和临时磁盘空间，请在升级前检查 `/home` 剩余空间并安排低峰时段。Seeder 只补充缺少的默认检测规则，不覆盖已修改的规则。若 `.env` 中仍是 `WORKER_CONCURRENCY=1`，worker 仍会串行探测。疑似加密代理线索需要把 0.3.0 或更新的 Agent 部署到宿主机，并由新的采集窗口产生；旧版 Agent 仍可上报原有数据，但不会产生新线索。历史证据不会凭空补齐。

Agent 升级重新运行安装器，保留一个 `vm-agent.previous`。回滚时停止服务，将该文件恢复为 `vm-agent`，核对兼容配置后启动。内存硬限额变更也需要重新运行安装器。

卸载：

```sh
sudo bash deploy/agent/uninstall.sh
```

卸载保留数据、凭据及人工配置的 OVS 镜像，供你检查后自行清理；到后台禁用节点或轮换其凭据。
