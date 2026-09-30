# 部署教程（BuildAdmin 管理后台）

本项目由四部分组成：宿主机上的 Go Agent、接收和分析数据的 Laravel API、BuildAdmin 管理后台、可选的截图 worker。VM 内不安装软件。公网域名的 `/api/v1/*` 转到 Laravel API，其余管理页面由 BuildAdmin 提供；Laravel 不提供管理登录页面。

## 1. 准备服务器

管理服务器建议使用仍受支持的 Linux 系统（例如 Debian 13），安装 Docker Engine、Docker Compose v2、Git 和 Python 3。首次试点可从 4–8 核、16 GiB 内存和 SSD 开始，实际容量须按事件量、截图并发和保留期测量。宿主机 Agent 支持目标为 CentOS 7、CentOS Stream 8、Debian 13；安装前需在各系统实际验证。宿主机需要 systemd、CA 证书和 Python 2.7+ 或 3，不需要在 VM 内安装任何组件。

域名的 A／AAAA 记录应指向管理服务器。开放 TCP 80、443；Web、数据库、Redis 和 PHP-FPM 仅在 Docker 网络或本机监听。监控数据、MySQL、PostgreSQL、Redis、截图和编译产物默认放在 `/home/vm-monitor-server`；可以在 `deploy/.env` 中用 `MONITOR_DATA_DIR` 改为其他大分区。不要把生产 VM 镜像分区用作截图或数据库的无界存储。

## 2. 全新安装

```sh
sudo git clone https://github.com/q992218196/vm-public-ip-monitor.git /home/vm-monitor-src
cd /home/vm-monitor-src/deploy
bash prepare.sh
```

编辑 `deploy/.env`，至少将 `APP_URL` 改为 `https://vm-monitor.lcayun.cn`（换域名时用自己的域名），并设置 `MONITOR_DOMAIN=vm-monitor.lcayun.cn`。`prepare.sh` 会生成随机密钥，切勿公开或在后续升级时重新生成。使用自定义数据目录时，下面所有 `/home/vm-monitor-server` 路径都要同步替换。

```sh
sudo mkdir -p /home/vm-monitor-server/{storage,postgres,redis,nginx-logs,agent-dist,caddy/data,caddy/config,buildadmin/mysql,buildadmin/runtime,buildadmin/uploads,worker/tmp}
docker compose -f compose.yml -f compose.buildadmin.yml build app web buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml up -d postgres redis buildadmin-db
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d app web queue scheduler buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php tools/init-admin.php admin@your-domain.example
```

最后一条命令会在终端交互输入并确认至少 12 位的密码，不会把密码放到命令行参数。请把邮箱换成自己的。该命令只初始化新数据库里尚未设置密码的管理员；若已有管理员，应在 BuildAdmin 的“管理员管理”或“个人资料”中修改，不能重复初始化。

在主控编译并提供 Linux amd64 Agent 下载文件，然后启动 HTTPS：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d https
```

打开 `https://你的域名/#/admin/login`，使用刚设置的邮箱和密码登录。BuildAdmin 的 MySQL 数据位于 `${MONITOR_DATA_DIR}/buildadmin/mysql`，监控记录位于 PostgreSQL；两个数据库都要备份。

## 3. 升级已运行的主控

先备份 `deploy/.env`、PostgreSQL、BuildAdmin MySQL 和 `${MONITOR_DATA_DIR}/storage`，并确认 `/home` 有足够空间。在低峰时段执行。现有邮箱和密码保留，不要再次运行 `prepare.sh` 或 `init-admin.php`。

```sh
cd /home/vm-monitor-src
git pull
cd deploy
docker compose -f compose.yml -f compose.buildadmin.yml build app web buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --force-recreate app web queue scheduler buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d --no-deps --force-recreate https
docker compose -f compose.yml -f compose.buildadmin.yml exec app php artisan view:clear
```

数据库迁移保留现有监控数据和 BuildAdmin 账号。重建 PHP 应用时 Web 容器也会重建，避免连接到已更换的容器地址。升级后检查：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile https ps
curl -sS -o /dev/null -w 'Agent API: %{http_code}\n' 'https://vm-monitor.lcayun.cn/api/v1/agent/update?version=0.3.0'
curl -sS -o /dev/null -w 'BuildAdmin: %{http_code}\n' 'https://vm-monitor.lcayun.cn/admin/Index/login'
```

第一项无 Agent 令牌时应返回 `401`，第二项应返回 `200`；把示例域名替换为实际域名。然后在 BuildAdmin“采集节点”确认“最近上报”持续更新。只看到容器为 `Up` 不等于上报链路已经恢复。

## 4. 截图 worker

如果需要网站截图和内容分类，再启动 worker。它只通过有界任务验证已登记的公网 IP、协议、端口和 Host；不在 Agent 宿主机运行 Chromium。默认并发 2，容器内存上限 2 GiB；`WORKER_CONCURRENCY` 可设为 1–4，增大并发前先观察内存和失败率。

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots build worker
worker_uid=$(docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots run --rm --no-deps --entrypoint id worker -u)
worker_gid=$(docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots run --rm --no-deps --entrypoint id worker -g)
sudo chown -R "$worker_uid:$worker_gid" /home/vm-monitor-server/worker
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots up -d worker
```

若自定义 `MONITOR_DATA_DIR`，更换 `chown` 路径。worker 日志默认是 `/home/vm-monitor-server/worker/worker.log`；启动即退出时可在 `deploy` 目录运行 `docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots run --rm --no-deps worker` 查看错误。IPv6 站点验证要求 worker 容器本身拥有 IPv6 出口，宿主机能访问 IPv6 并不能替代容器验证。

## 5. 接入宿主机 Agent

在 BuildAdmin 的“采集节点”创建节点，填写采集接口、可能出现的公网 IPv4／IPv6 CIDR 和资源预算。同一 CIDR 可以出现在多个节点；CIDR 只是授权匹配范围，不表示 VM 的唯一归属。默认 Agent 工作内存预算 2048 MiB、systemd 硬限额 4096 MiB、数据目录预算 2048 MiB，均可配置。Agent 默认把持续数据写到宿主机 `/home/vm-monitor`。

点击“生成安装命令”，在 10 分钟内到目标宿主机以 root 执行。命令会从本站 HTTPS 下载一次性 `agent.json`、安装脚本和已在主控编译的 amd64 二进制，并校验 SHA-256。一次性配置只能下载一次；生成新命令会立即轮换该节点令牌，因此应及时执行，且不要把命令贴到工单、公开日志或聊天记录。需要通过自己的安全通道传输时，可选择“接入配置”下载文件。

安装器不改防火墙、路由、网桥或 OVS。应先确认宿主机选定接口能看到公网 IP 的双向流量；KVM/libvirt 的 VM 身份无需由 Agent 推断。CentOS 7 的 systemd 使用 `MemoryLimit`，较新的系统使用 `MemoryMax`。`/home` 若挂载为 `noexec`，应改用允许执行的大分区数据目录。

节点验证：

```sh
systemctl status vm-monitor-agent --no-pager
tail -n 50 /home/vm-monitor/logs/agent.log
systemctl show vm-monitor-agent -p MemoryCurrent -p MemoryLimit -p MemoryMax
du -sh /home/vm-monitor
```

约一个采集窗口后，BuildAdmin 应显示新“最近上报”时间。旧积压批次会在网络恢复后重传；HTTP 429 批次保留并重试，日志会写明服务端原因；HTTP 422 代表服务端校验失败，当前 Agent 会丢弃该批次并记录原因。若出现 422，请先核对节点 CIDR、时间和上报字段。系统不会从已丢弃的批次重建证据。

Agent 0.3.x 或更早版本没有后台更新轮询能力，首次升级到 0.4.1 必须在节点执行新的安装命令。之后可在 BuildAdmin 对单节点或多节点下发已编译版本；先选一台试点，再批量更新。Agent 每分钟轮询更新，校验 SHA-256 后自检并保留上一版。节点侧若需立即检查后台已下发的更新：

```sh
sudo /home/vm-monitor/bin/vm-agent -config /home/vm-monitor/config/agent.json -update
sudo systemctl restart vm-monitor-agent
```

自定义 `data_dir` 时替换路径。更改采集接口、CIDR 或内存硬限额需要重新生成并部署配置。

## 6. 功能验证与维护

用可控 VM 分别产生 IPv4、IPv6 和非标准端口的正常访问，确认 BuildAdmin 的公网 IP、网站、流量窗口和节点时间都正确。在线只证明 Agent 可上报，不证明它看到了全部 VM 流量。网站截图与内容分类需要 worker 在线；内容分类是待人工复核线索，不能代替人工判断。

网站若没有流量线索，可对已授权的具体 IP 或小 IPv4 网段主动排队，端口自行选择：

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml exec app php artisan monitor:discover 节点UUID 实际公网IP --ports=80,443,8080,8443 --scheme=both
```

一次最多 128 个端口、2048 个 IP／端口组合，IPv4 范围不超过 `/24`；IPv6 必须给具体地址。未知服务只显示候选或验证失败，不会当成已确认网站。

常用维护命令：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml exec app php artisan monitor:dispatch --sync
docker compose -f compose.yml -f compose.buildadmin.yml exec app php artisan monitor:maintain
docker compose -f compose.yml -f compose.buildadmin.yml exec app php artisan queue:failed
docker compose -f compose.yml -f compose.buildadmin.yml exec -T postgres pg_dump -U monitor monitor > /home/monitor-backup.sql
```

几十台节点接入后，依据“待分析批次”积压、CPU、RSS、丢包及数据库 I/O 调整队列进程数量；不应直接把容器个数当作 500 VM 的容量保证。SMTP 告警使用 `deploy/.env` 的 `MONITOR_ALERT_EMAIL` 和 `MAIL_*` 参数，配置后重建相关应用容器。

## 7. 常见故障

- **登录页刷新、不能登录**：确认 `/admin/Index/login` 返回 BuildAdmin JSON；检查 BuildAdmin MySQL 是否健康，`buildadmin-app` 与 `buildadmin-web` 是否运行。验证码错误时检查 `/api/common/clickCaptcha`，返回数据应包含图片 `data:image/`。
- **Agent 持续 502**：检查 `app`、`web`、`https` 容器；可以先重启 `web` 恢复旧运行配置中的容器地址，然后按第 3 节升级并重建 Web 镜像。不要删除节点本地 `/home/vm-monitor/spool`。
- **Agent 持续 429**：可能是每节点请求限流，也可能是主控待处理批次达到容量上限；新版 Agent 日志显示响应原因。检查队列 worker、数据库和节点积压情况后再调整容量。
- **Agent 收到 422**：该批次不符合校验规则，优先核对授权 CIDR、采集窗口时间及新版日志中的字段错误；已丢弃批次不能通过重启恢复。
- **截图 worker 重启或无截图**：检查目录属主、`worker.log`、worker 内存及 IPv6 出口；探测任务页面会显示失败原因。

管理员可在 BuildAdmin 右上角“个人资料”修改邮箱或密码，在“管理员管理”创建只读账号并分配“监控只读”分组。生产环境不开放公开注册。卸载宿主机 Agent 可执行 `sudo bash deploy/agent/uninstall.sh`；该操作保留数据和人工配置的镜像接口，需单独检查后清理。
