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

docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d app web queue scheduler ai-queue buildadmin-app buildadmin-web
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
docker compose -f compose.yml -f compose.buildadmin.yml stop queue scheduler ai-queue
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan monitor:group-events
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan monitor:reassess-connections

docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --force-recreate app web queue scheduler ai-queue buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d --no-deps --force-recreate https
```

数据库迁移保留网站资产、流量记录、其他告警和 BuildAdmin 账号；迁移会删除旧的“发现新网站线索”告警，并为白名单增加按告警类型的范围和不需要 CIDR 的节点健康范围。必须先执行迁移，再使用新版白名单。重新运行 `agent-builder` 会发布安装、卸载脚本及 SHA-256 清单；`buildadmin-web` 也必须重建才能提供卸载脚本下载。重建 PHP 应用时 Web 容器也会重建，避免连接到已更换的容器地址。升级后检查：

本版采集服务没有管理界面、管理账号模型或账号导入工具。历史安装中不再使用的账号／会话表保留原样，新安装不会创建这些表；BuildAdmin 账号独立存于 MySQL。采集服务继续负责上报、异步分析和任务调度。`monitor:reassess-connections` 分批重新评估未处理连接／带宽告警及事件，保留人工审核结果。升级截图 worker 后，对需要新报告的站点点击“验证／截图”；历史报告不会凭空补出新证据。

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

点击“生成安装命令”，在 10 分钟内到目标宿主机以 root 执行。命令会从本站 HTTPS 下载一次性 `agent.json`、安装／卸载脚本和已在主控编译的 amd64 二进制，校验 SHA-256，然后为程序和脚本设置 `700` 执行权限、配置设置 `600`。一次性配置只能下载一次；生成新命令会立即轮换该节点令牌，因此应及时执行，且不要把命令贴到工单、公开日志或聊天记录。需要通过自己的安全通道传输时，可选择“接入配置”下载文件。

**重复安装会覆盖程序和配置并重启服务**，不必先卸载。安装器先检查新配置，检查失败不停止原服务；替换前在配置所在目录保留 `agent.json.previous`、`vm-monitor-agent.service.previous`，在程序目录保留 `vm-agent.previous`，各保留一份。继续使用相同 `data_dir` 时，缓存批次和日志保留；修改目录后不会自动迁移原目录的数据。安装器也会将卸载脚本存到 `${data_dir}/bin/uninstall.sh`。宿主机需有 `curl`、SHA-256 校验工具、Python 2.7+／3、systemd 和 `flock`。

安装器不改防火墙、路由、网桥或 OVS。应先确认宿主机选定接口能看到公网 IP 的双向流量；KVM/libvirt 的 VM 身份无需由 Agent 推断。CentOS 7 的 systemd 使用 `MemoryLimit`，较新的系统使用 `MemoryMax`。`/home` 若挂载为 `noexec`，应改用允许执行的大分区数据目录。

节点验证：

```sh
systemctl status vm-monitor-agent --no-pager
tail -n 50 /home/vm-monitor/logs/agent.log
systemctl show vm-monitor-agent -p MemoryCurrent -p MemoryLimit -p MemoryMax
du -sh /home/vm-monitor
```

约一个采集窗口后，BuildAdmin 应显示新“最近上报”时间。旧积压批次会在网络恢复后重传；HTTP 429 批次保留并重试，日志会写明服务端原因；HTTP 422 代表服务端校验失败，当前 Agent 会丢弃该批次并记录原因。若出现 422，请先核对节点 CIDR、时间和上报字段。系统不会从已丢弃的批次重建证据。

Agent 0.3.x 或更早版本没有后台更新轮询能力，首次升级到 0.5.0 必须在节点执行新的安装命令。之后可在 BuildAdmin 对单节点或多节点下发已编译版本；先选一台试点，再批量更新。Agent 每分钟轮询更新，校验 SHA-256 后自检并保留上一版。节点侧若需立即检查后台已下发的更新：

```sh
sudo /home/vm-monitor/bin/vm-agent -config /home/vm-monitor/config/agent.json -update
sudo systemctl restart vm-monitor-agent
```

自定义 `data_dir` 时替换路径。更改采集接口、CIDR 或内存硬限额需要重新生成并部署配置。

### 卸载宿主机 Agent

在“采集节点”点击“卸载命令”，复制到**对应宿主机**以 root 执行。此命令单独下载并校验卸载脚本，既不下载新配置，也不轮换凭据；旧安装没有本地卸载脚本时也能使用。如果已使用新版安装器，默认目录下可以直接执行：

```sh
sudo bash /home/vm-monitor/bin/uninstall.sh
```

卸载停止并禁用 `vm-monitor-agent`，移除 systemd 服务文件并重新加载 systemd。配置、二进制、缓存、日志、后台节点记录及人工创建的镜像接口全部保留；如不再使用，在后台禁用该节点以避免上报中断告警。自定义数据目录时替换命令路径；数据文件由管理员确认后另行清理。

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

管理员可在 BuildAdmin 右上角“个人资料”修改邮箱或密码，在“管理员管理”创建只读账号并分配“监控只读”分组。生产环境不开放公开注册。卸载流程见第 5 节，命令在宿主机执行。

## 8. 事件、PCAP 留存与手动 DeepSeek 分析

先按第 3 节升级主控，再在“采集节点”下发 Agent **1.0.0**。新版保留现有 `agent.json`；没有新增配置项时自动使用下面的默认值。刷新登录或重新登录后，告警中心使用事件页面及“AI 分析设置”菜单。无需安装 VM 内的组件。

同一观察节点、公网 IP 的持续行为合并为事件，不再每十分钟新建一条。不同规则保留独立证据；超过 30 分钟没有命中，再出现时建立新事件。人工标记“已核查正常”或“已处理”后，同类行为仅增加计数；新类型或级别上升可重新打开事件并记录原因。`monitor:group-events` 为历史告警建立事件关联，不调用 AI、不补造历史抓包。历史记录仍保留。

在告警详情中点击“申请定向抓包”，选择每包前 2048 字节或完整包。节点最多同时采集一个 IP，持续 60 秒或到 32 MiB 就停止；等待队列最多 10 项，同一 IP 的成功／等待任务间隔至少 30 分钟。新建高级别事件默认可申请一次自动抓包，`MONITOR_AUTO_CAPTURE=false` 可以关闭自动申请。**自动抓包不会调用 AI。**抓包从 Agent 接到任务时开始，不能恢复过去的报文。停止／禁用采集节点不会删除已经留存的证据。

抓包复用现有抓包通道，不增加另一份网卡套接字。文件写入和上传独立处理，队列满时丢弃证据副本并计数；不能据此声称对宿主机没有任何 CPU、I/O 或内存影响。PCAP 元数据包含时间、采集接口、抓到的包数、截断数、队列丢弃数、内核丢弃观察数和停止原因。内核统计按 5 秒区间读取，可能跨越本次抓包的开始／结束边界，不能把该数字当成精确的抓包丢包率。主控计算 SHA-256，并提供“抓包分析”和受管理员权限保护的下载入口；只读账号可看摘要，不能下载原始 PCAP。PCAP 不通过公开静态目录提供。

| 项目 | 默认值 |
| --- | --- |
| 节点文件目录 | `data_dir/evidence`，默认 `/home/vm-monitor/evidence` |
| 节点证据预算 | 最多 512 MiB，包含在 Agent 总磁盘预算中；另保留上报缓存和 128 MiB 余量 |
| 节点保留时间 | 最多 24 小时；容量／文件数达到上限时更早清理 |
| 证据上传限速 | 每节点 2048 KiB/s，约 16.8 Mbps；仅在上传 PCAP 时使用，不含正常聚合上报 |
| 主控私有目录 | `MONITOR_DATA_DIR/storage/app/private/packet-evidence` |
| 主控 PCAP 总预算 | 20 GiB，`MONITOR_CAPTURE_BYTES` 可调整；文件数最多 10000，满额暂停领取或拒绝新增文件 |
| 主控保留时间 | 7 天，`MONITOR_CAPTURE_DAYS` 可调整；等待／执行 AI 分析的文件暂缓清理 |

节点可在 `agent.json` 增加 `evidence_enabled`、`evidence_limit_mib`、`evidence_keep_hours`、`evidence_upload_kibps`。关闭 `evidence_enabled` 停止任务轮询。修改后先用 Agent `-check` 校验，再重启服务。证据额度加上 `spool_limit_mib` 和 128 MiB 余量不能超过 `disk_limit_mib`；默认内存硬限额仍为 4 GiB。主控限额不包含数据库和 nginx 临时文件；nginx 抓包请求最多并行 4 个，每个不超过 32 MiB，临时文件也放在 `/home` 对应的 nginx 日志挂载目录。

“抓包分析”由主控本地执行，**不需要 AI Key、不产生 AI 调用费用**。它列出目标与端口、SYNACK 回复、完整握手、RST、未观察到回复的流、可见明文 HTTP 请求头、完整单包 ClientHello 中的 SNI 及证据限制。SNI 不证明域名属于这台 VM，也不能恢复 ECH 隐藏的内部域名。解析最多 32 MiB、20 万帧、4096 个流，显示 32 个分层连接样本（完成握手、无回复、重置和已存在会话），不能用样本占比推断全部连接占比；超限会注明。TCP 发起按连接四元组及初始 SYN 序列区分，SYN 重传不算新的发起。同目标 IP 的多端口分布与端口级握手统计单独展示。发起连接目标数只统计抓包内看到出站 SYN 的流，不能代表所有存量连接。IP 分片、不能解析的协议、未完整捕获的 TCP 请求会显示为缺失证据；多接口抓包可能包含重复包。HTTPS／TLS／QUIC 的正文和认证结果不能直接读取，SS/VLESS 等伪装代理协议也不能仅凭这些统计确定。

管理员进入“AI 分析设置”，填写 DeepSeek API Key、模型、API 地址并启用。默认地址 `https://api.deepseek.com/chat/completions`，模型 `deepseek-flash`，可填写账户实际支持的模型。密钥由主控共享的 `APP_KEY` 派生密钥加密保存；BuildAdmin 容器通过 `MONITOR_SECRET_KEY` 使用同一密钥，Compose 已配置。升级时不要重置 `APP_KEY`。保存、启用、查看事件、抓包完成都不会调用 AI。

DeepSeek 的官方 [Files API](https://api-docs.deepseek.com/guides/files_api/) 支持图片，未支持 PCAP。这里将 PCAP 保留在主控，由主控解析成文字证据后发送至 DeepSeek，而不是上传二进制文件、Base64 或公开 PCAP 链接。只在事件详情选择已留存的文件，点击“AI 分析”并确认提交后执行一次。发送内容包括目标 IP、端口、握手、流量、可见 HTTP 方法／Host／路径、采集质量及规则摘要；查询参数值、Cookie、Authorization 和请求正文不发送。路径本身仍可能包含业务信息，提交窗口会说明外发范围。

分析前可选择两种发送方式：默认“统计摘要”，上限 128 KiB，包含最多 32 条连接样本，并增加按目标端口汇总的发起流数、目标数、SYN、SYNACK、完整握手、RST、未观察到回复及双向载荷；这些汇总覆盖本次解析所跟踪的最多 4096 个连接元组和 64 个端口组，超限会明确标记。不会用某端口的正常握手掩盖另一个端口的无回复情况。

“完整逐包文本”逐帧遍历整个已存储 PCAP，每帧一行，含时间、方向、源／目的 IP 和端口、TCP 标志、序号／确认号、线上／实际捕获长度、头部声明的载荷长度、可见 SNI 和脱敏 HTTP 请求线索。未支持解码的帧保留时间与长度并标为 unsupported，无关帧标为 unrelated；完整表示存储文件内所有帧都有对应行，不表示原始线上流量无遗漏或所有协议均可解码。文本不包含原始载荷、密文十六进制或请求正文，也不做 TCP 重组、TLS 解密；原始 PCAP 仍可下载用于二次分析。snaplen 造成的内容截断无法事后补回，头部声明的载荷长度不等于已捕获正文长度。

完整模式的整份 JSON 发送内容限 2 MiB，解析最多 20 万帧、8 秒。未完整转换或超过发送上限时直接失败，**不会调用 AI、不会悄悄改用摘要、不会自动分批收费**；可缩短抓包时间或再次手动选择摘要。字节上限不保证符合账户模型的实际 token 限制；供应商仍可能拒绝过大的输入。报告显示文件读取范围、逐包文本覆盖范围、模式和是否尝试提交，并按需展开实际证据，避免一打开报告就渲染巨大文本。完整模式通常消耗更多 tokens，仅在需要时手动选择。当前抓包与历史事件的时间分别记录；时间不重叠不能互相证明／否定历史行为，零散规则命中也不证明跨数日连续活动。

“采集覆盖下降”属于采集质量提醒，不提供事件／告警白名单按钮，接口和白名单新增／编辑也拒绝这一类型；请核查内核丢包、解码、重组或状态限额，而非忽略提醒。既有白名单不自动删除，其管理页仍可手动删除。

`ai-queue` 使用独立队列顺序处理本地证据解析和 AI 任务，避免阻塞采集分析队列。AI 请求采用非思考模式，输出上限 4096 tokens，连接超时 10 秒、请求超时 90 秒，无自动 HTTP 重试；同一次任务不会重复调用。失败可能已产生供应商费用，需要再次分析时由管理员重新申请。后台报告保留发送的文字证据、文件哈希、模型、分析结果和用量，内容按 Markdown 排版显示（标题、列表、表格、代码块），旧报告直接兼容，并可下载 Markdown 原文，不自动处理告警、封禁或修改白名单。

故障排查：抓包任务过期时，核对节点版本、启用状态、`evidence_enabled`、节点日志和数据分区余量；文件已留存但摘要未生成时，检查 `ai-queue` 和 `scheduler`。AI 分析一直等待时，也检查这两个服务；失败时后台显示错误，不要用 `queue:retry all` 试图重新收费调用，直接在后台人工重新申请。原始文件过期后不能再申请 AI 分析，已生成的报告仍可查看。

## 9. 1.0 证据审核版的使用与边界

主控先升级，再更新 Agent 到 1.0.0；旧 Agent 可以继续上报，缺少新统计时标为证据不足，不补造握手、时长或请求内容。第 3 节的 `monitor:reassess-connections` 对未处理的六类连接／带宽规则重新分级，同时刷新未处理事件的列表级别；已核查正常、观察中和已处理结果保留。旧命令 `monitor:reassess-scans` 是同一策略的兼容入口。迁移新增审核基线、行为变化原因及证据结论索引，不需要清空数据库或修改 Agent 配置。

告警中心新增“证据结论”列，可点击过滤，或用下拉框选择：

| 结论 | 使用条件 |
| --- | --- |
| 一般行为提醒 | 只有连接数量、单目标频率或带宽较高，没有更强的连接异常证据 |
| 疑似异常，待复核 | 多目标／多端口活动、认证服务重复连接或较多 RST，需要核对业务；旧版本或质量不足也不直接标高 |
| 强异常证据，优先复核 | 横向／端口扫描在规则观察范围内至少两个采集窗口持续扩散，并出现多数配对 RST、较少完整握手和可接受的采集质量；仍不等于确认攻击 |

规则配置的级别是自动评估上限，可以压低级别，不能仅凭把规则设为“高”绕过证据要求。默认高风险条件同时要求每窗口至少 50 次发起、至少 20 次已等待 3 秒的发起、至少 50% 配对 RST、最多 10% 完整握手；横向至少 50 个目标、纵向至少 10 个端口，且达到规则阈值。内核丢弃／捕获比不超过 1%、解码跳过不超过 10%、状态丢弃为零且目标计数未封顶。这些是可解释的行为筛选条件，不是经过生产标注验证的攻击概率；客户授权扫描、服务拒绝和故障也可能符合，应保留人工核查。

点击“详情与证据”后，自动加载本地 IP 审核报告，无需 AI：综合证据结论、判断理由、正常业务解释、主要目标和端口、完整握手／RST、双向载荷、可见请求线索、数量趋势、采集质量、证据缺口及核实建议。报告只查询该节点、该 IP、事件区间内最后一小时最多 120 个流量窗口，目标汇总最多 32 条、多端口目标最多 16 条；不把报告塞进列表、分页或批量处理请求。窗口数据默认保存 7 天，`MONITOR_METRICS_DAYS` 控制保存时间；过期后报告会说明缺失，不能凭规则快照补回趋势。可以导出含结构化证据的文本审核报告，供内部或客户复核。

Agent 复用现有 TCP 状态表，SYN-ACK 和最终 ACK 都核对序号，RST 按观察到的配对连接计数；同窗口重复报文不重复计握手／拒绝。计数限定为本窗口发起的连接，跨窗口到达的回复不混入新窗口发起比例。已等待至少 3 秒仍没有观察到回复，可能是防火墙、漏采或单向可见性，不等于失败。TCP 状态最多跟踪 60 秒，成熟样本计数是保守下界。每窗口最多上报 8 个目标连接样本，以及按端口数排序的 8 个多端口目标，每目标最多 32 个端口；多余部分标明截断。观察跨度仅是发起后前 60 秒内实际看到的报文跨度，不是整个连接寿命。载荷字节来自捕获到的数据，包含可能的重传；TLS 域名和 HTTP 首个请求仍是有限线索，不代表 VM 部署了对应的网站。

新增字段有固定数量上限，内存估算已计入配置校验；默认软／硬预算继续是 2048／4096 MiB，不扩大抓包缓冲、证据磁盘或 PCAP 上传限速。实际 CPU 与内存仍取决于流量和活跃连接，需要用节点健康页的 RSS、丢弃及状态限额观察。不会为了取证主动攻击目标或在 VM 内安装组件。

标记“已核查正常”或“已处理”必须填写依据，并保存当时行为基线。同类型重复活动只累加；新增检测类型、级别上升会重新复核。同规则中，新增认证／管理端口、明显扩大端口范围或新增更强异常证据，连续两个相隔超过 5 秒的新窗口出现时也可重新打开，详情说明原因。随机更换目标 IP 不会单独触发重新审核，端口样本不完整时不据此比较端口变化。补传的旧窗口不会覆盖较新的规则证据或仅凭旧级别重新打开事件。白名单按节点、源 IP、类型、已核实目标 IP/CIDR、端口、行为强度和证据级别限定 30 天。检测先执行，再决定是否应用业务例外：新目标、新端口、强度超过上限或更强异常证据立即重新进入复核；当前目标/端口仅有截断样本、计数封顶或缺少目标证据时不自动放行。历史仅按源 IP 创建的白名单不会继续整体关闭检测，需要从事件重新审核或在白名单编辑页补全范围。人工标记正常但未创建业务例外的事件仍使用前述连续窗口策略。

建议审核顺序：先看“强异常证据”，再核查“疑似异常”；纯数量提醒可以结合客户申报业务处理。无法判断时先申请定向 PCAP，再看本地抓包分析，需要辅助意见才手动申请 DeepSeek。AI 设置、调用条件、费用与保存上限继续按第 8 节执行，AI 不自动审核、不自动封禁。

## 10. 目标范围白名单与网站归属核实

本次只需升级主控和截图 worker，不需要更新 Agent。按第 3 节升级主控并执行数据库迁移，再执行：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots build worker
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots up -d --no-deps --force-recreate worker
```

后台强制刷新后，告警中心查询按钮位于所有筛选项之后。抓包分析增加目标 IP/端口分组和 SYN 重传说明；旧的本地抓包摘要由证据队列每分钟分批重算，每次最多 10 个，不调用 AI。历史 AI 报告原文不改变，重新申请 AI 分析才会使用新版摘要，并产生供应商调用费用。

从事件加入白名单时可以填写已核实的目标 IP/CIDR，留空使用当前可见目标。默认允许当前端口、当前证据级别与两倍当前规则行为值，可在白名单编辑页调整；不要把未核实的全网范围当成业务范围。新增目标或端口不会被旧的源 IP 白名单遮蔽，采集质量不足或目标样本截断时仍保留检测和复核。白名单到期后自动失效，采集和证据保存始终继续。

网站资产默认显示解析匹配、人工登记或 IP 直连的记录；其余数据在“归属待核实线索”“解析不匹配线索”或“全部资产和原始线索”中查看。被动 HTTP Host/TLS SNI 是客户端提供的请求名称，扫描器可以填写任意域名，既不能证明该域名解析到 VM，也不能证明网站部署。相同域名在多个 IP、端口、协议上出现会产生不同线索，但不能据此认定节点托管该网站。

归属核实由主控截图 worker 在请求网页前查询 A/AAAA；同域名结果缓存 10 分钟，缓存最多 512 个域名，单次查询最多约 4 秒，不在宿主机 Agent 或页面查询中执行。DNS 不匹配时仅保留原始线索，不抓取网页、截图或分类；DNS 查询故障标为暂不可确认，不能当作解析不匹配。DNS 匹配也仅证明当前解析关系，需要结合实际网页响应、证书和人工核查。CDN/隐藏源站可能不直接解析到公网 IP，可通过“添加已知网站”明确人工登记；这仍不等于确认合规。

迁移不会删除历史线索。历史被动域名记录先标为归属待验证，等待 worker 重新核实；人工登记记录保留。历史截图/内容可能由旧探测逻辑生成，归属未核实前不能作为此 VM 部署该网站的证据。开启自动网站探测时按既有调度逐批核实，也可以手动“验证／截图”。
