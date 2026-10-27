# 部署与使用教程

后台统一使用 **BuildAdmin**。Agent 只安装在 KVM 宿主机，VM 内不用安装软件。

- [首次安装](#首次安装)：新主控从这里开始。
- [升级主控](#升级主控)：已安装的主控只执行这一节，再更新 Agent。
- [网站验证与截图](#网站验证与截图)：需要网页、截图、内容分析时启用。
- [接入与更新节点](#接入与更新节点)：安装、更新和卸载 Agent。
- [告警与证据](#告警与证据)：规则、白名单、PCAP 和手动 AI。
- [常见问题](#常见问题)：连接故障、日志和账号维护。

## 首次安装

### 1. 准备

主控安装 Docker Engine、Docker Compose v2、Git、Python 3。试点建议 4–8 核、16 GiB 内存和 SSD；实际容量取决于流量、节点数量和保留期。

域名解析到主控公网 IP，开放 TCP **80、443**，确保这两个端口没有其他服务占用。默认数据目录为 `/home/vm-monitor-server`。

宿主机需要 systemd、curl、CA 证书、SHA-256 校验工具、flock、Python 2.7+ 或 3。Agent 面向 CentOS 7、CentOS Stream 8、Debian 13，先选择一台实际试点。

### 2. 下载并设置主控

以下命令在**主控服务器**执行：

```sh
git clone https://github.com/q992218196/vm-public-ip-monitor.git /home/vm-monitor-src
cd /home/vm-monitor-src/deploy
bash prepare.sh
```

编辑当前目录的 `.env`，至少设置：

```dotenv
APP_URL=https://vm-monitor.lcayun.cn
MONITOR_DOMAIN=vm-monitor.lcayun.cn
MONITOR_DATA_DIR=/home/vm-monitor-server
```

域名换成自己的。其他密钥由安装准备脚本生成，保留 `.env`，不要公开。自定义数据目录时，同步替换教程中的 `/home/vm-monitor-server`。

### 3. 启动数据库和后台

```sh
mkdir -p /home/vm-monitor-server/{storage,postgres,redis,nginx-logs,agent-dist,caddy/data,caddy/config,buildadmin/mysql,buildadmin/runtime,buildadmin/uploads,worker/tmp}
docker compose -f compose.yml -f compose.buildadmin.yml build app web buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml up -d postgres redis buildadmin-db
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d app web queue scheduler ai-queue buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php tools/init-admin.php admin@your-domain.example
```

最后一条命令初始化管理员：邮箱换成自己的，按提示输入至少 12 位密码。已有账号不要重新初始化。

### 4. 发布 Agent 并启动 HTTPS

Agent 在主控编译为 Linux amd64，宿主机不需要 Go 编译环境。

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d https
```

访问 **`https://你的域名/#/admin/login`**，用刚创建的邮箱和密码登录。

## 升级主控

**已安装的主控从这里开始，不要重做首次安装。** 先备份 `.env`、PostgreSQL、BuildAdmin MySQL 和数据目录的 `storage`。不要重置 `APP_KEY`，否则已加密的 AI 密钥无法读取。

在主控低峰时段执行：

```sh
cd /home/vm-monitor-src
git pull --ff-only
cd deploy
docker compose -f compose.yml -f compose.buildadmin.yml build app web buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots build worker
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml stop app queue scheduler ai-queue worker buildadmin-app
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan schedule:clear-cache
docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --force-recreate --scale queue=3 app web queue scheduler ai-queue buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
```

上面保留 3 个分析进程；其他部署可按原有数量调整 `--scale queue=3`。`schedule:clear-cache` 仅释放定时任务锁，不会清空 Redis 队列。

主控接收接口更新增加独立控制进程池：普通上报和 PCAP 上传仍最多 5 个 PHP 进程，更新检查和抓包任务领取另有最多 2 个按需进程，继续共用 `app` 原有 **1 GiB** 内存上限。需要同时重建并替换 `app` 与 `web`，不能只把新的 Nginx 配置热加载到旧 `app`；旧容器没有新的内部 9001 监听端口。这项主控修复不需要发布新的 Agent 版本。

如果已启用网站 worker，恢复它：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots up -d --no-deps --force-recreate worker
```

后台强制刷新，然后在“采集节点”确认最近上报持续更新。规则初始化只新增缺失规则，保留已修改阈值。

升级不强制重建已运行的 HTTPS 入口，避免无必要的 443 中断；如果修改了 Caddy 配置，可执行 `docker compose -f compose.yml -f compose.buildadmin.yml exec https caddy reload --config /etc/caddy/Caddyfile` 平滑重载。应用容器替换期间仍可能短暂出现 502，Agent 会保留普通上报批次并自动重试，入口恢复后无需逐个重启节点。

本版 Agent 为 **1.6.0**：先完成主控、数据库迁移、后台及 worker 升级，再在“采集节点”下发更新。网站自动发现改为配对同一连接上的明文 HTTP 请求与服务端响应；仅请求不再进入自动待验证。旧 Agent 的流量与告警数据继续接收，但其仅请求网站线索不再新增网站；节点升级后才恢复新的被动 HTTP 发现。

**本次迁移会永久删除“多端口连接”规则、该类型告警及纯该类型事件的关联抓包／AI 报告。** 混合事件保留其他告警、抓包和人工审核，重新选择主告警；原始流量窗口保留。旧 SSH／RDP／FTP 高频次数规则停用，历史证据仍保留，但退出异常通知。新三项规则使用新的类型和阈值，不会将旧“连接次数”阈值直接解释成“目标 IP 数”。

## 网站验证与截图

### 启用 worker

在主控执行一次，目录属主从实际镜像读取：

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots build worker
worker_uid=$(docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots run --rm --no-deps --entrypoint id worker -u)
worker_gid=$(docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots run --rm --no-deps --entrypoint id worker -g)
chown -R "$worker_uid:$worker_gid" /home/vm-monitor-server/worker
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots up -d worker
```

默认浏览器并发 2、内存上限 2 GiB；`.env` 中 `WORKER_CONCURRENCY` 可设 1–4。轻量检查与浏览器分开，领取任务最多为浏览器并发的两倍（默认 4），同时运行的浏览器仍最多 2 个。IPv6 网站验证需要 **worker 容器有 IPv6 出口**。

### 先筛选协议，再验证网页

本次响应准入升级需更新 **主控、后台、worker 和 Agent 1.6.0**，并执行数据库迁移，顺序见“升级主控”。迁移会分批调整历史请求及 TLS 线索，升级期间暂停应用、分析、定时任务和 worker，完成后恢复。

- 仅有明文 HTTP 请求、TLS/SNI、ALPN 声明或 RDP 协商：不进入自动验证。历史记录保留在“请求／RDP／TLS 服务线索”，默认不计入网站资产和待验证总数；新 Agent 不再上报仅请求的网站候选。
- Agent 在同一连接上配对到发往监控 IP 的 HTTP 请求和该 IP 返回的有效 HTTP/1.0／1.1 状态行后，上报 `http_response` 和被动响应码，才进入待验证。22 等非标准端口同样适用；SSH 欢迎信息不算 HTTP。已取得主动 HTTP 结果、已验证或人工确认的网站也可继续自动验证。
- 详情分别显示“被动观察 HTTP 响应”和“主动验证 HTTP 状态”，被动响应不会直接把网站标成已验证。被动观察时间使用所在采集窗口结束时间，不是精确响应报文时间。
- 人工登记网站、点击“验证／截图”或“测试源站”：可以手动探测这些服务线索，优先于自动任务领取，不会仅因点击就确认网站。
- 主控的 worker 先发送固定 IP、Host/SNI 的轻量 HTTP 请求，自动检查总超时 3 秒，手动检查 8 秒；TLS 证书仍严格验证。明确的 JSON、图片等非网页内容只记录 HTTP 结果，不启动浏览器。HTML 或未注明内容类型的响应才进入浏览器分析和截图。
- 同一线索重复上报不重复排队；自动失败后冷却 24 小时，手动操作可立即重试。确认到新的网页候选后，原先跳过的任务可重新排队。

升级迁移会将所有端口未验证、未人工登记且没有主动 HTTP／截图证据的旧请求及 TLS 记录移为服务线索，取消尚未执行的自动普通探测任务，直接解除这部分积压。手动任务、人工源站测试、已验证网站和人工分类保留，服务线索不删除。同一网站重复出现时，“最近观察”最多约五分钟更新一次，以减少索引写入；首次发现和来源升级仍保留。

配对只短暂保存有界请求头和响应状态行，不保存网页正文；等待响应最多 10 秒，使用现有重组数量上限。丢包、非对称采集、长延迟或不连续的 TCP 分段可能漏掉响应。旁路采集无法解密普通 HTTPS，未观察到 HTTP 响应不代表该 IP 没有网站；已知网站可人工登记或手动验证。

### 如何确认网站归属

| 入口或状态 | 作用 |
| --- | --- |
| 验证／截图 | 核实 DNS 归属后，请求网站、截图并分析首页 |
| 测试源站 | 不要求 DNS 指向此 IP；直接连接记录的公网 IP 和端口，携带域名 Host/SNI；不自动登记归属 |
| 登记 CDN 源站 | 根据客户配置、申报或日志，填写核实依据，保存人工归属并排队验证 |
| 添加已知网站 | 手动登记已知域名、IP、端口、协议 |

普通 DNS 检查不匹配时，保留线索，不请求网页。CDN 源站可能没有直接 DNS 指向，最快的流程是：**选择线索 → 测试源站 → 看详情中的网页、截图和归属证据 → 核实后登记**。源站测试需要 worker 在线。

测试成功只能证明该 IP 对此 Host/SNI 有响应；默认站点、通配站点、反向代理也可能响应。测试失败也可能是源站只允许 CDN 回源、证书限制或访问控制。测试不会修改公网 DNS，也不会自动寻找其他源站 IP。

网站资产默认显示具有主动 HTTP、已验证或人工确认证据，且解析匹配、人工登记或 IP 直连的记录。新被动响应先进入“待验证／归属待核实线索”；“指定 IP 响应，待核实”也保留在那里。客户端填写的 Host/SNI 不等于 VM 部署的网站。

首页标题、描述、正文可形成博彩、成人、诈骗、支付、贷款或影视等分类线索；报告给出理由、原文证据和截图，仍需人工复核。

## 接入与更新节点

### 安装 Agent

1. 在后台“采集节点”创建节点，填写节点名、实际采集接口、公网 IPv4／IPv6 CIDR。
2. 点击“生成安装命令”，在 **10 分钟内**到对应宿主机以 root 执行。
3. 等待一个采集窗口，在后台查看最近上报、当前版本和采集质量。

安装命令自动下载 `agent.json`、二进制和安装／卸载脚本，校验 SHA-256，并设置执行权限和配置权限。配置链接只能下载一次；重新生成命令会轮换节点令牌，请及时执行，不要公开命令。

重复安装会覆盖程序和配置并重启服务；相同数据目录下的缓存和日志保留。安装前检查新配置，保留上一份程序和配置备份。更换数据目录不会自动搬迁原数据。

| 资源 | 默认值 | 调整方式 |
| --- | --- | --- |
| 工作内存预算 | 2048 MiB | 节点设置 |
| systemd 内存硬限额 | 4096 MiB | 节点设置并重新安装配置 |
| 总磁盘预算 | 2048 MiB | 节点设置 |
| 数据目录 | `/home/vm-monitor` | 节点设置 |

同一 CIDR 可以出现在多个节点；观察记录始终区分节点。采集接口需能看到 VM 公网 IP 的双向流量。安装器不修改防火墙、路由、网桥或 OVS。数据目录需要允许执行，不能挂载为 `noexec`。

宿主机检查：

```sh
systemctl status vm-monitor-agent --no-pager
tail -n 30 /home/vm-monitor/logs/agent.log
du -sh /home/vm-monitor
```

### 更新 Agent

主控发布二进制后，在“采集节点”下发单节点或批量更新，先试点一台。当前 Agent 启动时立即检查，正常每分钟轮询；暂时性网络错误按 15、30、60、120 秒退避重试，二进制校验失败或无权限保留 10 分钟间隔。下载最长允许 3 分钟，仍限制文件大小和 SHA-256 校验。后台显示当前版本及自动重试状态；重新下发后，上一次指令之前的错误不再覆盖新状态。旧 Agent 仍按原来的 10 分钟间隔重试；急需恢复时可执行下面的手动更新命令。

节点需要立即检查已下发更新时执行：

```sh
/home/vm-monitor/bin/vm-agent -config /home/vm-monitor/config/agent.json -update
systemctl restart vm-monitor-agent
```

接口、CIDR、资源限额等配置修改后，重新生成安装命令并执行。自定义目录时替换上述路径。

### 卸载 Agent

后台“采集节点 → 卸载命令”复制到对应宿主机执行。已有本地脚本也可执行：

```sh
bash /home/vm-monitor/bin/uninstall.sh
```

卸载停止并移除 systemd 服务，保留数据和后台节点记录。卸载后在后台禁用该节点；确认不再需要的文件再另行清理。

## 告警与证据

### 清空告警中心

更新主控后，先预览数量：

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan monitor:clear-alerts
```

需要实际清空时执行以下命令。**永久删除所有告警、事件、关联抓包及 AI 报告**；保留节点、网站、规则、白名单和原始流量窗口。执行期间暂停采集 API 与分析服务，避免并发生成记录；节点暂时无法上报的数据会保留在本地缓冲中。

```sh
docker compose -f compose.yml -f compose.buildadmin.yml stop app queue scheduler ai-queue
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan monitor:clear-alerts --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d app queue scheduler ai-queue
```

完成后刷新后台。检测仍会继续，新的命中会生成新告警；已存在的流量窗口也可能参与之后的规则评估。无需重建数据库或删除 Redis。

### 检测与审核

同一节点、公网 IP 的持续规则命中归并成事件。“事件报告与证据”显示规则证据（主要告警优先）、PCAP 留存和手动 AI。重复的 IP 审核报告已移除，打开详情不再额外读取最近一小时流量窗口生成报告。规则证据默认展示命中数、阈值、实际时间、目标及结果，长说明收在“计数口径与证据限制”，原始证据仍可展开。告警中心只显示疑似异常、强异常证据和节点运行异常。一般行为提醒不再生成通知，也不计入列表、总数、首页计数和导出；原始流量继续保留。

**“采集覆盖下降”可在检测规则中配置。** 编辑系统默认的同名规则，选择全部节点或指定节点（支持多选），设置阈值、级别、告警合并窗口和启用开关。阈值是当前采集窗口内核丢包、状态丢弃及上报缓存丢弃计数之和，默认 1；不使用流量规则的评估窗口累积计数。升级后默认保持全部节点启用；关闭或排除节点只停止生成该质量告警，节点健康数据仍保留，既有告警不会自动删除。

**协议观察也由检测规则控制。** “VPN 双向握手”和“疑似加密代理”均可选择全部节点或多选指定节点。未启用节点不新增对应的协议观察记录和告警，已有记录仍按 `MONITOR_PROTOCOL_DAYS` 保留。阈值只控制告警触发，启用范围同时控制记录保存；两者均按单个采集窗口评估。该设置在主控生效，不需要更新 Agent，也不改变宿主机的旁路采集方式。

SSH、RDP、FTP 使用“多目标建连”规则，默认 **60 秒内达到 10 个不同目标 IP**，阈值可设为 2–128 个。端口分别为 22、3389、21／990。只计入主动 SYN 的目标；同一目标的重连、跨窗口重复及 FTP 两个控制端口合并后只计一个 IP，连接后的数据交互不增加目标数。详情显示目标数／阈值、实际覆盖、目标 IP 列表和辅助建连次数。仅使用配置范围内完整、支持新统计的采集窗口，不外推边界和采集间断；集合触及上限时明确标记为观察下界。

SMB 继续按目标级 TCP 建连尝试（SYN 有界去重）检测，跨窗口取最大值；该次数不是登录次数。常见端口不能确认实际协议。多目标建连只提示需要复核的扩散行为，也可能是已授权运维或文件分发，不能确认攻击；只针对一台目标的爆破不在这三条规则的覆盖范围。

**登录失败次数仍显示“不可观测”。** TCP 握手成功不等于登录成功，不能为了排除正常业务而忽略全部握手成功的连接，否则会漏掉需要先建立 TCP 再认证的攻击。加密 RDP/NLA、SSH 的准确认证结果需服务日志；明文 FTP、SMB2 的可见认证响应可在 PCAP 中辅助核查。旧 RDP 次数记录保持原来的精简展示；新 RDP 多目标规则显示目标统计。

主要告警按级别、证据结论、规则具体程度依次选择，同等级时服务专项规则优先。其他命中仍在详情保留；优先级不提高风险级别，也不代表已确认违规。检测规则列表显示级别和启用状态，配置级别是证据评估允许的上限。“多目标连接”“多端口连接”“认证服务重复连接”泛化规则已移除。TCP 连接数量提醒继续保留原始发起统计，一般活跃数量不产生异常通知；实际范围和样本范围单独显示，未保存的历史范围不推算。

**UDP 包数和流数量仅用于流量统计，不作为异常告警。** 两条纯数量规则已移除；升级迁移删除已有规则配置，将历史纯数量提醒移出告警中心，保留历史证据、PCAP 和 AI 报告。混合事件如果还有异常命中，继续显示对应异常。TCP、单目标连接或带宽规则仅产生一般行为提醒时也不通知；有其他异常证据时仍可进入复核。

在“流量窗口 → 详情”查看 UDP 统计：实际窗口秒数、平均出站 PPS、平均带宽、出入包数与字节数、五元组数，以及最多 8 个对端样本。原始统计包含 DNS；新版节点另有排除目的端口 53 的统计。平均速率不是逐秒峰值；五元组数不是连接或登录次数，同一五元组可在多个窗口重复。采集时间未知时不推算速率，有界对端样本不代表全部目标。

UDP 没有统一的攻击 PPS 门槛。游戏、音视频和传输业务也可能出现高包速率；确定攻击需要结合协议内容、发起方向、目标行为和客户申报业务。数量提醒移出不等于将整个 IP 加入白名单，其他异常规则仍会检测。

事件白名单先显示最近一小时窗口、近期抓包与此前已批准的目标／端口，逐项核实后确认。按每个目标分别批准端口，重复审批保留之前批准范围；需要缩减时删除原例外再重新审核。白名单限定节点、源 IP、类型、已核实目标范围、端口、强度和级别，默认 30 天；新目标、新端口、更强证据或样本不足时仍进入复核。“采集覆盖下降”是采集质量提醒，不提供白名单，应检查漏采或状态限额。

### PCAP 与手动 AI

无法判断的事件，可在详情申请定向抓包，再查看本地抓包分析或下载原始 PCAP。抓包从节点领取任务时开始，不能恢复历史流量。手动任务完成或失败后可立即重新申请；同一 IP 不能同时有等待或执行中的任务，节点队列最多 10 个。自动抓包保留 30 分钟限频。

| 项目 | 默认值 |
| --- | --- |
| 手动抓包 | 默认最长 60 秒、文件最多 8 MiB；达到任一上限即停止 |
| 每包保留长度 | 默认 2048 字节；可选 256、512、2048、65535 字节 |
| 可选时长／文件上限 | 15、30、60 秒／1、4、8、16、32 MiB；单节点同时 1 个 IP |
| 节点证据 | `/home/vm-monitor/evidence`，512 MiB、24 小时，计入总磁盘预算 |
| PCAP 上传限速 | 每节点 2048 KiB/s，仅上传 PCAP 时使用 |
| 主控证据 | `storage/app/private/packet-evidence`，20 GiB、7 天 |

每包保留长度不是文件大小限制。普通以太网包通常小于 2048 字节，因此选 2048 或 65535 时都可能累积到文件上限；256／512 字节更小，但可能截断 TLS、HTTP 或认证证据。PCAP 列表显示申请设置、实际时长及停止原因，达到文件上限的抓包不能视为覆盖完整申请时长。自动任务和已有任务沿用原设置（最长 60 秒、最多 32 MiB）；新手动设置不需要升级 Agent。

节点可调整 `evidence_enabled`、`evidence_limit_mib`、`evidence_keep_hours`、`evidence_upload_kibps`；证据额度加上缓存额度和 128 MiB 余量不能超过总磁盘预算。PCAP 下载显示进度，可取消，取消固定一分钟超时；由 Nginx 传输，持续下载不会因总时长超过一分钟失败（连接中断仍需重试）。

主控 `.env` 可调整 `MONITOR_CAPTURE_BYTES`、`MONITOR_CAPTURE_DAYS`。容量或文件数满时可能提前清理或暂停任务。只读账号不能下载原始 PCAP。

“AI 分析设置”填写 API 地址、模型和密钥。**只有手动申请 AI 分析才调用接口**；保存设置、抓包和本地解析不调用 AI。使用独立 `ai-queue`，报告按 Markdown 展示。

AI 发送方式：

- **统计摘要**：上限 128 KiB。
- **完整逐包文本**：完整转换并发送，文本本地保护上限 16 MiB；超限失败，不自动截取或分批。
- **逐包文本前 2 MiB**：读取整份抓包并计算统计，发送逐包文本前段的完整行，明确标注未发送的后续文本；解析未读完整文件则不调用 AI。

这些是系统保护值；DeepSeek 按模型上下文 token 数限制输入与输出，并非固定 2 MiB。大文本可能超过所选模型限制，接口拒绝后不会自动重试。文本包含包头、方向、端口及脱敏请求线索，不含原始二进制、密码、Cookie、Authorization 或请求正文。解析最多 32 MiB、20 万帧、4096 个流、8 秒；完整模式超限会失败，不自动分批收费。HTTPS 正文无法从旁路抓包直接读取。

AI 报告优先回答本次抓包窗口该 IP 是否有对外攻击证据，分别说明扫描、爆破、UDP 行为、置信度和限制。报告不自动封禁或审核；历史事件与当前抓包时间不一致时不能互相证明。失败后需要再次分析，由管理员重新申请，供应商费用以实际调用为准。

## 常见问题

所有主控命令先进入 **`/home/vm-monitor-src/deploy`**。默认关闭 Docker 日志驱动，`docker compose logs` 可能无法读取，使用下列文件日志。

| 问题 | 优先检查 |
| --- | --- |
| 后台打不开／登录失败 | 域名、80/443、`https`、`buildadmin-web`、`buildadmin-app`、MySQL |
| Agent HTTP 502 | `app`、`web`、`https`，查看 nginx 和 PHP 日志；不要删除节点缓存 |
| 更新、抓包领取、上报同时超时 | 检查主控 PHP 进程池、数据库等待及 Redis；按下节同时更新 `app` 与 `web`，仅重启 Agent 不能解除主控堵塞 |
| 抓包轮询 HTTP 503 | nginx 日志若有 `limiting connections by zone "monitor_capture"`，升级主控 `web`；旧配置把领取指令也算入全局 4 个上传名额，新配置只限制 PCAP 上传 |
| Agent connection refused | 当时无法连接主控 443；检查 HTTPS 入口是否正在重建、是否运行以及网络连接，重启 Agent 不会修复主控入口 |
| Agent HTTP 429 | 上报限流或主控积压，检查分析队列和数据库；批次会保留重试 |
| Agent HTTP 422 | 日志中的校验字段、CIDR 和采集时间；被丢弃批次不能通过重启恢复 |
| worker 权限错误 | worker 数据目录属主，按启用步骤重新设置 |
| 抓包／AI 一直等待 | 节点当前版本、最近上报、`scheduler`、`ai-queue`，详情中的失败原因 |

主控检查：

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml --profile https ps
tail -n 40 /home/vm-monitor-server/nginx-logs/error.log
tail -n 40 /home/vm-monitor-server/storage/logs/php-fpm.log
tail -n 40 /home/vm-monitor-server/worker/worker.log
curl -sS -o /dev/null -w 'Agent API: %{http_code}\n' 'https://vm-monitor.lcayun.cn/api/v1/agent/update?version=1.6.0'
```

无 Agent 令牌的最后一项正常应为 **401**。示例域名和自定义目录请替换。BuildAdmin 日志在 `buildadmin/runtime`；节点日志在宿主机的 `data_dir/logs/agent.log`。

### 控制接口超时或抓包轮询被限流

主控修复不需要更新节点、重新编译 Agent 或重建 HTTPS 入口。新的 Nginx 控制路由依赖 `app` 的独立 9001 进程池，必须一起更新；不要只复制配置到旧 `web`。在主控执行：

```sh
cd /home/vm-monitor-src
git pull --ff-only
cd deploy
docker compose -f compose.yml -f compose.buildadmin.yml build app web
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php-fpm -t
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps web nginx -t
docker compose -f compose.yml -f compose.buildadmin.yml stop app queue scheduler ai-queue
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan schedule:clear-cache
docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --force-recreate --scale queue=3 app web queue scheduler ai-queue
curl -sS --max-time 15 -o /dev/null -w '更新接口 HTTP %{http_code}\n' 'https://vm-monitor.lcayun.cn/api/v1/agent/update?version=1.6.0'
curl -sS --max-time 15 -o /dev/null -w '抓包领取 HTTP %{http_code}\n' 'https://vm-monitor.lcayun.cn/api/v1/agent/captures/claim'
```

两项配置检查通过后才替换容器；无令牌访问应返回 **401**。普通批次和 PCAP 上传使用 9000 池，只有两个精确路径的 GET 使用 9001 池，认证和限流继续生效。PCAP 仍保留 120 秒 PHP 执行预算，普通池总请求上限 125 秒、Nginx 等待 130 秒；控制池请求上限 20 秒，Nginx 等待 25 秒。控制隔离能避免普通池排队拖住控制请求，数据库、Redis 或内存耗尽仍需单独排查。

本次接收端按单条指标验证嵌套字段，保留数量上限、字段约束和统计一致性检查；已经持久化接收的同节点批次直接确认，不重复深层校验，也不覆盖健康数据。截图清理由每张图单独查库改为每批最多 200 个路径查询，并增加仅覆盖非空截图路径的索引。索引在 PostgreSQL 中并发创建，大表上首次迁移可能需要等待；不要因暂时没有输出就重复启动迁移。清理保留在用截图和最近 24 小时文件，与截图写入共用文件锁；查询失败会停止当前批清理。

请求超过 5 秒时，PHP 尝试记录调用栈到 `storage/logs/php-fpm-www-slow.log` 或 `php-fpm-control-slow.log`；同时查看 `php-fpm.log` 中的进程数上限、终止和慢日志错误。容器若不允许抓取调用栈，以数据库等待、Nginx 错误和 FPM 日志为准，不必额外放开容器权限。

节点日志出现 `started 1.6.0` 表示已经启动新版本。后台“当前版本”来自成功接收的上报；主控阻塞时，它可能仍显示旧版本或“等待节点领取”，不能据此反复下发或重启节点。修复后确认“最近上报”持续更新，再检查后台版本；保留节点本地缓存等待自动重试。

### 上报队列满时检查分析进度

出现“节点接收队列已达容量上限”说明请求已通过认证，但该节点未分析的批次达到容量限制。主控先按请求体大小预检查余量，满时跳过昂贵的嵌套字段校验；最终入库仍在事务中按规范化大小检查容量，已接收批次的重复上报不因满队列被拒绝。先查处理进度和最新任务失败原因，不要清空 Redis、删除 `batches` 或节点缓存，也不要直接放大容量掩盖积压：

```sh
cd /home/vm-monitor-src/deploy
docker compose -f compose.yml -f compose.buildadmin.yml ps queue scheduler redis
docker compose -f compose.yml -f compose.buildadmin.yml exec -T postgres psql -U monitor -d monitor -c "SELECT count(*) AS pending, round(sum(payload_bytes)/1048576.0,1) AS pending_mib, min(created_at) AS oldest, count(*) FILTER (WHERE dispatched_at IS NULL) AS not_dispatched FROM batches WHERE processed_at IS NULL; SELECT max(processed_at) AS last_processed FROM batches; SELECT failed_at,left(exception,700) AS error FROM failed_jobs ORDER BY failed_at DESC LIMIT 3;"
```

等待一两分钟重复查询：待处理数量持续下降且 `last_processed` 更新，说明正在消化积压；若不变，检查任务失败、数据库锁等待和主控资源。修复分析异常后 Agent 会自动重试保留的批次。清理异常前不要重复执行所有失败任务，其中可能含邮件等副作用任务或人工申请的 AI 分析。

流量窗口默认仅保留 **24 小时**，在主控 `.env` 设置 `MONITOR_METRICS_HOURS=24`（允许 1–168）。旧 `MONITOR_METRICS_DAYS` 不再生效，请替换；此设置不缩短告警自身证据、PCAP 或 AI 报告的保留期。

清理独立每分钟运行，沿现有时间索引分批删除，默认每批 5,000 条、每轮最多 100 批、约 20 秒后不再开启下一批。每批独立提交，PostgreSQL 每条查询最多 8 秒、等待锁最多 2 秒；失败会保留已完成批次，剩余下轮重试。`MONITOR_METRICS_PRUNE_SECONDS`（1–45）、`MONITOR_METRICS_PRUNE_BATCHES`（1–1000）可调整预算，达到预算会写日志提醒。保留边界上的窗口和未分析批次原文不随此命令删除。

手动检查一轮：`docker compose -f compose.yml -f compose.buildadmin.yml exec -T app php artisan monitor:prune-traffic`。保留时长不是磁盘硬配额，应继续监控分区余量。普通删除／autovacuum 通常将空间留给数据库复用，不保证文件立即缩小；此次升级调整流量和网站表的 autovacuum 阈值，但不会自动重建已有膨胀索引。

更新退出前的最后一个采集窗口可能不足一秒。本版主控按小数秒比较并保存窗口时间，避免有效短窗口被误拒绝；时间相等或倒退仍拒绝。日志中已经被 HTTP 422 丢弃的旧批次无法恢复。出现 `started 1.4.0` 表示该进程已启动此版本；后台显示的当前版本还要等待下一次成功上报。

管理员邮箱和密码在右上角“个人资料”修改；其他账号在“管理员管理”维护。只读人员分配“监控只读”分组。
