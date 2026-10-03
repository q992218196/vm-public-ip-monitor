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
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build build agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml --profile agent-build run --rm agent-builder
docker compose -f compose.yml -f compose.buildadmin.yml stop queue scheduler ai-queue
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan migrate --force
docker compose -f compose.yml -f compose.buildadmin.yml run --rm --no-deps app php artisan db:seed --class=MonitorSeeder --force
docker compose -f compose.yml -f compose.buildadmin.yml up -d --no-deps --force-recreate app web queue scheduler ai-queue buildadmin-app buildadmin-web
docker compose -f compose.yml -f compose.buildadmin.yml exec buildadmin-app php think migrate:run
docker compose -f compose.yml -f compose.buildadmin.yml --profile https up -d --no-deps --force-recreate https
```

如果已启用网站 worker，**也要更新它**：

```sh
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots build worker
docker compose -f compose.yml -f compose.buildadmin.yml --profile screenshots up -d --no-deps --force-recreate worker
```

后台强制刷新，然后在“采集节点”确认最近上报持续更新。规则初始化只新增缺失规则，保留已修改阈值。

本版 Agent 为 **1.2.0**：先升级主控，再在采集节点下发更新。新版本补全每目标最多 128 个端口的业务范围，减少白名单因截断反复失效。先更新主控，再更新节点，重新审核业务白名单；旧节点的截断数据仍要求复核。UDP 检测同样需要新版节点统计。

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

默认并发 2、内存上限 2 GiB；`.env` 中 `WORKER_CONCURRENCY` 可设 1–4。IPv6 网站验证需要 **worker 容器有 IPv6 出口**。

### 如何确认网站归属

| 入口或状态 | 作用 |
| --- | --- |
| 验证／截图 | 核实 DNS 归属后，请求网站、截图并分析首页 |
| 测试源站 | 不要求 DNS 指向此 IP；直接连接记录的公网 IP 和端口，携带域名 Host/SNI；不自动登记归属 |
| 登记 CDN 源站 | 根据客户配置、申报或日志，填写核实依据，保存人工归属并排队验证 |
| 添加已知网站 | 手动登记已知域名、IP、端口、协议 |

普通 DNS 检查不匹配时，保留线索，不请求网页。CDN 源站可能没有直接 DNS 指向，最快的流程是：**选择线索 → 测试源站 → 看详情中的网页、截图和归属证据 → 核实后登记**。源站测试需要 worker 在线。

测试成功只能证明该 IP 对此 Host/SNI 有响应；默认站点、通配站点、反向代理也可能响应。测试失败也可能是源站只允许 CDN 回源、证书限制或访问控制。测试不会修改公网 DNS，也不会自动寻找其他源站 IP。

网站资产默认显示解析匹配、人工登记和 IP 直连记录。其余线索通过归属筛选查看；“指定 IP 响应，待核实”保留在待核实线索中。客户端填写的 Host/SNI 不等于 VM 部署的网站。

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

主控发布二进制后，在“采集节点”下发单节点或批量更新，先试点一台。节点一般每分钟检查一次，校验并自检后更新，后台显示当前版本和更新错误。

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

### 检测与审核

同一节点、公网 IP 的持续规则命中归并成事件。详情先看本地 IP 报告：目标、端口、连接状态、双向流量、时间趋势、采集质量和证据缺口。纯数量提醒、疑似异常和强异常证据分别分级，不将连接数量直接当作攻击结论。

常见服务规则包括 SSH、SMB、RDP、FTP 高频连接。明文 FTP、SMB2 的可见认证响应可以在 PCAP 中辅助核查；加密 SSH、RDP/NLA 等登录结果需服务日志，不能仅凭端口认定爆破。

主要告警按级别、证据结论、规则具体程度依次选择：同等级、同结论时，SMB／SSH／RDP／FTP 服务规则优先于泛化的多目标、多端口和连接数量提醒。其他命中仍在详情保留；显示优先级不提高风险级别，也不代表已确认违规。升级时执行数据库迁移，会同步修正已有事件的主标题，保留审核状态和原始证据。

检测规则列表显示配置级别和启用状态。配置级别是证据评估允许的级别上限；数量提醒可能仍显示为低级别。多目标连接取评估范围内各采集窗口的目标数最大值；认证服务重复连接取单目标常见认证端口 TCP 发起数的窗口最大值，不统计登录失败。TCP 连接数量提醒累加范围内窗口的发起数，SYN 重传有界去重，不等于 HTTP 请求或成功连接。详情分别显示规则命中值、配置窗口、实际范围和单个样本窗口；按完整窗口统计，时间边界可能超过配置秒数，采集间断也不代表连续覆盖。旧记录未保存的范围不推算。目标计数触及限额时只表示观察下界。

**UDP 新增两类规则：**

| 规则 | 默认阈值 | 统计含义 |
| --- | --- | --- |
| UDP 出站流数量 | 1000 | 规则观察范围内，单个采集窗口的不同五元组数量最大值 |
| UDP 出站包速率 PPS | 10000 包/秒 | 规则观察范围内，出站 UDP 包数除以实际已观察窗口秒数 |

UDP 没有 TCP 握手，五元组只是源／目的 IP、源／目的端口和协议。同一窗口相同五元组只计一次，跨窗口可能重复；出站数据也可能是服务器回复。默认作为低级别行为提醒，详情显示目标端口、双向包量和字节量。DNS、QUIC、游戏等正常业务也可能较高，阈值在“检测规则”按业务调整。流状态最多 16384 项，每个 IP 上报最多 8 个端点样本，达到限额会注明；旧 Agent 不参与 UDP 检测。

事件白名单先显示最近一小时窗口、近期抓包与此前已批准的目标／端口，逐项核实后确认。按每个目标分别批准端口，重复审批保留之前批准范围；需要缩减时删除原例外再重新审核。白名单限定节点、源 IP、类型、已核实目标范围、端口、强度和级别，默认 30 天；新目标、新端口、更强证据或样本不足时仍进入复核。“采集覆盖下降”是采集质量提醒，不提供白名单，应检查漏采或状态限额。

### PCAP 与手动 AI

无法判断的事件，可在详情申请定向抓包，再查看本地抓包分析或下载原始 PCAP。抓包从节点领取任务时开始，不能恢复历史流量。手动任务完成或失败后可立即重新申请；同一 IP 不能同时有等待或执行中的任务，节点队列最多 10 个。自动抓包保留 30 分钟限频。

| 项目 | 默认值 |
| --- | --- |
| 单次抓包 | 60 秒，最多 32 MiB；单节点同时 1 个 IP |
| 节点证据 | `/home/vm-monitor/evidence`，512 MiB、24 小时，计入总磁盘预算 |
| PCAP 上传限速 | 每节点 2048 KiB/s，仅上传 PCAP 时使用 |
| 主控证据 | `storage/app/private/packet-evidence`，20 GiB、7 天 |

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
curl -sS -o /dev/null -w 'Agent API: %{http_code}\n' 'https://vm-monitor.lcayun.cn/api/v1/agent/update?version=1.2.0'
```

无 Agent 令牌的最后一项正常应为 **401**。示例域名和自定义目录请替换。BuildAdmin 日志在 `buildadmin/runtime`；节点日志在宿主机的 `data_dir/logs/agent.log`。

管理员邮箱和密码在右上角“个人资料”修改；其他账号在“管理员管理”维护。只读人员分配“监控只读”分组。
