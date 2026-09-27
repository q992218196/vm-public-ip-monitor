# OVS、网桥与公网 IP 可见性

## 原则

CIDR 是匹配范围，不是节点归属。后台只记录公网 IP 和观察点，不使用 libvirt、VM UUID 或 MAC 做身份归属。同一流量经过多个节点时，统计独立保留，不直接汇总。

Agent 当前采集 Ethernet 帧，不解封装 VXLAN/GRE、不读取 VM 内网络命名空间、不处理 SR-IOV 直通流量。必须选择能看到需要监控的公网 IP 这一层的接口。

VPC 内只出现私网地址、公网 NAT 在独立网关上的情况，VM 宿主机无法仅凭 CIDR 还原公网 IP。将采集点放到公网转换之后的网关，或先提供可靠的转换关系。不要把隧道外层地址误认为 VM 地址。

## Linux bridge

先查看接口与桥成员：

```sh
ip -br link
bridge link
ip -br address
```

在候选出口接口观察一个已知公网地址：

```sh
sudo tcpdump -ni 实际接口 -c 30 host 实际公网IP
```

此诊断命令仅观察，不保存完整包。测试入站和出站，分别验证 IPv4、IPv6；留意 VLAN、offload、重复包和流量方向。

仅在物理上联采集通常不能覆盖同宿主机的本地转发。若这些通信也在范围内，选择相应成员接口，并用受控通信验证。Agent 支持最多 8 个指定接口；不是为 500 个 tap 各创建一套独立服务。

## OVS

```sh
ovs-vsctl show
ovs-vsctl list-br
ovs-vsctl list-ports 实际网桥名
```

可以为目标网桥配置专用 mirror 输出端口。以下仅为**新建专用镜像**的操作模板；先根据实际桥和现有镜像审核，不能原样复制示例网桥名：

```sh
ovs-vsctl add-port 实际网桥名 mon-vm0 -- set Interface mon-vm0 type=internal
ip link set mon-vm0 up
ovs-vsctl -- --id=@p get Port mon-vm0 \
  -- --id=@m create Mirror name=vm-monitor select-all=true output-port=@p \
  -- add Bridge 实际网桥名 mirrors @m
```

`add ... mirrors` 保留现有镜像引用。不要使用清空所有 mirrors 的命令来卸载本系统。选中的 mirror 输出口必须专用；不要将 VM 业务口设置成输出口。

随后在 `mon-vm0` 用已知公网 IP 做验证，再填入 Agent 配置。端口名字不代表一定具备可见性；生产中应按需要仅镜像相关端口，控制镜像开销。

回滚时，先查询本次新建 Mirror 的 UUID，只移除这一引用和这一专用端口：

```sh
ovs-vsctl --columns=_uuid,name list Mirror
ovs-vsctl remove Bridge 实际网桥名 mirrors 本次镜像UUID
ovs-vsctl destroy Mirror 本次镜像UUID
ovs-vsctl del-port 实际网桥名 mon-vm0
```

OVS DPDK、硬件 offload、直通路径必须单独验证。Agent 不自动修改这些路径。

## 计数解释

- 当前字节数为观察到的帧字节数，不等同于计费平台的 IP 流量统计。
- TCP 发起次数使用 SYN 且非 ACK；同五元组 60 秒内的 SYN 重传合并。
- 多选接口时只对短时间内内容一致、接口不同的帧做有界去重。VLAN/offload 导致包形态变化时不能保证跨接口完全去重，优先选择一个明确的观察边界。
- 相同公网 IP 同时匹配源和目的范围时，两端分别记出／入方向，不强行选出唯一 VM。
- 不把出站访问的 HTTP Host/SNI 当成源 IP 承载的网站。
- 地址来源是网络观测，不具有防源地址伪造的强身份认证能力。

参考：[OVS 官方镜像配置](https://docs.openvswitch.org/en/latest/faq/configuration/)、[Linux bridge 文档](https://docs.kernel.org/networking/bridge.html)。
