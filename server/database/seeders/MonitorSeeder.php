<?php

namespace Database\Seeders;

use App\Models\Rule;
use Illuminate\Database\Seeder;

class MonitorSeeder extends Seeder
{
    public function run(): void
    {
        foreach ([['端口扫描', 'vertical_scan', 50, 'high'], ['单目标高频连接', 'single_target_attempts', 80, 'medium'], ['TCP 连接突增', 'tcp_connection_burst', 1000, 'medium'], ['出站流量 Mbps', 'egress_mbps', 100, 'medium'], ['VPN 双向握手特征', 'vpn_protocol', 1, 'medium'], ['疑似加密代理样态', 'proxy_suspect', 3, 'low'], ['SSH 服务高频连接', 'ssh_connections', 60, 'medium'], ['SMB 服务高频连接', 'smb_connections', 60, 'medium'], ['远程桌面 RDP 高频连接', 'rdp_connections', 60, 'medium'], ['FTP 服务高频连接', 'ftp_connections', 60, 'medium'], ['UDP 出站流数量', 'udp_flow_burst', 1000, 'low'], ['UDP 出站包速率 PPS', 'udp_packet_rate', 10000, 'low']] as [$name,$kind,$threshold,$severity]) {
            Rule::firstOrCreate(['kind' => $kind, 'node_id' => null], ['name' => $name, 'threshold' => $threshold, 'severity' => $severity, 'window_seconds' => 60, 'cooldown_seconds' => 600]);
        }
        Rule::firstOrCreate(['kind' => 'capture_degraded', 'node_id' => null], [
            'name' => '采集覆盖下降', 'threshold' => 1, 'severity' => 'medium', 'window_seconds' => 60, 'cooldown_seconds' => 600,
        ]);
    }
}
