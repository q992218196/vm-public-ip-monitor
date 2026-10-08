<?php

namespace Database\Seeders;

use App\Models\Rule;
use Illuminate\Database\Seeder;

class MonitorSeeder extends Seeder
{
    public function run(): void
    {
        foreach ([['单目标高频连接', 'single_target_attempts', 80, 'medium'], ['TCP 连接突增', 'tcp_connection_burst', 1000, 'medium'], ['出站流量 Mbps', 'egress_mbps', 100, 'medium'], ['VPN 双向握手特征', 'vpn_protocol', 1, 'medium'], ['疑似加密代理样态', 'proxy_suspect', 3, 'low'], ['SSH 多目标建连', 'ssh_target_spread', 10, 'medium'], ['SMB 服务高频连接', 'smb_connections', 60, 'medium'], ['RDP 多目标建连', 'rdp_target_spread', 10, 'medium'], ['FTP 多目标建连', 'ftp_target_spread', 10, 'medium']] as [$name,$kind,$threshold,$severity]) {
            Rule::firstOrCreate(['kind' => $kind, 'node_id' => null], ['name' => $name, 'threshold' => $threshold, 'severity' => $severity, 'window_seconds' => 60, 'cooldown_seconds' => 600]);
        }
        Rule::firstOrCreate(['kind' => 'capture_degraded', 'node_id' => null], [
            'name' => '采集覆盖下降', 'threshold' => 1, 'severity' => 'medium', 'window_seconds' => 60, 'cooldown_seconds' => 600,
        ]);
    }
}
