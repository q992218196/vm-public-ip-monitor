<?php

namespace Database\Seeders;

use App\Models\Rule;
use Illuminate\Database\Seeder;

class MonitorSeeder extends Seeder
{
    public function run(): void
    {
        foreach ([['横向扫描', 'horizontal_scan', 100, 'high'], ['端口扫描', 'vertical_scan', 50, 'high'], ['认证服务重复连接', 'suspected_bruteforce', 60, 'medium'], ['单目标高频连接', 'single_target_attempts', 80, 'medium'], ['TCP 连接突增', 'tcp_connection_burst', 1000, 'medium'], ['出站流量 Mbps', 'egress_mbps', 100, 'medium'], ['VPN 双向握手特征', 'vpn_protocol', 1, 'medium']] as [$name,$kind,$threshold,$severity]) {
            Rule::firstOrCreate(['kind' => $kind, 'node_id' => null], ['name' => $name, 'threshold' => $threshold, 'severity' => $severity, 'window_seconds' => 60, 'cooldown_seconds' => 600]);
        }
    }
}
