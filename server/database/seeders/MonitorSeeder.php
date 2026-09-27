<?php

namespace Database\Seeders;

use App\Models\Rule;
use Illuminate\Database\Seeder;

class MonitorSeeder extends Seeder
{
    public function run(): void
    {
        foreach ([['横向扫描', 'horizontal_scan', 100, 'high'], ['端口扫描', 'vertical_scan', 50, 'high'], ['认证服务重复连接', 'suspected_bruteforce', 60, 'medium'], ['出站流量 Mbps', 'egress_mbps', 100, 'medium']] as [$name,$kind,$threshold,$severity]) {
            Rule::firstOrCreate(['kind' => $kind, 'node_id' => null], ['name' => $name, 'threshold' => $threshold, 'severity' => $severity, 'window_seconds' => 60, 'cooldown_seconds' => 600]);
        }
    }
}
