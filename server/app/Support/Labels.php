<?php

namespace App\Support;

final class Labels
{
    public static function get(?string $state): string
    {
        return match ($state) {
            'open' => '待处理','acknowledged' => '已确认','resolved' => '已解决',
            'high' => '高','medium' => '中','low' => '低',
            'observed' => '待验证线索','candidate' => '探测候选','verified' => '已验证','failed' => '失败',
            'pending' => '排队中','leased' => '执行中','complete' => '已完成',
            'horizontal_scan' => '横向扫描','vertical_scan' => '端口扫描','suspected_bruteforce' => '认证端口重复连接',
            'single_target_attempts' => '单目标高频连接','tcp_connection_burst' => 'TCP 连接突增','egress_mbps' => '出站流量',
            default => $state ?? '—',
        };
    }
}
