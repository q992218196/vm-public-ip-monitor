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
            'http_host' => 'HTTP Host 线索','tls_sni' => 'TLS SNI 线索','manual' => '人工添加','active_candidate' => '主动探测候选',
            'horizontal_scan' => '横向扫描','vertical_scan' => '端口扫描','suspected_bruteforce' => '认证端口重复连接',
            'single_target_attempts' => '单目标高频连接','tcp_connection_burst' => 'TCP 连接突增','egress_mbps' => '出站流量',
            'vpn_protocol' => 'VPN 握手特征', 'wireguard' => 'WireGuard', 'openvpn' => 'OpenVPN', 'ikev2' => 'IKEv2/IPsec',
            'proxy_suspect' => '疑似加密代理', 'opaque_tcp' => '不透明 TCP', 'opaque_udp' => '不透明 UDP', 'tls' => 'TLS 外观', 'quic' => 'QUIC 外观',
            default => $state ?? '—',
        };
    }
}
