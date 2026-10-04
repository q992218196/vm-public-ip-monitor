<?php

namespace App\Services;

class ServiceConnectionRules
{
    public const RULES = [
        'ssh_connections' => ['name' => 'SSH 服务高频连接', 'ports' => [22]],
        'smb_connections' => ['name' => 'SMB 服务高频连接', 'ports' => [139, 445]],
        'rdp_connections' => ['name' => '远程桌面 RDP 高频连接', 'ports' => [3389]],
        'ftp_connections' => ['name' => 'FTP 服务高频连接', 'ports' => [21, 990]],
    ];

    public function sample(string $kind, array $evidence): ?array
    {
        $definition = self::RULES[$kind] ?? null;
        if (! $definition) {
            return null;
        }
        $groups = [];
        foreach ($evidence['outbound_endpoints'] ?? [] as $endpoint) {
            if (in_array($endpoint['peer_port'], $definition['ports'], true)) {
                $groups[$endpoint['peer_ip']][] = $endpoint;
            }
        }
        if (! $groups) {
            return null;
        }
        uasort($groups, fn ($a, $b) => array_sum(array_column($b, 'attempts')) <=> array_sum(array_column($a, 'attempts')));
        $endpoints = reset($groups);
        $target = array_key_first($groups);
        $attempts = array_sum(array_column($endpoints, 'attempts'));
        $ports = array_values(array_unique(array_column($endpoints, 'peer_port')));
        $sample = ['tcp_attempts' => $attempts, 'targets' => [$target], 'ports' => $ports, 'unique_targets' => 1, 'target_endpoints' => array_map(fn ($port) => (str_contains($target, ':') ? '['.$target.']' : $target).':'.$port, $ports), 'max_attempts_per_target' => $attempts, 'outbound_endpoints' => $endpoints,
            'completed_handshakes' => array_sum(array_column($endpoints, 'completed_handshakes')), 'rst_replies' => array_sum(array_column($endpoints, 'rst_replies')), 'synack_replies' => array_sum(array_column($endpoints, 'synack_replies')),
            'connection_stats_version' => ($evidence['connection_stats_version'] ?? 0) === 1 && count(array_filter($endpoints, fn ($endpoint) => isset($endpoint['completed_handshakes'], $endpoint['rst_replies'], $endpoint['synack_replies']))) === count($endpoints) ? 1 : 0,
            'count_basis' => 'deduplicated_tcp_syn_attempts',
            'outbound_samples_truncated' => $evidence['outbound_samples_truncated'] ?? true, 'capture_quality' => $evidence['capture_quality'] ?? [], 'cardinality_capped' => $evidence['cardinality_capped'] ?? false,
            'service' => $definition['name'], 'protocol_basis' => 'common destination ports only; actual service may differ', 'login_result' => 'not visible in aggregate traffic', 'counting_note' => 'Per-target outgoing SYN attempts, retransmissions deduplicated; completed_handshakes counts observed three-way handshakes; bounded lower bounds, not post-connect packets or login attempts/failures'];

        return $sample;
    }
}
