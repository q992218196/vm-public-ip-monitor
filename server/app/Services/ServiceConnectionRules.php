<?php

namespace App\Services;

class ServiceConnectionRules
{
    public const RULES = [
        'smb_connections' => ['name' => 'SMB 服务高频连接', 'ports' => [139, 445]],
        'ssh_target_spread' => ['name' => 'SSH 多目标建连', 'ports' => [22], 'service' => 'ssh'],
        'rdp_target_spread' => ['name' => 'RDP 多目标建连', 'ports' => [3389], 'service' => 'rdp'],
        'ftp_target_spread' => ['name' => 'FTP 多目标建连', 'ports' => [21, 990], 'service' => 'ftp'],
    ];

    public static function countsTargets(string $kind): bool
    {
        return isset(self::RULES[$kind]['service']);
    }

    public function targetSample(string $kind, array $windows): ?array
    {
        $definition = self::RULES[$kind] ?? null;
        if (! isset($definition['service'])) {
            return null;
        }
        $targets = [];
        $ports = [];
        $attempts = 0;
        $capped = false;
        foreach ($windows as $window) {
            if (($window['service_target_stats_version'] ?? 0) !== 1) {
                continue;
            }
            foreach ($window['service_targets'] ?? [] as $service) {
                if ($service['service'] !== $definition['service']) {
                    continue;
                }
                $attempts += $service['attempts'];
                $capped = $capped || $service['targets_capped'] || ($window['capture_quality']['state_dropped'] ?? 0) > 0;
                foreach ($service['targets'] as $target) {
                    if (! isset($targets[$target]) && count($targets) >= 128) {
                        $capped = true;
                    } else {
                        $targets[$target] = true;
                    }
                }
                foreach ($service['ports'] as $port) {
                    $ports[$port] = true;
                }
            }
        }
        if (! $targets) {
            return null;
        }
        $targets = array_keys($targets);
        sort($targets, SORT_STRING);
        $ports = array_keys($ports);
        sort($ports, SORT_NUMERIC);

        return ['service_target_stats_version' => 1, 'count_basis' => 'distinct_service_target_ips', 'targets' => $targets,
            'unique_targets' => count($targets), 'service_targets_capped' => $capped, 'cardinality_capped' => $capped, 'ports' => $ports,
            'port_samples_truncated' => false, 'endpoint_samples_truncated' => false, 'outbound_samples_truncated' => false,
            'tcp_attempts' => $attempts, 'outbound_endpoints' => [], 'service' => $definition['name'],
            'login_result' => 'not visible in aggregate traffic', 'protocol_basis' => 'common destination ports only; actual service may differ',
            'counting_note' => 'Distinct destination IPs with outgoing TCP SYN within fully contained collection windows; retransmissions and post-connect data do not add targets; a repeated target across windows or FTP ports counts once; bounded lower bound, not login failures'];
    }

    public function sample(string $kind, array $evidence): ?array
    {
        if (self::countsTargets($kind)) {
            return $this->targetSample($kind, [$evidence]);
        }
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
