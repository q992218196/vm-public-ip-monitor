<?php

namespace app\common\service;

class BusinessScope
{
    public static function profile(array $samples, array $summaries = [], array $approved = []): array
    {
        $targets = [];
        foreach ($approved as $scope) {
            foreach ($scope['target_ports'] ?? [] as $peer => $ports) {
                foreach ($ports as $port) {
                    $targets[$peer][(int) $port] = true;
                }
            }
        }
        foreach ($samples as $sample) {
            foreach ($sample['port_scan_targets'] ?? [] as $peer) {
                foreach ($peer['ports'] ?? [] as $port) {
                    $targets[$peer['peer_ip']][(int) $port] = true;
                }
            }
            if (($sample['service_target_stats_version'] ?? 0) === 1) {
                foreach ($sample['service_targets'] ?? [] as $service) {
                    self::addServiceTargetPorts($targets, $service['targets'] ?? [], $service['ports'] ?? []);
                }
                if (($sample['count_basis'] ?? '') === 'distinct_service_target_ips') {
                    self::addServiceTargetPorts($targets, $sample['targets'] ?? [], $sample['ports'] ?? []);
                }
            }
        }
        foreach ($summaries as $summary) {
            if (! ($summary['pcap_fully_read'] ?? false) || ($summary['summary_capped'] ?? true)) {
                continue;
            }
            foreach ($summary['peer_groups'] ?? [] as $peer) {
                foreach ($peer['ports'] ?? [] as $port) {
                    $targets[$peer['peer_ip']][(int) $port] = true;
                }
            }
        }
        ksort($targets);
        foreach ($targets as &$ports) {
            $ports = array_keys($ports);
            sort($ports, SORT_NUMERIC);
        }
        unset($ports);

        return $targets;
    }

    private static function addServiceTargetPorts(array &$targets, array $peers, array $ports): void
    {
        foreach ($peers as $peer) {
            if (! is_string($peer) || ! filter_var($peer, FILTER_VALIDATE_IP)) {
                continue;
            }
            foreach ($ports as $port) {
                if (in_array($port, [21, 22, 990, 3389], true)) {
                    $targets[$peer][$port] = true;
                }
            }
        }
    }

    public static function fingerprint(array $targets): string
    {
        return hash('sha256', json_encode($targets));
    }
}
