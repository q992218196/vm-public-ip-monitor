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

    public static function fingerprint(array $targets): string
    {
        return hash('sha256', json_encode($targets));
    }
}
