<?php

namespace app\common\service;

class EventEvidencePriority
{
    public static function prioritize(array $alerts, string $title): array
    {
        $alerts = array_filter($alerts, fn ($alert) => ($alert['kind'] ?? '') !== 'vertical_scan');
        $ranked = array_map(fn ($row) => ['alert' => $row, 'score' => 100000 * (int) ! self::isBehaviorNotice($row)
            + 10000 * (int) in_array($row['status'] ?? 'open', ['open', 'acknowledged'], true)
            + 1000 * (['low' => 1, 'medium' => 2, 'high' => 3][$row['severity'] ?? ''] ?? 0)
            + 100 * (['behavior_notice' => 1, 'needs_review' => 2, 'strong_anomaly' => 3][$row['assessment_category'] ?? ''] ?? 2)
            + (int) (($row['title'] ?? '') === $title)], $alerts);
        usort($ranked, fn ($a, $b) => $b['score'] <=> $a['score']);

        return array_column($ranked, 'alert');
    }

    private static function decode(mixed $value): array
    {
        return is_array($value) ? $value : (json_decode((string) $value, true) ?: []);
    }

    private static function isBehaviorNotice(array $alert): bool
    {
        if (in_array($alert['kind'] ?? '', ['ssh_connections', 'rdp_connections', 'ftp_connections', 'udp_flow_burst', 'udp_packet_rate'], true)) {
            return true;
        }

        return ($alert['assessment_category'] ?? null) === 'behavior_notice'
            || (self::decode($alert['evidence'] ?? [])['connection_analysis']['category'] ?? null) === 'behavior_notice';
    }
}
