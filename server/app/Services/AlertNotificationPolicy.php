<?php

namespace App\Services;

class AlertNotificationPolicy
{
    public const RETIRED_UDP_RULES = ['udp_flow_burst', 'udp_packet_rate'];

    public static function allows(string $kind, array $evidence, ?string $category = null): bool
    {
        if (in_array($kind, self::RETIRED_UDP_RULES, true)) {
            return false;
        }

        $evidenceCategory = $evidence['connection_analysis']['category'] ?? null;
        if ($category === 'behavior_notice' || $evidenceCategory === 'behavior_notice') {
            return false;
        }
        $category ??= $evidenceCategory;
        if (in_array($kind, ['single_target_attempts', 'tcp_connection_burst', 'egress_mbps'], true)) {
            return in_array($evidenceCategory, ['needs_review', 'strong_anomaly'], true);
        }

        return $category !== 'behavior_notice';
    }
}
