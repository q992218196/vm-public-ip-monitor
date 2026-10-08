<?php

namespace App\Services;

class EventPriority
{
    public static function rank(string $severity, string $category, string $kind): int
    {
        $specificity = match ($kind) {
            'smb_connections', 'ssh_target_spread', 'rdp_target_spread', 'ftp_target_spread' => 30,
            'suspected_bruteforce', 'single_target_attempts', 'vpn_protocol', 'proxy_suspect' => 20,
            'horizontal_scan' => 10,
            default => 0,
        };

        return 1000 * (['low' => 1, 'medium' => 2, 'high' => 3][$severity] ?? 0)
            + 100 * (['behavior_notice' => 1, 'needs_review' => 2, 'strong_anomaly' => 3][$category] ?? 2)
            + $specificity;
    }
}
