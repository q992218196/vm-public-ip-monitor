<?php

namespace App\Services;

use App\Models\ProbeTask;

class WebsiteDiscovery
{
    public static function kind(string $source, int $port): string
    {
        return match (true) {
            $source === 'rdp_negotiation' => 'rdp',
            $source === 'tls_sni' && $port === 3389 => 'tls_unknown',
            default => 'web_candidate',
        };
    }

    public static function cancelAutomaticTasks(int $websiteId): void
    {
        ProbeTask::where('website_id', $websiteId)->where('status', 'pending')->where('mode', 'normal')
            ->whereIn('request_source', ['auto', 'legacy'])->update(['status' => 'skipped', 'last_error' => '非网页协议或仅有 3389 TLS 线索，不自动探测', 'lease_token' => null, 'leased_until' => null]);
    }
}
