<?php

namespace App\Services;

use App\Models\ProbeTask;
use App\Models\Website;
use Illuminate\Database\Eloquent\Builder;

class WebsiteDiscovery
{
    public static function kind(string $source, int $port): string
    {
        return match (true) {
            $source === 'rdp_negotiation' => 'rdp',
            in_array($source, ['tls_sni', 'tls_alpn'], true) => 'tls_unknown',
            default => 'web_candidate',
        };
    }

    public static function automaticCandidates(Builder $query): Builder
    {
        return $query->where('discovery_kind', 'web_candidate')->where(function (Builder $proof): void {
            $proof->whereIn('source', ['http_host', 'manual', 'active_candidate'])->orWhereNotNull('http_status')
                ->orWhere('status', 'verified')->orWhere('ownership_status', 'manual')->orWhereNotNull('manual_category')->orWhereNotNull('screenshot_path');
        });
    }

    public static function canProbeAutomatically(Website $site): bool
    {
        return $site->discovery_kind === 'web_candidate' && (in_array($site->source, ['http_host', 'manual', 'active_candidate'], true)
            || $site->http_status !== null || $site->status === 'verified' || $site->ownership_status === 'manual'
            || $site->manual_category !== null || $site->screenshot_path !== null);
    }

    public static function cancelAutomaticTasks(int $websiteId): void
    {
        ProbeTask::where('website_id', $websiteId)->where('status', 'pending')->where('mode', 'normal')
            ->whereIn('request_source', ['auto', 'legacy'])->update(['status' => 'skipped', 'last_error' => '仅有 TLS 或非网页协议线索，不自动探测；可手动验证', 'lease_token' => null, 'leased_until' => null]);
    }
}
