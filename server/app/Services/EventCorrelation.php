<?php

namespace App\Services;

use App\Models\AuditLog;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Models\PacketCapture;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

class EventCorrelation
{
    public function correlate(Node $node, ?IpAsset $asset, string $kind, string $severity, string $title, \DateTimeInterface $at): MonitorEvent
    {
        return DB::transaction(function () use ($node, $asset, $kind, $severity, $title, $at) {
            Node::whereKey($node->id)->lockForUpdate()->firstOrFail();
            $key = hash('sha256', $node->id.'|'.($asset?->id ?? $kind));
            $event = MonitorEvent::where('active_key', $key)->lockForUpdate()->first();
            $time = CarbonImmutable::instance($at);
            if ($event && $time->gt($event->last_seen_at->copy()->addMinutes(30))) {
                $event->update(['active_key' => null]);
                $event = null;
            }
            $quality = array_intersect_key($node->health ?? [], array_flip(['captured', 'kernel_drops', 'decode_skipped', 'state_dropped', 'reassembly_dropped', 'spool_dropped', 'interfaces', 'version']));
            $quality['observed_at'] = $node->health_observed_at?->toIso8601String();
            if (! $event) {
                $event = MonitorEvent::create(['node_id' => $node->id, 'ip_asset_id' => $asset?->id, 'active_key' => $key, 'title' => $title, 'severity' => $severity, 'kinds' => [$kind], 'quality' => $quality, 'first_seen_at' => $time, 'last_seen_at' => $time]);
                if ($asset && $severity === 'high' && config('monitor.auto_capture') && version_compare($node->health['version'] ?? '0.0.0', '0.6.0', '>=')) {
                    $this->requestCapture($event, $asset->ip, 'auto');
                }
            } else {
                $ranks = ['low' => 1, 'medium' => 2, 'high' => 3];
                $newKind = ! in_array($kind, $event->kinds, true);
                $raised = ($ranks[$severity] ?? 0) > ($ranks[$event->severity] ?? 0);
                $data = ['kinds' => array_values(array_unique([...$event->kinds, $kind])), 'last_seen_at' => max($event->last_seen_at, $time), 'occurrences' => $event->occurrences + 1, 'quality' => $quality];
                if ($raised) {
                    $data += ['severity' => $severity, 'title' => $title];
                }
                if (($newKind || $raised) && in_array($event->status, ['normal', 'resolved'], true)) {
                    $data['status'] = 'open';
                    AuditLog::create(['action' => 'event.reopened', 'subject' => (string) $event->id, 'details' => ['new_kind' => $newKind, 'severity_raised' => $raised], 'created_at' => now()]);
                }
                $event->update($data);
            }

            return $event;
        });
    }

    public function requestCapture(MonitorEvent $event, string $ip, string $source = 'manual'): ?PacketCapture
    {
        $query = PacketCapture::where('node_id', $event->node_id);
        if ((clone $query)->whereIn('status', ['pending', 'leased'])->count() >= 10 || (clone $query)->where('ip', $ip)->where('created_at', '>', now()->subMinutes(30))->exists()) {
            return null;
        }

        return PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => $ip, 'source' => $source]);
    }
}
