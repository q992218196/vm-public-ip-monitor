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
    public function correlate(Node $node, ?IpAsset $asset, string $kind, string $severity, string $title, \DateTimeInterface $at, array $evidence = []): MonitorEvent
    {
        return DB::transaction(function () use ($node, $asset, $kind, $severity, $title, $at, $evidence) {
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
            $sample = $evidence['sample'] ?? [];
            $behaviorTime = isset($evidence['sample_window_end']) ? min($time, CarbonImmutable::parse($evidence['sample_window_end'])) : $time;
            if (isset($sample['capture_quality'])) {
                $quality = $sample['capture_quality'] + ['observed_at' => $evidence['sample_window_end'] ?? $time->toIso8601String()];
            }
            $behavior = ['ports' => array_slice(array_values(array_unique($sample['ports'] ?? [])), 0, 64),
                'complete_ports' => isset($sample['ports']) && ! ($sample['port_samples_truncated'] ?? true) && ! ($sample['cardinality_capped'] ?? false),
                'category' => $evidence['connection_analysis']['category'] ?? 'unknown', 'observed_at' => $behaviorTime->toIso8601String(), 'change_streak' => 0];
            if (! $event) {
                $event = MonitorEvent::create(['node_id' => $node->id, 'ip_asset_id' => $asset?->id, 'active_key' => $key, 'title' => $title, 'severity' => $severity, 'assessment_category' => $evidence['connection_analysis']['category'] ?? 'needs_review', 'kinds' => [$kind], 'quality' => $quality, 'behavior' => [$kind => $behavior], 'first_seen_at' => $time, 'last_seen_at' => $time]);
                if ($asset && $severity === 'high' && config('monitor.auto_capture') && version_compare($node->health['version'] ?? '0.0.0', '0.6.0', '>=')) {
                    $this->requestCapture($event, $asset->ip, 'auto');
                }
            } else {
                $ranks = ['low' => 1, 'medium' => 2, 'high' => 3];
                $newKind = ! in_array($kind, $event->kinds, true);
                $raised = ($ranks[$severity] ?? 0) > ($ranks[$event->severity] ?? 0);
                $currentObservation = $time->gte($event->last_seen_at);
                $previous = $event->behavior[$kind] ?? [];
                $baseline = $event->review_context[$kind] ?? $previous;
                $reason = $this->behaviorChange($baseline, $behavior);
                $freshWindow = ! $previous || $behaviorTime->gt(CarbonImmutable::parse($previous['observed_at'])->addSeconds(5));
                $behavior['change_streak'] = $reason ? (($previous['change_reason'] ?? '') === $reason ? ($previous['change_streak'] ?? 0) + (int) $freshWindow : 1) : 0;
                $behavior['change_reason'] = $reason;
                $changed = $reason && $behavior['change_streak'] >= 2;
                $data = ['kinds' => array_values(array_unique([...$event->kinds, $kind])), 'last_seen_at' => max($event->last_seen_at, $time), 'occurrences' => $event->occurrences + 1];
                if ($currentObservation) {
                    $data['quality'] = $quality;
                }
                if (! $previous || $behaviorTime->gte(CarbonImmutable::parse($previous['observed_at']))) {
                    $data['behavior'] = array_replace($event->behavior ?? [], [$kind => $behavior]);
                }
                if ($raised && $currentObservation) {
                    $data += ['severity' => $severity, 'title' => $title];
                }
                if ($currentObservation && ($newKind || $raised || $changed) && in_array($event->status, ['normal', 'resolved'], true)) {
                    $data['status'] = 'open';
                    $data['reopen_reason'] = $newKind ? '命中新的检测类型：'.$kind : ($raised ? '证据级别上升' : $reason.'（连续两个新窗口）');
                    AuditLog::create(['action' => 'event.reopened', 'subject' => (string) $event->id, 'details' => ['new_kind' => $newKind, 'severity_raised' => $raised, 'behavior_change' => $changed, 'reason' => $data['reopen_reason']], 'created_at' => now()]);
                }
                $event->update($data);
                if ($asset && $raised && $currentObservation && $severity === 'high' && config('monitor.auto_capture') && version_compare($node->health['version'] ?? '0', '0.6.0', '>=')
                    && ! PacketCapture::where('event_id', $event->id)->where('source', 'auto')->exists()) {
                    $this->requestCapture($event, $asset->ip, 'auto');
                }
            }

            return $event;
        });
    }

    private function behaviorChange(array $baseline, array $current): ?string
    {
        if (($current['category'] ?? '') === 'strong_anomaly' && ($baseline['category'] ?? '') !== 'strong_anomaly') {
            return '同类行为出现更强的配对连接异常证据';
        }
        if (! ($baseline['complete_ports'] ?? false) || ! $current['complete_ports'] || ! $baseline['ports']) {
            return null;
        }
        $added = array_diff($current['ports'], $baseline['ports']);
        if (array_intersect($added, [22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379])) {
            return '新增认证或管理服务目标端口';
        }
        if (count($added) >= 3 && count($current['ports']) >= 5) {
            return '目标端口范围明显扩大';
        }

        return null;
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
