<?php

namespace App\Services;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class RetireConnectionRules
{
    private const SERVICE_COUNT_KINDS = ['ssh_connections', 'rdp_connections', 'ftp_connections'];

    private const DELETED_KIND = 'vertical_scan';

    public function run(): void
    {
        DB::table('rules')->whereIn('kind', [self::DELETED_KIND, ...self::SERVICE_COUNT_KINDS])->delete();
        DB::table('exclusions')->where('kind', self::DELETED_KIND)->delete();
        DB::table('alerts')->whereIn('kind', self::SERVICE_COUNT_KINDS)->orderBy('id')
            ->select(['id', 'evidence'])->chunkById(100, function ($alerts): void {
                foreach ($alerts as $alert) {
                    $evidence = $this->decode($alert->evidence);
                    $evidence['connection_analysis'] = array_replace($evidence['connection_analysis'] ?? [], [
                        'category' => 'behavior_notice',
                        'conclusion' => '旧服务连接次数规则已停用；此记录仅保留历史证据，不参与异常通知',
                    ]);
                    DB::table('alerts')->where('id', $alert->id)->update([
                        'assessment_category' => 'behavior_notice', 'evidence' => json_encode($evidence, JSON_UNESCAPED_UNICODE),
                    ]);
                }
            });
        DB::table('monitor_events')->where(function (Builder $query): void {
            foreach ([self::DELETED_KIND, ...self::SERVICE_COUNT_KINDS] as $kind) {
                $query->orWhereJsonContains('kinds', $kind);
            }
            $query->orWhereNotNull('behavior->'.self::DELETED_KIND)
                ->orWhereNotNull('review_context->'.self::DELETED_KIND)
                ->orWhereExists(function (Builder $alerts): void {
                    $alerts->selectRaw('1')->from('alerts')->whereColumn('alerts.event_id', 'monitor_events.id')
                        ->whereIn('alerts.kind', [self::DELETED_KIND, ...self::SERVICE_COUNT_KINDS]);
                });
        })->select('id')->orderBy('id')->chunkById(100, function ($events): void {
            foreach ($events as $event) {
                $this->retireEvent((int) $event->id);
            }
        });
        DB::table('alerts')->where('kind', self::DELETED_KIND)->delete();
    }

    private function retireEvent(int $id): void
    {
        DB::transaction(function () use ($id): void {
            $event = DB::table('monitor_events')->where('id', $id)->lockForUpdate()->first();
            if (! $event) {
                return;
            }
            DB::table('alerts')->where('event_id', $id)->where('kind', self::DELETED_KIND)->delete();
            $children = DB::table('alerts')->where('event_id', $id);
            $kinds = array_values(array_unique(array_merge(
                array_diff($this->decode($event->kinds), [self::DELETED_KIND]),
                (clone $children)->distinct()->pluck('kind')->all(),
            )));
            if (! $kinds) {
                DB::table('packet_captures')->where('event_id', $id)->whereNotNull('path')->orderBy('id')
                    ->select('path')->chunk(100, function ($captures): void {
                        foreach ($captures as $capture) {
                            DB::afterCommit(fn () => $this->reclaimManagedCapture($capture->path));
                        }
                    });
                DB::table('monitor_events')->where('id', $id)->delete();

                return;
            }
            $behavior = $this->decode($event->behavior);
            $review = $this->decode($event->review_context);
            unset($behavior[self::DELETED_KIND], $review[self::DELETED_KIND]);
            $data = ['kinds' => json_encode($kinds), 'behavior' => json_encode((object) $behavior), 'review_context' => json_encode((object) $review)];
            $primary = null;
            $rank = -1;
            foreach ($this->notificationAlerts($id)->select(['kind', 'title', 'severity', 'assessment_category', 'status'])->orderBy('id')->cursor() as $alert) {
                if (in_array($event->status, ['open', 'acknowledged'], true) && ! in_array($alert->status, ['open', 'acknowledged'], true)) {
                    continue;
                }
                $score = EventPriority::rank($alert->severity, $alert->assessment_category ?? 'needs_review', $alert->kind);
                if ($score > $rank) {
                    $primary = $alert;
                    $rank = $score;
                }
            }
            $eligibleKinds = array_diff($kinds, [self::DELETED_KIND, ...self::SERVICE_COUNT_KINDS, ...AlertNotificationPolicy::RETIRED_UDP_RULES, 'new_website']);
            if ($primary) {
                $data += ['title' => $primary->title, 'severity' => $primary->severity, 'assessment_category' => $primary->assessment_category ?? 'needs_review'];
            } elseif ($eligibleKinds && ! (clone $children)->exists()) {
                $data += ['title' => '历史检测事件：'.implode(', ', $eligibleKinds), 'assessment_category' => $event->assessment_category === 'behavior_notice' ? 'needs_review' : $event->assessment_category];
            } else {
                $data += ['assessment_category' => 'behavior_notice', 'active_key' => null];
            }
            $statsQuery = $primary ? $this->notificationAlerts($id) : $children;
            $stats = $statsQuery->selectRaw('SUM(occurrences) AS occurrences, MIN(first_seen_at) AS first_seen_at, MAX(last_seen_at) AS last_seen_at')->first();
            if ($stats->first_seen_at !== null) {
                $data += ['occurrences' => (int) $stats->occurrences, 'first_seen_at' => $stats->first_seen_at, 'last_seen_at' => $stats->last_seen_at];
            }
            DB::table('monitor_events')->where('id', $id)->update($data);
        });
    }

    private function notificationAlerts(int $eventId): Builder
    {
        return DB::table('alerts')->where('event_id', $eventId)
            ->whereNotIn('kind', [self::DELETED_KIND, ...self::SERVICE_COUNT_KINDS, ...AlertNotificationPolicy::RETIRED_UDP_RULES, 'new_website'])
            ->where(fn (Builder $query) => $query->whereNull('assessment_category')->orWhere('assessment_category', '<>', 'behavior_notice'));
    }

    private function reclaimManagedCapture(string $path): void
    {
        if (! preg_match('/^packet-evidence\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.pcap$/iD', $path)
            || DB::table('packet_captures')->where('path', $path)->exists()) {
            return;
        }
        $disk = Storage::disk('local');
        $root = $disk->path('packet-evidence');
        $file = $disk->path($path);
        if (is_link($root) || is_link($file) || ! is_file($file)) {
            return;
        }
        $resolvedRoot = realpath($root);
        $resolvedFile = realpath($file);
        if ($resolvedRoot === false || $resolvedFile === false || dirname($resolvedFile) !== $resolvedRoot) {
            return;
        }
        try {
            if (! $disk->delete($path)) {
                Log::warning('Retired rule PCAP reclamation failed', ['path' => $path]);
            }
        } catch (\Throwable $error) {
            Log::warning('Retired rule PCAP reclamation failed', ['path' => $path, 'error' => $error->getMessage()]);
        }
    }

    private function decode(?string $value): array
    {
        $decoded = json_decode($value ?? '', true);

        return is_array($decoded) ? $decoded : [];
    }
}
