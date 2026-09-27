<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\Batch;
use App\Models\Node;
use App\Models\ProbeTask;
use App\Models\TrafficMetric;
use App\Models\Website;
use App\Services\Analyzer;
use App\Services\ProbeQueue;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

class Maintain extends Command
{
    protected $signature = 'monitor:maintain';

    protected $description = 'Retention, stale leases and offline detection';

    public function handle(Analyzer $analyzer, ProbeQueue $queue): int
    {
        foreach (Node::where('enabled', true)->whereNotNull('last_seen_at')->where('last_seen_at', '<', now()->subMinutes(config('monitor.offline_minutes')))->get() as $node) {
            $analyzer->alert($node, null, 'node_offline', 'high', '节点上报中断', ['last_seen_at' => $node->last_seen_at], now(), 3600);
        }
        ProbeTask::where('status', 'leased')->where('leased_until', '<', now())->where('attempts', '>=', 3)->update(['status' => 'failed', 'last_error' => '工作节点租约连续超时']);
        if (config('monitor.auto_probe')) {
            $capacity = max(0, 1000 - ProbeTask::whereIn('status', ['pending', 'leased'])->count());
            if ($capacity > 0) {
                Website::where(fn (Builder $query) => $query->whereNull('last_probed_at')->orWhere('last_probed_at', '<', now()->subDay()))
                    ->whereDoesntHave('task', fn (Builder $query) => $query->whereIn('status', ['pending', 'leased'])->orWhere('updated_at', '>', now()->subDay()))
                    ->orderByRaw('CASE WHEN last_probed_at IS NULL THEN 0 ELSE 1 END')
                    ->orderBy('last_probed_at')
                    ->limit(min(50, $capacity))
                    ->get()
                    ->each(fn (Website $site) => $queue->enqueue($site, false));
            }
        }
        TrafficMetric::where('window_end', '<', now()->subDays(config('monitor.metrics_days')))->delete();
        // Keep inbox IDs longer than the accepted replay horizon, preventing old
        // retries from creating a second copy after metric retention.
        Batch::whereNotNull('processed_at')->where('window_end', '<', now()->subDays(16))->delete();
        Alert::where('status', 'resolved')->where('last_seen_at', '<', now()->subDays(config('monitor.alerts_days')))->delete();
        $root = storage_path('app/private/screenshots');
        foreach (glob($root.'/*.png') ?: [] as $f) {
            if (filemtime($f) < time() - 86400 && ! Website::where('screenshot_path', 'screenshots/'.basename($f))->exists()) {
                unlink($f);
            }
        }

        return self::SUCCESS;
    }
}
