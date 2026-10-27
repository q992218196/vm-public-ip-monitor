<?php

namespace App\Console\Commands;

use App\Models\TrafficMetric;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

#[Signature('monitor:prune-traffic {--hours= : Retention in hours, from 1 to 168}')]
#[Description('Prune expired traffic windows in bounded, independently committed chunks')]
class PruneTraffic extends Command
{
    public function handle(): int
    {
        $hours = filter_var($this->option('hours') ?? config('monitor.metrics_hours'), FILTER_VALIDATE_INT);
        if ($hours === false || $hours < 1 || $hours > 168) {
            $this->error('流量窗口保留期必须为 1–168 小时');

            return self::FAILURE;
        }
        $lock = Cache::lock('traffic-retention', 120);
        if (! $lock->get()) {
            $this->warn('已有流量清理正在运行，本次跳过');

            return self::SUCCESS;
        }
        $deleted = 0;
        $cutoff = now()->subHours($hours)->format('Y-m-d H:i:s.u');
        $deadline = microtime(true) + max(1, min(45, (int) config('monitor.metrics_prune_seconds')));
        $maxBatches = max(1, min(1000, (int) config('monitor.metrics_prune_batches')));
        $lastCount = 0;
        try {
            for ($chunk = 0; $chunk < $maxBatches; $chunk++) {
                $lastCount = DB::transaction(function () use ($cutoff): int {
                    if (DB::getDriverName() === 'pgsql') {
                        DB::statement("SET LOCAL lock_timeout = '2s'");
                        DB::statement("SET LOCAL statement_timeout = '8s'");
                    }
                    $ids = TrafficMetric::where('window_start', '<', $cutoff)->where('window_end', '<', $cutoff)
                        ->orderBy('window_start')->limit(5000)->pluck('id');

                    return $ids->isEmpty() ? 0 : TrafficMetric::whereIn('id', $ids)->where('window_end', '<', $cutoff)->delete();
                });
                $deleted += $lastCount;
                if ($lastCount < 5000 || microtime(true) >= $deadline) {
                    break;
                }
                usleep(20000);
            }
            if ($lastCount === 5000) {
                Log::warning('Traffic retention reached its round budget; check for expired-window backlog', ['deleted' => $deleted, 'cutoff' => $cutoff]);
            }
            $this->info('流量窗口保留 '.$hours.' 小时；本轮删除 '.$deleted.' 条');

            return self::SUCCESS;
        } catch (QueryException $exception) {
            Log::warning('Traffic retention stopped; committed chunks are retained and remaining rows will retry', ['deleted' => $deleted, 'sqlstate' => $exception->getCode()]);
            $this->error('本轮清理中止；已完成批次保留，下轮重试。请查看主控日志。');

            return self::FAILURE;
        } finally {
            $lock->release();
        }
    }
}
