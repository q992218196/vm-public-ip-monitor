<?php

namespace App\Console\Commands;

use App\Jobs\AnalyzeEvidence;
use App\Jobs\SummarizeCapture;
use App\Models\AiAnalysis;
use App\Models\PacketCapture;
use App\Services\PcapSummary;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

#[Signature('monitor:evidence')]
#[Description('Dispatch manually requested AI jobs and expire bounded packet evidence')]
class MaintainEvidence extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        PacketCapture::whereIn('status', ['pending', 'leased'])->where('created_at', '<', now()->subMinutes(15))->update(['status' => 'failed', 'last_error' => '采集任务过期；请检查 Agent 版本和节点连接']);
        foreach (AiAnalysis::where('status', 'running')->where('started_at', '<', now()->subMinutes(5))->limit(100)->get() as $stale) {
            $stale->update(['status' => 'failed', 'last_error' => '分析任务中断；不会自动重试', 'finished_at' => now(), 'config_snapshot' => array_intersect_key($stale->config_snapshot, array_flip(['endpoint', 'model']))]);
        }
        foreach (AiAnalysis::where('status', 'pending')->where(fn ($q) => $q->whereNull('dispatched_at')->orWhere('dispatched_at', '<', now()->subMinutes(5)))->limit(10)->get() as $analysis) {
            DB::transaction(function () use ($analysis) {
                $row = AiAnalysis::whereKey($analysis->id)->lockForUpdate()->first();
                if ($row->status === 'pending' && (! $row->dispatched_at || $row->dispatched_at < now()->subMinutes(5))) {
                    $row->update(['dispatched_at' => now()]);
                    AnalyzeEvidence::dispatch($row->id)->afterCommit();
                }
            });
        }
        $disk = Storage::disk('local');
        foreach (PacketCapture::where('status', 'uploaded')->where(fn ($q) => $q->whereNull('summary')->orWhereNull('summary->analysis_version')->orWhere('summary->analysis_version', '<', PcapSummary::ANALYSIS_VERSION))->whereNull('last_error')->where('updated_at', '<', now()->subMinute())->limit(10)->get() as $pendingSummary) {
            $pendingSummary->update(['updated_at' => now()]);
            SummarizeCapture::dispatch($pendingSummary->id)->afterCommit();
        }
        $root = $disk->path('packet-evidence');
        if (is_dir($root)) {
            $checked = 0;
            $knownPaths = array_fill_keys(PacketCapture::whereNotNull('path')->pluck('path')->all(), true);
            foreach (new \DirectoryIterator($root) as $file) {
                if (++$checked > 10000) {
                    break;
                }
                if ($file->isFile() && $file->getMTime() < time() - 3600 && (str_ends_with($file->getFilename(), '.part') || (str_ends_with($file->getFilename(), '.pcap') && ! isset($knownPaths['packet-evidence/'.$file->getFilename()])))) {
                    @unlink($file->getPathname());
                }
            }
        }
        foreach (PacketCapture::whereNotNull('path')->where('created_at', '<', now()->subDays(max(1, config('monitor.capture_days'))))->limit(100)->get() as $capture) {
            if (AiAnalysis::where('capture_id', $capture->id)->whereIn('status', ['pending', 'running'])->exists()) {
                continue;
            }
            if ($disk->delete($capture->path)) {
                $capture->update(['status' => 'expired', 'path' => null]);
            }
        }

        return self::SUCCESS;
    }
}
