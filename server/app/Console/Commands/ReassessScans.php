<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\Rule;
use App\Services\ScanAssessment;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

#[Signature('monitor:reassess-scans')]
#[Description('按新版连接证据重新评估未处理的横向扫描告警，不改变人工处理状态')]
class ReassessScans extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(ScanAssessment $assessment): int
    {
        $count = 0;
        $severities = Rule::pluck('severity', 'id');
        Alert::where('kind', 'horizontal_scan')->where('status', 'open')->chunkById(200, function ($alerts) use ($assessment, $severities, &$count) {
            foreach ($alerts as $alert) {
                DB::transaction(function () use ($alert, $assessment, $severities, &$count) {
                    $current = Alert::whereKey($alert->id)->where('status', 'open')->lockForUpdate()->first();
                    if (! $current) {
                        return;
                    }
                    $evidence = $current->evidence;
                    $result = $assessment->assess($evidence['sample'] ?? [], $severities[$evidence['rule_id'] ?? 0] ?? $current->severity);
                    $current->update(['severity' => $result['severity'], 'title' => $result['title'], 'evidence' => array_replace($evidence, array_diff_key($result, array_flip(['severity', 'title'])))]);
                    $count++;
                });
            }
        });
        $this->info("已重新评估 $count 条未处理告警。已确认和已解决记录保持不变。");

        return self::SUCCESS;
    }
}
