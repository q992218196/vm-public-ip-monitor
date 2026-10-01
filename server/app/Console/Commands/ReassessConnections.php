<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\MonitorEvent;
use App\Models\Rule;
use App\Models\TrafficMetric;
use App\Services\ConnectionAssessment;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

#[Signature('monitor:reassess-connections')]
#[Description('重新分级未处理连接规则与事件，保留人工审核结果和原始证据')]
class ReassessConnections extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(ConnectionAssessment $assessment): int
    {
        $rules = Rule::all()->keyBy('id');
        $count = 0;
        Alert::whereIn('kind', ConnectionAssessment::KINDS)->where('status', 'open')->chunkById(100, function ($alerts) use ($assessment, $rules, &$count) {
            foreach ($alerts as $alert) {
                DB::transaction(function () use ($alert, $assessment, $rules, &$count) {
                    $current = Alert::whereKey($alert->id)->where('status', 'open')->lockForUpdate()->first();
                    if (! $current) {
                        return;
                    }
                    $evidence = $current->evidence ?? [];
                    $rule = $rules[$evidence['rule_id'] ?? 0] ?? null;
                    $windows = TrafficMetric::where('node_id', $current->node_id)->where('ip_asset_id', $current->ip_asset_id)
                        ->where('window_end', '<=', $current->last_seen_at)->where('window_end', '>', $current->last_seen_at->copy()->subSeconds($rule?->window_seconds ?? 60))
                        ->latest('window_end')->limit(120)->pluck('evidence')->all();
                    $result = $assessment->assess($current->kind, $evidence['sample'] ?? [], $rule?->threshold ?? (int) ($evidence['threshold'] ?? 0), $rule?->severity ?? 'high', $windows);
                    $current->update(['severity' => $result['severity'], 'title' => $result['title'], 'assessment_category' => $result['connection_analysis']['category'], 'evidence' => array_replace($evidence, array_diff_key($result, array_flip(['severity', 'title'])))]);
                    $count++;
                });
            }
        });
        MonitorEvent::where('status', 'open')->chunkById(100, function ($events) {
            foreach ($events as $event) {
                $top = Alert::where('event_id', $event->id)->whereIn('status', ['open', 'acknowledged'])->get(['severity', 'title', 'assessment_category'])
                    ->sortByDesc(fn ($a) => 10 * (['low' => 1, 'medium' => 2, 'high' => 3][$a->severity] ?? 0) + (['behavior_notice' => 1, 'needs_review' => 2, 'strong_anomaly' => 3][$a->assessment_category] ?? 2))->first();
                if ($top) {
                    MonitorEvent::whereKey($event->id)->where('status', 'open')->update(['severity' => $top->severity, 'title' => $top->title, 'assessment_category' => $top->assessment_category]);
                }
            }
        });
        $this->info("已重新评估 $count 条未处理连接告警；缺少新证据的记录不自动标为高风险，已审核记录保持原样。");

        return self::SUCCESS;
    }
}
