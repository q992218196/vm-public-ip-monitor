<?php

use App\Services\AlertNotificationPolicy;
use App\Services\EventPriority;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        DB::table('rules')->whereIn('kind', AlertNotificationPolicy::RETIRED_UDP_RULES)->delete();
        DB::table('alerts')->whereIn('kind', AlertNotificationPolicy::RETIRED_UDP_RULES)->update(['assessment_category' => 'behavior_notice']);
        DB::table('alerts')->where('evidence->connection_analysis->category', 'behavior_notice')->update(['assessment_category' => 'behavior_notice']);
        DB::table('alerts')->whereIn('kind', ['single_target_attempts', 'tcp_connection_burst', 'egress_mbps'])->orderBy('id')
            ->select(['id', 'kind', 'evidence'])->chunkById(200, function ($alerts) {
                $noticeIds = [];
                foreach ($alerts as $alert) {
                    $evidence = json_decode($alert->evidence, true) ?: [];
                    if (! AlertNotificationPolicy::allows($alert->kind, $evidence)) {
                        $noticeIds[] = $alert->id;
                    }
                }
                if ($noticeIds) {
                    DB::table('alerts')->whereIn('id', $noticeIds)->update(['assessment_category' => 'behavior_notice']);
                }
            });
        DB::table('monitor_events')->select(['id', 'status'])->orderBy('id')->chunkById(200, function ($events) {
            $alerts = DB::table('alerts')->whereIn('event_id', $events->pluck('id'))
                ->where('assessment_category', '!=', 'behavior_notice')->whereNotIn('kind', AlertNotificationPolicy::RETIRED_UDP_RULES)
                ->select(['event_id', 'kind', 'title', 'severity', 'assessment_category', 'status'])->orderBy('id')->get()->groupBy('event_id');
            foreach ($events as $event) {
                $candidates = $alerts->get($event->id, collect());
                if (in_array($event->status, ['open', 'acknowledged'], true)) {
                    $candidates = $candidates->whereIn('status', ['open', 'acknowledged']);
                }
                $primary = $candidates->sortByDesc(fn ($row) => EventPriority::rank($row->severity, $row->assessment_category, $row->kind))->first();
                $data = $primary ? ['title' => $primary->title, 'severity' => $primary->severity, 'assessment_category' => $primary->assessment_category]
                    : ['assessment_category' => 'behavior_notice', 'active_key' => null];
                DB::table('monitor_events')->where('id', $event->id)->update($data);
            }
        });
        if (DB::getDriverName() === 'pgsql') {
            DB::statement("CREATE INDEX IF NOT EXISTS events_anomaly_page ON monitor_events (status,last_seen_at DESC,id DESC) WHERE COALESCE(assessment_category,'needs_review') <> 'behavior_notice'");
            DB::statement("CREATE INDEX IF NOT EXISTS alerts_anomaly_page ON alerts (status,last_seen_at DESC,id DESC) WHERE COALESCE(assessment_category,'needs_review') <> 'behavior_notice' AND kind NOT IN ('udp_flow_burst','udp_packet_rate')");
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            DB::statement('DROP INDEX IF EXISTS events_anomaly_page');
            DB::statement('DROP INDEX IF EXISTS alerts_anomaly_page');
        }
    }
};
