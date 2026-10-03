<?php

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
        DB::table('monitor_events')->select(['id', 'status'])->orderBy('id')->chunkById(100, function ($events) {
            $alerts = DB::table('alerts')->whereIn('event_id', $events->pluck('id'))
                ->select(['event_id', 'kind', 'title', 'severity', 'assessment_category', 'status'])->orderBy('id')->get()->groupBy('event_id');
            foreach ($events as $event) {
                $candidates = $alerts->get($event->id, collect());
                if (in_array($event->status, ['open', 'acknowledged'], true)) {
                    $candidates = $candidates->whereIn('status', ['open', 'acknowledged']);
                }
                $primary = $candidates->sortByDesc(fn ($row) => EventPriority::rank($row->severity, $row->assessment_category, $row->kind))->first();
                if ($primary) {
                    DB::table('monitor_events')->where('id', $event->id)->update(['title' => $primary->title]);
                }
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Display titles are derived from retained alerts; there is no schema change to reverse.
    }
};
