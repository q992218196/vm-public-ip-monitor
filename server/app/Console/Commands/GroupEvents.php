<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\MonitorEvent;
use App\Services\EventCorrelation;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

#[Signature('monitor:group-events')]
#[Description('Attach historical rule alerts to continuous IP events, without capture or AI calls')]
class GroupEvents extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        config(['monitor.auto_capture' => false]);
        Alert::whereNull('event_id')->where('kind', '<>', 'new_website')->orderBy('id')->chunkById(200, function ($alerts) {
            foreach ($alerts as $alert) {
                DB::transaction(function () use ($alert) {
                    $event = app(EventCorrelation::class)->correlate($alert->node, $alert->ipAsset, $alert->kind, $alert->severity, $alert->title, $alert->first_seen_at);
                    $event->update(['last_seen_at' => max($event->last_seen_at, $alert->last_seen_at), 'occurrences' => $event->occurrences + max(0, $alert->occurrences - 1)]);
                    $alert->update(['event_id' => $event->id]);
                });
            }
        });
        MonitorEvent::where('status', 'open')->whereIn('id', Alert::whereNotNull('event_id')->select('event_id')->groupBy('event_id')->havingRaw("SUM(CASE WHEN status IN ('open', 'acknowledged') THEN 1 ELSE 0 END) = 0"))->update(['status' => 'resolved']);
        $this->info('Historical alerts grouped; no AI requests were made.');

        return self::SUCCESS;
    }
}
