<?php

namespace App\Console\Commands;

use App\Jobs\ProcessBatch;
use App\Models\Batch;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class DispatchBatches extends Command
{
    protected $signature = 'monitor:dispatch {--sync : Process without a queue, for verification}';

    protected $description = 'Dispatch durable inbox batches; safely retries after queue outages';

    public function handle(): int
    {
        $query = Batch::whereNull('processed_at')->where(fn ($q) => $q->whereNull('dispatched_at')->orWhere('dispatched_at', '<', now()->subMinutes(5)));
        foreach ($query->orderBy('id')->limit(100)->get(['id']) as $b) {
            if ($this->option('sync')) {
                ProcessBatch::dispatchSync($b->id);
            } else {
                DB::transaction(function () use ($b) {
                    $locked = Batch::whereKey($b->id)->lockForUpdate()->first();
                    if (! $locked || $locked->processed_at || ($locked->dispatched_at && $locked->dispatched_at > now()->subMinutes(5))) {
                        return;
                    }
                    $locked->update(['dispatched_at' => now()]);
                    ProcessBatch::dispatch($locked->id);
                });
            }
        }

        return self::SUCCESS;
    }
}
