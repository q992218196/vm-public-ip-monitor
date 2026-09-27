<?php

namespace App\Jobs;

use App\Models\Batch;
use App\Models\Node;
use App\Services\Analyzer;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;

class ProcessBatch implements ShouldQueue
{
    use Queueable;

    public int $tries = 5;

    public int $timeout = 120;

    public function __construct(public int $id) {}

    public function backoff(): array
    {
        return [10, 30, 60, 120];
    }

    public function handle(Analyzer $analyzer): void
    {
        DB::transaction(function () use ($analyzer) {
            $b = Batch::whereKey($this->id)->lockForUpdate()->first();
            if (! $b || $b->processed_at) {
                return;
            }
            Node::whereKey($b->node_id)->lockForUpdate()->firstOrFail();
            $analyzer->process($b);
            $b->update(['processed_at' => now(), 'payload' => null, 'payload_bytes' => 0]);
        }, 5);
    }
}
