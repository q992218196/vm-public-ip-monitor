<?php

namespace App\Services;

use App\Models\ProbeTask;
use App\Models\Website;
use Illuminate\Support\Facades\DB;

class ProbeQueue
{
    public function enqueue(Website $site, bool $force = true): ProbeTask
    {
        return DB::transaction(function () use ($site, $force) {
            Website::whereKey($site->id)->lockForUpdate()->firstOrFail();
            $task = ProbeTask::firstOrCreate(['website_id' => $site->id], ['status' => 'pending', 'available_at' => now()]);
            if (in_array($task->status, ['pending', 'leased'])) {
                return $task;
            }
            if (! $force && $task->updated_at->gt(now()->subDay())) {
                return $task;
            }
            $task->update(['status' => 'pending', 'attempts' => 0, 'available_at' => now(), 'lease_token' => null, 'leased_until' => null]);

            return $task;
        });
    }
}
