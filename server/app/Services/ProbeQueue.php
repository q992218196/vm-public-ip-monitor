<?php

namespace App\Services;

use App\Models\ProbeTask;
use App\Models\Website;
use Illuminate\Support\Facades\DB;

class ProbeQueue
{
    public function enqueue(Website $site, bool $force = true): ?ProbeTask
    {
        return DB::transaction(function () use ($site, $force) {
            $site = Website::whereKey($site->id)->lockForUpdate()->firstOrFail();
            if (! $force && $site->discovery_kind !== 'web_candidate') {
                return null;
            }
            $task = ProbeTask::firstOrCreate(['website_id' => $site->id], ['status' => 'pending', 'available_at' => now(), 'request_source' => $force ? 'manual' : 'auto']);
            if (in_array($task->status, ['pending', 'leased'])) {
                if ($force && $task->status === 'pending') {
                    $task->update(['request_source' => 'manual']);
                }

                return $task;
            }
            if (! $force && $task->status !== 'skipped' && $task->updated_at->gt(now()->subDay())) {
                return $task;
            }
            $task->update(['mode' => 'normal', 'status' => 'pending', 'request_source' => $force ? 'manual' : 'auto', 'attempts' => 0, 'available_at' => now(), 'lease_token' => null, 'leased_until' => null]);

            return $task;
        });
    }
}
