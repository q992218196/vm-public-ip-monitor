<?php

namespace App\Http\Controllers;

use App\Models\ProbeTask;
use App\Services\Screenshots;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProbeController extends Controller
{
    public function claim()
    {
        return DB::transaction(function () {
            $task = ProbeTask::where('attempts', '<', 3)->where('available_at', '<=', now())->where(fn ($q) => $q->where('status', 'pending')->orWhere(fn ($q) => $q->where('status', 'leased')->where('leased_until', '<', now())))->orderBy('id')->lockForUpdate()->first();
            if (! $task) {
                return response()->json(['task' => null]);
            }
            $token = bin2hex(random_bytes(32));
            $task->update(['status' => 'leased', 'attempts' => $task->attempts + 1, 'lease_token' => hash('sha256', $token), 'leased_until' => now()->addMinutes(3)]);
            $site = $task->website;

            return response()->json(['task' => ['id' => $task->id, 'lease_token' => $token, 'ip' => $site->ipAsset->ip, 'host' => $site->host, 'port' => $site->port, 'scheme' => $site->scheme]]);
        });
    }

    public function complete(Request $r, ProbeTask $task, Screenshots $screenshots)
    {
        $v = $r->validate(['lease_token' => 'required|string|size:64', 'status' => 'required|in:verified,failed',
            'title' => 'nullable|string|max:255', 'description' => 'nullable|string|max:1024', 'http_status' => 'nullable|integer|min:100|max:599', 'final_url' => 'nullable|string|max:2048',
            'category' => 'nullable|string|max:64', 'classification' => 'nullable|array', 'classification.confidence' => 'nullable|numeric|min:0|max:1',
            'classification.reasons' => 'nullable|array|max:20', 'classification.reasons.*' => 'string|max:255',
            'classification.method' => 'nullable|string|max:64', 'classification.review_required' => 'nullable|boolean', 'content_hash' => 'nullable|string|size:64',
            'screenshot' => 'nullable|string|max:2800000', 'error' => 'nullable|string|max:1000']);

        return DB::transaction(function () use ($v, $task, $screenshots) {
            $task = ProbeTask::whereKey($task->id)->lockForUpdate()->firstOrFail();
            abort_unless($task->status === 'leased' && $task->leased_until->isFuture() && hash_equals($task->lease_token, hash('sha256', $v['lease_token'])), 409, '任务租约已失效');
            $site = $task->website;
            $path = null;
            if ($v['status'] === 'verified') {
                $path = $screenshots->store($v['screenshot'] ?? null);
            }
            $data = ['status' => $v['status'], 'last_error' => $v['error'] ?? null, 'last_probed_at' => now()];
            if ($v['status'] === 'verified') {
                $data += ['title' => $v['title'] ?? null, 'description' => $v['description'] ?? null, 'http_status' => $v['http_status'] ?? null, 'final_url' => $v['final_url'] ?? null, 'category' => $v['category'] ?? 'unknown', 'classification' => $v['classification'] ?? null, 'content_hash' => $v['content_hash'] ?? null, 'screenshot_path' => $path];
            }
            $site->update($data);
            $task->update(['status' => $v['status'] === 'verified' ? 'complete' : 'failed', 'last_error' => $v['error'] ?? null, 'lease_token' => null, 'leased_until' => null]);

            return response()->json(['accepted' => true, 'screenshot_stored' => $path !== null]);
        });
    }
}
