<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\AuditLog;
use App\Models\IpAsset;
use App\Models\Website;
use App\Services\ProbeQueue;
use App\Support\Ip;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class MonitorActionController extends Controller
{
    public function bulkAlerts(Request $request): RedirectResponse
    {
        abort_unless($request->user()?->role === 'admin', 403);
        $data = $request->validate([
            'ids' => 'required|array|min:1|max:500',
            'ids.*' => 'required|integer|min:1|distinct',
            'status' => 'required|in:open,acknowledged,resolved',
            'resolution' => 'required|string|max:4000',
        ]);
        $ids = array_map('intval', $data['ids']);
        DB::transaction(function () use ($ids, $data, $request): void {
            $found = Alert::whereKey($ids)->lockForUpdate()->pluck('id')->all();
            abort_unless(count($found) === count($ids), 422, '有告警已不存在，请刷新列表');
            Alert::whereKey($ids)->update(['status' => $data['status'], 'resolution' => $data['resolution']]);
            AuditLog::create([
                'user_id' => $request->user()->id,
                'action' => 'alerts_bulk_handled',
                'subject' => 'Alert:batch',
                'details' => ['ids' => $ids, 'status' => $data['status'], 'resolution' => $data['resolution']],
            ]);
        });

        return back()->with('status', count($ids).' 条告警已更新');
    }

    public function manualWebsite(Request $request, ProbeQueue $queue): RedirectResponse
    {
        abort_unless($request->user()?->role === 'admin', 403);
        $data = $request->validate([
            'ip' => 'required|ip',
            'port' => 'required|integer|min:1|max:65535',
            'scheme' => 'required|in:http,https',
            'host' => ['nullable', 'string', 'max:253', 'regex:/^[a-zA-Z0-9.\-]*$/'],
        ]);
        $asset = IpAsset::where('ip', Ip::normalize($data['ip']))->firstOrFail();
        $host = strtolower(rtrim($data['host'] ?? '', '.'));
        $key = hash('sha256', implode('|', [$asset->ip, $data['port'], $data['scheme'], $host]));
        $site = Website::firstOrCreate(['fingerprint' => $key], [
            'ip_asset_id' => $asset->id,
            'host' => $host,
            'port' => $data['port'],
            'scheme' => $data['scheme'],
            'source' => 'manual',
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);
        $queue->enqueue($site);
        AuditLog::record('probe_queued', $site);

        return back()->with('status', '网站已加入验证队列');
    }

    public function probeWebsite(Request $request, Website $website, ProbeQueue $queue): RedirectResponse
    {
        abort_unless($request->user()?->role === 'admin', 403);
        $queue->enqueue($website);
        AuditLog::record('probe_queued', $website);

        return back()->with('status', '网站已加入验证队列');
    }

    public function categoryWebsite(Request $request, Website $website): RedirectResponse
    {
        abort_unless($request->user()?->role === 'admin', 403);
        $data = $request->validate(['manual_category' => 'nullable|string|max:64']);
        $website->update(['manual_category' => ($data['manual_category'] ?? null) ?: null]);

        return back()->with('status', '人工分类已保存');
    }
}
