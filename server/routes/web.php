<?php

use App\Http\Controllers\ExportController;
use App\Http\Controllers\MonitorActionController;
use App\Models\Alert;
use App\Models\Node;
use App\Models\ProtocolObservation;
use App\Models\Website;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => redirect('/admin'));
Route::middleware('auth')->group(function () {
    Route::get('/nodes/{node}/evidence', function (Node $node) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer'], true), 403);

        return response()->json(['name' => $node->name, 'data' => $node->toArray()])
            ->header('Cache-Control', 'private, no-store');
    })->name('nodes.evidence');
    Route::post('/alerts/bulk-handle', [MonitorActionController::class, 'bulkAlerts'])->name('alerts.bulk');
    Route::get('/alerts/{alert}/evidence', function (Alert $alert) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer'], true), 403);

        return response()->view('monitor.alert-evidence', ['alert' => $alert->load(['node', 'ipAsset'])])
            ->header('Cache-Control', 'private, no-store');
    })->name('alerts.evidence');
    Route::get('/protocol-observations/{observation}/evidence.json', function (ProtocolObservation $observation) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer'], true), 403);
        $observation->load(['node:id,name', 'ipAsset:id,ip']);

        return response()->json([
            'observation_id' => $observation->id,
            'node' => $observation->node?->name,
            'vm_ip' => $observation->ipAsset?->ip,
            'window_start' => $observation->window_start?->toIso8601String(),
            'window_end' => $observation->window_end?->toIso8601String(),
            'evidence' => $observation->evidence,
            'interpretation' => in_array($observation->protocol, ['wireguard', 'openvpn', 'ikev2'], true)
                ? '双向握手报文结构匹配；不证明认证成功、隧道建立或用途违规。'
                : '多对端双向连接与多目标出站 TCP 连接相关的疑似样态；不能确认具体代理协议或用途。',
        ], 200, [
            'Cache-Control' => 'private, no-store',
            'Content-Disposition' => 'attachment; filename="protocol-observation-'.$observation->id.'.json"',
        ]);
    })->name('protocol-observations.evidence');
    Route::get('/screenshots/{website}', function (Website $website) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer']), 403);
        abort_unless($website->screenshot_path && preg_match('#^screenshots/[a-f0-9]{64}\.png$#', $website->screenshot_path), 404);
        $path = storage_path('app/private/'.$website->screenshot_path);
        abort_unless(is_file($path), 404);

        return response()->file($path, ['Cache-Control' => 'private, no-store', 'X-Content-Type-Options' => 'nosniff']);
    })->name('screenshots.show');
    Route::get('/websites/{website}/details', function (Website $website) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer'], true), 403);

        return response()->view('monitor.website-details', ['website' => $website->load(['ipAsset', 'task'])])
            ->header('Cache-Control', 'private, no-store');
    })->name('websites.details');
    Route::post('/websites/manual', [MonitorActionController::class, 'manualWebsite'])->name('websites.manual');
    Route::post('/websites/{website}/probe', [MonitorActionController::class, 'probeWebsite'])->name('websites.probe');
    Route::post('/websites/{website}/category', [MonitorActionController::class, 'categoryWebsite'])->name('websites.category');
    Route::get('/exports/{type}', ExportController::class)->name('exports');
});
