<?php

use App\Http\Controllers\ExportController;
use App\Models\Website;
use App\Models\Alert;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => redirect('/admin'));
Route::middleware('auth')->group(function () {
    Route::get('/alerts/{alert}/evidence', function (Alert $alert) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer'], true), 403);

        return response()->view('monitor.alert-evidence', ['alert' => $alert->load(['node', 'ipAsset'])])
            ->header('Cache-Control', 'private, no-store');
    })->name('alerts.evidence');
    Route::get('/screenshots/{website}', function (Website $website) {
        abort_unless(in_array(auth()->user()->role, ['admin', 'viewer']), 403);
        abort_unless($website->screenshot_path && preg_match('#^screenshots/[a-f0-9]{64}\.png$#', $website->screenshot_path), 404);
        $path = storage_path('app/private/'.$website->screenshot_path);
        abort_unless(is_file($path), 404);

        return response()->file($path, ['Cache-Control' => 'private, no-store', 'X-Content-Type-Options' => 'nosniff']);
    })->name('screenshots.show');
    Route::get('/exports/{type}', ExportController::class)->name('exports');
});
