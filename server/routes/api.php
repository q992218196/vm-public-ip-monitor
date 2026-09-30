<?php

use App\Http\Controllers\IngestController;
use App\Http\Controllers\AgentUpdateController;
use App\Http\Controllers\ProbeController;
use App\Http\Middleware\AgentAuth;
use App\Http\Middleware\WorkerAuth;
use Illuminate\Support\Facades\Route;

Route::post('/v1/agent/batches', IngestController::class)->middleware([AgentAuth::class, 'throttle:agent']);
Route::get('/v1/agent/update', AgentUpdateController::class)->middleware([AgentAuth::class, 'throttle:agent']);
Route::middleware([WorkerAuth::class, 'throttle:worker'])->prefix('/v1/worker')->group(function () {
    Route::post('/claim', [ProbeController::class, 'claim']);
    Route::post('/tasks/{task}/complete', [ProbeController::class, 'complete']);
});
