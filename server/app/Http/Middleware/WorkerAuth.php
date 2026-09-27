<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class WorkerAuth
{
    public function handle(Request $request, Closure $next)
    {
        $token = (string) config('monitor.worker_token');
        abort_unless(strlen($token) >= 32 && $request->bearerToken() && hash_equals($token, $request->bearerToken()), 401);

        return $next($request);
    }
}
