<?php

namespace App\Http\Middleware;

use App\Models\Node;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AgentAuth
{
    public function handle(Request $request, Closure $next)
    {
        abort_if((int) $request->header('Content-Length', 0) > 8 * 1024 * 1024, 413);
        abort_unless(Str::isUuid($request->header('X-Node-ID', '')), 401);
        $node = Node::find($request->header('X-Node-ID'));
        abort_unless($node && $node->enabled && $node->token_hash && $request->bearerToken() && hash_equals($node->token_hash, hash('sha256', $request->bearerToken())), 401);
        $request->attributes->set('node', $node);

        return $next($request);
    }
}
