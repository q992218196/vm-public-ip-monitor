<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AgentUpdateController extends Controller
{
    public function __invoke(Request $request)
    {
        $node = $request->attributes->get('node');
        $current = (string) $request->query('version', '');
        abort_unless(preg_match('/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/', $current), 422);

        $desired = $node->agent_desired_version;
        if (! $desired || hash_equals($desired, $current)) {
            return response()->json(['update' => false])->header('Cache-Control', 'no-store');
        }

        $sha = (string) $node->agent_desired_sha256;
        abort_unless(preg_match('/^[a-f0-9]{64}$/', $sha), 503);

        return response()->json([
            'update' => true,
            'version' => $desired,
            'sha256' => $sha,
            'path' => '/downloads/vm-agent-linux-amd64',
        ])->header('Cache-Control', 'no-store');
    }
}
