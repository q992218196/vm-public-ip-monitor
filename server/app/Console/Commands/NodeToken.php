<?php

namespace App\Console\Commands;

use App\Models\AuditLog;
use App\Models\Node;
use Illuminate\Console\Command;

class NodeToken extends Command
{
    protected $signature = 'monitor:node-token {node : Node UUID}';

    protected $description = 'Rotate node credential; prints plaintext once';

    public function handle(): int
    {
        $node = Node::findOrFail($this->argument('node'));
        $token = bin2hex(random_bytes(32));
        $node->update(['token_hash' => hash('sha256', $token)]);
        AuditLog::record('token_rotated', $node);
        $this->line($token);

        return self::SUCCESS;
    }
}
