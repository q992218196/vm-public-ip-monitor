<?php

namespace app\api\controller;

use app\common\controller\Api;
use think\facade\Db;

class AgentBootstrap extends Api
{
    protected bool $useSystemSettings = false;

    public function config()
    {
        $ticket = (string)$this->request->get('ticket', '');
        if (!preg_match('/^[a-f0-9]{64}$/', $ticket)) return json(['error' => '配置链接无效'], 404);

        $payload = Db::transaction(function () use ($ticket) {
            $hash = hash('sha256', $ticket);
            $prefix = (string)config('database.connections.mysql.prefix', 'ba_');
            if (!preg_match('/^[a-zA-Z0-9_]*$/', $prefix)) throw new \RuntimeException('数据库前缀无效');
            $rows = Db::query('SELECT payload, expires_at FROM `' . $prefix . 'agent_enrollments` WHERE ticket_hash = ? FOR UPDATE', [$hash]);
            $row = $rows[0] ?? null;
            if (!$row || $row['expires_at'] < gmdate('Y-m-d H:i:s')) return null;
            Db::name('agent_enrollments')->where('ticket_hash', $hash)->delete();
            return $row['payload'];
        });
        if (!$payload) return json(['error' => '配置链接已失效或已使用'], 404);

        $bytes = base64_decode($payload, true);
        if ($bytes === false || strlen($bytes) < 29) return json(['error' => '配置不可用'], 500);
        $key = hash('sha256', (string)getenv('BUILDADMIN_TOKEN_KEY'), true);
        $plain = openssl_decrypt(substr($bytes, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($bytes, 0, 12), substr($bytes, 12, 16));
        if ($plain === false) return json(['error' => '配置不可用'], 500);

        return json(json_decode($plain, true), 200)->header(['Cache-Control' => 'no-store', 'Pragma' => 'no-cache', 'X-Content-Type-Options' => 'nosniff']);
    }
}
