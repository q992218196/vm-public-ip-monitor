<?php

// Integration checks run only against the disposable CI database and local HTTP server.
if (getenv('MONITOR_DB_DATABASE') !== 'monitor_test' || ! getenv('TEST_ADMIN_TOKEN') || ! getenv('TEST_VIEWER_TOKEN')) {
    throw new RuntimeException('Isolated CI credentials required');
}
$db = new PDO('pgsql:host=127.0.0.1;dbname=monitor_test', getenv('MONITOR_DB_USERNAME'), getenv('MONITOR_DB_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec(<<<'SQL'
ALTER TABLE alerts ADD COLUMN event_id bigint, ADD COLUMN evidence jsonb, ADD COLUMN first_seen_at timestamp;
CREATE TABLE monitor_events (id bigserial primary key,node_id uuid,ip_asset_id bigint,active_key text,title text,severity text,status text default 'open',kinds jsonb,quality jsonb,occurrences bigint default 1,review_notes text,first_seen_at timestamp,last_seen_at timestamp,created_at timestamp,updated_at timestamp);
CREATE TABLE packet_captures (id uuid primary key,event_id bigint,node_id uuid,ip text,status text default 'pending',source text default 'manual',lease_token text,lease_until timestamp,duration_seconds integer default 60,max_bytes integer default 33554432,snaplen integer default 2048,path text,sha256 text,bytes bigint default 0,metadata jsonb,summary jsonb,last_error text,created_at timestamp,updated_at timestamp);
CREATE TABLE ai_settings (id integer primary key,endpoint text,model text,enabled boolean default false,api_key_cipher text,created_at timestamp,updated_at timestamp);
CREATE TABLE ai_analyses (id bigserial primary key,event_id bigint,capture_id uuid,requested_by bigint,status text default 'pending',config_snapshot jsonb,evidence jsonb,report text,usage jsonb,last_error text,dispatched_at timestamp,started_at timestamp,finished_at timestamp,created_at timestamp,updated_at timestamp);
INSERT INTO monitor_events (id,node_id,ip_asset_id,title,severity,kinds,quality,first_seen_at,last_seen_at,created_at,updated_at) VALUES (100,'00000000-0000-4000-8000-000000000001',1,'Test scan','medium','["horizontal_scan","tcp_connection_burst"]','{}',now(),now(),now(),now());
UPDATE alerts SET event_id=100,first_seen_at=now(),evidence='{"note":"test evidence"}' WHERE id=1;
UPDATE nodes SET health='{"version":"0.6.0"}',cidrs='["203.0.113.0/24"]',enabled=true WHERE id='00000000-0000-4000-8000-000000000001';
SQL);
$request = function (string $action, array $data = [], bool $post = false, bool $viewer = false): array {
    $context = stream_context_create(['http' => ['method' => $post ? 'POST' : 'GET', 'ignore_errors' => true, 'timeout' => 20,
        'header' => ['Content-Type: application/json', 'server: true', 'batoken: '.getenv($viewer ? 'TEST_VIEWER_TOKEN' : 'TEST_ADMIN_TOKEN')], 'content' => $post ? json_encode($data) : '']]);
    $url = 'http://127.0.0.1:8099/admin/EventEvidence/'.$action.($post ? '' : '?'.http_build_query($data));

    return json_decode(file_get_contents($url, false, $context), true, 512, JSON_THROW_ON_ERROR);
};
$ok = function (array $result): array {
    if (($result['code'] ?? null) !== 1) {
        throw new RuntimeException(json_encode($result));
    }

    return $result['data'];
};
$rows = $ok($request('index', ['limit' => 500]));
if (count($rows['list']) !== 1 || isset($rows['list'][0]['evidence']) || strlen(json_encode($rows)) > 4096) {
    throw new RuntimeException('Event list contains heavy evidence');
}
if ($ok($request('count'))['total'] !== 1) {
    throw new RuntimeException('Event total incorrect');
}
$detail = $ok($request('detail', ['id' => 100]));
if (isset($ok($request('progress', ['id' => 100]))['alerts'])) {
    throw new RuntimeException('Progress reloads rule evidence');
}
if (count($detail['alerts']) !== 1 || $detail['alerts'][0]['evidence']['note'] !== 'test evidence') {
    throw new RuntimeException('Evidence detail incorrect');
}
$settings = ['endpoint' => 'https://api.deepseek.com/chat/completions', 'model' => 'deepseek-flash', 'enabled' => false, 'api_key' => 'test-only-api-key-for-ci-123456'];
$ok($request('saveSettings', $settings, true));
$saved = $ok($request('settings'));
if (! $saved['key_configured'] || isset($saved['api_key_cipher']) || str_contains(json_encode($saved), $settings['api_key'])) {
    throw new RuntimeException('Credential leaked');
}
$encrypted = $db->query('SELECT api_key_cipher FROM ai_settings WHERE id=1')->fetchColumn();
$packed = base64_decode($encrypted);
$plain = openssl_decrypt(substr($packed, 28), 'aes-256-gcm', hash('sha256', getenv('MONITOR_SECRET_KEY'), true), OPENSSL_RAW_DATA, substr($packed, 0, 12), substr($packed, 12, 16), 'vm-monitor-ai-v1');
if ($plain !== $settings['api_key']) {
    throw new RuntimeException('Shared credential encryption incompatible');
}
$task = $ok($request('capture', ['id' => 100, 'snaplen' => 65535], true))['id'];
if (($request('requestAi', ['capture_id' => $task], true)['code'] ?? null) === 1) {
    throw new RuntimeException('AI requested before capture');
}
$settings['enabled'] = true;
$settings['api_key'] = '';
$ok($request('saveSettings', $settings, true));
$db->prepare('UPDATE packet_captures SET status=?,sha256=?,metadata=?,summary=? WHERE id=?')->execute(['uploaded', str_repeat('a', 64), '{}', '{"matched_packets":3}', $task]);
$id = $ok($request('requestAi', ['capture_id' => $task], true))['id'];
if (($request('requestAi', ['capture_id' => $task], true)['code'] ?? null) === 1 || $db->query('SELECT count(*) FROM ai_analyses')->fetchColumn() != 1) {
    throw new RuntimeException('Duplicate manual AI request');
}
$analysis = $ok($request('analysis', ['id' => $id]))['record'];
if ($analysis['status'] !== 'pending' || isset($analysis['config_snapshot'])) {
    throw new RuntimeException('AI credentials exposed or automatically executed');
}
if ($ok($request('captureSummary', ['id' => $task]))['record']['summary']['matched_packets'] !== 3) {
    throw new RuntimeException('Local summary missing');
}
foreach (['capture', 'review', 'whitelist', 'requestAi', 'saveSettings'] as $action) {
    if (($request($action, ['id' => 100, 'ids' => [100], 'capture_id' => $task], true, true)['code'] ?? null) !== 403) {
        throw new RuntimeException('Viewer can mutate evidence: '.$action);
    }
}
foreach (['settings', 'download'] as $action) {
    if (($request($action, ['id' => $task], false, true)['code'] ?? null) !== 403) {
        throw new RuntimeException('Viewer can read secrets or PCAP');
    }
}
if ($ok($request('count', [], false, true))['total'] !== 1) {
    throw new RuntimeException('Viewer cannot read events');
}
$ok($request('review', ['ids' => [100], 'status' => 'normal', 'notes' => 'Authorized business'], true));
$ok($request('whitelist', ['id' => 100], true));
$event = $db->query('SELECT status FROM monitor_events WHERE id=100')->fetchColumn();
if ($event !== 'normal') {
    throw new RuntimeException('Whitelist review incorrect');
}
echo "Event list/count/detail, local PCAP summary, manual AI, encrypted secrets, duplicate prevention and read-only permissions passed.\n";
