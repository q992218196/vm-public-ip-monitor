<?php

// Integration checks run only against the disposable CI database and local HTTP server.
if (getenv('MONITOR_DB_DATABASE') !== 'monitor_test' || ! getenv('TEST_ADMIN_TOKEN') || ! getenv('TEST_VIEWER_TOKEN')) {
    throw new RuntimeException('Isolated CI credentials required');
}
$db = new PDO('pgsql:host=127.0.0.1;dbname=monitor_test', getenv('MONITOR_DB_USERNAME'), getenv('MONITOR_DB_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec(<<<'SQL'
ALTER TABLE alerts ADD COLUMN event_id bigint, ADD COLUMN first_seen_at timestamp;
CREATE TABLE monitor_events (id bigserial primary key,node_id uuid,ip_asset_id bigint,active_key text,title text,severity text,status text default 'open',kinds jsonb,quality jsonb,occurrences bigint default 1,review_notes text,first_seen_at timestamp,last_seen_at timestamp,created_at timestamp,updated_at timestamp);
ALTER TABLE monitor_events ADD COLUMN behavior jsonb, ADD COLUMN review_context jsonb, ADD COLUMN reopen_reason text, ADD COLUMN assessment_category text default 'needs_review';
ALTER TABLE alerts ADD COLUMN assessment_category text default 'needs_review';
CREATE TABLE traffic_metrics (id bigserial primary key,node_id uuid,ip_asset_id bigint,window_start timestamp,window_end timestamp,tcp_attempts bigint,bytes_in bigint,bytes_out bigint,evidence jsonb);
CREATE TABLE packet_captures (id uuid primary key,event_id bigint,node_id uuid,ip text,status text default 'pending',source text default 'manual',lease_token text,lease_until timestamp,duration_seconds integer default 60,max_bytes integer default 33554432,snaplen integer default 2048,path text,sha256 text,bytes bigint default 0,metadata jsonb,summary jsonb,last_error text,created_at timestamp,updated_at timestamp);
CREATE TABLE ai_settings (id integer primary key,endpoint text,model text,enabled boolean default false,api_key_cipher text,created_at timestamp,updated_at timestamp);
CREATE TABLE ai_analyses (id bigserial primary key,event_id bigint,capture_id uuid,requested_by bigint,status text default 'pending',config_snapshot jsonb,evidence jsonb,report text,usage jsonb,last_error text,dispatched_at timestamp,started_at timestamp,finished_at timestamp,created_at timestamp,updated_at timestamp);
INSERT INTO monitor_events (id,node_id,ip_asset_id,title,severity,kinds,quality,first_seen_at,last_seen_at,created_at,updated_at) VALUES (100,'00000000-0000-4000-8000-000000000001',1,'Test scan','medium','["horizontal_scan","tcp_connection_burst"]','{}',now(),now(),now(),now());
UPDATE alerts SET event_id=100,first_seen_at=now(),evidence='{"note":"test evidence"}' WHERE id=1;
UPDATE nodes SET health='{"version":"0.6.0"}',cidrs='["203.0.113.0/24"]',enabled=true WHERE id='00000000-0000-4000-8000-000000000001';
SQL);
$request = function (string $action, array $data = [], bool $post = false, bool $viewer = false, string $controller = 'EventEvidence'): array {
    $context = stream_context_create(['http' => ['method' => $post ? 'POST' : 'GET', 'ignore_errors' => true, 'timeout' => 20,
        'header' => ['Content-Type: application/json', 'server: true', 'batoken: '.getenv($viewer ? 'TEST_VIEWER_TOKEN' : 'TEST_ADMIN_TOKEN')], 'content' => $post ? json_encode($data) : '']]);
    $url = 'http://127.0.0.1:8099/admin/'.$controller.'/'.$action.($post ? '' : '?'.http_build_query($data));

    $body = file_get_contents($url, false, $context);
    $result = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    if (! is_array($result)) {
        throw new RuntimeException('Invalid response for '.$action.': '.substr($body, 0, 1000));
    }

    return $result;
};
$ok = function (array $result): array {
    if (($result['code'] ?? null) !== 1) {
        throw new RuntimeException(json_encode($result));
    }

    return $result['data'] ?? [];
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
$db->prepare('INSERT INTO traffic_metrics(node_id,ip_asset_id,window_start,window_end,tcp_attempts,bytes_in,bytes_out,evidence) VALUES(?,?,now()-INTERVAL \'30 second\',now(),10,1000,500,?)')->execute(['00000000-0000-4000-8000-000000000001', 1, json_encode(['tcp_attempts' => 10, 'connection_stats_version' => 1, 'completed_handshakes' => 8, 'rst_replies' => 1, 'outbound_endpoints' => [['peer_ip' => '192.0.2.2', 'peer_port' => 443, 'attempts' => 10, 'synack_replies' => 8, 'completed_handshakes' => 8, 'rst_replies' => 1, 'payload_out' => 100, 'payload_in' => 200, 'max_observed_span_ms' => 6000]], 'port_scan_targets' => [['peer_ip' => '192.0.2.2', 'port_count' => 1, 'ports' => [443], 'truncated' => false]]])]);
$db->exec('UPDATE monitor_events SET first_seen_at=now()-INTERVAL \'60 second\',last_seen_at=now() WHERE id=100');
$reviewReport = $ok($request('reviewReport', ['id' => 100]))['report'];
if ($reviewReport['totals']['completed'] !== 8 || count($reviewReport['timeline']) !== 1 || $reviewReport['targets'][0]['peer_ip'] !== '192.0.2.2' || strlen(json_encode($reviewReport)) > 16384) {
    throw new RuntimeException('Review report scope or bounds incorrect');
}
if ($ok($request('reviewReport', ['id' => 100], false, true))['report']['totals']['attempts'] !== 10) {
    throw new RuntimeException('Viewer cannot read local review report');
}
if (($request('review', ['ids' => [100], 'status' => 'normal', 'notes' => ''], true)['code'] ?? null) === 1) {
    throw new RuntimeException('Normal review has no justification');
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
if (($request('requestAi', ['capture_id' => $task, 'evidence_mode' => 'invalid'], true)['code'] ?? null) === 1) {
    throw new RuntimeException('Unknown AI evidence mode accepted');
}
$id = $ok($request('requestAi', ['capture_id' => $task, 'evidence_mode' => 'full_packets'], true))['id'];
if (($request('requestAi', ['capture_id' => $task], true)['code'] ?? null) === 1 || $db->query('SELECT count(*) FROM ai_analyses')->fetchColumn() != 1) {
    throw new RuntimeException('Duplicate manual AI request');
}
$analysis = $ok($request('analysis', ['id' => $id]))['record'];
if ($analysis['status'] !== 'pending' || $analysis['evidence_mode'] !== 'full_packets' || isset($analysis['config_snapshot'])) {
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
$db->exec("UPDATE monitor_events SET kinds='[\"capture_degraded\"]',status='open' WHERE id=100");
$before = $db->query('SELECT count(*) FROM exclusions')->fetchColumn();
if (($request('whitelist', ['id' => 100], true)['code'] ?? null) === 1 || $db->query('SELECT count(*) FROM exclusions')->fetchColumn() != $before || $db->query('SELECT status FROM monitor_events WHERE id=100')->fetchColumn() !== 'open') {
    throw new RuntimeException('Capture quality can be muted through event whitelist');
}
echo "Event list/count/detail, local PCAP summary, manual AI, encrypted secrets, duplicate prevention and read-only permissions passed.\n";

$db->exec('CREATE TABLE websites (id bigserial primary key,ip_asset_id bigint,host text,port integer,scheme text,status text,ownership_status text,title text,description text,category text,manual_category text,last_probed_at timestamp,last_seen_at timestamp,source text default \'http_host\',ownership_evidence jsonb,updated_at timestamp)');
$db->exec("INSERT INTO websites(ip_asset_id,host,port,scheme,status,ownership_status,last_seen_at) VALUES(1,'owned.example',443,'https','verified','dns_match',now()),(1,'foreign.example',80,'http','failed','dns_mismatch',now()),(1,'unknown.example',80,'http','observed','unverified',now()),(1,'tested.example',443,'https','verified','origin_response',now())");
foreach (['assets' => 1, 'foreign' => 1, 'candidates' => 2, 'all' => 4] as $ownership => $count) {
    $query = ['resource' => 'websites', 'ownership' => $ownership];
    if ($ok($request('count', $query, false, false, 'Monitor'))['total'] !== $count || count($ok($request('index', $query, false, true, 'Monitor'))['list']) !== $count) {
        throw new RuntimeException('Website ownership filter incorrect: '.$ownership);
    }
}
if ($ok($request('index', ['resource' => 'websites'], false, false, 'Monitor'))['list'][0]['host'] !== 'owned.example') {
    throw new RuntimeException('Default website list exposes unrelated client Host');
}
echo "Website default/list/count ownership separation passed.\n";

$db->exec('CREATE TABLE probe_tasks (id bigserial primary key,website_id bigint unique,mode text default \'normal\',status text,attempts integer,available_at timestamp,lease_token text,leased_until timestamp,created_at timestamp,updated_at timestamp)');
$foreignId = $db->query("SELECT id FROM websites WHERE host='foreign.example'")->fetchColumn();
$db->exec("UPDATE websites SET ownership_evidence='{\"host\":\"foreign.example\",\"addresses\":[\"198.51.100.1\"],\"checked_at\":\"2026-10-03T00:00:00Z\",\"method\":\"dns_A_AAAA\"}' WHERE id=".$foreignId);
if (($request('testOrigin', ['id' => $foreignId], true, true, 'Monitor')['code'] ?? null) !== 403) {
    throw new RuntimeException('Viewer can queue an origin test');
}
$ok($request('testOrigin', ['id' => $foreignId], true, false, 'Monitor'));
$site = $db->query('SELECT source,ownership_status FROM websites WHERE id='.$foreignId)->fetch(PDO::FETCH_ASSOC);
$task = $db->query('SELECT status,mode FROM probe_tasks')->fetch(PDO::FETCH_ASSOC);
if ($site['source'] !== 'http_host' || $site['ownership_status'] !== 'dns_mismatch' || $task['mode'] !== 'origin_test' || $task['status'] !== 'pending') {
    throw new RuntimeException('Origin test silently registers ownership');
}
$db->exec("UPDATE probe_tasks SET status='leased',lease_token='old-origin-task',leased_until=now()+INTERVAL '3 minute'");
$ok($request('testOrigin', ['id' => $foreignId], true, false, 'Monitor'));
if ($db->query('SELECT lease_token FROM probe_tasks')->fetchColumn() !== null || $db->query('SELECT count(*) FROM probe_tasks')->fetchColumn() != 1) {
    throw new RuntimeException('Origin test does not fence or deduplicate tasks');
}
foreach ([['', false], ['not authorized', true]] as [$reason, $viewer]) {
    if (($request('confirmOrigin', ['id' => $foreignId, 'reason' => $reason], true, $viewer, 'Monitor')['code'] ?? null) === 1) {
        throw new RuntimeException('Origin registration accepted missing basis or viewer');
    }
}
$ok($request('confirmOrigin', ['id' => $foreignId, 'reason' => 'Customer CDN origin configuration verified'], true, false, 'Monitor'));
$site = $db->query('SELECT source,ownership_status,ownership_evidence FROM websites WHERE id='.$foreignId)->fetch(PDO::FETCH_ASSOC);
$proof = json_decode($site['ownership_evidence'], true);
if ($site['source'] !== 'manual' || $site['ownership_status'] !== 'manual' || $proof['registration']['type'] !== 'cdn_origin' || $proof['previous_dns']['evidence']['addresses'] !== ['198.51.100.1'] || $db->query('SELECT count(*) FROM probe_tasks')->fetchColumn() != 1) {
    throw new RuntimeException('Origin registration or original DNS evidence not preserved');
}
$db->exec("UPDATE probe_tasks SET status='leased',lease_token='old-task',leased_until=now()+INTERVAL '3 minute'");
$ok($request('confirmOrigin', ['id' => $foreignId, 'reason' => 'Rechecked configuration'], true, false, 'Monitor'));
$task = $db->query('SELECT status,lease_token,mode FROM probe_tasks')->fetch(PDO::FETCH_ASSOC);
if ($task['mode'] !== 'normal' || $task['status'] !== 'pending' || $task['lease_token'] !== null || $db->query('SELECT count(*) FROM probe_tasks')->fetchColumn() != 1) {
    throw new RuntimeException('Stale passive probe lease was not fenced');
}
echo "CDN origin registration permissions, explicit basis, DNS provenance and stale lease fencing passed.\n";

foreach ([['00000000-0000-4000-8000-000000000081', 'Sort C', '1.9.0'], ['00000000-0000-4000-8000-000000000082', 'Sort A', '1.10.0'], ['00000000-0000-4000-8000-000000000083', 'Sort B', null]] as [$id,$name,$version]) {
    $db->prepare('INSERT INTO nodes(id,name,enabled,cidrs,health) VALUES(?,?,true,?,?)')->execute([$id, $name, '[]', json_encode(['version' => $version])]);
}
foreach ([['name', 'asc', ['Sort A', 'Sort B', 'Sort C']], ['name', 'desc', ['Sort C', 'Sort B', 'Sort A']], ['agent_version', 'asc', ['Sort C', 'Sort A', 'Sort B']], ['agent_version', 'desc', ['Sort A', 'Sort C', 'Sort B']]] as [$sort,$direction,$names]) {
    $rows = $ok($request('index', ['resource' => 'nodes', 'search' => 'Sort', 'sort' => $sort, 'direction' => $direction], false, true, 'Monitor'))['list'];
    if (array_column($rows, 'name') !== $names) {
        throw new RuntimeException('Node numeric version/name sorting failed: '.$sort.' '.$direction);
    }
}
echo "Node names and numeric versions sort across server results; unknown versions remain last.\n";
