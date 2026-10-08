<?php

// Integration checks run only against the disposable CI database and local HTTP server.
if (getenv('MONITOR_DB_DATABASE') !== 'monitor_test' || ! getenv('TEST_ADMIN_TOKEN') || ! getenv('TEST_VIEWER_TOKEN')) {
    throw new RuntimeException('Isolated CI credentials required');
}
$db = new PDO('pgsql:host=127.0.0.1;dbname=monitor_test', getenv('MONITOR_DB_USERNAME'), getenv('MONITOR_DB_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec(<<<'SQL'
CREATE TABLE rules (id bigserial primary key,name text,kind text,enabled boolean default true,severity text default 'medium',threshold integer,window_seconds integer default 60,cooldown_seconds integer default 600,node_id uuid,node_ids jsonb,created_at timestamp,updated_at timestamp);
ALTER TABLE alerts ADD COLUMN event_id bigint, ADD COLUMN first_seen_at timestamp;
CREATE TABLE monitor_events (id bigserial primary key,node_id uuid,ip_asset_id bigint,active_key text,title text,severity text,status text default 'open',kinds json,quality jsonb,occurrences bigint default 1,review_notes text,first_seen_at timestamp,last_seen_at timestamp,created_at timestamp,updated_at timestamp);
ALTER TABLE monitor_events ADD COLUMN behavior jsonb, ADD COLUMN review_context jsonb, ADD COLUMN reopen_reason text, ADD COLUMN assessment_category text default 'needs_review';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assessment_category text default 'needs_review';
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
$secondTask = $ok($request('capture', ['id' => 100], true))['id'];
if (($request('capture', ['id' => 100], true)['code'] ?? null) === 1) {
    throw new RuntimeException('Concurrent captures for the same IP allowed');
}
$db->prepare('UPDATE packet_captures SET status=? WHERE id=?')->execute(['failed', $secondTask]);
$thirdTask = $ok($request('capture', ['id' => 100], true))['id'];
$db->prepare('UPDATE packet_captures SET status=? WHERE id=?')->execute(['failed', $thirdTask]);

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
$db->prepare('UPDATE ai_analyses SET status=?,evidence=? WHERE id=?')->execute(['completed', json_encode(['packet_text' => ['text' => str_repeat('sensitive-packet-text', 10000), 'bytes' => 210000]]), $id]);
$read = $ok($request('analysis', ['id' => $id]))['record'];
if (isset($read['evidence']['packet_text']['text']) || strlen(json_encode($read)) > 4096) {
    throw new RuntimeException('Report opening transfers all packet text again');
}
$excerptId = $ok($request('requestAi', ['capture_id' => $task, 'evidence_mode' => 'packet_excerpt'], true))['id'];
if ($ok($request('analysis', ['id' => $excerptId]))['record']['evidence_mode'] !== 'packet_excerpt') {
    throw new RuntimeException('Packet excerpt mode lost');
}
if ($ok($request('captureSummary', ['id' => $task]))['record']['summary']['matched_packets'] !== 3) {
    throw new RuntimeException('Local summary missing');
}
foreach (['capture', 'review', 'whitelist', 'requestAi', 'saveSettings'] as $action) {
    if (($request($action, ['id' => 100, 'ids' => [100], 'capture_id' => $task], true, true)['code'] ?? null) !== 403) {
        throw new RuntimeException('Viewer can mutate evidence: '.$action);
    }
}
foreach (['settings', 'download', 'whitelistPreview'] as $action) {
    if (($request($action, ['id' => $task], false, true)['code'] ?? null) !== 403) {
        throw new RuntimeException('Viewer can read secrets or PCAP');
    }
}
if ($ok($request('count', [], false, true))['total'] !== 1) {
    throw new RuntimeException('Viewer cannot read events');
}
$ok($request('review', ['ids' => [100], 'status' => 'normal', 'notes' => 'Authorized business'], true));
$db->prepare('UPDATE alerts SET evidence=? WHERE id=1')->execute([json_encode(['value' => 100, 'sample' => ['targets' => ['192.0.2.2'], 'ports' => [443], 'unique_targets' => 1, 'port_scan_targets' => [['peer_ip' => '192.0.2.2', 'port_count' => 1, 'ports' => [443], 'truncated' => false]]]])]);
$preview = $ok($request('whitelistPreview', ['id' => 100]));
if ($preview['target_ports']['192.0.2.2'] !== [443] || ($request('whitelist', ['id' => 100, 'fingerprint' => 'stale'], true)['code'] ?? null) === 1) {
    throw new RuntimeException('Reviewed target profile missing or stale preview accepted');
}
$ok($request('whitelist', ['id' => 100, 'fingerprint' => $preview['fingerprint']], true));
$ok($request('whitelist', ['id' => 100, 'fingerprint' => $preview['fingerprint']], true));
$scopes = $db->query("SELECT behavior_scope FROM exclusions WHERE kind='horizontal_scan' AND node_id='00000000-0000-4000-8000-000000000001'")->fetchAll(PDO::FETCH_COLUMN);
if (! array_filter($scopes, fn ($raw) => (json_decode($raw, true)['target_ports']['192.0.2.2'] ?? []) === [443])) {
    throw new RuntimeException('Per-target business scope was not saved');
}
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

$db->exec("UPDATE nodes SET health='{\"version\":\"1.3.0\",\"update_error\":\"dial tcp: timeout\"}',health_observed_at='2026-10-04 01:00:00',agent_update_requested_at='2026-10-04 02:00:00',agent_desired_version='1.3.1' WHERE name='Sort A'");
$rows = $ok($request('index', ['resource' => 'nodes', 'search' => 'Sort A'], false, true, 'Monitor'))['list'];
if ($rows[0]['agent_update_error'] !== null) {
    throw new RuntimeException('An error older than the new update request must not override waiting status');
}
$db->exec("UPDATE nodes SET health_observed_at='2026-10-04 02:01:00' WHERE name='Sort A'");
$rows = $ok($request('index', ['resource' => 'nodes', 'search' => 'Sort A'], false, true, 'Monitor'))['list'];
if ($rows[0]['agent_update_error'] !== 'dial tcp: timeout') {
    throw new RuntimeException('Current update failures must remain visible');
}
echo "Update requests fence stale errors while preserving current failures.\n";

$qualityNodes = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];
$db->prepare('INSERT INTO nodes(id,name,enabled,cidrs) VALUES (?, ?, true, ?) ON CONFLICT(id) DO NOTHING')->execute([$qualityNodes[1], 'Quality node two', '[]']);
$qualityData = ['name' => '采集覆盖下降', 'kind' => 'capture_degraded', 'threshold' => 10, 'severity' => 'medium', 'enabled' => true, 'node_ids' => $qualityNodes];
$qualityId = $ok($request('save', ['resource' => 'rules', 'data' => $qualityData], true, false, 'Monitor'))['id'];
$qualityRule = $ok($request('detail', ['resource' => 'rules', 'id' => $qualityId], false, false, 'Monitor'))['record'];
if ($qualityRule['node_ids'] !== $qualityNodes || $qualityRule['node_id'] !== null) {
    throw new RuntimeException('Capture quality rule loses multi-node selection');
}
$scopedRules = $ok($request('index', ['resource' => 'rules', 'node' => $qualityNodes[1]], false, false, 'Monitor'))['list'];
if (count($scopedRules) !== 1 || $scopedRules[0]['node_ids'] !== $qualityNodes) {
    throw new RuntimeException('Rules node filter misses multi-node scope');
}
$invalidScope = $qualityData;
$invalidScope['node_ids'] = ['00000000-0000-4000-8000-999999999999'];
if (($request('save', ['resource' => 'rules', 'id' => $qualityId, 'data' => $invalidScope], true, false, 'Monitor')['code'] ?? null) === 1) {
    throw new RuntimeException('Unknown nodes allowed in capture quality scope');
}
$invalidScope['node_ids'] = ['not-a-uuid'];
if (($request('save', ['resource' => 'rules', 'id' => $qualityId, 'data' => $invalidScope], true, false, 'Monitor')['code'] ?? null) === 1) {
    throw new RuntimeException('Invalid node IDs allowed in capture quality scope');
}
$invalidScope = $qualityData;
$invalidScope['kind'] = 'ssh_connections';
if (($request('save', ['resource' => 'rules', 'id' => $qualityId, 'data' => $invalidScope], true, false, 'Monitor')['code'] ?? null) === 1) {
    throw new RuntimeException('Multi-node quality scope applied to unrelated rule types');
}
if (($request('save', ['resource' => 'rules', 'id' => $qualityId, 'data' => ['enabled' => false]], true, true, 'Monitor')['code'] ?? null) !== 403) {
    throw new RuntimeException('Viewer can disable capture quality rules');
}
$ok($request('save', ['resource' => 'rules', 'id' => $qualityId, 'data' => ['enabled' => false, 'node_ids' => null]], true, false, 'Monitor'));
$qualityRule = $ok($request('detail', ['resource' => 'rules', 'id' => $qualityId], false, false, 'Monitor'))['record'];
if ($qualityRule['node_ids'] !== null || ! in_array($qualityRule['enabled'], [false, 'f', 0, '0'], true)) {
    throw new RuntimeException('Capture quality scope cannot restore all nodes or disable');
}
echo "Capture quality rules enforce multi-node scope, validation and administrator permissions.\n";

// Notifications use only stored classifications and kinds; evidence remains accessible on demand.
$notificationNode = $qualityNodes[0];
$originalEventTotal = $ok($request('count'))['total'];
$eventInsert = $db->prepare('INSERT INTO monitor_events(id,node_id,ip_asset_id,title,severity,status,kinds,assessment_category,first_seen_at,last_seen_at,created_at,updated_at) VALUES(?,?,1,?,?,\'open\',?,?,now(),now(),now(),now())');
foreach ([
    [301, 'UDP normal', 'low', ['udp_packet_rate'], 'behavior_notice'],
    [302, 'UDP stale classification', 'high', ['udp_flow_burst'], 'strong_anomaly'],
    [303, 'TCP volume only', 'medium', ['tcp_connection_burst'], 'behavior_notice'],
    [304, 'Mixed proxy evidence', 'low', ['udp_packet_rate', 'proxy_suspect'], 'needs_review'],
    [305, 'Low-severity proxy evidence', 'low', ['proxy_suspect'], 'needs_review'],
    [306, 'Legacy unclassified evidence', 'medium', ['vpn_protocol'], null],
    [307, 'Deleted multi-port evidence', 'high', ['vertical_scan'], 'strong_anomaly'],
    [308, 'Retired SSH connection count', 'high', ['ssh_connections'], 'strong_anomaly'],
    [309, 'Retired RDP connection count', 'high', ['rdp_connections'], 'needs_review'],
    [310, 'Retired FTP connection count', 'medium', ['ftp_connections'], 'needs_review'],
    [311, 'Mixed SMB evidence', 'medium', ['vertical_scan', 'smb_connections'], 'needs_review'],
] as [$eventId, $title, $severity, $kinds, $category]) {
    $eventInsert->execute([$eventId, $notificationNode, 'Notification fixture '.$title, $severity, json_encode($kinds), $category]);
}
$alertInsert = $db->prepare('INSERT INTO alerts(id,event_id,node_id,ip_asset_id,title,kind,severity,status,occurrences,assessment_category,evidence,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,1,?,?,?,\'open\',1,?,?,now(),now(),now())');
foreach ([
    [500, 301, 'UDP normal', 'udp_packet_rate', 'low', 'behavior_notice'],
    [501, 302, 'UDP stale classification', 'udp_flow_burst', 'high', 'strong_anomaly'],
    [502, 303, 'TCP volume only', 'tcp_connection_burst', 'medium', 'behavior_notice'],
    [503, 304, 'Mixed UDP history', 'udp_packet_rate', 'high', 'strong_anomaly'],
    [504, 304, 'Mixed proxy evidence', 'proxy_suspect', 'low', 'needs_review'],
    [505, 305, 'Low-severity proxy evidence', 'proxy_suspect', 'low', 'needs_review'],
    [506, 306, 'Legacy unclassified evidence', 'vpn_protocol', 'medium', null],
    [507, null, 'Retired website clue', 'new_website', 'medium', 'needs_review'],
    [508, 307, 'Deleted multi-port evidence', 'vertical_scan', 'high', 'strong_anomaly'],
    [509, 308, 'Retired SSH connection count', 'ssh_connections', 'high', 'strong_anomaly'],
    [510, 309, 'Retired RDP connection count', 'rdp_connections', 'high', 'needs_review'],
    [511, 310, 'Retired FTP connection count', 'ftp_connections', 'medium', 'needs_review'],
    [512, 311, 'Deleted mixed multi-port evidence', 'vertical_scan', 'high', 'strong_anomaly'],
    [513, 311, 'Mixed SMB evidence', 'smb_connections', 'medium', 'needs_review'],
] as [$alertId, $eventId, $title, $kind, $severity, $category]) {
    $alertInsert->execute([$alertId, $eventId, $notificationNode, 'Notification fixture '.$title, $kind, $severity, $category, json_encode(['note' => 'Preserved original evidence', 'padding' => str_repeat('e', 100000)])]);
}
$notificationQuery = ['search' => 'Notification fixture', 'limit' => 500];
foreach ([false, true] as $viewer) {
    $eventList = $ok($request('index', $notificationQuery, false, $viewer))['list'];
    $eventIds = array_map('intval', array_column($eventList, 'id'));
    sort($eventIds);
    if ($eventIds !== [304, 305, 306, 311] || $ok($request('count', $notificationQuery, false, $viewer))['total'] !== 4 || strlen(json_encode($eventList)) > 4096) {
        throw new RuntimeException('Event notifications lose mixed/low-severity evidence or include volume-only notices');
    }
    if ($ok($request('index', $notificationQuery + ['assessment_category' => 'behavior_notice'], false, $viewer))['list'] !== [] || $ok($request('count', $notificationQuery + ['assessment_category' => 'behavior_notice'], false, $viewer))['total'] !== 0) {
        throw new RuntimeException('A category filter bypasses notification-only policy');
    }
    $legacyQuery = $notificationQuery + ['resource' => 'alerts'];
    $alertIds = array_map('intval', array_column($ok($request('index', $legacyQuery, false, $viewer, 'Monitor'))['list'], 'id'));
    sort($alertIds);
    if ($alertIds !== [504, 505, 506, 513] || $ok($request('count', $legacyQuery, false, $viewer, 'Monitor'))['total'] !== 4) {
        throw new RuntimeException('Legacy alert list/count includes retired UDP or behavior-only notices');
    }
}
$db->exec('CREATE TABLE batches (id bigserial primary key,processed_at timestamp)');
if ($ok($request('overview', [], false, false, 'Monitor'))['alerts'] !== $originalEventTotal + 4) {
    throw new RuntimeException('Dashboard count disagrees with notification-only event list');
}
$mixedDetail = $ok($request('detail', ['id' => 304]));
if (count($mixedDetail['alerts']) !== 2 || $mixedDetail['alerts'][0]['evidence']['note'] !== 'Preserved original evidence' || count($ok($request('detail', ['id' => 301]))['alerts']) !== 1) {
    throw new RuntimeException('Hiding volume-only notifications deletes historical rule evidence');
}
$csvContext = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 20, 'header' => ['server: true', 'batoken: '.getenv('TEST_ADMIN_TOKEN')]]]);
$deletedMixedDetail = $ok($request('detail', ['id' => 311]));
if (array_column($deletedMixedDetail['alerts'], 'kind') !== ['smb_connections'] || $deletedMixedDetail['event']['kinds'] !== ['smb_connections'] || count($ok($request('detail', ['id' => 308]))['alerts']) !== 1) {
    throw new RuntimeException('Deleted multi-port data leaks into mixed details or retired service evidence is lost');
}
$csv = file_get_contents('http://127.0.0.1:8099/admin/Monitor/export?'.http_build_query($notificationQuery + ['resource' => 'alerts']), false, $csvContext);
$csvRows = array_map(fn ($line) => str_getcsv($line, escape: ''), explode("\n", trim(substr($csv, 3))));
if (count($csvRows) !== 5 || array_column(array_slice($csvRows, 1), 2) !== ['proxy_suspect', 'proxy_suspect', 'vpn_protocol', 'smb_connections'] || str_contains($csv, 'UDP') || str_contains($csv, 'TCP volume') || str_contains($csv, 'multi-port') || str_contains($csv, 'Retired')) {
    throw new RuntimeException('CSV export disagrees with notification-only list and count');
}
foreach (['udp_flow_burst', 'udp_packet_rate', 'vertical_scan', 'ssh_connections', 'rdp_connections', 'ftp_connections'] as $index => $retiredKind) {
    if (($request('save', ['resource' => 'rules', 'data' => ['name' => 'Retired volume rule', 'kind' => $retiredKind, 'threshold' => 10000, 'severity' => 'low', 'enabled' => true]], true, false, 'Monitor')['code'] ?? null) === 1) {
        throw new RuntimeException('Retired rule can be recreated: '.$retiredKind);
    }
    $retiredId = 700 + $index;
    $db->prepare('INSERT INTO rules(id,name,kind,threshold,enabled) VALUES(?,?,?,?,false)')->execute([$retiredId, 'Retired fixture '.$retiredKind, $retiredKind, 10]);
    if (($request('save', ['resource' => 'rules', 'id' => $retiredId, 'data' => ['enabled' => true]], true, false, 'Monitor')['code'] ?? null) === 1) {
        throw new RuntimeException('A partial edit re-enables a retired rule: '.$retiredKind);
    }
}
if ($ok($request('index', ['resource' => 'rules', 'search' => 'Retired fixture'], false, false, 'Monitor'))['list'] !== [] || $ok($request('count', ['resource' => 'rules', 'search' => 'Retired fixture'], false, false, 'Monitor'))['total'] !== 0) {
    throw new RuntimeException('Retired rules remain in list/count before database migration');
}
foreach (['ssh_target_spread', 'rdp_target_spread', 'ftp_target_spread'] as $serviceKind) {
    $serviceData = ['name' => 'Service spread '.$serviceKind, 'kind' => $serviceKind, 'threshold' => 10, 'window_seconds' => 60, 'severity' => 'medium', 'enabled' => true];
    $serviceId = $ok($request('save', ['resource' => 'rules', 'data' => $serviceData], true, false, 'Monitor'))['id'];
    foreach ([1, 129] as $invalidThreshold) {
        if (($request('save', ['resource' => 'rules', 'id' => $serviceId, 'data' => ['threshold' => $invalidThreshold]], true, false, 'Monitor')['code'] ?? null) === 1 || ($request('save', ['resource' => 'rules', 'data' => array_replace($serviceData, ['threshold' => $invalidThreshold])], true, false, 'Monitor')['code'] ?? null) === 1) {
            throw new RuntimeException('A service target rule accepts an out-of-range threshold');
        }
    }
    $service = ['ssh_target_spread' => 'ssh', 'rdp_target_spread' => 'rdp', 'ftp_target_spread' => 'ftp'][$serviceKind];
    $servicePorts = ['ssh' => [22], 'rdp' => [3389], 'ftp' => [21, 990]][$service];
    $serviceEventId = ['ssh' => 400, 'rdp' => 401, 'ftp' => 402][$service];
    $serviceTargets = array_map(fn ($last) => '192.0.2.'.$last, range(1, 16));
    $eventInsert->execute([$serviceEventId, $notificationNode, 'Service approval fixture '.$service, 'medium', json_encode([$serviceKind]), 'needs_review']);
    $serviceSample = ['service_target_stats_version' => 1, 'count_basis' => 'distinct_service_target_ips', 'targets' => [...$serviceTargets, '192.0.2.99'], 'ports' => $servicePorts, 'service_targets_capped' => false, 'tcp_attempts' => 17];
    $alertInsert->execute([$serviceEventId + 200, $serviceEventId, $notificationNode, 'Service approval fixture '.$service, $serviceKind, 'medium', 'needs_review', json_encode(['value' => 17, 'sample' => $serviceSample])]);
    $db->prepare('INSERT INTO traffic_metrics(node_id,ip_asset_id,window_start,window_end,tcp_attempts,bytes_in,bytes_out,evidence) VALUES(?,1,now()-INTERVAL \'32 second\',now()-INTERVAL \'2 second\',16,0,0,?)')->execute([$notificationNode, json_encode(['service_target_stats_version' => 1, 'service_targets' => [['service' => $service, 'targets' => $serviceTargets, 'ports' => $servicePorts, 'targets_capped' => false, 'attempts' => 16]]])]);
    $servicePreview = $ok($request('whitelistPreview', ['id' => $serviceEventId]));
    foreach ([...$serviceTargets, '192.0.2.99'] as $target) {
        if (array_diff($servicePorts, $servicePreview['target_ports'][$target] ?? [])) {
            throw new RuntimeException('Service approval preview loses independent raw targets or alert target evidence');
        }
    }
    $ok($request('whitelist', ['id' => $serviceEventId, 'fingerprint' => $servicePreview['fingerprint']], true));
    $serviceScopeQuery = $db->prepare('SELECT behavior_scope FROM exclusions WHERE kind=? AND node_id=? AND cidr=\'203.0.113.10/32\'');
    $serviceScopeQuery->execute([$serviceKind, $notificationNode]);
    $serviceScope = json_decode($serviceScopeQuery->fetchColumn(), true, 512, JSON_THROW_ON_ERROR);
    if ($serviceScope['version'] !== 2 || count($serviceScope['target_ports']) < 17 || array_diff($servicePorts, $serviceScope['target_ports']['192.0.2.99'] ?? []) || array_diff($servicePorts, $serviceScope['target_ports']['192.0.2.16'] ?? [])) {
        throw new RuntimeException('Service target approval fails without fabricated port_scan_targets or loses target/port scope');
    }
}
echo "Notification lists, totals, dashboard and CSV exclude volume-only reminders; mixed and low-severity evidence remain visible, historical evidence survives, and UDP quantity rules cannot be recreated.\n";
