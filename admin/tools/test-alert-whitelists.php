<?php

// CI-only integration tests against disposable PostgreSQL and the local test API.
if (getenv('MONITOR_DB_DATABASE') !== 'monitor_test' || ! getenv('TEST_ADMIN_TOKEN')) {
    throw new RuntimeException('This test requires the isolated CI database and test admin token');
}
$db = new PDO('pgsql:host=127.0.0.1;dbname=monitor_test', getenv('MONITOR_DB_USERNAME'), getenv('MONITOR_DB_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$node = '00000000-0000-4000-8000-000000000001';
$otherNode = '00000000-0000-4000-8000-000000000002';
$db->prepare('INSERT INTO nodes (id,name,enabled,cidrs) VALUES (?,?,true,?)')->execute([$node, 'Test node', '[]']);
$db->prepare('INSERT INTO nodes (id,name,enabled,cidrs) VALUES (?,?,true,?)')->execute([$otherNode, 'Other node', '[]']);
$db->prepare('INSERT INTO ip_assets VALUES (?,?)')->execute([2, '2001:db8::1']);
$request = function (string $method, array $payload): array {
    $context = stream_context_create(['http' => [
        'method' => 'POST', 'ignore_errors' => true, 'timeout' => 20,
        'header' => ['Content-Type: application/json', 'server: true', 'batoken: '.getenv('TEST_ADMIN_TOKEN')],
        'content' => json_encode($payload, JSON_THROW_ON_ERROR),
    ]]);

    return json_decode(file_get_contents('http://127.0.0.1:8099/admin/Monitor/'.$method, false, $context), true, 512, JSON_THROW_ON_ERROR);
};
$kinds = ['horizontal_scan', 'vertical_scan', 'suspected_bruteforce', 'single_target_attempts', 'tcp_connection_burst', 'udp_flow_burst', 'udp_packet_rate', 'egress_mbps', 'vpn_protocol', 'proxy_suspect', 'capture_degraded', 'node_offline'];
foreach ($kinds as $index => $kind) {
    $id = 10 + 3 * $index;
    $asset = in_array($kind, ['capture_degraded', 'node_offline'], true) ? null : ($kind === 'proxy_suspect' ? 2 : 1);
    $insert = $db->prepare('INSERT INTO alerts (id,node_id,ip_asset_id,title,kind,severity,status,occurrences,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)');
    foreach ([[$id, $node], [$id + 1, $node], [$id + 2, $otherNode]] as [$alertId, $observer]) {
        $insert->execute([$alertId, $observer, $asset, $kind, $kind, 'medium', 'open', 1, '2026-10-01 00:00:00']);
    }
    $db->prepare('UPDATE alerts SET evidence=? WHERE id IN (?,?,?)')->execute([json_encode(['value' => 100, 'sample' => ['targets' => ['192.0.2.2'], 'ports' => [443], 'unique_targets' => 1]]), $id, $id + 1, $id + 2]);
    if (in_array($kind, ['capture_degraded', 'vertical_scan'], true)) {
        if (($request('whitelistAlert', ['id' => $id])['code'] ?? null) === 1 || $db->query("SELECT count(*) FROM exclusions WHERE kind='".$kind."'")->fetchColumn() != 0 || $db->query('SELECT status FROM alerts WHERE id='.$id)->fetchColumn() !== 'open') {
            throw new RuntimeException('Capture quality or deleted multi-port rule can be muted through alert whitelist');
        }

        continue;
    }
    foreach ([$id, $id] as $whitelistId) {
        $result = $request('whitelistAlert', ['id' => $whitelistId]);
        if (($result['code'] ?? null) !== 1) {
            throw new RuntimeException('Whitelist failed for '.$kind.': '.($result['msg'] ?? 'unknown'));
        }
    }
    $scopes = $db->prepare('SELECT * FROM exclusions WHERE node_id=? AND kind=?');
    $scopes->execute([$node, $kind]);
    $entries = $scopes->fetchAll(PDO::FETCH_ASSOC);
    $expectedCidr = $asset === null ? null : ($asset === 2 ? '2001:db8::1/128' : '203.0.113.10/32');
    if (count($entries) !== 1 || $entries[0]['cidr'] !== $expectedCidr || strtotime($entries[0]['expires_at'].' UTC') < time() + 29 * 86400) {
        throw new RuntimeException('Incorrect whitelist scope or duplicate for '.$kind);
    }
    if ($asset !== null) {
        $scope = json_decode($entries[0]['behavior_scope'], true);
        if ($scope['target_cidrs'] !== ['192.0.2.2/32'] || $scope['ports'] !== [443] || $scope['max_value'] !== 200 || $scope['severity'] !== 'medium') {
            throw new RuntimeException('Destination business scope was not captured for '.$kind);
        }
        $result = $request('save', ['resource' => 'exclusions', 'id' => $entries[0]['id'], 'data' => ['target_cidrs' => ['198.51.100.0/24'], 'allowed_ports' => [443], 'max_value' => 250, 'allowed_severity' => 'medium', 'reason' => 'Explicit reviewed targets']]);
        if (($result['code'] ?? null) !== 1 || json_decode($db->query('SELECT behavior_scope FROM exclusions WHERE id='.(int) $entries[0]['id'])->fetchColumn(), true)['target_cidrs'] !== ['198.51.100.0/24']) {
            throw new RuntimeException('Explicit destination edit failed for '.$kind);
        }
    }
    $statuses = $db->prepare('SELECT status FROM alerts WHERE id IN (?,?,?) ORDER BY id');
    $statuses->execute([$id, $id + 1, $id + 2]);
    if ($statuses->fetchAll(PDO::FETCH_COLUMN) !== ['resolved', 'resolved', 'open']) {
        throw new RuntimeException('Resolution escaped node scope for '.$kind);
    }
    if ($asset === null) {
        $result = $request('save', ['resource' => 'exclusions', 'id' => $entries[0]['id'], 'data' => ['reason' => 'Maintenance reviewed', 'expires_at' => gmdate('Y-m-d H:i:s', time() + 86400)]]);
        if (($result['code'] ?? null) !== 1) {
            throw new RuntimeException('Partial node whitelist edit failed');
        }
    }
}
foreach ([['kind' => 'node_offline', 'cidr' => '203.0.113.10/32'], ['kind' => 'vpn_protocol', 'cidr' => ''], ['kind' => 'capture_degraded', 'cidr' => '']] as $invalid) {
    $result = $request('save', ['resource' => 'exclusions', 'data' => $invalid + ['node_id' => $node, 'reason' => 'Invalid scope', 'expires_at' => gmdate('Y-m-d H:i:s', time() + 86400)]]);
    if (($result['code'] ?? null) === 1) {
        throw new RuntimeException('Invalid whitelist scope was accepted');
    }
}
echo "Nine whitelist types and capture-quality rejection passed: IPv4, IPv6, node health, repeat action, scoped resolution and partial edit.\n";
