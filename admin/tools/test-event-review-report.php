<?php

require __DIR__.'/../app/common/service/EventReviewReport.php';
require __DIR__.'/../app/common/service/BusinessScope.php';

use app\common\service\BusinessScope;
use app\common\service\EventReviewReport;

$event = ['id' => 1, 'status' => 'open', 'quality' => '{}'];
$alerts = [
    ['title' => '旧的高风险', 'kind' => 'horizontal_scan', 'status' => 'resolved', 'evidence' => ['connection_analysis' => ['category' => 'strong_anomaly']]],
    ['title' => '数量提醒', 'kind' => 'tcp_connection_burst', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'behavior_notice', 'reasons' => ['仅数量阈值']]]],
];
$endpoint = ['peer_ip' => '192.0.2.1', 'peer_port' => 443, 'attempts' => 10, 'synack_replies' => 8, 'completed_handshakes' => 8, 'rst_replies' => 1, 'payload_in' => 200, 'payload_out' => 100];
$row = ['window_start' => '2026-10-01 00:00:00', 'window_end' => '2026-10-01 00:00:30', 'tcp_attempts' => 10, 'bytes_in' => 200, 'bytes_out' => 100,
    'evidence' => ['connection_stats_version' => 1, 'completed_handshakes' => 8, 'rst_replies' => 1, 'outbound_endpoints' => [$endpoint]]];
$old = $row;
$old['evidence'] = ['synack_replies' => 10];
$mixed = EventReviewReport::build($event, $alerts, [$row, $old]);
if ($mixed['category'] !== 'behavior_notice' || $mixed['totals']['attempts'] !== 20 || $mixed['totals']['paired_attempts'] !== 10
    || $mixed['totals']['completed'] !== 8 || $mixed['timeline'][0]['completed'] !== null) {
    throw new RuntimeException('Archived rules or old statistics distort the current assessment');
}
$metrics = [];
for ($i = 0; $i < 121; $i++) {
    $window = $row;
    $window['evidence']['outbound_endpoints'] = [];
    $window['evidence']['port_scan_targets'] = [];
    for ($j = 0; $j < 8; $j++) {
        $window['evidence']['outbound_endpoints'][] = array_replace($endpoint, ['peer_ip' => '192.0.'.intdiv($i * 8 + $j, 256).'.'.(($i * 8 + $j) % 256)]);
        $window['evidence']['port_scan_targets'][] = ['peer_ip' => '198.51.100.'.(($i * 8 + $j) % 256), 'port_count' => 32, 'ports' => range(1, 32), 'truncated' => true];
    }
    $metrics[] = $window;
}
$bounded = EventReviewReport::build($event, $alerts, $metrics);
if (count($bounded['timeline']) !== 120 || count($bounded['targets']) !== 32 || count($bounded['port_targets']) !== 16
    || $bounded['totals']['attempts'] !== 1200 || strlen(json_encode($bounded)) > 100000
    || ! str_contains(implode(' ', $bounded['evidence_gaps']), '有界样本')) {
    throw new RuntimeException('Report bounds or truncation explanation incorrect');
}
$empty = EventReviewReport::build($event, [], []);
if ($empty['category'] !== 'needs_review' || $empty['timeline'] || ! str_contains(implode(' ', $empty['evidence_gaps']), '没有可用的流量窗口')) {
    throw new RuntimeException('Missing evidence is mistaken for normal activity');
}
echo "Event review report bounds, mixed versions and review priorities passed\n";

$serviceAlerts = [
    ['title' => '多目标连接', 'kind' => 'horizontal_scan', 'severity' => 'medium', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'needs_review', 'reasons' => ['目标较多']]]],
    ['title' => 'SMB 服务高频连接', 'kind' => 'smb_connections', 'severity' => 'medium', 'status' => 'open', 'evidence' => ['value' => 100, 'window_seconds' => 60, 'sample' => ['target_endpoints' => ['192.0.2.1:445']], 'connection_analysis' => ['category' => 'needs_review']]],
    ['title' => '旧强异常', 'kind' => 'vertical_scan', 'severity' => 'high', 'status' => 'resolved', 'evidence' => []],
];
$serviceEvent = $event + ['title' => 'SMB 服务高频连接'];
$ordered = EventReviewReport::prioritize($serviceAlerts, $serviceEvent['title']);
$serviceReport = EventReviewReport::build($serviceEvent, $serviceAlerts, [$row]);
if ($ordered[0]['kind'] !== 'smb_connections' || $ordered[2]['status'] !== 'resolved'
    || ! str_contains($serviceReport['reasons'][0], '192.0.2.1:445')
    || ! str_contains($serviceReport['reasons'][0], '100 次') || $serviceReport['category'] !== 'needs_review') {
    throw new RuntimeException('Specific service evidence must be first without treating connections as confirmed attacks');
}
echo "Service headline and review evidence priority passed.\n";

$rdpAlert = ['title' => 'RDP 高频连接', 'kind' => 'rdp_connections', 'status' => 'open', 'evidence' => []];
$rdpReport = EventReviewReport::build($event + ['kinds' => '["rdp_connections"]'], [$rdpAlert], [$row]);
$fallbackReport = EventReviewReport::build($event, [$rdpAlert], [$row]);
$mixedRdpReport = EventReviewReport::build($event + ['kinds' => ['rdp_connections', 'smb_connections']], [$rdpAlert], [$row]);
if ($rdpReport['event']['kinds'] !== ['rdp_connections'] || $fallbackReport['event']['kinds'] !== ['rdp_connections']
    || $mixedRdpReport['event']['kinds'] !== ['rdp_connections', 'smb_connections']) {
    throw new RuntimeException('Report kinds must distinguish RDP-only events from mixed events without losing unreturned rules');
}
echo "RDP-only report selection preserves mixed event evidence.\n";

$udpRow = $row;
$udpRow['evidence'] = ['udp_stats_version' => 1, 'udp_flows_out' => 2, 'udp_packets_out' => 20, 'udp_packets_in' => 3, 'udp_bytes_out' => 2000, 'udp_bytes_in' => 300, 'udp_flows_capped' => true, 'udp_endpoints' => [['peer_ip' => '192.0.2.1', 'peer_port' => 53, 'flows' => 2, 'packets_out' => 20, 'packets_in' => 3, 'bytes_out' => 2000, 'bytes_in' => 300]]];
$udp = EventReviewReport::build($event, $alerts, [$udpRow, $udpRow, $old]);
if ($udp['udp_totals']['windows'] !== 2 || $udp['udp_totals']['flows'] !== 4 || $udp['udp_totals']['packets_out'] !== 40 || $udp['udp_totals']['packets_in'] !== 6 || ! $udp['udp_totals']['capped'] || $udp['udp_targets'][0]['peer_port'] !== 53 || $udp['udp_targets'][0]['bytes_in'] !== 600) {
    throw new RuntimeException('UDP report mixes transport statistics or old versions');
}
echo "UDP windows and endpoint packet evidence remain separate from TCP.\n";

$profile = BusinessScope::profile(
    [['port_scan_targets' => [['peer_ip' => '192.0.2.1', 'ports' => [11001, 11002]]]], ['port_scan_targets' => [['peer_ip' => '192.0.2.1', 'ports' => [11000]]]]],
    [['pcap_fully_read' => true, 'summary_capped' => false, 'peer_groups' => [['peer_ip' => '192.0.2.2', 'ports' => [3389]]]]],
    [['target_ports' => ['192.0.2.1' => [11003]]]]
);
if ($profile !== ['192.0.2.1' => [11000, 11001, 11002, 11003], '192.0.2.2' => [3389]]) {
    throw new RuntimeException('Business approval must combine recent windows and preserve previous approval without mixing ports across targets');
}
echo "Business scope aggregation passed.\n";
