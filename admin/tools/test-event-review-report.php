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
    ['title' => '旧强异常', 'kind' => 'vpn_protocol', 'severity' => 'high', 'status' => 'resolved', 'evidence' => []],
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
$spreadEvidence = ['value' => 10, 'threshold' => 10, 'window_seconds' => 60, 'rule_observed_span_seconds' => 60, 'rule_window_count' => 2,
    'sample' => ['service_target_stats_version' => 1, 'targets' => ['192.0.2.1', '192.0.2.2'], 'tcp_attempts' => 317, 'ports' => [3389], 'service_targets_capped' => true],
    'connection_analysis' => ['category' => 'needs_review']];
foreach (['ssh_target_spread', 'rdp_target_spread', 'ftp_target_spread'] as $spreadKind) {
    $spreadAlert = ['kind' => $spreadKind, 'title' => '服务多目标建连', 'severity' => 'medium', 'status' => 'open', 'evidence' => $spreadEvidence];
    $retiredAlert = ['kind' => 'rdp_connections', 'title' => '旧 RDP 次数提醒', 'severity' => 'high', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'strong_anomaly', 'reasons' => ['Retired count assessment']]]];
    $deletedAlert = ['kind' => 'vertical_scan', 'title' => '已删除多端口', 'severity' => 'high', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'strong_anomaly']]];
    $spreadReport = EventReviewReport::build($event + ['kinds' => [$spreadKind, 'rdp_connections', 'vertical_scan']], [$retiredAlert, $deletedAlert, $spreadAlert], [$row]);
    if ($spreadReport['category'] !== 'needs_review' || ! str_contains($spreadReport['reasons'][0], '不同目标 IP 10 个') || ! str_contains($spreadReport['reasons'][0], '实际观察跨度 60 秒、2 个有效采集窗口') || str_contains(implode(' ', $spreadReport['reasons']), '317 次') || str_contains(json_encode($spreadReport), 'Retired count assessment') || in_array('vertical_scan', $spreadReport['event']['kinds'], true) || ! str_contains(implode(' ', $spreadReport['evidence_gaps']), '128 个 IP')) {
        throw new RuntimeException('Service target reports confuse distinct IPs with retired connection counts or deleted data');
    }
}

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

$mixedNoticeAlerts = [
    ['title' => 'Old high UDP notice', 'kind' => 'udp_packet_rate', 'severity' => 'high', 'assessment_category' => 'strong_anomaly', 'status' => 'open', 'evidence' => json_encode(['connection_analysis' => ['category' => 'strong_anomaly', 'reasons' => ['UDP legacy classification'], 'normal_explanations' => ['UDP legacy explanation'], 'evidence_gaps' => ['UDP legacy gap']]])],
    ['title' => 'Old high TCP notice', 'kind' => 'tcp_connection_burst', 'severity' => 'high', 'assessment_category' => 'behavior_notice', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'strong_anomaly', 'reasons' => ['TCP volume reminder']]]],
    ['title' => 'Low proxy candidate', 'kind' => 'proxy_suspect', 'severity' => 'low', 'assessment_category' => 'needs_review', 'status' => 'open', 'evidence' => ['connection_analysis' => ['category' => 'needs_review', 'reasons' => ['Visible proxy candidate evidence']]]],
];
$noticeOrder = EventReviewReport::prioritize($mixedNoticeAlerts, 'Old high UDP notice');
$mixedNoticeReport = EventReviewReport::build($event + ['title' => 'Low proxy candidate', 'kinds' => ['udp_packet_rate', 'tcp_connection_burst', 'proxy_suspect']], $mixedNoticeAlerts, [$row, $udpRow]);
if ($noticeOrder[0]['kind'] !== 'proxy_suspect' || count($noticeOrder) !== 3 || $noticeOrder[1]['evidence'] !== $mixedNoticeAlerts[0]['evidence']
    || $mixedNoticeReport['category'] !== 'needs_review' || $mixedNoticeReport['reasons'] !== ['Visible proxy candidate evidence']
    || str_contains(json_encode($mixedNoticeReport), 'UDP legacy') || str_contains(json_encode($mixedNoticeReport), 'TCP volume reminder')
    || ! str_contains(implode(' ', $mixedNoticeReport['evidence_gaps']), '历史一般行为提醒')
    || $mixedNoticeReport['event']['kinds'] !== ['udp_packet_rate', 'tcp_connection_burst', 'proxy_suspect']
    || $mixedNoticeReport['udp_totals']['packets_out'] !== 20 || $mixedNoticeReport['totals']['attempts'] !== 20) {
    throw new RuntimeException('Historical volume-only rules must remain as evidence without outranking or reclassifying mixed security events');
}
$onlyNotices = EventReviewReport::build($event + ['kinds' => ['udp_packet_rate']], [$mixedNoticeAlerts[0]], [$udpRow]);
if ($onlyNotices['category'] !== 'behavior_notice' || $onlyNotices['reasons'] !== [] || $onlyNotices['udp_totals']['packets_out'] !== 20) {
    throw new RuntimeException('A retired UDP rule must not retain its stale strong-anomaly conclusion');
}
echo "Mixed reports prioritize actual anomaly evidence, omit historical volume-only conclusions and preserve original kinds/statistics.\n";

$profile = BusinessScope::profile(
    [['port_scan_targets' => [['peer_ip' => '192.0.2.1', 'ports' => [11001, 11002]]]], ['port_scan_targets' => [['peer_ip' => '192.0.2.1', 'ports' => [11000]]]]],
    [['pcap_fully_read' => true, 'summary_capped' => false, 'peer_groups' => [['peer_ip' => '192.0.2.2', 'ports' => [3389]]]]],
    [['target_ports' => ['192.0.2.1' => [11003]]]]
);
if ($profile !== ['192.0.2.1' => [11000, 11001, 11002, 11003], '192.0.2.2' => [3389]]) {
    throw new RuntimeException('Business approval must combine recent windows and preserve previous approval without mixing ports across targets');
}
$serviceProfile = BusinessScope::profile([
    ['service_target_stats_version' => 1, 'service_targets' => [
        ['service' => 'ssh', 'targets' => ['192.0.2.3'], 'ports' => [22]],
        ['service' => 'rdp', 'targets' => ['192.0.2.4'], 'ports' => [3389]],
        ['service' => 'ftp', 'targets' => ['192.0.2.3', '192.0.2.5'], 'ports' => [21, 990]],
    ]],
    ['service_target_stats_version' => 1, 'count_basis' => 'distinct_service_target_ips', 'targets' => ['192.0.2.6'], 'ports' => [3389]],
    ['service_target_stats_version' => 0, 'service_targets' => [['targets' => ['192.0.2.7'], 'ports' => [22]]]],
]);
if ($serviceProfile !== ['192.0.2.3' => [21, 22, 990], '192.0.2.4' => [3389], '192.0.2.5' => [21, 990], '192.0.2.6' => [3389]]) {
    throw new RuntimeException('Service business approval loses independent target sets or invents port pairings');
}
echo "Business scope aggregation passed.\n";
