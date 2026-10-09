<?php

require __DIR__.'/../app/common/service/EventEvidencePriority.php';
require __DIR__.'/../app/common/service/BusinessScope.php';

use app\common\service\BusinessScope;
use app\common\service\EventEvidencePriority;

$alerts = [
    ['kind' => 'udp_packet_rate', 'title' => 'Old UDP notice', 'severity' => 'high', 'status' => 'open'],
    ['kind' => 'proxy_suspect', 'title' => 'Proxy candidate', 'severity' => 'low', 'status' => 'open', 'assessment_category' => 'needs_review'],
    ['kind' => 'smb_connections', 'title' => 'SMB evidence', 'severity' => 'medium', 'status' => 'open', 'assessment_category' => 'needs_review'],
    ['kind' => 'vpn_protocol', 'title' => 'Resolved high', 'severity' => 'high', 'status' => 'resolved'],
    ['kind' => 'vertical_scan', 'title' => 'Deleted rule', 'severity' => 'high', 'status' => 'open'],
    ['kind' => 'tcp_connection_burst', 'title' => 'Old TCP notice', 'severity' => 'high', 'status' => 'open', 'evidence' => '{"connection_analysis":{"category":"behavior_notice"}}'],
];
$ordered = EventEvidencePriority::prioritize($alerts, 'SMB evidence');
if (array_column($ordered, 'kind') !== ['smb_connections', 'proxy_suspect', 'vpn_protocol', 'udp_packet_rate', 'tcp_connection_burst']
    || $ordered[0] !== $alerts[2] || $ordered[3] !== $alerts[0]) {
    throw new RuntimeException('Evidence priority must preserve evidence, hide deleted rules and rank active anomalies ahead of historical notices');
}
echo "Rule evidence priority passed.\n";

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
