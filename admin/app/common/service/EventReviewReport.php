<?php

namespace app\common\service;

class EventReviewReport
{
    public static function prioritize(array $alerts, string $title): array
    {
        $ranked = array_map(fn ($row) => ['alert' => $row, 'score' => 100000 * (int) ! self::isBehaviorNotice($row)
            + 10000 * (int) in_array($row['status'] ?? 'open', ['open', 'acknowledged'], true)
            + 1000 * (['low' => 1, 'medium' => 2, 'high' => 3][$row['severity'] ?? ''] ?? 0)
            + 100 * (['behavior_notice' => 1, 'needs_review' => 2, 'strong_anomaly' => 3][$row['assessment_category'] ?? ''] ?? 2)
            + (int) (($row['title'] ?? '') === $title)], $alerts);
        usort($ranked, fn ($a, $b) => $b['score'] <=> $a['score']);

        return array_column($ranked, 'alert');
    }

    private static function decode(mixed $value): array
    {
        return is_array($value) ? $value : (json_decode((string) $value, true) ?: []);
    }

    private static function isBehaviorNotice(array $alert): bool
    {
        if (in_array($alert['kind'] ?? '', ['udp_flow_burst', 'udp_packet_rate'], true)) {
            return true;
        }

        return ($alert['assessment_category'] ?? null) === 'behavior_notice'
            || (self::decode($alert['evidence'] ?? [])['connection_analysis']['category'] ?? null) === 'behavior_notice';
    }

    public static function build(array $event, array $alerts, array $metrics): array
    {
        $eventKinds = self::decode($event['kinds'] ?? []);
        if (! $eventKinds) {
            $eventKinds = array_values(array_unique(array_column($alerts, 'kind')));
        }
        $capped = count($metrics) > 120;
        $metrics = array_reverse(array_slice($metrics, 0, 120));
        $timeline = [];
        $udpTargets = [];
        $udpTotals = ['windows' => 0, 'flows' => 0, 'packets_out' => 0, 'packets_in' => 0, 'bytes_out' => 0, 'bytes_in' => 0, 'capped' => false];
        $targets = [];
        $portTargets = [];
        $hints = [];
        $reasons = [];
        $gaps = [];
        $explanations = [];
        $historicalNotices = array_filter($alerts, fn ($alert) => self::isBehaviorNotice($alert));
        if ($historicalNotices) {
            $gaps[] = '历史一般行为提醒保留原始证据，不参与本次自动评估或异常证据排序';
            $alerts = array_filter($alerts, fn ($alert) => ! self::isBehaviorNotice($alert));
        }
        if (in_array($event['status'], ['open', 'acknowledged'], true)) {
            $active = array_filter($alerts, fn ($alert) => in_array($alert['status'] ?? 'open', ['open', 'acknowledged'], true));
            if (count($active) !== count($alerts)) {
                $gaps[] = '已处理子项保留原始证据，不计入本次自动复核优先级';
            }
            $alerts = $active;
        }
        $category = ! $alerts && $historicalNotices ? 'behavior_notice' : 'needs_review';
        $rank = ['behavior_notice' => 1, 'needs_review' => 2, 'strong_anomaly' => 3];
        foreach (self::prioritize($alerts, $event['title'] ?? '') as $alert) {
            $e = self::decode($alert['evidence']);
            if (in_array($alert['kind'], ['smb_connections', 'ssh_connections', 'rdp_connections', 'ftp_connections'], true)) {
                $sample = $e['sample'] ?? [];
                $target = implode(', ', array_slice($sample['target_endpoints'] ?? [], 0, 4));
                $reasons[] = $alert['title'].'：'.$target.'；规则窗口 '.($e['window_seconds'] ?? '未知').' 秒，最活跃目标连接下界 '.($e['value'] ?? '未知').' 次。握手成功不排除认证或应用层异常，需结合配对认证结果和业务授权核实';
            }
            $a = $e['connection_analysis'] ?? [];
            $current = $a['category'] ?? 'needs_review';
            if (($rank[$current] ?? 2) > $rank[$category]) {
                $category = $current;
            }
            $reasons = array_merge($reasons, $a['reasons'] ?? [$alert['title'].'：'.($e['note'] ?? '请查看原始规则证据')]);
            $gaps = array_merge($gaps, $a['evidence_gaps'] ?? ['部分规则尚无配对连接评估，规则级别不等于确认违规']);
            $explanations = array_merge($explanations, $a['normal_explanations'] ?? []);
            if ($alert['kind'] === 'proxy_suspect') {
                $explanations[] = '反向代理、API 网关及客户申报的多客户端服务也可能表现为入站与出站并发';
                $gaps[] = '加密代理样态是候选线索，不能据此确认 SS/VLESS 等具体协议或违规用途';
            }
            if ($alert['kind'] === 'vpn_protocol') {
                $explanations[] = '企业组网、远程办公、客户授权 VPN 服务可能使用相同协议';
                $gaps[] = '协议握手证据不等于确认用途，需结合发起方向、服务端口和业务授权';
            }
        }
        $totals = ['attempts' => 0, 'completed' => 0, 'rst' => 0, 'bytes_out' => 0, 'bytes_in' => 0, 'paired_attempts' => 0, 'paired_windows' => 0];
        foreach ($metrics as $row) {
            $e = self::decode($row['evidence']);
            if (($e['udp_stats_version'] ?? 0) === 1) {
                $udpTotals['windows']++;
                foreach (['udp_flows_out' => 'flows', 'udp_packets_out' => 'packets_out', 'udp_packets_in' => 'packets_in', 'udp_bytes_out' => 'bytes_out', 'udp_bytes_in' => 'bytes_in'] as $from => $to) {
                    $udpTotals[$to] += $e[$from] ?? 0;
                }
                $udpTotals['capped'] = $udpTotals['capped'] || ($e['udp_flows_capped'] ?? false) || ($e['udp_endpoints_truncated'] ?? false);
                foreach ($e['udp_endpoints'] ?? [] as $ep) {
                    $key = $ep['peer_ip'].'|'.$ep['peer_port'];
                    if (! isset($udpTargets[$key]) && count($udpTargets) >= 256) {
                        $udpTotals['capped'] = true;

                        continue;
                    }
                    $udpTargets[$key] ??= ['peer_ip' => $ep['peer_ip'], 'peer_port' => $ep['peer_port'], 'flows' => 0, 'packets_out' => 0, 'packets_in' => 0, 'bytes_out' => 0, 'bytes_in' => 0];
                    foreach (['flows', 'packets_out', 'packets_in', 'bytes_out', 'bytes_in'] as $field) {
                        $udpTargets[$key][$field] += $ep[$field] ?? 0;
                    }
                }
            }
            $n = (int) $row['tcp_attempts'];
            $paired = ($e['connection_stats_version'] ?? 0) === 1 && isset($e['completed_handshakes'], $e['rst_replies']) && max($e['completed_handshakes'], $e['rst_replies']) <= $n;
            $totals['attempts'] += $n;
            $totals['bytes_out'] += (int) $row['bytes_out'];
            $totals['bytes_in'] += (int) $row['bytes_in'];
            if ($paired) {
                $totals['paired_attempts'] += $n;
                $totals['completed'] += $e['completed_handshakes'];
                $totals['rst'] += $e['rst_replies'];
                $totals['paired_windows']++;
            }
            $timeline[] = ['start' => $row['window_start'], 'end' => $row['window_end'], 'attempts' => $n, 'completed' => $paired ? $e['completed_handshakes'] : null, 'rst' => $paired ? $e['rst_replies'] : null,
                'targets' => $e['unique_targets'] ?? null, 'max_ports' => $e['max_ports_per_target'] ?? null, 'bytes_out' => (int) $row['bytes_out'], 'bytes_in' => (int) $row['bytes_in'],
                'kernel_drops' => $e['capture_quality']['kernel_drops'] ?? null, 'state_dropped' => $e['capture_quality']['state_dropped'] ?? null,
                'decode_skipped' => $e['capture_quality']['decode_skipped'] ?? null, 'cardinality_capped' => $e['cardinality_capped'] ?? null];
            foreach ($e['outbound_endpoints'] ?? [] as $ep) {
                $key = $ep['peer_ip'].'|'.$ep['peer_port'];
                if (! isset($targets[$key]) && count($targets) >= 256) {
                    $capped = true;

                    continue;
                }
                $target = $targets[$key] ?? ['peer_ip' => $ep['peer_ip'], 'peer_port' => $ep['peer_port'], 'attempts' => 0, 'synack' => 0, 'completed' => 0, 'rst' => 0, 'payload_out' => 0, 'payload_in' => 0, 'max_observed_span_ms' => 0, 'paired_samples' => 0];
                foreach (['attempts' => 'attempts', 'synack_replies' => 'synack', 'payload_out' => 'payload_out', 'payload_in' => 'payload_in'] as $from => $to) {
                    $target[$to] += $ep[$from] ?? 0;
                }
                if ($paired && isset($ep['completed_handshakes'])) {
                    $target['completed'] += $ep['completed_handshakes'];
                    $target['rst'] += $ep['rst_replies'] ?? 0;
                    $target['paired_samples']++;
                }
                $target['max_observed_span_ms'] = max($target['max_observed_span_ms'], $ep['max_observed_span_ms'] ?? 0);
                $targets[$key] = $target;
                if (! empty($ep['host']) || ! empty($ep['http_path'])) {
                    $hint = array_intersect_key($ep, array_flip(['peer_ip', 'peer_port', 'scheme', 'host', 'http_method', 'http_path', 'query_keys']));
                    $hintKey = hash('sha256', json_encode($hint));
                    if (count($hints) < 32) {
                        $hints[$hintKey] = $hint;
                    }
                }
            }
            foreach ($e['port_scan_targets'] ?? [] as $pt) {
                $key = $pt['peer_ip'];
                if (! isset($portTargets[$key]) && count($portTargets) >= 64) {
                    $capped = true;

                    continue;
                }
                $old = $portTargets[$key] ?? ['peer_ip' => $key, 'port_count' => 0, 'ports' => [], 'truncated' => false];
                $ports = array_unique(array_merge($old['ports'], $pt['ports']));
                sort($ports);
                $portTargets[$key] = ['peer_ip' => $key, 'port_count' => max($old['port_count'], $pt['port_count'], count($ports)), 'ports' => array_slice($ports, 0, 64), 'truncated' => $old['truncated'] || $pt['truncated'] || count($ports) > 64];
            }
            $capped = $capped || ($e['outbound_samples_truncated'] ?? false) || ($e['cardinality_capped'] ?? false);
        }
        uasort($udpTargets, fn ($a, $b) => $b['packets_out'] <=> $a['packets_out']);
        $udpTotals['capped'] = $udpTotals['capped'] || count($udpTargets) > 32;
        uasort($targets, fn ($a, $b) => $b['attempts'] <=> $a['attempts']);
        uasort($portTargets, fn ($a, $b) => $b['port_count'] <=> $a['port_count']);
        if (! $metrics) {
            $gaps[] = '此事件没有可用的流量窗口，可能已过保存期限；规则与 PCAP 证据仍可单独查看';
        }
        if ($totals['paired_windows'] !== count($metrics)) {
            $gaps[] = '部分窗口来自旧 Agent，完整握手比例只针对有新版统计的窗口';
        }
        if ($capped || count($targets) > 32 || count($portTargets) > 16) {
            $gaps[] = '目标、端口和请求线索为有界样本，数量是保守下界，不能覆盖所有连接';
        }
        $gaps[] = '载荷包含可能的重传；观察时长仅限发起连接前 60 秒，不是完整连接寿命。HTTPS 路径和正文不可见';
        $labels = ['behavior_notice' => '一般行为提醒', 'needs_review' => '疑似异常，待复核', 'strong_anomaly' => '强异常证据，优先复核'];

        return ['version' => 1, 'generated_at' => gmdate('c'), 'event' => array_intersect_key($event, array_flip(['id', 'ip', 'node_name', 'title', 'status', 'severity', 'first_seen_at', 'last_seen_at', 'review_notes', 'reopen_reason'])) + ['kinds' => $eventKinds],
            'category' => $category, 'conclusion' => $labels[$category] ?? $labels['needs_review'], 'reasons' => array_map(fn ($v) => mb_substr($v, 0, 512), array_slice(array_values(array_unique($reasons)), 0, 16)),
            'normal_explanations' => array_map(fn ($v) => mb_substr($v, 0, 512), array_slice(array_values(array_unique($explanations)), 0, 8)), 'evidence_gaps' => array_map(fn ($v) => mb_substr($v, 0, 512), array_slice(array_values(array_unique($gaps)), 0, 16)),
            'next_steps' => ['核对目标与域名是否符合客户申报业务', '根据时间趋势核查是否持续扩散；证据不足可继续观察或定向抓包', '认证失败及应用攻击需要服务日志；需要时手动提交 AI 辅助分析'],
            'udp_totals' => $udpTotals, 'udp_targets' => array_values(array_slice($udpTargets, 0, 32)),
            'totals' => $totals, 'timeline' => $timeline, 'targets' => array_values(array_slice($targets, 0, 32)), 'port_targets' => array_values(array_slice($portTargets, 0, 16)),
            'request_hints' => array_values($hints), 'quality' => self::decode($event['quality']), 'scope' => '事件内最后一小时、最多 120 个流量窗口；目标汇总最多 32 项，端口汇总最多 16 个目标。无需 AI，无外部调用'];
    }
}
