<?php

namespace App\Services;

class ConnectionAssessment
{
    public const KINDS = ['horizontal_scan', 'suspected_bruteforce', 'single_target_attempts', 'tcp_connection_burst', 'egress_mbps', 'smb_connections', 'ssh_target_spread', 'rdp_target_spread', 'ftp_target_spread', 'udp_flow_burst', 'udp_packet_rate'];

    public function assess(string $kind, array $sample, int $threshold = 0, string $ceiling = 'high', array $windows = []): array
    {
        if (ServiceConnectionRules::countsTargets($kind)) {
            return $this->assessServiceTargets($kind, $sample, $threshold, $ceiling);
        }
        if (in_array($kind, ['udp_flow_burst', 'udp_packet_rate'], true)) {
            $reasons = ['UDP 流数量或包速率达到阈值，只证明流量活跃，不能直接判断攻击', 'UDP 流按单采集窗口内不同五元组计数，重复包不增加流数，服务回复也可能计入出站流；不是连接握手或应用请求数'];
            if (($sample['udp_filter_version'] ?? 0) === 1) {
                $reasons[] = '两个 UDP 规则均排除目标端口 53；原始流量与抓包保留 DNS，源端口 53 的出站回复不在排除范围';
            }
            $gaps = ['DNS、QUIC、游戏、音视频和业务突发都可能符合；无 TCP 握手，不能计算握手成功率或把双向包视为认证成功', '目标样本最多 8 条，包速率按实际覆盖窗口时长计算，不代表未采集时间的速率'];
            if (($sample['udp_flows_capped'] ?? false) || ($sample['udp_endpoints_truncated'] ?? false)) {
                $gaps[] = 'UDP 状态触及限额或目标样本截断，计数是观察下界，业务例外不自动放行';
            }

            return ['severity' => 'low', 'title' => $kind === 'udp_flow_burst' ? 'UDP 出站流数量提醒' : 'UDP 出站包速率提醒', 'confidence' => 'limited_behavior', 'note' => implode('。', [...$reasons, ...$gaps]), 'connection_analysis' => [
                'assessment_version' => 3, 'category' => 'behavior_notice', 'conclusion' => $reasons[0], 'reasons' => $reasons, 'evidence_gaps' => $gaps,
                'udp_flows_out' => $sample['udp_flows_out'] ?? null, 'udp_packets_out' => $sample['udp_packets_out'] ?? null, 'completion_ratio' => null,
                'normal_explanations' => ['DNS、QUIC、游戏、音视频、业务突发或服务回复'], 'next_steps' => ['核对主要目标与端口、客户业务和历史趋势', '无法判断时申请定向抓包，不凭数量直接认定 UDP 攻击'],
            ]];
        }
        $attempts = (int) ($sample['tcp_attempts'] ?? 0);
        $completed = $sample['completed_handshakes'] ?? null;
        $resets = $sample['rst_replies'] ?? null;
        $mature = $sample['mature_attempts'] ?? null;
        $missing = $sample['mature_no_reply'] ?? null;
        $service = isset(ServiceConnectionRules::RULES[$kind]);
        $paired = ($sample['connection_stats_version'] ?? 0) === 1 && $attempts > 0 && is_int($completed) && is_int($resets)
            && min($completed, $resets) >= 0 && max($completed, $resets) <= $attempts
            && ($service && $mature === null && $missing === null || is_int($mature) && is_int($missing) && min($mature, $missing) >= 0 && $mature <= $attempts && $missing <= $mature);
        $qualityGood = $this->qualityGood($sample);
        $titles = ['horizontal_scan' => '多目标连接（待复核）', 'suspected_bruteforce' => '认证服务重复连接（待复核）', 'single_target_attempts' => '单目标高频连接提醒', 'tcp_connection_burst' => 'TCP 连接数量提醒', 'egress_mbps' => '出站带宽提醒'];
        foreach (ServiceConnectionRules::RULES as $serviceKind => $definition) {
            $titles[$serviceKind] = $definition['name'].'（待复核）';
        }
        $scan = $kind === 'horizontal_scan';
        $severity = $scan || $service || $kind === 'suspected_bruteforce' ? 'medium' : 'low';
        $category = $severity === 'low' ? 'behavior_notice' : 'needs_review';
        $reasons = [$scan ? '目标或端口数量达到规则阈值，仍需区分业务连接与探测行为' : '连接数量或带宽阈值只能证明活跃程度，不能证明攻击'];
        if ($service) {
            $reasons[] = '仅统计有界目标样本中最活跃目标的连接下界，跨窗口取最大值；常见端口只提示服务类型，不代表已观察登录失败或爆破';
            $reasons[] = '规则计数是主动 TCP 建连尝试（SYN 有界去重），连接后的数据交互不增加次数；完整握手数另列，未成功的发起仍保留用于扫描核查';
        }
        $sustained = count(array_filter($windows, fn ($window) => $this->rejectionPattern($window, $kind, $threshold)));
        if ($scan && $paired && $qualityGood && $sustained >= 2 && $this->rejectionPattern($sample, $kind, $threshold)) {
            $severity = 'high';
            $category = 'strong_anomaly';
            $reasons[] = '至少两个采集窗口内出现扩散、多数配对拒绝响应和较少完整握手；优先复核，不等于已确认攻击';
        } elseif ($paired && $completed / $attempts >= 0.7) {
            $reasons[] = '多数 TCP 发起观察到完整三次握手，存在正常业务解释；仍不能排除应用层异常';
        } elseif ($paired && $resets / $attempts >= 0.5) {
            $severity = 'medium';
            $category = 'needs_review';
            $reasons[] = '较多连接观察到配对 RST，可能是拒绝、服务故障或探测，需要结合目标和时间核查';
        }
        $gaps = ['旁路采集无法读取 HTTPS 正文、认证失败结果或确定加密代理协议；必要时提供服务日志'];
        if (! $paired) {
            $gaps[] = '缺少新版本配对统计或计数不一致，不计算完整握手比例，不支持自动高风险定性';
        }
        if (! $qualityGood) {
            $gaps[] = '本窗口采集质量未知、存在漏采/状态限额或目标计数截断；不支持自动高风险定性';
        }
        if (($sample['capture_quality']['reassembly_dropped'] ?? 0) > 0) {
            $gaps[] = '存在请求头重组丢弃，可见域名和路径只是部分线索';
        }
        if ($paired && $missing > 0) {
            $gaps[] = '等待至少 3 秒后仍未观察到回复仅是观察事实，可能受到防火墙、单向可见性及窗口边界影响';
        }
        $ranks = ['low' => 1, 'medium' => 2, 'high' => 3];
        if (($ranks[$ceiling] ?? 3) < $ranks[$severity]) {
            $severity = $ceiling;
            $category = $severity === 'low' ? 'behavior_notice' : 'needs_review';
        }

        return ['severity' => $severity, 'title' => $titles[$kind] ?? '连接行为待复核', 'confidence' => $paired && $qualityGood ? 'paired_transport' : 'limited_behavior',
            'note' => implode('。', $reasons).'。'.implode('。', $gaps),
            'connection_analysis' => ['assessment_version' => 2, 'category' => $category, 'conclusion' => $reasons[0], 'reasons' => $reasons, 'evidence_gaps' => $gaps,
                'tcp_attempts' => $attempts, 'synack_replies' => $sample['synack_replies'] ?? null, 'completed_handshakes' => $paired ? $completed : null,
                'reply_ratio' => $paired && is_int($sample['synack_replies'] ?? null) && $sample['synack_replies'] >= 0 && $sample['synack_replies'] <= $attempts ? round($sample['synack_replies'] / $attempts, 4) : null,
                'completion_ratio' => $paired ? round($completed / $attempts, 4) : null, 'rst_replies' => $paired ? $resets : null,
                'mature_attempts' => $paired ? $mature : null, 'mature_no_reply' => $paired ? $missing : null,
                'quality_good' => $qualityGood, 'sustained_rejection_windows' => $sustained,
                'normal_explanations' => ['网站/API 调用、监控和重试、软件更新、客户申报的并发业务', '目标服务拒绝或网络故障也可能导致大量 RST'],
                'next_steps' => ['核对主要目标、端口、可见域名和路径是否符合申报业务', '结合趋势确认是否持续扩散；证据不足时申请定向抓包', '认证或应用攻击需要服务访问/登录日志佐证']]];
    }

    private function qualityGood(array $sample): bool
    {
        $q = $sample['capture_quality'] ?? [];

        return ($q['captured'] ?? 0) > 0 && ($q['state_dropped'] ?? -1) === 0 && ($q['kernel_drops'] ?? PHP_INT_MAX) / max(1, $q['captured']) <= 0.01
            && ($q['decode_skipped'] ?? PHP_INT_MAX) / max(1, $q['captured']) <= 0.1 && ! ($sample['cardinality_capped'] ?? false);
    }

    private function assessServiceTargets(string $kind, array $sample, int $threshold, string $ceiling): array
    {
        $valid = ($sample['service_target_stats_version'] ?? 0) === 1 && ($sample['unique_targets'] ?? 0) >= max(2, $threshold);
        $severity = $valid && $ceiling !== 'low' ? 'medium' : 'low';
        $reasons = ['同一公网 IP 在规则覆盖范围内向多个不同目标 IP 的指定服务端口主动建连，需核实业务授权与探测用途',
            '同一目标跨窗口、跨 FTP 控制端口只算一个 IP；SYN 重传及连接后的交互不增加目标数，同目标反复重连不单凭次数告警'];
        $gaps = ['端口仅提供 RDP、SSH 或 FTP 服务线索，不能确认实际协议；多目标行为也可能是授权运维、监控或批量任务',
            '完整 TCP 握手不等于登录成功，不能据此排除爆破；加密认证结果不可观测，单目标爆破不在此规则覆盖范围',
            '仅使用配置时间范围内完整且支持服务目标统计的采集窗口；跨边界或旧 Agent 窗口不计入，可能存在观察间断'];
        if ($sample['service_targets_capped'] ?? false) {
            $gaps[] = '服务目标集合或状态触及容量上限，目标数是观察下界，业务白名单不自动放行';
        }
        if (! $this->qualityGood($sample)) {
            $gaps[] = '采集质量未知或存在漏采，观察到的目标数量不能代表全部行为';
        }

        return ['severity' => $severity, 'title' => ServiceConnectionRules::RULES[$kind]['name'].'（待复核）', 'confidence' => 'observed_target_spread',
            'note' => implode('。', [...$reasons, ...$gaps]), 'connection_analysis' => ['assessment_version' => 4,
                'category' => $severity === 'low' ? 'behavior_notice' : 'needs_review', 'conclusion' => $reasons[0], 'reasons' => $reasons, 'evidence_gaps' => $gaps,
                'count_basis' => 'distinct_service_target_ips', 'unique_targets' => $sample['unique_targets'] ?? 0,
                'tcp_attempts' => $sample['tcp_attempts'] ?? 0, 'completion_ratio' => null, 'login_failures' => null,
                'normal_explanations' => ['已授权的跨服务器运维、监控、批量管理或 FTP 文件分发'],
                'next_steps' => ['核对完整目标 IP 集合与服务端口是否在客户业务授权范围', '必要时申请定向抓包或认证日志，不把握手、RST 或目标数当作登录失败']]];
    }

    private function rejectionPattern(array $s, string $kind, int $threshold): bool
    {
        $n = (int) ($s['tcp_attempts'] ?? 0);

        return ($s['connection_stats_version'] ?? 0) === 1 && $n >= 50 && ($s['rst_replies'] ?? 0) <= $n && ($s['rst_replies'] ?? 0) / $n >= 0.5
            && ($s['completed_handshakes'] ?? $n) >= 0 && ($s['completed_handshakes'] ?? $n) / $n <= 0.1
            && ($s['mature_attempts'] ?? 0) >= 20 && ($s['mature_attempts'] ?? $n + 1) <= $n && $this->qualityGood($s)
            && ($s['unique_targets'] ?? 0) >= max(50, $threshold);
    }
}
