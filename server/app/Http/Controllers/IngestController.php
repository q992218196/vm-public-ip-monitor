<?php

namespace App\Http\Controllers;

use App\Models\Batch;
use App\Models\Node;
use App\Support\IngestPayloadValidator;
use App\Support\Ip;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class IngestController extends Controller
{
    public function __invoke(Request $r)
    {
        $wireBytes = strlen($r->getContent());
        abort_if($wireBytes > 8 * 1024 * 1024, 413);
        $node = $r->attributes->get('node');
        $identity = $r->validate(['batch_id' => 'required|string|regex:/^[a-zA-Z0-9-]{16,64}$/']);
        if (Batch::where('node_id', $node->id)->where('batch_id', $identity['batch_id'])->exists()) {
            return response()->json(['accepted' => true, 'duplicate' => true]);
        }
        // The durable acknowledgement already exists for duplicate batch IDs.
        // New payloads still receive a transaction-protected capacity check below.
        $pending = Batch::where('node_id', $node->id)->whereNull('processed_at')->sum('payload_bytes');
        abort_if($pending + $wireBytes > config('monitor.pending_bytes_per_node'), 429, '节点接收队列已达容量上限，请等待分析完成');
        $v = app(IngestPayloadValidator::class)->validate($r->all());
        $start = CarbonImmutable::parse($v['window_start']);
        $end = CarbonImmutable::parse($v['window_end']);
        if (! $end->isAfter($start)) {
            throw ValidationException::withMessages(['window_end' => '窗口结束时间必须晚于开始时间（按小数秒比较）']);
        }
        if ($end->isAfter(now()->addMinutes(5)) || $start->isBefore(now()->subDays(14)) || $start->diffInSeconds($end) > 600) {
            throw ValidationException::withMessages(['window_start' => '窗口必须在过去14天内、长度不超过600秒，未来偏差不超过5分钟']);
        }
        foreach ($v['sites'] as $index => &$site) {
            if ($site['source'] === 'http_response') {
                if (! isset($site['http_status']) || $site['scheme'] !== 'http') {
                    throw ValidationException::withMessages(["sites.$index.http_status" => '配对 HTTP 响应必须包含有效状态码，且为明文 HTTP']);
                }
                $site['http_status'] = (int) $site['http_status'];
            } elseif (isset($site['http_status'])) {
                throw ValidationException::withMessages(["sites.$index.http_status" => '仅配对 HTTP 响应来源可上报被动响应码']);
            }
        }
        unset($site);
        $seen = [];
        $v['vpn'] ??= [];
        $v['proxies'] ??= [];
        foreach (['metrics', 'sites', 'vpn', 'proxies'] as $type) {
            foreach ($v[$type] as &$item) {
                $item['ip'] = Ip::normalize($item['ip']);
                if ($type === 'vpn') {
                    $item['peer_ip'] = Ip::normalize($item['peer_ip']);
                }
                if ($type === 'proxies') {
                    $item['peer_samples'] = array_map(Ip::normalize(...), $item['peer_samples']);
                    $item['egress_target_samples'] = array_map(Ip::normalize(...), $item['egress_target_samples']);
                }
                if (! Ip::inRanges($item['ip'], $node->cidrs)) {
                    throw ValidationException::withMessages([$type => 'IP 不在该节点授权 CIDR 中']);
                }
                if ($type === 'metrics' && isset($seen[$item['ip']])) {
                    throw ValidationException::withMessages(['metrics' => '同一批次不能包含重复 IP']);
                }
                if ($type === 'metrics') {
                    $seen[$item['ip']] = true;
                }
                if ($type === 'sites') {
                    $item['host'] = strtolower(rtrim($item['host'] ?? '', '.'));
                }
            }
        } unset($item);
        $health = [];
        foreach (['captured', 'kernel_drops', 'decode_skipped', 'state_dropped', 'spool_dropped', 'duplicate_packets', 'reassembly_dropped', 'rss_bytes', 'heap_bytes', 'spool_bytes', 'disk_bytes'] as $f) {
            $n = $v['health'][$f] ?? 0;
            if (! is_int($n) || $n < 0) {
                throw ValidationException::withMessages(["health.$f" => '必须为非负整数']);
            }$health[$f] = $n;
        }
        $v['health'] = $health + ['version' => $v['health']['version'], 'interfaces' => $v['health']['interfaces'] ?? [], 'update_error' => $v['health']['update_error'] ?? null];
        foreach ($v['metrics'] as $index => &$metric) {
            if (array_key_exists('service_targets', $metric) || isset($metric['service_target_stats_version'])) {
                if (($metric['service_target_stats_version'] ?? 0) !== 1 || ! isset($metric['service_targets'])) {
                    throw ValidationException::withMessages(["metrics.$index.service_targets" => '服务目标统计版本或集合缺失']);
                }
                $services = [];
                $totalAttempts = 0;
                foreach ($metric['service_targets'] as $serviceIndex => $service) {
                    $targets = array_map(Ip::normalize(...), $service['targets']);
                    $allowedPorts = match ($service['service']) {
                        'ssh' => [22], 'rdp' => [3389], 'ftp' => [21, 990],
                    };
                    if (isset($services[$service['service']]) || count(array_unique($targets)) !== count($targets)
                        || count($targets) > $service['attempts'] || array_diff($service['ports'], $allowedPorts)
                        || count(array_unique($service['ports'])) !== count($service['ports'])) {
                        throw ValidationException::withMessages(["metrics.$index.service_targets.$serviceIndex" => '服务、去重目标、端口或建连统计不一致']);
                    }
                    $services[$service['service']] = true;
                    $totalAttempts += $service['attempts'];
                    $metric['service_targets'][$serviceIndex]['targets'] = $targets;
                }
                if ($totalAttempts > $metric['tcp_attempts']) {
                    throw ValidationException::withMessages(["metrics.$index.service_targets" => '服务建连尝试之和超过本窗口 TCP 发起总数']);
                }
            }
            if (($metric['udp_filter_version'] ?? 0) === 1) {
                if (($metric['udp_stats_version'] ?? 0) !== 1 || $metric['udp_non_dns_flows_out'] > $metric['udp_non_dns_packets_out'] || $metric['udp_non_dns_flows_out'] > $metric['udp_flows_out'] || $metric['udp_non_dns_packets_out'] > $metric['udp_packets_out']) {
                    throw ValidationException::withMessages(["metrics.$index.udp_filter_version" => '排除目标端口 53 后的 UDP 统计不一致']);
                }
                foreach ($metric['udp_non_dns_endpoints'] ?? [] as $endpoint) {
                    if ($endpoint['flows'] > $endpoint['packets_out'] || $endpoint['flows'] > $metric['udp_non_dns_flows_out'] || $endpoint['packets_out'] > $metric['udp_non_dns_packets_out'] || $endpoint['packets_in'] > $metric['udp_packets_in'] || $endpoint['bytes_out'] > $metric['udp_bytes_out'] || $endpoint['bytes_in'] > $metric['udp_bytes_in']) {
                        throw ValidationException::withMessages(["metrics.$index.udp_non_dns_endpoints" => '非 DNS 端点统计不一致']);
                    }
                }
            }
            if (($metric['udp_stats_version'] ?? 0) === 1) {
                if ($metric['udp_flows_out'] > $metric['udp_packets_out'] || $metric['udp_packets_out'] > $metric['packets_out'] || $metric['udp_packets_in'] > $metric['packets_in'] || $metric['udp_bytes_out'] > $metric['bytes_out'] || $metric['udp_bytes_in'] > $metric['bytes_in']) {
                    throw ValidationException::withMessages(["metrics.$index.udp_flows_out" => 'UDP 统计超过包数或整体流量']);
                }
                foreach ($metric['udp_endpoints'] ?? [] as $endpoint) {
                    if ($endpoint['flows'] > $endpoint['packets_out'] || $endpoint['packets_out'] > $metric['udp_packets_out'] || $endpoint['packets_in'] > $metric['udp_packets_in'] || $endpoint['bytes_out'] > $metric['udp_bytes_out'] || $endpoint['bytes_in'] > $metric['udp_bytes_in']) {
                        throw ValidationException::withMessages(["metrics.$index.udp_endpoints" => 'UDP 目标统计不一致']);
                    }
                }
            }
            if (($metric['connection_stats_version'] ?? 0) !== 1) {
                continue;
            }
            foreach (['completed_handshakes', 'rst_replies', 'mature_attempts', 'mature_no_reply', 'synack_replies'] as $counter) {
                if (! isset($metric[$counter]) || $metric[$counter] > $metric['tcp_attempts']) {
                    throw ValidationException::withMessages(["metrics.$index.$counter" => '新版配对统计缺失或超过本窗口发起数']);
                }
            }
            if ($metric['completed_handshakes'] > $metric['synack_replies'] || $metric['mature_no_reply'] > $metric['mature_attempts']) {
                throw ValidationException::withMessages(["metrics.$index.completed_handshakes" => '配对统计不一致']);
            }
            foreach ($metric['outbound_endpoints'] ?? [] as $endpoint) {
                if (($endpoint['completed_handshakes'] ?? 0) > ($endpoint['synack_replies'] ?? 0) || max($endpoint['completed_handshakes'] ?? 0, $endpoint['rst_replies'] ?? 0, $endpoint['synack_replies'] ?? 0) > $endpoint['attempts']) {
                    throw ValidationException::withMessages(["metrics.$index.outbound_endpoints" => '目标配对统计不一致']);
                }
            }
        } unset($metric);
        // A durable DB inbox is the acknowledgement boundary. The scheduler retries
        // undispatched rows after crashes / Redis outages; no event is acked in RAM.
        $duplicate = DB::transaction(function () use ($node, $v, $start, $end) {
            $locked = Node::whereKey($node->id)->lockForUpdate()->firstOrFail();
            $exists = Batch::where('node_id', $node->id)->where('batch_id', $v['batch_id'])->exists();
            if ($exists) {
                return true;
            }
            $bytes = strlen(json_encode($v));
            $pending = Batch::where('node_id', $node->id)->whereNull('processed_at')->sum('payload_bytes');
            abort_if($pending + $bytes > config('monitor.pending_bytes_per_node'), 429, '节点接收队列已达容量上限，请等待分析完成');
            Batch::create(['node_id' => $node->id, 'batch_id' => $v['batch_id'], 'payload' => $v, 'payload_bytes' => $bytes, 'window_start' => $start, 'window_end' => $end]);
            $locked->update(['last_seen_at' => now()]);
            if (! $locked->health_observed_at || $locked->health_observed_at->lte($end)) {
                $locked->update(['health' => $v['health'], 'health_observed_at' => $end]);
            }

            return false;
        });

        return response()->json(['accepted' => true, 'duplicate' => $duplicate]);
    }
}
