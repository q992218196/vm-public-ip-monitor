<?php

namespace App\Http\Controllers;

use App\Models\Batch;
use App\Models\Node;
use App\Support\Ip;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class IngestController extends Controller
{
    public function __invoke(Request $r)
    {
        abort_if(strlen($r->getContent()) > 8 * 1024 * 1024, 413);
        $v = $r->validate([
            'batch_id' => 'required|string|regex:/^[a-zA-Z0-9-]{16,64}$/',
            'window_start' => 'required|date', 'window_end' => 'required|date|after:window_start',
            'health' => 'required|array', 'health.version' => 'required|string|max:32',
            'health.update_error' => 'sometimes|string|max:255',
            'health.interfaces' => 'sometimes|array|max:8', 'health.interfaces.*' => 'string|max:64',
            'health.*' => ['nullable'],
            'metrics' => 'present|array|max:8192', 'sites' => 'present|array|max:4096', 'vpn' => 'sometimes|array|max:2048', 'proxies' => 'sometimes|array|max:256',
            'proxies.*.ip' => 'required|ip', 'proxies.*.local_port' => 'required|integer|min:1|max:65535',
            'proxies.*.transport' => 'required|in:opaque_tcp,opaque_udp,tls,quic',
            'proxies.*.peer_count' => 'required|integer|min:3|max:4096', 'proxies.*.session_count' => 'required|integer|min:3|max:4096',
            'proxies.*.bytes_from_peers' => 'required|integer|min:0|max:1000000000000000',
            'proxies.*.bytes_to_peers' => 'required|integer|min:0|max:1000000000000000',
            'proxies.*.peer_samples' => 'required|array|min:1|max:8', 'proxies.*.peer_samples.*' => 'ip',
            'proxies.*.egress_target_count' => 'required|integer|min:5|max:256',
            'proxies.*.egress_target_samples' => 'required|array|min:1|max:8', 'proxies.*.egress_target_samples.*' => 'ip',
            'vpn.*.ip' => 'required|ip', 'vpn.*.peer_ip' => 'required|ip',
            'vpn.*.local_port' => 'required|integer|min:1|max:65535', 'vpn.*.peer_port' => 'required|integer|min:1|max:65535',
            'vpn.*.protocol' => 'required|in:wireguard,openvpn,ikev2', 'vpn.*.initiator' => 'required|in:vm,peer',
            'vpn.*.request_count' => 'required|integer|min:1|max:1000000', 'vpn.*.response_count' => 'required|integer|min:1|max:1000000',
            'vpn.*.request_length' => 'required|integer|min:8|max:65535', 'vpn.*.response_length' => 'required|integer|min:8|max:65535',
            'vpn.*.request_header' => 'required|string|regex:/^[a-f0-9]{16}$/', 'vpn.*.response_header' => 'required|string|regex:/^[a-f0-9]{16}$/',
            'metrics.*.ip' => 'required|ip', 'metrics.*.targets' => 'present|array|max:16', 'metrics.*.targets.*' => 'ip',
            'metrics.*.ports' => 'sometimes|array|max:64', 'metrics.*.ports.*' => 'integer|min:1|max:65535',
            'metrics.*.target_endpoints' => 'sometimes|array|max:32', 'metrics.*.target_endpoints.*' => 'string|max:64',
            'metrics.*.port_samples_truncated' => 'sometimes|boolean', 'metrics.*.endpoint_samples_truncated' => 'sometimes|boolean',
            'metrics.*.cardinality_capped' => 'required|boolean',
            'metrics.*.udp_stats_version' => 'sometimes|integer|in:1',
            'metrics.*.udp_flows_capped' => 'sometimes|boolean', 'metrics.*.udp_endpoints_truncated' => 'sometimes|boolean',
            ...collect(['udp_flows_out', 'udp_packets_out', 'udp_packets_in', 'udp_bytes_out', 'udp_bytes_in'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'required_with:metrics.*.udp_stats_version|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.udp_endpoints' => 'sometimes|array|max:8',
            'metrics.*.udp_endpoints.*' => 'array:peer_ip,peer_port,flows,packets_out,packets_in,bytes_out,bytes_in',
            'metrics.*.udp_endpoints.*.peer_ip' => 'required|ip', 'metrics.*.udp_endpoints.*.peer_port' => 'required|integer|min:0|max:65535',
            ...collect(['flows', 'packets_out', 'packets_in', 'bytes_out', 'bytes_in'])->mapWithKeys(fn ($f) => ["metrics.*.udp_endpoints.*.$f" => 'required|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.synack_replies' => 'sometimes|integer|min:0|max:1000000000000000',
            'metrics.*.connection_stats_version' => 'sometimes|integer|in:1',
            ...collect(['completed_handshakes', 'rst_replies', 'mature_attempts', 'mature_no_reply'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'sometimes|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.port_scan_targets' => 'sometimes|array|max:8',
            'metrics.*.port_scan_targets.*' => 'array:peer_ip,port_count,ports,truncated',
            'metrics.*.port_scan_targets.*.peer_ip' => 'required|ip',
            'metrics.*.port_scan_targets.*.port_count' => 'required|integer|min:1|max:256',
            'metrics.*.port_scan_targets.*.ports' => 'required|array|max:32',
            'metrics.*.port_scan_targets.*.ports.*' => 'integer|min:1|max:65535',
            'metrics.*.port_scan_targets.*.truncated' => 'required|boolean',
            'metrics.*.outbound_samples_truncated' => 'sometimes|boolean',
            'metrics.*.outbound_endpoints' => 'sometimes|array|max:8',
            'metrics.*.outbound_endpoints.*' => 'array:peer_ip,peer_port,attempts,synack_replies,payload_out,payload_in,scheme,host,http_method,http_path,query_keys,completed_handshakes,rst_replies,max_observed_span_ms',
            ...collect(['completed_handshakes', 'rst_replies'])->mapWithKeys(fn ($f) => ["metrics.*.outbound_endpoints.*.$f" => 'sometimes|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.outbound_endpoints.*.max_observed_span_ms' => 'sometimes|integer|min:0|max:60000',
            'metrics.*.outbound_endpoints.*.peer_ip' => 'required|ip',
            'metrics.*.outbound_endpoints.*.peer_port' => 'required|integer|min:1|max:65535',
            'metrics.*.outbound_endpoints.*.attempts' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.synack_replies' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.payload_out' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.payload_in' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.scheme' => 'sometimes|in:http,https',
            'metrics.*.outbound_endpoints.*.host' => 'sometimes|string|max:253',
            'metrics.*.outbound_endpoints.*.http_method' => 'sometimes|in:GET,HEAD,POST,PUT,OPTIONS,DELETE,PATCH',
            'metrics.*.outbound_endpoints.*.http_path' => 'sometimes|string|max:256',
            'metrics.*.outbound_endpoints.*.query_keys' => 'sometimes|array|max:8',
            'metrics.*.outbound_endpoints.*.query_keys.*' => 'string|max:32',
            'sites.*.ip' => 'required|ip', 'sites.*.port' => 'required|integer|min:1|max:65535',
            'sites.*.scheme' => 'required|in:http,https', 'sites.*.host' => ['present', 'nullable', 'string', 'max:253', 'regex:/^[a-zA-Z0-9.\-:\[\]]*$/'],
            'sites.*.source' => 'required|in:http_host,tls_sni',
            ...collect(['bytes_out', 'bytes_in', 'packets_out', 'packets_in', 'tcp_attempts', 'unique_targets', 'max_ports_per_target', 'max_attempts_per_target', 'auth_attempts'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'required|integer|min:0|max:1000000000000000'])->all(),
        ]);
        $start = CarbonImmutable::parse($v['window_start']);
        $end = CarbonImmutable::parse($v['window_end']);
        if ($end->isAfter(now()->addMinutes(5)) || $start->isBefore(now()->subDays(14)) || $start->diffInSeconds($end) > 600) {
            throw ValidationException::withMessages(['window_start' => '窗口必须在过去14天内、长度不超过600秒，未来偏差不超过5分钟']);
        }
        $node = $r->attributes->get('node');
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
        foreach ($v['metrics'] as $index => $metric) {
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
        }
        // A durable DB inbox is the acknowledgement boundary. The scheduler retries
        // undispatched rows after crashes / Redis outages; no event is acked in RAM.
        $duplicate = DB::transaction(function () use ($node, $v, $start, $end) {
            $locked = Node::whereKey($node->id)->lockForUpdate()->firstOrFail();
            $exists = Batch::where('node_id', $node->id)->where('batch_id', $v['batch_id'])->exists();
            if (! $exists) {
                $bytes = strlen(json_encode($v));
                $pending = Batch::where('node_id', $node->id)->whereNull('processed_at')->sum('payload_bytes');
                abort_if($pending + $bytes > config('monitor.pending_bytes_per_node'), 429, '节点接收队列已达容量上限，请等待分析完成');
                Batch::create(['node_id' => $node->id, 'batch_id' => $v['batch_id'], 'payload' => $v, 'payload_bytes' => $bytes, 'window_start' => $start, 'window_end' => $end]);
            }
            $locked->update(['last_seen_at' => now()]);
            if (! $locked->health_observed_at || $locked->health_observed_at->lte($end)) {
                $locked->update(['health' => $v['health'], 'health_observed_at' => $end]);
            }

            return $exists;
        });

        return response()->json(['accepted' => true, 'duplicate' => $duplicate]);
    }
}
