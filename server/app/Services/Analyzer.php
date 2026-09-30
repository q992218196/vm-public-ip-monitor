<?php

namespace App\Services;

use App\Jobs\SendAlertEmail;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\IpObservation;
use App\Models\Node;
use App\Models\ProtocolObservation;
use App\Models\Rule;
use App\Models\TrafficMetric;
use App\Models\Website;
use App\Support\Ip;
use Carbon\CarbonImmutable;

class Analyzer
{
    private array $observed = [];

    private $rules;

    private $exclusions;

    public function process(Batch $batch): void
    {
        $node = $batch->node;
        $p = $batch->payload;
        $at = $batch->window_end;
        $this->observed = [];
        $this->rules = Rule::where('enabled', true)->where(fn ($q) => $q->whereNull('node_id')->orWhere('node_id', $node->id))->get();
        $this->exclusions = Exclusion::where('expires_at', '>', $at)->where(fn ($q) => $q->whereNull('node_id')->orWhere('node_id', $node->id))->get();
        foreach ($p['metrics'] as $m) {
            $asset = $this->observe($m['ip'], $node, $at);
            TrafficMetric::create(['node_id' => $node->id, 'ip_asset_id' => $asset->id, 'batch_id' => $batch->id, 'window_start' => $batch->window_start, 'window_end' => $at,
                ...array_intersect_key($m, array_flip(['bytes_out', 'bytes_in', 'packets_out', 'packets_in', 'tcp_attempts'])), 'evidence' => $m]);
            $this->detect($node, $asset, $batch);
        }
        foreach ($p['sites'] as $s) {
            $asset = $this->observe($s['ip'], $node, $at);
            $key = hash('sha256', implode('|', [$s['ip'], $s['port'], $s['scheme'], $s['host']]));
            $website = Website::firstOrCreate(['fingerprint' => $key], ['ip_asset_id' => $asset->id, 'port' => $s['port'], 'scheme' => $s['scheme'], 'host' => $s['host'], 'source' => $s['source'], 'first_seen_at' => $at, 'last_seen_at' => $at]);
            if ($website->last_seen_at->lt($at)) {
                $website->update(['last_seen_at' => $at]);
            }
        }
        $vpnRule = $this->rules->where('kind', 'vpn_protocol')->sortByDesc(fn ($rule) => $rule->node_id !== null)->first();
        foreach ($p['vpn'] ?? [] as $observation) {
            $asset = $this->observe($observation['ip'], $node, $at);
            $stored = ProtocolObservation::create([
                'batch_id' => $batch->id,
                'node_id' => $node->id,
                'ip_asset_id' => $asset->id,
                'protocol' => $observation['protocol'],
                'peer_ip' => $observation['peer_ip'],
                'local_port' => $observation['local_port'],
                'peer_port' => $observation['peer_port'],
                'window_start' => $batch->window_start,
                'window_end' => $at,
                'evidence' => $observation,
            ]);
            if ($vpnRule) {
                if ($this->isExcluded($asset->ip, 'vpn_protocol')) {
                    continue;
                }
                if (min($observation['request_count'], $observation['response_count']) < $vpnRule->threshold) {
                    continue;
                }
                $label = match ($observation['protocol']) {
                    'wireguard' => 'WireGuard', 'openvpn' => 'OpenVPN', 'ikev2' => 'IKEv2/IPsec',
                };
                $evidence = $observation + [
                    'observation_id' => $stored->id,
                    'method' => '双向握手报文结构匹配',
                    'confidence' => 'protocol_signature',
                    'note' => '仅证明观察到与协议握手一致的报文结构；不证明隧道已建立、认证成功或用途违规。',
                ];
                $salt = implode('|', [$observation['protocol'], $observation['peer_ip'], $observation['local_port'], $observation['peer_port']]);
                $this->alert($node, $asset, 'vpn_protocol', $vpnRule->severity, '观察到 '.$label.' 双向握手特征', $evidence, $at, $vpnRule->cooldown_seconds, $salt);
            }
        }
        $proxyRule = $this->rules->where('kind', 'proxy_suspect')->sortByDesc(fn ($rule) => $rule->node_id !== null)->first();
        foreach ($p['proxies'] ?? [] as $observation) {
            $asset = $this->observe($observation['ip'], $node, $at);
            $candidates = match ($observation['transport']) {
                'opaque_tcp' => ['Shadowsocks (SS)', 'ShadowsocksR (SSR)', 'VMess'],
                'opaque_udp' => ['Shadowsocks (SS)', 'ShadowsocksR (SSR)', 'Hysteria（混淆）'],
                'tls' => ['Trojan/Trojan-Go', 'VLESS', 'AnyTLS', 'VMess', 'Shadowsocks (SS)/SSR（插件）'],
                'quic' => ['Hysteria', '其他 QUIC 应用'],
            };
            $recordEvidence = $observation + [
                'candidate_protocols' => $candidates,
                'method' => '同端口多对端双向加密传输外观与同窗口多目标出站 TCP 连接相关',
                'confidence' => 'behavioral_suspect',
                'note' => '只能说明流量样态可疑；候选协议不能区分或确认，出站目标也可能属于其他业务。普通网站、游戏或其他加密服务可能出现相同特征。',
            ];
            $stored = ProtocolObservation::create([
                'batch_id' => $batch->id,
                'node_id' => $node->id,
                'ip_asset_id' => $asset->id,
                'protocol' => $observation['transport'],
                'peer_ip' => $observation['peer_samples'][0],
                'local_port' => $observation['local_port'],
                'peer_port' => 0,
                'window_start' => $batch->window_start,
                'window_end' => $at,
                'evidence' => $recordEvidence,
            ]);
            if (! $proxyRule || $observation['peer_count'] < max(3, $proxyRule->threshold) || $observation['egress_target_count'] < 5) {
                continue;
            }
            if ($this->isExcluded($asset->ip, 'proxy_suspect')) {
                continue;
            }
            $evidence = $recordEvidence + ['observation_id' => $stored->id];
            $salt = implode('|', [$observation['local_port'], $observation['transport']]);
            $this->alert($node, $asset, 'proxy_suspect', $proxyRule->severity, '疑似加密代理样态（未确认协议）', $evidence, $at, $proxyRule->cooldown_seconds, $salt);
        }
        $h = $p['health'];
        if (($h['kernel_drops'] ?? 0) + ($h['state_dropped'] ?? 0) + ($h['spool_dropped'] ?? 0) > 0) {
            $this->alert($node, null, 'capture_degraded', 'medium', '采集覆盖下降', $h, $at, 600);
        }
    }

    private function observe(string $ip, Node $node, $at): IpAsset
    {
        if (isset($this->observed[$ip])) {
            return $this->observed[$ip];
        }
        $asset = IpAsset::firstOrCreate(['ip' => $ip], ['version' => str_contains($ip, ':') ? 6 : 4, 'first_seen_at' => $at, 'last_seen_at' => $at]);
        $asset = IpAsset::whereKey($asset->id)->lockForUpdate()->firstOrFail();
        if ($asset->last_seen_at->lt($at)) {
            $asset->update(['last_seen_at' => $at]);
        }
        if ($asset->first_seen_at->gt($at)) {
            $asset->update(['first_seen_at' => $at]);
        }
        $o = IpObservation::firstOrCreate(['ip_asset_id' => $asset->id, 'node_id' => $node->id], ['first_seen_at' => $at, 'last_seen_at' => $at]);
        if (CarbonImmutable::parse($o->last_seen_at)->lt($at)) {
            $o->update(['last_seen_at' => $at]);
        }

        return $this->observed[$ip] = $asset;
    }

    private function detect(Node $node, IpAsset $asset, Batch $batch): void
    {
        if ($this->rules->isEmpty()) {
            return;
        }
        $history = TrafficMetric::where('node_id', $node->id)->where('ip_asset_id', $asset->id)->where('window_end', '>', $batch->window_end->copy()->subSeconds($this->rules->max('window_seconds')))->where('window_end', '<=', $batch->window_end)->orderBy('window_end')->get();
        foreach ($this->rules as $rule) {
            if ($this->isExcluded($asset->ip, $rule->kind)) {
                continue;
            }
            $cutoff = $batch->window_end->copy()->subSeconds($rule->window_seconds);
            $rows = $history->filter(fn ($row) => $row->window_end->gt($cutoff));
            $value = match ($rule->kind) {
                'horizontal_scan' => (int) $rows->max(fn ($m) => $m->evidence['unique_targets'] ?? 0),
                'vertical_scan' => (int) $rows->max(fn ($m) => $m->evidence['max_ports_per_target'] ?? 0),
                'suspected_bruteforce' => (int) $rows->max(fn ($m) => $m->evidence['auth_attempts'] ?? 0),
                'single_target_attempts' => (int) $rows->max(fn ($m) => $m->evidence['max_attempts_per_target'] ?? 0),
                'tcp_connection_burst' => (int) $rows->sum('tcp_attempts'),
                'egress_mbps' => (int) ($rows->sum('bytes_out') * 8 / max(1, $rows->sum(fn ($m) => $m->window_start->diffInSeconds($m->window_end))) / 1000000),
                default => 0,
            };
            if ($value < $rule->threshold) {
                continue;
            }
            $title = match ($rule->kind) {
                'horizontal_scan' => '疑似对外横向扫描','vertical_scan' => '疑似对外端口扫描','suspected_bruteforce' => '疑似认证服务高频连接',
                'single_target_attempts' => '单目标高频连接','tcp_connection_burst' => 'TCP 连接突增',default => '出站流量超出阈值'
            };
            $note = match ($rule->kind) {
                'horizontal_scan', 'vertical_scan' => '仅当前观察节点；跨窗口取最大值，目标/端口数是保守下界',
                'suspected_bruteforce' => '按单目标认证端口连接计数，不代表登录失败或密码爆破已发生',
                'single_target_attempts' => '按单目标 TCP 发起计数，可能是正常重连；不代表登录失败',
                'tcp_connection_burst' => '按窗口累积 TCP 发起计数，可能包含正常高并发连接',
                default => '按当前观察节点估算的出站速率',
            };
            $sample = match ($rule->kind) {
                'horizontal_scan' => $rows->sortByDesc(fn ($row) => $row->evidence['unique_targets'] ?? 0)->first(),
                'vertical_scan' => $rows->sortByDesc(fn ($row) => $row->evidence['max_ports_per_target'] ?? 0)->first(),
                'suspected_bruteforce' => $rows->sortByDesc(fn ($row) => $row->evidence['auth_attempts'] ?? 0)->first(),
                'single_target_attempts' => $rows->sortByDesc(fn ($row) => $row->evidence['max_attempts_per_target'] ?? 0)->first(),
                default => $rows->last(),
            };
            $sampleEvidence = $sample?->evidence ?? [];
            $severity = $rule->severity;
            $confidence = 'behavioral';
            if ($rule->kind === 'horizontal_scan') {
                if (!array_key_exists('synack_replies', $sampleEvidence)) {
                    $note .= '；当前 Agent 未上报 SYN-ACK 响应数，无法判断连接是否得到回复';
                } else {
                    $attempts = (int) ($sampleEvidence['tcp_attempts'] ?? 0);
                    $replies = (int) $sampleEvidence['synack_replies'];
                    $out = (int) ($sampleEvidence['bytes_out'] ?? 0);
                    $in = (int) ($sampleEvidence['bytes_in'] ?? 0);
                    if ($attempts >= $rule->threshold && $replies * 10 >= $attempts * 7
                        && (int) ($sampleEvidence['max_ports_per_target'] ?? 0) <= 1
                        && (int) ($sampleEvidence['max_attempts_per_target'] ?? 0) <= 2
                        && min($out, $in) >= 262144 && max($out, $in) <= min($out, $in) * 4) {
                        $severity = $severity === 'high' ? 'medium' : $severity;
                        $title = '疑似多目标双向连接（待复核）';
                        $confidence = 'bidirectional_candidate';
                        $note .= '；多数 TCP 发起收到 SYN-ACK，且单目标连接少、双向流量明显，可能是正常组网或 P2P；仍需人工核对业务用途';
                    } else {
                        $note .= '；Agent 记录到 '.min($replies, $attempts).'/'.$attempts.' 次 TCP 发起获得 SYN-ACK，出入总字节可能混合了其他已建立连接，不能单独证明这些目标均正常响应；高级别表示优先复核，不代表已确认违规';
                    }
                }
            }
            $this->alert($node, $asset, $rule->kind, $severity, $title, ['rule_id' => $rule->id, 'value' => $value, 'threshold' => $rule->threshold, 'window_seconds' => $rule->window_seconds, 'sample' => $sampleEvidence, 'confidence' => $confidence, 'note' => $note], $batch->window_end, $rule->cooldown_seconds, (string) $rule->id);
        }
    }

    private function isExcluded(string $ip, string $kind): bool
    {
        return $this->exclusions->contains(fn ($exclusion) => ($exclusion->kind === null || $exclusion->kind === $kind)
            && Ip::contains($exclusion->cidr, $ip));
    }

    public function alert(Node $node, ?IpAsset $asset, string $kind, string $severity, string $title, array $evidence, $at, int $cooldown = 600, string $salt = ''): Alert
    {
        $key = hash('sha256', implode('|', [$node->id, $asset?->id, $kind, $salt, intdiv($at->getTimestamp(), max(1, $cooldown))]));
        $alert = Alert::firstOrCreate(['dedup_key' => $key], ['node_id' => $node->id, 'ip_asset_id' => $asset?->id, 'kind' => $kind, 'severity' => $severity, 'title' => $title, 'evidence' => $evidence, 'first_seen_at' => $at, 'last_seen_at' => $at]);
        if ($alert->wasRecentlyCreated && config('monitor.alert_email')) {
            SendAlertEmail::dispatch($alert->id)->afterCommit();
        }
        if (! $alert->wasRecentlyCreated) {
            $alert->update(['occurrences' => $alert->occurrences + 1, 'last_seen_at' => max($alert->last_seen_at, $at), 'evidence' => $evidence]);
        }

        return $alert;
    }
}
