<?php

namespace App\Services;

use App\Jobs\SendAlertEmail;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\IpObservation;
use App\Models\Node;
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
            if ($website->wasRecentlyCreated) {
                $this->alert($node, $asset, 'new_website', 'low', '发现新网站线索', ['website_id' => $website->id, 'port' => $s['port'], 'scheme' => $s['scheme'], 'host' => $s['host'], 'verification' => '尚未主动验证'], $at, 86400, $key);
            }
            if ($website->last_seen_at->lt($at)) {
                $website->update(['last_seen_at' => $at]);
            }
            if (config('monitor.auto_probe') && (! $website->last_probed_at || $website->last_probed_at->lt(now()->subDay()))) {
                app(ProbeQueue::class)->enqueue($website, false);
            }
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
        $excluded = $this->exclusions;
        foreach ($excluded as $x) {
            if (Ip::contains($x->cidr, $asset->ip)) {
                return;
            }
        }
        if ($this->rules->isEmpty()) {
            return;
        }
        $history = TrafficMetric::where('node_id', $node->id)->where('ip_asset_id', $asset->id)->where('window_end', '>', $batch->window_end->copy()->subSeconds($this->rules->max('window_seconds')))->where('window_end', '<=', $batch->window_end)->orderBy('window_end')->get();
        foreach ($this->rules as $rule) {
            $cutoff = $batch->window_end->copy()->subSeconds($rule->window_seconds);
            $rows = $history->filter(fn ($row) => $row->window_end->gt($cutoff));
            $value = match ($rule->kind) {
                'horizontal_scan' => (int) $rows->max(fn ($m) => $m->evidence['unique_targets'] ?? 0),
                'vertical_scan' => (int) $rows->max(fn ($m) => $m->evidence['max_ports_per_target'] ?? 0),
                'suspected_bruteforce' => (int) $rows->max(fn ($m) => $m->evidence['auth_attempts'] ?? 0),
                'egress_mbps' => (int) ($rows->sum('bytes_out') * 8 / max(1, $rows->sum(fn ($m) => $m->window_start->diffInSeconds($m->window_end))) / 1000000),
                default => 0,
            };
            if ($value < $rule->threshold) {
                continue;
            }
            $title = match ($rule->kind) {
                'horizontal_scan' => '疑似对外横向扫描','vertical_scan' => '疑似对外端口扫描','suspected_bruteforce' => '疑似认证服务高频连接',default => '出站流量超出阈值'
            };
            $this->alert($node, $asset, $rule->kind, $rule->severity, $title, ['rule_id' => $rule->id, 'value' => $value, 'threshold' => $rule->threshold, 'window_seconds' => $rule->window_seconds, 'sample' => $rows->last()?->evidence, 'confidence' => 'behavioral', 'note' => '仅当前观察节点；去重目标数取各采集窗口最大值，属于保守下界；认证连接不等于登录失败'], $batch->window_end, $rule->cooldown_seconds, (string) $rule->id);
        }
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
