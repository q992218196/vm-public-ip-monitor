<?php

namespace Tests\Feature;

use App\Jobs\ProcessBatch;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Models\Rule;
use App\Models\TrafficMetric;
use App\Services\Analyzer;
use App\Services\BehaviorWhitelist;
use App\Services\ConnectionAssessment;
use Database\Seeders\MonitorSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class ServiceTargetRulesTest extends TestCase
{
    use RefreshDatabase;

    private string $token = 'test-service-token-abcdefghijklmnopqrstuvwxyz';

    private function node(): Node
    {
        return Node::create(['name' => 'service targets', 'cidrs' => ['203.0.113.0/24'], 'token_hash' => hash('sha256', $this->token)]);
    }

    private function payload(array $services, int $endOffset = 0, int $seconds = 30): array
    {
        $end = now()->addSeconds($endOffset);

        return ['batch_id' => (string) Str::uuid(), 'window_start' => $end->copy()->subSeconds($seconds)->toIso8601String(), 'window_end' => $end->toIso8601String(),
            'health' => ['version' => '1.4.0', 'captured' => 10000, 'kernel_drops' => 0, 'state_dropped' => 0, 'decode_skipped' => 0], 'sites' => [],
            'metrics' => [['ip' => '203.0.113.10', 'bytes_out' => 100000, 'bytes_in' => 100000, 'packets_out' => 10000, 'packets_in' => 10000,
                'tcp_attempts' => max(120, array_sum(array_column($services, 'attempts'))), 'unique_targets' => 256, 'max_ports_per_target' => 2,
                'max_attempts_per_target' => 317, 'auth_attempts' => 0, 'targets' => [], 'cardinality_capped' => true,
                'service_target_stats_version' => 1, 'service_targets' => $services]]];
    }

    private function service(string $service, array $targets, int $attempts = 317): array
    {
        return ['service' => $service, 'targets' => $targets, 'targets_capped' => false, 'attempts' => $attempts,
            'ports' => match ($service) {
                'rdp' => [3389], 'ssh' => [22], 'ftp' => [21, 990]
            }];
    }

    private function upload(Node $node, array $payload): void
    {
        $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $node->id])->postJson('/api/v1/agent/batches', $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
    }

    public function test_normal_reconnects_to_one_target_never_trigger_service_spread_or_retired_rules(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        foreach (['vertical_scan', 'ssh_connections', 'rdp_connections', 'ftp_connections'] as $kind) {
            $this->assertDatabaseMissing('rules', ['kind' => $kind]);
            Rule::create(['kind' => $kind, 'name' => 'Stale count rule', 'threshold' => 1]);
        }
        $node = $this->node();
        foreach ([-30, 0] as $offset) {
            $services = array_map(fn ($service) => $this->service($service, ['43.128.8.64']), ['rdp', 'ssh', 'ftp']);
            $payload = $this->payload($services, $offset);
            $payload['metrics'][0]['max_ports_per_target'] = 200;
            $this->upload($node, $payload);
        }
        $this->assertDatabaseCount('alerts', 0);
        $this->assertDatabaseCount('monitor_events', 0);
        $this->assertDatabaseCount('traffic_metrics', 2);
        $this->assertSame(951, TrafficMetric::firstOrFail()->tcp_attempts);
    }

    public function test_distinct_service_targets_union_across_windows_without_counting_a_target_twice(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $first = array_map(fn ($i) => '198.51.100.'.$i, range(1, 6));
        $second = array_map(fn ($i) => '198.51.100.'.$i, range(4, 12));
        foreach ([-30 => $first, 0 => $second] as $offset => $targets) {
            $this->upload($node, $this->payload(array_map(fn ($service) => $this->service($service, $targets), ['rdp', 'ssh', 'ftp']), $offset));
        }
        foreach (['rdp_target_spread', 'ssh_target_spread', 'ftp_target_spread'] as $kind) {
            $alert = Alert::where('kind', $kind)->firstOrFail();
            $evidence = $alert->evidence;
            $this->assertSame(12, $evidence['value']);
            $this->assertSame(10, $evidence['threshold']);
            $this->assertSame(2, $evidence['rule_window_count']);
            $this->assertSame(60, $evidence['rule_observed_span_seconds']);
            $this->assertSame(634, $evidence['sample']['tcp_attempts']);
            $this->assertCount(12, $evidence['sample']['targets']);
            $this->assertFalse($evidence['sample']['service_targets_capped']);
            $this->assertSame('distinct_service_target_ips', $evidence['sample']['count_basis']);
            $this->assertSame('medium', $alert->severity);
            $this->assertNull($evidence['connection_analysis']['completion_ratio']);
            $this->assertNull($evidence['connection_analysis']['login_failures']);
        }
        $this->assertDatabaseCount('alerts', 3);
        $this->assertDatabaseCount('monitor_events', 1);
    }

    public function test_legacy_agent_and_window_crossing_the_rule_start_do_not_supply_unproven_service_counts(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        Rule::where('kind', 'rdp_target_spread')->update(['enabled' => false]);
        $node = $this->node();
        $many = array_map(fn ($i) => '198.51.100.'.$i, range(1, 20));
        $legacy = $this->payload([$this->service('rdp', $many)], -31, 30);
        unset($legacy['metrics'][0]['service_target_stats_version'], $legacy['metrics'][0]['service_targets']);
        $legacy['metrics'][0]['outbound_endpoints'] = [['peer_ip' => '43.128.8.64', 'peer_port' => 3389, 'attempts' => 317,
            'synack_replies' => 317, 'payload_out' => 100000, 'payload_in' => 100000]];
        $legacy['metrics'][0]['tcp_attempts'] = 317;
        $legacy['health']['version'] = '1.3.1';
        $this->upload($node, $legacy);
        $this->upload($node, $this->payload([$this->service('rdp', $many)], -30, 31));
        Rule::where('kind', 'rdp_target_spread')->update(['enabled' => true]);
        $this->upload($node, $this->payload([$this->service('rdp', ['43.128.8.64'])]));
        $this->assertDatabaseCount('alerts', 0);
        $this->assertDatabaseCount('traffic_metrics', 3);
    }

    public function test_target_capacity_is_a_lower_bound_and_cannot_suppress_changed_business(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $first = array_map(fn ($i) => '198.51.100.'.$i, range(1, 100));
        $second = array_map(fn ($i) => '192.0.2.'.$i, range(1, 100));
        $this->upload($node, $this->payload([$this->service('rdp', $first)], -30));
        $this->upload($node, $this->payload([$this->service('rdp', $second)]));
        $evidence = Alert::where('kind', 'rdp_target_spread')->firstOrFail()->evidence;
        $this->assertSame(128, $evidence['value']);
        $this->assertTrue($evidence['sample']['service_targets_capped']);
        $entry = new Exclusion(['behavior_scope' => ['version' => 1, 'target_cidrs' => ['0.0.0.0/0'], 'ports' => [3389], 'max_value' => 1000, 'severity' => 'high']]);
        $this->assertFalse(app(BehaviorWhitelist::class)->evaluate($entry, $evidence)['match']);
    }

    public function test_service_targets_are_normalized_and_invalid_counter_sets_are_atomically_rejected(): void
    {
        $this->freezeTime();
        $node = $this->node();
        $base = $this->payload([$this->service('rdp', ['2001:0db8:0000::1', '192.0.2.1'])]);
        $invalid = [];
        $invalid[] = array_replace_recursive($base, ['metrics' => [0 => ['service_targets' => [0 => ['ports' => [22]]]]]]);
        $invalid[] = array_replace_recursive($base, ['metrics' => [0 => ['service_targets' => [0 => ['attempts' => 1]]]]]);
        $invalid[] = array_replace_recursive($base, ['metrics' => [0 => ['service_targets' => [0 => ['targets' => ['2001:db8::1', '2001:0db8:0::1']]]]]]);
        $invalid[] = array_replace_recursive($base, ['metrics' => [0 => ['tcp_attempts' => 1]]]);
        $tooLarge = $base;
        $tooLarge['metrics'][0]['service_targets'][0]['targets'] = array_fill(0, 129, '192.0.2.1');
        $invalid[] = $tooLarge;
        $duplicateService = $base;
        $duplicateService['metrics'][0]['service_targets'][] = $base['metrics'][0]['service_targets'][0];
        $invalid[] = $duplicateService;
        foreach ($invalid as $payload) {
            $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $node->id])->postJson('/api/v1/agent/batches', $payload)->assertUnprocessable();
        }
        $this->assertDatabaseCount('batches', 0);
        $this->upload($node, $base);
        $this->assertSame('2001:db8::1', TrafficMetric::firstOrFail()->evidence['service_targets'][0]['targets'][0]);
    }

    public function test_reviewed_service_event_reopens_after_persistent_new_target_evidence(): void
    {
        $this->freezeTime();
        $node = $this->node();
        $this->upload($node, $this->payload([$this->service('rdp', ['192.0.2.1', '192.0.2.2'])]));
        $ip = IpAsset::firstOrFail();
        $sample = ['service_target_stats_version' => 1, 'targets' => ['192.0.2.1', '192.0.2.2'], 'unique_targets' => 2, 'ports' => [3389],
            'service_targets_capped' => false, 'cardinality_capped' => false, 'port_samples_truncated' => false];
        $assessment = app(ConnectionAssessment::class)->assess('rdp_target_spread', $sample, 2);
        $at = now();
        $evidence = ['sample' => $sample, 'connection_analysis' => $assessment['connection_analysis'], 'sample_window_end' => $at->toIso8601String()];
        $analyzer = app(Analyzer::class);
        $alert = $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at);
        $event = MonitorEvent::findOrFail($alert->event_id);
        $event->update(['status' => 'normal', 'review_context' => $event->behavior]);
        $evidence['sample']['targets'] = ['192.0.2.1', '192.0.2.3'];
        foreach ([10, 20] as $offset) {
            $evidence['sample_window_end'] = $at->copy()->addSeconds($offset)->toIso8601String();
            $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at->copy()->addSeconds($offset));
            $this->assertSame($offset === 10 ? 'normal' : 'open', $event->fresh()->status);
        }
        $this->assertStringContainsString('新增目标 IP', $event->fresh()->reopen_reason);
    }

    public function test_empty_supported_service_sets_keep_raw_traffic_without_notifying(): void
    {
        $this->seed(MonitorSeeder::class);
        $this->upload($this->node(), $this->payload([]));
        $this->assertDatabaseCount('alerts', 0);
        $this->assertSame([], TrafficMetric::firstOrFail()->evidence['service_targets']);
    }

    public function test_incomplete_reviewed_target_baseline_reopens_only_after_two_new_windows_outside_verified_scope(): void
    {
        $this->freezeTime();
        foreach (['normal', 'resolved'] as $status) {
            $node = $this->node();
            $ip = IpAsset::firstOrCreate(['ip' => '203.0.113.10'], ['version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);
            $sample = ['service_target_stats_version' => 1, 'count_basis' => 'distinct_service_target_ips',
                'targets' => ['192.0.2.1', '192.0.2.2'], 'unique_targets' => 2, 'ports' => [3389],
                'service_targets_capped' => true, 'cardinality_capped' => true, 'port_samples_truncated' => false];
            $assessment = app(ConnectionAssessment::class)->assess('rdp_target_spread', $sample, 2);
            $at = now();
            $evidence = ['sample' => $sample, 'connection_analysis' => $assessment['connection_analysis'], 'sample_window_end' => $at->toIso8601String()];
            $analyzer = app(Analyzer::class);
            $alert = $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at);
            $event = MonitorEvent::findOrFail($alert->event_id);
            $this->assertFalse($event->behavior['rdp_target_spread']['complete_targets']);
            $event->update(['status' => $status, 'review_context' => $event->behavior, 'review_notes' => 'Customer reviewed captured sample']);
            $evidence['sample'] = array_replace($sample, ['targets' => ['192.0.2.1', '192.0.2.3'], 'service_targets_capped' => false, 'cardinality_capped' => false]);
            $evidence['sample_window_end'] = $at->copy()->addSeconds(10)->toIso8601String();
            $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at->copy()->addSeconds(10));
            $this->assertSame($status, $event->fresh()->status);
            $this->assertSame(1, $event->fresh()->behavior['rdp_target_spread']['change_streak']);
            $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at->copy()->addSeconds(15));
            $this->assertSame($status, $event->fresh()->status);
            $this->assertSame(1, $event->fresh()->behavior['rdp_target_spread']['change_streak']);
            $evidence['sample_window_end'] = $at->copy()->addSeconds(20)->toIso8601String();
            $analyzer->alert($node, $ip, 'rdp_target_spread', 'medium', 'RDP 多目标建连', $evidence, $at->copy()->addSeconds(20));
            $event->refresh();
            $this->assertSame('open', $event->status);
            $this->assertSame(2, $event->behavior['rdp_target_spread']['change_streak']);
            $this->assertStringContainsString('目标超出可核实审核范围', $event->reopen_reason);
            $this->assertStringNotContainsString('新增', $event->reopen_reason);
            $this->assertSame('Customer reviewed captured sample', $event->review_notes);
        }
    }

    public function test_reviewed_service_whitelist_allows_only_complete_approved_targets_and_ports(): void
    {
        $entry = new Exclusion(['behavior_scope' => ['version' => 2, 'target_cidrs' => ['192.0.2.1/32', '192.0.2.2/32'],
            'target_ports' => ['192.0.2.1' => [3389], '192.0.2.2' => [3389]], 'max_value' => 10, 'severity' => 'medium']]);
        $evidence = ['value' => 2, 'assessed_severity' => 'medium', 'sample' => ['count_basis' => 'distinct_service_target_ips',
            'service_target_stats_version' => 1, 'targets' => ['192.0.2.1', '192.0.2.2'], 'ports' => [3389], 'unique_targets' => 2,
            'service_targets_capped' => false, 'cardinality_capped' => false, 'capture_quality' => ['captured' => 10000, 'kernel_drops' => 0, 'state_dropped' => 0, 'decode_skipped' => 0]]];
        $whitelist = app(BehaviorWhitelist::class);
        $this->assertTrue($whitelist->evaluate($entry, $evidence)['match']);
        $changed = $evidence;
        $changed['sample']['targets'][1] = '192.0.2.3';
        $this->assertFalse($whitelist->evaluate($entry, $changed)['match']);
        $changed = $evidence;
        $changed['sample']['ports'][] = 22;
        $this->assertFalse($whitelist->evaluate($entry, $changed)['match']);
        $changed = $evidence;
        $changed['sample']['service_targets_capped'] = true;
        $this->assertFalse($whitelist->evaluate($entry, $changed)['match']);
    }
}
