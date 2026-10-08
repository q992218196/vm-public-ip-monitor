<?php

namespace Tests\Feature;

use App\Jobs\ProcessBatch;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\Node;
use App\Models\ProtocolObservation;
use App\Models\Rule;
use App\Models\TrafficMetric;
use App\Models\Website;
use App\Services\ProbeQueue;
use App\Services\ScanAssessment;
use Database\Seeders\MonitorSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

class MonitorTest extends TestCase
{
    use RefreshDatabase;

    public function test_retired_rules_are_removed_and_stale_configurations_do_not_detect(): void
    {
        $this->seed(MonitorSeeder::class);
        $this->assertDatabaseMissing('rules', ['kind' => 'horizontal_scan']);
        $this->assertDatabaseMissing('rules', ['kind' => 'suspected_bruteforce']);
        foreach (['horizontal_scan', 'suspected_bruteforce'] as $kind) {
            Rule::create(['name' => 'Retired rule', 'kind' => $kind, 'threshold' => 1, 'severity' => 'high']);
        }
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['auth_attempts'] = 100;
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'horizontal_scan']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'suspected_bruteforce']);
        $this->assertDatabaseCount('traffic_metrics', 1);
        $migration = require database_path('migrations/2026_10_03_160000_remove_retired_connection_rules.php');
        $migration->up();
        $migration->up();
        $this->assertDatabaseMissing('rules', ['kind' => 'horizontal_scan']);
        $this->assertDatabaseMissing('rules', ['kind' => 'suspected_bruteforce']);
        $this->assertDatabaseHas('rules', ['kind' => 'smb_connections']);
    }

    public function test_dns_and_legacy_udp_windows_never_trigger_udp_quantity_rules(): void
    {
        $this->seed(MonitorSeeder::class);
        Rule::whereIn('kind', ['udp_flow_burst', 'udp_packet_rate'])->update(['threshold' => 1]);
        $node = $this->node();
        foreach ([false, true] as $filtered) {
            $payload = $this->payload();
            $payload['metrics'][0] = array_replace($payload['metrics'][0], [
                'packets_out' => 10000, 'packets_in' => 0, 'bytes_out' => 400000, 'bytes_in' => 0,
                'udp_stats_version' => 1, 'udp_flows_out' => 2000, 'udp_packets_out' => 10000, 'udp_packets_in' => 0,
                'udp_bytes_out' => 400000, 'udp_bytes_in' => 0,
                'udp_endpoints' => [['peer_ip' => '1.1.1.1', 'peer_port' => 53, 'flows' => 2000, 'packets_out' => 10000, 'packets_in' => 0, 'bytes_out' => 400000, 'bytes_in' => 0]],
            ]);
            if ($filtered) {
                $payload['metrics'][0] += ['udp_filter_version' => 1, 'udp_non_dns_flows_out' => 0, 'udp_non_dns_packets_out' => 0];
            }
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        }
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_flow_burst']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_packet_rate']);
        $this->assertDatabaseCount('traffic_metrics', 2);
        $payload['batch_id'] = Str::uuid()->toString();
        $payload['metrics'][0]['udp_non_dns_packets_out'] = 10001;
        $this->upload($node, $payload)->assertUnprocessable();
        $payload['metrics'][0]['udp_non_dns_packets_out'] = 0;
        unset($payload['metrics'][0]['udp_non_dns_flows_out']);
        $this->upload($node, $payload)->assertUnprocessable();
    }

    private string $token = 'abcdefghijklmnopqrstuvwxyz0123456789abcdef';

    private function node(array $cidrs = ['203.0.113.0/24', '2001:db8::/48']): Node
    {
        return Node::create(['name' => '测试宿主机', 'cidrs' => $cidrs, 'token_hash' => hash('sha256', $this->token)]);
    }

    private function payload(string $ip = '203.0.113.10'): array
    {
        return ['batch_id' => Str::uuid()->toString(), 'window_start' => now()->subSeconds(30)->toIso8601String(), 'window_end' => now()->toIso8601String(), 'health' => ['version' => 'test', 'kernel_drops' => 0], 'metrics' => [['ip' => $ip, 'bytes_out' => 1000, 'bytes_in' => 300, 'packets_out' => 150, 'packets_in' => 2, 'tcp_attempts' => 120, 'unique_targets' => 120, 'max_ports_per_target' => 3, 'max_attempts_per_target' => 2, 'auth_attempts' => 0, 'targets' => ['1.1.1.1'], 'cardinality_capped' => false]], 'sites' => [['ip' => $ip, 'port' => 18443, 'scheme' => 'https', 'host' => 'test.example', 'source' => 'tls_sni']]];
    }

    private function upload(Node $n, array $p)
    {
        return $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $n->id])->postJson('/api/v1/agent/batches', $p);
    }

    private function smbEndpoint(int $attempts = 70, array $overrides = []): array
    {
        return array_replace(['peer_ip' => '192.0.2.1', 'peer_port' => 445, 'attempts' => $attempts,
            'synack_replies' => $attempts, 'completed_handshakes' => $attempts, 'rst_replies' => 0,
            'payload_out' => 100, 'payload_in' => 200], $overrides);
    }

    public function test_scope_auth_and_atomic_rejection(): void
    {
        $n = $this->node();
        $this->postJson('/api/v1/agent/batches', $this->payload())->assertUnauthorized();
        $this->upload($n, $this->payload('8.8.8.8'))->assertUnprocessable();
        $this->assertDatabaseCount('batches', 0);
        $n->update(['enabled' => false]);
        $this->upload($n, $this->payload())->assertUnauthorized();
    }

    public function test_subsecond_agent_windows_preserve_precision_and_still_detect(): void
    {
        $this->freezeTime();
        $node = $this->node();
        Rule::create(['name' => 'SMB connections', 'kind' => 'smb_connections', 'threshold' => 1]);
        Rule::create(['name' => 'UDP rate reminder', 'kind' => 'udp_packet_rate', 'threshold' => 180]);
        $payload = $this->payload();
        $second = now()->utc()->format('Y-m-d\TH:i:s');
        $payload['window_start'] = $second.'.100000123Z';
        $payload['window_end'] = $second.'.900000987Z';
        $payload['metrics'][0] = array_replace($payload['metrics'][0], [
            'udp_stats_version' => 1, 'udp_filter_version' => 1, 'udp_flows_out' => 1, 'udp_non_dns_flows_out' => 1,
            'udp_packets_out' => 150, 'udp_non_dns_packets_out' => 150, 'udp_packets_in' => 0,
            'udp_bytes_out' => 6000, 'udp_bytes_in' => 0, 'packets_out' => 270, 'bytes_out' => 10000,
            'outbound_endpoints' => [$this->smbEndpoint(3)],
        ]);
        $this->upload($node, $payload)->assertOk();
        $batch = Batch::firstOrFail();
        $this->assertSame('100000', $batch->window_start->format('u'));
        $this->assertSame('900000', $batch->window_end->format('u'));
        ProcessBatch::dispatchSync($batch->id);
        $metric = TrafficMetric::firstOrFail();
        $this->assertEqualsWithDelta(0.8, $metric->window_start->diffInSeconds($metric->window_end), 0.000001);
        $alert = Alert::where('kind', 'smb_connections')->firstOrFail();
        $this->assertSame(3, $alert->evidence['value']);
        $this->assertEquals(0.8, $alert->evidence['rule_observed_span_seconds']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_packet_rate']);
        $this->assertSame(150, $metric->evidence['udp_non_dns_packets_out']);
        $payload['batch_id'] = Str::uuid()->toString();
        $payload['window_start'] = $payload['window_end'];
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('window_end');
        $payload['window_end'] = $second.'.100000123Z';
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('window_end');
        $this->assertDatabaseCount('batches', 1);
    }

    public function test_capture_quality_rule_can_select_nodes_disable_and_set_threshold(): void
    {
        $this->seed(MonitorSeeder::class);
        $included = $this->node();
        $excluded = $this->node();
        $rule = Rule::where('kind', 'capture_degraded')->firstOrFail();
        $rule->update(['node_ids' => [$included->id], 'threshold' => 5, 'severity' => 'low', 'cooldown_seconds' => 300]);
        foreach ([$included, $excluded] as $node) {
            $payload = $this->payload();
            $payload['metrics'] = [];
            $payload['sites'] = [];
            $payload['health'] += ['state_dropped' => 2, 'spool_dropped' => 0];
            $payload['health']['kernel_drops'] = 3;
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        }
        $alert = Alert::where('kind', 'capture_degraded')->firstOrFail();
        $this->assertSame($included->id, $alert->node_id);
        $this->assertSame('low', $alert->severity);
        $this->assertSame(5, $alert->evidence['value']);
        $this->assertSame(5, $alert->evidence['threshold']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'capture_degraded', 'node_id' => $excluded->id]);
        $this->assertSame(3, $excluded->fresh()->health['kernel_drops']);
        $rule->update(['enabled' => false]);
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($included, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertSame(1, $alert->fresh()->occurrences);
        $rule->update(['enabled' => true, 'threshold' => 6]);
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($included, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertSame(1, $alert->fresh()->occurrences);
        $rule->update(['threshold' => 1, 'node_ids' => null]);
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($excluded, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseHas('alerts', ['kind' => 'capture_degraded', 'node_id' => $excluded->id]);
        $rule->update(['node_ids' => []]);
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($included, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertSame(1, $alert->fresh()->occurrences);
        $this->seed(MonitorSeeder::class);
        $this->assertSame([], $rule->fresh()->node_ids);
    }

    public function test_agent_update_requires_node_token_and_returns_only_assigned_release(): void
    {
        $node = $this->node();
        $url = '/api/v1/agent/update?version=0.3.0';
        $this->getJson($url)->assertUnauthorized();
        $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $node->id])
            ->getJson($url)->assertOk()->assertJson(['update' => false]);
        $sha = str_repeat('a', 64);
        $node->update(['agent_desired_version' => '0.4.0', 'agent_desired_sha256' => $sha]);
        $this->getJson($url)->assertOk()->assertJson([
            'update' => true, 'version' => '0.4.0', 'sha256' => $sha,
            'path' => '/downloads/vm-agent-linux-amd64',
        ]);
        $this->getJson('/api/v1/agent/update?version=0.4.0')->assertOk()->assertJson(['update' => false]);
        $this->getJson('/api/v1/agent/update?version=%2F')->assertUnprocessable();
    }

    public function test_agent_update_error_is_bounded_and_visible_in_health(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $payload['health']['update_error'] = 'SHA-256 mismatch';
        $this->upload($node, $payload)->assertOk();
        $this->assertSame('SHA-256 mismatch', $node->fresh()->health['update_error']);
        $payload = $this->payload();
        $payload['health']['update_error'] = str_repeat('x', 256);
        $this->upload($node, $payload)->assertUnprocessable();
    }

    public function test_agent_rate_limit_is_isolated_by_authenticated_node(): void
    {
        $first = $this->node();
        $second = $this->node();
        for ($attempt = 0; $attempt < 120; $attempt++) {
            $this->upload($first, [])->assertUnprocessable();
        }
        $this->upload($first, [])->assertStatus(429);
        $this->upload($second, [])->assertUnprocessable();
    }

    public function test_durable_inbox_duplicate_replay_and_detection(): void
    {
        $this->seed(MonitorSeeder::class);
        $n = $this->node();
        $p = $this->payload();
        $p['metrics'][0]['max_ports_per_target'] = 50;
        $p['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint()];
        $this->upload($n, $p)->assertOk()->assertJson(['accepted' => true, 'duplicate' => false]);
        $this->upload($n, $p)->assertOk()->assertJson(['duplicate' => true]);
        $this->assertDatabaseCount('batches', 1);
        $this->assertDatabaseCount('traffic_metrics', 0);
        ProcessBatch::dispatchSync(Batch::first()->id);
        ProcessBatch::dispatchSync(Batch::first()->id);
        $this->assertDatabaseCount('traffic_metrics', 1);
        $this->assertDatabaseCount('websites', 1);
        $this->assertDatabaseHas('alerts', ['kind' => 'smb_connections']);
        $this->assertSame(1, Alert::firstOrFail()->occurrences);
        $this->assertNull(Batch::first()->payload);
    }

    public function test_connection_burst_and_single_target_rules_use_observed_counts(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['tcp_attempts'] = 1200;
        $payload['metrics'][0]['max_attempts_per_target'] = 90;
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'single_target_attempts']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'tcp_connection_burst']);
        $this->assertSame(1200, TrafficMetric::firstOrFail()->tcp_attempts);
    }

    public function test_new_agent_counters_are_validated_and_window_quality_is_saved_with_evidence(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['max_ports_per_target'] = 50;
        $payload['health'] = ['version' => '1.0.0', 'captured' => 10000, 'kernel_drops' => 0, 'state_dropped' => 0, 'decode_skipped' => 0];
        $payload['metrics'][0] += ['connection_stats_version' => 1, 'synack_replies' => 100, 'completed_handshakes' => 90, 'rst_replies' => 10, 'mature_attempts' => 110, 'mature_no_reply' => 10,
            'port_scan_targets' => [['peer_ip' => '192.0.2.1', 'port_count' => 2, 'ports' => [22, 443], 'truncated' => false]]];
        $payload['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint(70, ['synack_replies' => 65, 'completed_handshakes' => 60, 'rst_replies' => 5])];
        $invalid = $payload;
        $invalid['metrics'][0]['completed_handshakes'] = 101;
        $this->upload($node, $invalid)->assertUnprocessable();
        $invalid = $payload;
        unset($invalid['metrics'][0]['mature_no_reply']);
        $this->upload($node, $invalid)->assertUnprocessable();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $alert = Alert::where('kind', 'smb_connections')->firstOrFail();
        $this->assertSame('medium', $alert->severity);
        $this->assertSame('paired_transport', $alert->evidence['confidence']);
        $this->assertSame(10000, $alert->evidence['sample']['capture_quality']['captured']);
        $this->assertSame(60, $alert->evidence['connection_analysis']['completed_handshakes']);
        $this->assertSame(5, $alert->evidence['connection_analysis']['rst_replies']);
        $this->assertSame([22, 443], TrafficMetric::firstOrFail()->evidence['port_scan_targets'][0]['ports']);
        $this->assertSame('needs_review', $alert->assessment_category);
    }

    public function test_tcp_rule_total_is_distinct_from_its_last_sample_window(): void
    {
        $this->seed(MonitorSeeder::class);
        Rule::where('kind', 'tcp_connection_burst')->update(['threshold' => 2000, 'window_seconds' => 60]);
        $node = $this->node();
        $end = now()->startOfSecond();
        $this->travelTo($end);
        foreach ([-30 => 1000, 0 => 2226] as $offset => $attempts) {
            $payload = $this->payload();
            $payload['window_end'] = $end->copy()->addSeconds($offset)->toIso8601String();
            $payload['window_start'] = $end->copy()->addSeconds($offset - ($offset === -30 ? 31 : 30))->toIso8601String();
            $payload['metrics'][0]['tcp_attempts'] = $attempts;
            $payload['metrics'][0] += ['connection_stats_version' => 1, 'synack_replies' => 0, 'completed_handshakes' => 0, 'rst_replies' => intdiv($attempts, 2) + 1, 'mature_attempts' => $attempts, 'mature_no_reply' => 0];
            $payload['metrics'][0]['packets_in'] = $attempts;
            $payload['metrics'][0]['packets_out'] = $attempts;
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        }
        $evidence = Alert::where('kind', 'tcp_connection_burst')->firstOrFail()->evidence;
        $this->assertSame(3226, $evidence['value']);
        $this->assertSame(2226, $evidence['sample']['tcp_attempts']);
        $this->assertSame(60, $evidence['window_seconds']);
        $this->assertSame(61, $evidence['rule_observed_span_seconds']);
        $this->assertSame(2, $evidence['rule_window_count']);
        $this->assertSame($end->copy()->subSeconds(61)->toIso8601String(), $evidence['rule_observed_start']);
        $this->assertSame($end->copy()->subSeconds(30)->toIso8601String(), $evidence['sample_window_start']);
    }

    public function test_inconsistent_handshake_counts_do_not_imply_success(): void
    {
        $assessment = app(ScanAssessment::class)->assess(['tcp_attempts' => 100, 'synack_replies' => 101, 'max_ports_per_target' => 1]);
        $this->assertSame('medium', $assessment['severity']);
        $this->assertNull($assessment['connection_analysis']['completion_ratio']);
    }

    public function test_endpoint_evidence_is_preserved_and_large_samples_rejected(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $endpoint = ['peer_ip' => '1.1.1.1', 'peer_port' => 80, 'attempts' => 5, 'synack_replies' => 5,
            'payload_out' => 600, 'payload_in' => 800, 'scheme' => 'http', 'host' => 'example.com',
            'http_method' => 'GET', 'http_path' => '/api', 'query_keys' => ['id']];
        $payload['metrics'][0]['outbound_endpoints'] = [$endpoint];
        $this->upload($node, $payload)->assertOk();
        $this->assertSame('/api', Batch::firstOrFail()->payload['metrics'][0]['outbound_endpoints'][0]['http_path']);
        $payload['metrics'][0]['outbound_endpoints'] = array_fill(0, 9, $endpoint);
        $this->upload($node, $payload)->assertUnprocessable();
    }

    public function test_fresh_collector_has_no_management_account_tables(): void
    {
        $this->assertFalse(Schema::hasTable('users'));
        $this->assertFalse(Schema::hasTable('sessions'));
        $this->assertFalse(Schema::hasTable('password_reset_tokens'));
    }

    public function test_legacy_ip_exclusion_requires_target_scope_and_preserves_metrics(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        Exclusion::create([
            'node_id' => $node->id, 'cidr' => '203.0.113.10/32',
            'kind' => 'smb_connections', 'reason' => '业务复核', 'expires_at' => now()->addDays(30),
        ]);
        $payload = $this->payload();
        $payload['metrics'][0]['max_ports_per_target'] = 50;
        $payload['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint()];
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'horizontal_scan']);
        $this->assertDatabaseHas('alerts', ['kind' => 'smb_connections']);
        $this->assertDatabaseCount('traffic_metrics', 1);
    }

    public function test_shared_cidr_keeps_observers_and_single_ip_site(): void
    {
        foreach ([$this->node(), $this->node()] as $n) {
            $this->upload($n, $this->payload('2001:0db8:0000::1'))->assertOk();
        }
        foreach (Batch::all() as $b) {
            ProcessBatch::dispatchSync($b->id);
        }
        $this->assertDatabaseCount('ip_assets', 1);
        $this->assertDatabaseHas('ip_assets', ['ip' => '2001:db8::1']);
        $this->assertDatabaseCount('ip_observations', 2);
        $this->assertDatabaseCount('websites', 1);
        $this->assertDatabaseCount('traffic_metrics', 2);
    }

    public function test_legacy_ip_whitelists_do_not_disable_detection_or_lose_evidence(): void
    {
        $this->seed(MonitorSeeder::class);
        Rule::query()->update(['threshold' => 1]);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['bytes_out'] = 1000000000;
        $payload['metrics'][0]['auth_attempts'] = 100;
        $payload['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint()];
        $payload['vpn'] = [[
            'ip' => '203.0.113.10', 'peer_ip' => '1.1.1.1', 'local_port' => 40000,
            'peer_port' => 51820, 'protocol' => 'wireguard', 'initiator' => 'vm',
            'request_count' => 1, 'response_count' => 1, 'request_length' => 148,
            'response_length' => 92, 'request_header' => '010000007b000000',
            'response_header' => '02000000c8010000',
        ]];
        $payload['proxies'] = [[
            'ip' => '203.0.113.10', 'local_port' => 8443, 'transport' => 'tls',
            'peer_count' => 3, 'session_count' => 4, 'bytes_from_peers' => 12000,
            'bytes_to_peers' => 34000, 'peer_samples' => ['198.51.100.1'],
            'egress_target_count' => 5, 'egress_target_samples' => ['192.0.2.1'],
        ]];
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseCount('alerts', 3);
        foreach (Alert::all() as $alert) {
            Exclusion::create(['node_id' => $node->id, 'cidr' => '203.0.113.10/32',
                'kind' => $alert->kind, 'reason' => '业务复核', 'expires_at' => now()->addDays(30)]);
        }
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseCount('alerts', 3);
        $this->assertSame(6, (int) Alert::sum('occurrences'));
        $this->assertDatabaseCount('traffic_metrics', 2);
        $this->assertDatabaseCount('protocol_observations', 4);
        $this->assertDatabaseCount('websites', 1);

        $otherNode = $this->node();
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($otherNode, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertSame(3, Alert::where('node_id', $otherNode->id)->count());
    }

    public function test_node_health_whitelist_is_scoped_by_node_kind_and_expiry(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $exclusion = Exclusion::create(['node_id' => $node->id, 'cidr' => null,
            'kind' => 'capture_degraded', 'reason' => '维护', 'expires_at' => now()->addDays(30)]);
        $payload = $this->payload();
        $payload['metrics'][0]['max_ports_per_target'] = 50;
        $payload['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint()];
        $payload['health']['kernel_drops'] = 1;
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'capture_degraded']);
        $this->assertDatabaseHas('alerts', ['kind' => 'smb_connections']);
        $this->assertSame(1, $node->fresh()->health['kernel_drops']);
        $node->update(['last_seen_at' => now()->subHour()]);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseHas('alerts', ['node_id' => $node->id, 'kind' => 'node_offline']);

        $otherNode = $this->node();
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($otherNode, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseHas('alerts', ['node_id' => $otherNode->id, 'kind' => 'capture_degraded']);

        $exclusion->update(['expires_at' => now()->subSecond()]);
        $payload['batch_id'] = Str::uuid()->toString();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseHas('alerts', ['node_id' => $node->id, 'kind' => 'capture_degraded']);
    }

    public function test_offline_whitelist_does_not_mute_another_node(): void
    {
        $node = $this->node();
        $otherNode = $this->node();
        foreach ([$node, $otherNode] as $offlineNode) {
            $offlineNode->update(['last_seen_at' => now()->subHour()]);
        }
        Exclusion::create(['node_id' => $node->id, 'cidr' => null,
            'kind' => 'node_offline', 'reason' => '维护', 'expires_at' => now()->addDays(30)]);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseMissing('alerts', ['node_id' => $node->id, 'kind' => 'node_offline']);
        $this->assertDatabaseHas('alerts', ['node_id' => $otherNode->id, 'kind' => 'node_offline']);
    }

    public function test_old_batch_cannot_replace_latest_health(): void
    {
        $n = $this->node();
        $this->upload($n, $this->payload())->assertOk();
        $p = $this->payload();
        $p['window_start'] = now()->subHours(2)->toIso8601String();
        $p['window_end'] = now()->subHours(2)->addSeconds(30)->toIso8601String();
        $p['health']['version'] = 'old';
        $this->upload($n, $p)->assertOk();
        $this->assertSame('test', $n->fresh()->health['version']);
    }

    public function test_worker_lease_fencing_and_global_task_dedup(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $n = $this->node();
        $this->upload($n, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::first();
        $q = app(ProbeQueue::class);
        $q->enqueue($site);
        $q->enqueue($site);
        $this->assertDatabaseCount('probe_tasks', 1);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', ['lease_token' => str_repeat('0', 64), 'status' => 'failed'])->assertConflict();
        $this->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', ['lease_token' => $claim['lease_token'], 'status' => 'verified', 'title' => '测试', 'http_status' => 200, 'category' => '管理后台'])->assertOk();
        $this->assertSame('verified', $site->fresh()->status);
        $this->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', ['lease_token' => $claim['lease_token'], 'status' => 'failed'])->assertConflict();
    }

    public function test_legacy_admin_and_screenshot_routes_are_not_exposed(): void
    {
        $this->get('/admin/login')->assertNotFound();
        $this->get('/admin/alerts')->assertNotFound();
        $this->get('/screenshots/1')->assertNotFound();
    }

    public function test_future_window_and_duplicate_normalized_ip_rejected(): void
    {
        $n = $this->node();
        $p = $this->payload();
        $p['metrics'][] = $p['metrics'][0];
        $this->upload($n, $p)->assertUnprocessable();
        $p = $this->payload();
        $p['window_end'] = now()->addDay()->toIso8601String();
        $this->upload($n, $p)->assertUnprocessable();
    }

    public function test_inbox_backpressure_does_not_ack_or_store_new_batch(): void
    {
        $n = $this->node();
        config(['monitor.pending_bytes_per_node' => 1]);
        $this->upload($n, $this->payload())->assertStatus(429);
        $this->assertDatabaseCount('batches', 0);
    }

    public function test_dispatcher_does_not_flood_queue_with_same_pending_batch(): void
    {
        Queue::fake();
        $n = $this->node();
        $this->upload($n, $this->payload())->assertOk();
        $this->artisan('monitor:dispatch')->assertSuccessful();
        $this->artisan('monitor:dispatch')->assertSuccessful();
        Queue::assertPushed(ProcessBatch::class, 1);
        Batch::first()->update(['dispatched_at' => now()->subMinutes(6)]);
        $this->artisan('monitor:dispatch')->assertSuccessful();
        Queue::assertPushed(ProcessBatch::class, 2);
    }

    public function test_active_discovery_respects_scope_and_rejects_large_ipv6_ranges(): void
    {
        $n = $this->node();
        $this->artisan('monitor:discover', ['node' => $n->id, 'target' => '8.8.8.8'])->assertFailed();
        $this->artisan('monitor:discover', ['node' => $n->id, 'target' => '2001:db8::/64'])->assertFailed();
        $this->artisan('monitor:discover', ['node' => $n->id, 'target' => '203.0.113.10', '--ports' => '18080', '--scheme' => 'both'])->assertSuccessful();
        $this->assertDatabaseCount('probe_tasks', 2);
        $this->assertDatabaseCount('ip_observations', 0);
    }

    public function test_maintenance_queues_existing_sites_only_when_auto_probe_is_enabled(): void
    {
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        config(['monitor.auto_probe' => false]);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseCount('probe_tasks', 0);
        config(['monitor.auto_probe' => true]);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseCount('probe_tasks', 1);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseCount('probe_tasks', 1);
    }

    public function test_website_observations_do_not_create_alerts(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $payload['sites'][0]['host'] = 'account.skrill.com';
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'new_website']);

        $this->travel(1)->days();
        $payload['batch_id'] = Str::uuid()->toString();
        $payload['window_start'] = now()->subSeconds(30)->toIso8601String();
        $payload['window_end'] = now()->toIso8601String();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseCount('websites', 1);
        $this->assertDatabaseMissing('alerts', ['kind' => 'new_website']);
    }

    public function test_website_description_and_domain_link(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::firstOrFail();
        $this->assertSame('https://test.example:18443/', $site->publicUrl());
        $site->update(['host' => 'internal.local']);
        $this->assertNull($site->publicUrl());
        $site->update(['host' => 'test.example']);
        app(ProbeQueue::class)->enqueue($site);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->withToken($this->token)->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', [
            'lease_token' => $claim['lease_token'], 'status' => 'verified',
            'classification' => ['evidence' => [['source' => 'body', 'keyword' => 'word', 'excerpt' => str_repeat('x', 256)]]],
        ])->assertUnprocessable();
        $this->withToken($this->token)->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', [
            'lease_token' => $claim['lease_token'], 'status' => 'verified', 'title' => '测试网站',
            'description' => '这是一段网站描述', 'http_status' => 200,
            'classification' => ['risk_level' => 'medium', 'business_type' => '影视聚合／在线播放',
                'nature' => '待人工核实', 'summary' => '公开首页文本命中，需要核实授权', 'observed_at' => now()->toIso8601String(),
                'findings' => [['category' => '影视授权待核实', 'explanation' => '授权未确认', 'evidence' => [
                    ['source' => 'description', 'keyword' => '免费影视', 'excerpt' => '提供免费影视'],
                ]]],
            ],
        ])->assertOk();
        $this->assertSame('这是一段网站描述', $site->fresh()->description);
        $this->assertSame('description', $site->fresh()->classification['findings'][0]['evidence'][0]['source']);

    }

    public function test_vpn_alert_requires_bounded_bidirectional_signature(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['vpn'] = [[
            'ip' => '203.0.113.10', 'peer_ip' => '1.1.1.1', 'local_port' => 40000,
            'peer_port' => 51820, 'protocol' => 'wireguard', 'initiator' => 'vm',
            'request_count' => 1, 'response_count' => 1, 'request_length' => 148,
            'response_length' => 92, 'request_header' => '010000007b000000',
            'response_header' => '02000000c8010000',
        ]];
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $alert = Alert::where('kind', 'vpn_protocol')->firstOrFail();
        $this->assertSame('wireguard', $alert->evidence['protocol']);
        $this->assertSame('1.1.1.1', $alert->evidence['peer_ip']);
        $this->assertDatabaseCount('protocol_observations', 1);
    }

    public function test_proxy_clue_is_scoped_and_kept_distinct_from_protocol_confirmation(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['proxies'] = [[
            'ip' => '203.0.113.10', 'local_port' => 8443, 'transport' => 'tls',
            'peer_count' => 3, 'session_count' => 4,
            'bytes_from_peers' => 12000, 'bytes_to_peers' => 34000,
            'peer_samples' => ['198.51.100.1', '198.51.100.2', '198.51.100.3'],
            'egress_target_count' => 5,
            'egress_target_samples' => ['192.0.2.1', '192.0.2.2'],
        ]];
        $invalid = $payload;
        $invalid['proxies'][0]['ip'] = '198.51.100.10';
        $this->upload($node, $invalid)->assertUnprocessable();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $alert = Alert::where('kind', 'proxy_suspect')->firstOrFail();
        $this->assertSame('behavioral_suspect', $alert->evidence['confidence']);
        $this->assertContains('AnyTLS', $alert->evidence['candidate_protocols']);
        $this->assertSame('tls', ProtocolObservation::firstOrFail()->protocol);
    }

    public function test_proxy_rule_threshold_can_suppress_alert_without_losing_observation(): void
    {
        $this->seed(MonitorSeeder::class);
        Rule::where('kind', 'proxy_suspect')->update(['threshold' => 5]);
        $node = $this->node();
        $payload = $this->payload();
        $payload['proxies'] = [[
            'ip' => '203.0.113.10', 'local_port' => 443, 'transport' => 'quic',
            'peer_count' => 3, 'session_count' => 3, 'bytes_from_peers' => 9000,
            'bytes_to_peers' => 12000, 'peer_samples' => ['198.51.100.1'],
            'egress_target_count' => 5, 'egress_target_samples' => ['192.0.2.1'],
        ]];
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseCount('protocol_observations', 1);
        $this->assertDatabaseMissing('alerts', ['kind' => 'proxy_suspect']);
    }

    public function test_foreign_host_ownership_is_preserved_as_a_clue_without_verified_content(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::firstOrFail();
        $this->assertSame('unverified', $site->ownership_status);
        app(ProbeQueue::class)->enqueue($site);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame($site->source, $claim['source']);
        $url = '/api/v1/worker/tasks/'.$claim['id'].'/complete';
        $body = ['lease_token' => $claim['lease_token'], 'status' => 'verified', 'ownership_status' => 'dns_match', 'ownership_evidence' => ['host' => $site->host, 'checked_at' => now()->toIso8601String(), 'method' => 'dns_A_AAAA', 'addresses' => ['198.51.100.1']]];
        $this->postJson($url, $body)->assertUnprocessable();
        $body['ownership_status'] = 'manual';
        $this->postJson($url, $body)->assertUnprocessable();
        $body['ownership_status'] = 'dns_mismatch';
        $this->postJson($url, $body)->assertUnprocessable();
        $body['status'] = 'failed';
        $body['error'] = 'Foreign client Host; no webpage requested';
        $this->postJson($url, $body)->assertOk();
        $site->refresh();
        $this->assertSame('dns_mismatch', $site->ownership_status);
        $this->assertNull($site->classification);
        $this->assertNull($site->screenshot_path);
        $this->assertSame(['198.51.100.1'], $site->ownership_evidence['addresses']);
    }

    public function test_origin_test_is_explicit_target_bound_and_does_not_register_ownership(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::firstOrFail();
        $queue = app(ProbeQueue::class);
        $task = $queue->enqueue($site);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame('normal', $claim['mode']);
        $url = '/api/v1/worker/tasks/'.$claim['id'].'/complete';
        $proof = ['host' => $site->host, 'checked_at' => now()->toIso8601String(), 'method' => 'dns_A_AAAA', 'addresses' => ['198.51.100.1'],
            'origin_test' => ['target_ip' => $claim['ip'], 'checked_at' => now()->toIso8601String(), 'method' => 'fixed_ip_host_sni', 'dns_status' => 'dns_mismatch']];
        $body = ['lease_token' => $claim['lease_token'], 'status' => 'verified', 'ownership_status' => 'origin_response', 'ownership_evidence' => $proof, 'title' => 'Response from explicit test', 'http_status' => 200];
        $this->postJson($url, $body)->assertUnprocessable();
        $task->refresh()->update(['mode' => 'origin_test', 'status' => 'pending', 'lease_token' => null, 'leased_until' => null]);
        $claim = $this->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame('origin_test', $claim['mode']);
        $body['lease_token'] = $claim['lease_token'];
        $body['ownership_evidence']['origin_test']['target_ip'] = '203.0.113.11';
        $this->postJson($url, $body)->assertUnprocessable();
        $body['ownership_evidence'] = $proof;
        $this->postJson($url, $body)->assertOk();
        $this->assertSame('origin_response', $site->fresh()->ownership_status);
        $this->assertSame('tls_sni', $site->fresh()->source);
        $this->assertSame(['198.51.100.1'], $site->fresh()->ownership_evidence['addresses']);
        $this->assertSame('normal', $task->fresh()->mode);
        $queue->enqueue($site);
        $claim = $this->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame('normal', $claim['mode']);
        $body['lease_token'] = $claim['lease_token'];
        $body['status'] = 'failed';
        $body['ownership_status'] = 'dns_mismatch';
        unset($body['ownership_evidence']['origin_test']);
        $this->postJson($url, $body)->assertOk();
        $this->assertSame($proof['origin_test'], $site->fresh()->ownership_evidence['origin_test']);
        $this->assertSame('dns_mismatch', $site->fresh()->ownership_status);
    }

    public function test_udp_statistics_are_validated_and_preserved_without_quantity_alerts(): void
    {
        $this->seed(MonitorSeeder::class);
        Rule::where('kind', 'udp_flow_burst')->update(['threshold' => 2]);
        Rule::where('kind', 'udp_packet_rate')->update(['threshold' => 10]);
        $node = $this->node();
        $payload = $this->payload();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_flow_burst']);
        $payload = $this->payload();
        $payload['metrics'][0] = array_replace($payload['metrics'][0], [
            'udp_stats_version' => 1, 'udp_flows_out' => 1003, 'udp_packets_out' => 10600, 'udp_packets_in' => 20,
            'udp_filter_version' => 1, 'udp_non_dns_flows_out' => 3, 'udp_non_dns_packets_out' => 600,
            'udp_bytes_out' => 424000, 'udp_bytes_in' => 800, 'udp_flows_capped' => false, 'udp_endpoints_truncated' => false,
            'packets_out' => 10600, 'packets_in' => 20, 'bytes_out' => 424000, 'bytes_in' => 800,
            'udp_endpoints' => [['peer_ip' => '198.51.100.1', 'peer_port' => 53, 'flows' => 1000, 'packets_out' => 10000, 'packets_in' => 0, 'bytes_out' => 400000, 'bytes_in' => 0]],
            'udp_non_dns_endpoints' => [['peer_ip' => '198.51.100.2', 'peer_port' => 443, 'flows' => 3, 'packets_out' => 600, 'packets_in' => 20, 'bytes_out' => 24000, 'bytes_in' => 800]],
        ]);
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::latest('id')->first()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_flow_burst']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_packet_rate']);
        $metric = TrafficMetric::latest('id')->firstOrFail();
        $this->assertSame(10600, $metric->evidence['udp_packets_out']);
        $this->assertSame(600, $metric->evidence['udp_non_dns_packets_out']);
        $this->assertSame(3, $metric->evidence['udp_non_dns_flows_out']);
        $this->assertSame(443, $metric->evidence['udp_non_dns_endpoints'][0]['peer_port']);
        $payload['batch_id'] = Str::uuid()->toString();
        $payload['metrics'][0]['udp_flows_out'] = 10601;
        $this->upload($node, $payload)->assertUnprocessable();
        $payload['metrics'][0]['udp_flows_out'] = 1003;
        $invalid = $payload;
        $invalid['metrics'][0]['udp_non_dns_endpoints'][0]['peer_port'] = 53;
        $this->upload($node, $invalid)->assertUnprocessable();
        $invalid = $payload;
        $invalid['metrics'][0]['udp_non_dns_flows_out'] = 601;
        $this->upload($node, $invalid)->assertUnprocessable();
        $payload['metrics'][0]['udp_endpoints'] = array_fill(0, 9, $payload['metrics'][0]['udp_endpoints'][0]);
        $this->upload($node, $payload)->assertUnprocessable();
    }

    public function test_large_udp_windows_keep_statistics_without_notifying(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        Rule::create(['name' => 'Stale UDP rate rule', 'kind' => 'udp_packet_rate', 'threshold' => 10000, 'window_seconds' => 60]);
        $node = $this->node();
        foreach ([217716, 406944] as $index => $packets) {
            $payload = $this->payload();
            $payload['window_start'] = now()->subSeconds(60 - $index * 30)->toIso8601String();
            $payload['window_end'] = now()->subSeconds(30 - $index * 30)->toIso8601String();
            $payload['metrics'][0] = array_replace($payload['metrics'][0], [
                'udp_stats_version' => 1, 'udp_filter_version' => 1,
                'udp_flows_out' => 351, 'udp_non_dns_flows_out' => 351,
                'udp_packets_out' => $packets, 'udp_non_dns_packets_out' => $packets, 'udp_packets_in' => 20,
                'udp_bytes_out' => $packets * 100, 'udp_bytes_in' => 800,
                'packets_out' => $packets, 'packets_in' => 20, 'bytes_out' => $packets * 100, 'bytes_in' => 800,
                'udp_flows_capped' => false, 'udp_endpoints_truncated' => true,
                'udp_endpoints' => [],
                'udp_non_dns_endpoints' => [['peer_ip' => '198.51.100.2', 'peer_port' => 63845, 'flows' => 1, 'packets_out' => 100, 'packets_in' => 20, 'bytes_out' => 10000, 'bytes_in' => 800]],
            ]);
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::latest('id')->firstOrFail()->id);
            if ($index === 0) {
                $this->assertDatabaseMissing('alerts', ['kind' => 'udp_packet_rate']);
            }
        }
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_packet_rate']);
        $this->assertDatabaseCount('monitor_events', 0);
        $metrics = TrafficMetric::orderBy('window_start')->get();
        $this->assertCount(2, $metrics);
        $this->assertSame(217716, $metrics[0]->evidence['udp_non_dns_packets_out']);
        $this->assertSame(406944, $metrics[1]->evidence['udp_non_dns_packets_out']);
        $this->assertSame(63845, $metrics[1]->evidence['udp_non_dns_endpoints'][0]['peer_port']);
        $this->assertEquals(30, $metrics[1]->window_start->diffInSeconds($metrics[1]->window_end));
    }

    public function test_udp_tuple_counts_remain_separate_per_window_without_notifications(): void
    {
        $this->freezeTime();
        $this->seed(MonitorSeeder::class);
        Rule::create(['name' => 'Stale UDP flow rule', 'kind' => 'udp_flow_burst', 'threshold' => 1000, 'window_seconds' => 60]);
        $node = $this->node();
        foreach ([1056, 1001] as $index => $flows) {
            $payload = $this->payload();
            $payload['window_start'] = now()->subSeconds(60 - $index * 30)->toIso8601String();
            $payload['window_end'] = now()->subSeconds(30 - $index * 30)->toIso8601String();
            $payload['metrics'][0] = array_replace($payload['metrics'][0], [
                'udp_stats_version' => 1, 'udp_filter_version' => 1,
                'udp_flows_out' => $flows, 'udp_non_dns_flows_out' => $flows,
                'udp_packets_out' => 24325, 'udp_non_dns_packets_out' => 24325, 'udp_packets_in' => 100,
                'udp_bytes_out' => 2432500, 'udp_bytes_in' => 10000,
                'packets_out' => 24325, 'packets_in' => 100, 'bytes_out' => 2432500, 'bytes_in' => 10000,
                'udp_flows_capped' => false, 'udp_endpoints_truncated' => true, 'udp_endpoints' => [],
                'udp_non_dns_endpoints' => [],
            ]);
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::latest('id')->firstOrFail()->id);
        }
        $this->assertDatabaseMissing('alerts', ['kind' => 'udp_flow_burst']);
        $this->assertDatabaseCount('monitor_events', 0);
        $metrics = TrafficMetric::orderBy('window_start')->get();
        $this->assertCount(2, $metrics);
        $this->assertSame(1056, $metrics[0]->evidence['udp_non_dns_flows_out']);
        $this->assertSame(1001, $metrics[1]->evidence['udp_non_dns_flows_out']);
    }

    public function test_service_connection_rules_use_destination_samples_and_keep_login_outcomes_unknown(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['outbound_endpoints'] = array_map(fn ($port) => [
            'peer_ip' => '198.51.100.1', 'peer_port' => $port, 'attempts' => 70,
            'synack_replies' => 65, 'completed_handshakes' => 65, 'rst_replies' => 1,
            'payload_out' => 100, 'payload_in' => 200,
        ], [21, 22, 445, 3389]);
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        foreach (['ssh_connections', 'rdp_connections', 'ftp_connections'] as $kind) {
            $this->assertDatabaseMissing('alerts', ['kind' => $kind]);
        }
        $alert = Alert::where('kind', 'smb_connections')->firstOrFail();
        $this->assertSame('medium', $alert->severity);
        $this->assertSame(70, $alert->evidence['value']);
        $this->assertSame('not visible in aggregate traffic', $alert->evidence['sample']['login_result']);
        $this->assertNull($alert->evidence['connection_analysis']['completion_ratio']);
        $this->assertDatabaseCount('alerts', 1);
        $this->assertDatabaseCount('monitor_events', 1);
    }

    public function test_service_handshakes_are_paired_without_inventing_target_no_reply_counts(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0] += ['connection_stats_version' => 1, 'synack_replies' => 317, 'completed_handshakes' => 317, 'rst_replies' => 3, 'mature_attempts' => 317, 'mature_no_reply' => 0];
        $payload['metrics'][0]['tcp_attempts'] = 317;
        $payload['metrics'][0]['outbound_endpoints'] = [$this->smbEndpoint(317, ['peer_ip' => '43.128.8.64', 'rst_replies' => 3, 'payload_out' => 424670, 'payload_in' => 355694])];
        $payload['health'] = ['version' => '1.3.0', 'captured' => 782815, 'kernel_drops' => 84, 'decode_skipped' => 6973, 'state_dropped' => 0];
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $evidence = Alert::where('kind', 'smb_connections')->firstOrFail()->evidence;
        $this->assertSame(317, $evidence['value']);
        $this->assertSame(317, $evidence['connection_analysis']['completed_handshakes']);
        $this->assertEquals(1.0, $evidence['connection_analysis']['completion_ratio']);
        $this->assertSame(3, $evidence['connection_analysis']['rst_replies']);
        $this->assertNull($evidence['connection_analysis']['mature_no_reply']);
        $this->assertSame('paired_transport', $evidence['confidence']);
        $this->assertSame('deduplicated_tcp_syn_attempts', $evidence['sample']['count_basis']);
    }

    public function test_worker_completion_preserves_administrator_origin_registration_and_previous_dns(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::firstOrFail();
        $registration = ['type' => 'cdn_origin', 'reason' => 'Customer CDN configuration verified', 'confirmed_by' => 1];
        $previous = ['status' => 'dns_mismatch', 'evidence' => ['addresses' => ['198.51.100.1']]];
        $site->update(['source' => 'manual', 'ownership_status' => 'manual', 'ownership_evidence' => ['registration' => $registration, 'previous_dns' => $previous]]);
        app(ProbeQueue::class)->enqueue($site);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame('manual', $claim['source']);
        $this->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', [
            'lease_token' => $claim['lease_token'], 'status' => 'failed', 'error' => 'Origin access restricted',
            'ownership_status' => 'manual', 'ownership_evidence' => [
                'host' => $site->host, 'checked_at' => now()->toIso8601String(), 'method' => 'administrator_registered', 'addresses' => [],
                'registration' => ['reason' => 'untrusted worker overwrite'],
            ],
        ])->assertOk();
        $this->assertSame($registration, $site->fresh()->ownership_evidence['registration']);
        $this->assertSame($previous, $site->fresh()->ownership_evidence['previous_dns']);
    }

    public function test_ip_only_ownership_accepts_empty_dns_address_evidence(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $node = $this->node();
        $payload = $this->payload();
        $payload['sites'][0]['host'] = '';
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $site = Website::firstOrFail();
        $this->assertSame('ip_only', $site->ownership_status);
        app(ProbeQueue::class)->enqueue($site);
        $claim = $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->postJson('/api/v1/worker/tasks/'.$claim['id'].'/complete', ['lease_token' => $claim['lease_token'], 'status' => 'verified', 'ownership_status' => 'ip_only', 'ownership_evidence' => ['host' => $claim['ip'], 'checked_at' => now()->toIso8601String(), 'method' => 'literal_ip_comparison', 'addresses' => []]])->assertOk();
        $this->assertSame('verified', $site->fresh()->status);
    }
}
