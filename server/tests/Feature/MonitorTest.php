<?php

namespace Tests\Feature;

use App\Jobs\ProcessBatch;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\Node;
use App\Models\ProtocolObservation;
use App\Models\Rule;
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

    public function test_scope_auth_and_atomic_rejection(): void
    {
        $n = $this->node();
        $this->postJson('/api/v1/agent/batches', $this->payload())->assertUnauthorized();
        $this->upload($n, $this->payload('8.8.8.8'))->assertUnprocessable();
        $this->assertDatabaseCount('batches', 0);
        $n->update(['enabled' => false]);
        $this->upload($n, $this->payload())->assertUnauthorized();
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
        $this->upload($n, $p)->assertOk()->assertJson(['accepted' => true, 'duplicate' => false]);
        $this->upload($n, $p)->assertOk()->assertJson(['duplicate' => true]);
        $this->assertDatabaseCount('batches', 1);
        $this->assertDatabaseCount('traffic_metrics', 0);
        ProcessBatch::dispatchSync(Batch::first()->id);
        ProcessBatch::dispatchSync(Batch::first()->id);
        $this->assertDatabaseCount('traffic_metrics', 1);
        $this->assertDatabaseCount('websites', 1);
        $this->assertDatabaseHas('alerts', ['kind' => 'horizontal_scan']);
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
        $this->assertDatabaseHas('alerts', ['kind' => 'single_target_attempts']);
        $this->assertDatabaseHas('alerts', ['kind' => 'tcp_connection_burst']);
    }

    public function test_horizontal_scan_with_many_replied_bidirectional_connections_is_review_level(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0] = array_replace($payload['metrics'][0], [
            'bytes_out' => 3492528, 'bytes_in' => 3657616,
            'tcp_attempts' => 113, 'unique_targets' => 112,
            'max_ports_per_target' => 1, 'max_attempts_per_target' => 2,
            'synack_replies' => 100,
        ]);
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $alert = Alert::where('kind', 'horizontal_scan')->firstOrFail();
        $this->assertSame('medium', $alert->severity);
        $this->assertSame('bidirectional_candidate', $alert->evidence['confidence']);
        $this->assertSame(100, $alert->evidence['sample']['synack_replies']);
    }

    public function test_horizontal_scan_without_replies_keeps_high_severity(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['synack_replies'] = 0;
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $this->assertSame('high', Alert::where('kind', 'horizontal_scan')->firstOrFail()->severity);
    }

    public function test_replied_web_fanout_with_hotspot_is_not_high_scan_and_can_be_reassessed(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        foreach ([[1313, 1301, 232, 6], [386, 383, 123, 203]] as [$attempts, $replies, $targets, $hotspot]) {
            $payload = $this->payload();
            $payload['metrics'][0] = array_replace($payload['metrics'][0], [
                'tcp_attempts' => $attempts, 'synack_replies' => $replies, 'unique_targets' => $targets,
                'max_attempts_per_target' => $hotspot, 'max_ports_per_target' => 1, 'ports' => [443],
            ]);
            $this->upload($node, $payload)->assertOk();
            ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
            $alert = Alert::where('kind', 'horizontal_scan')->firstOrFail();
            $this->assertSame('medium', $alert->severity);
            $this->assertSame('多目标 Web 端口连接（待复核）', $alert->title);
            $this->assertGreaterThan(0.99, $alert->evidence['connection_analysis']['reply_ratio']);
        }
        $this->assertDatabaseHas('alerts', ['kind' => 'single_target_attempts']);
        $alert->update(['severity' => 'high']);
        $this->artisan('monitor:reassess-scans')->assertSuccessful();
        $alert->refresh();
        $this->assertSame('medium', $alert->severity);
        $alert->update(['status' => 'resolved', 'severity' => 'high']);
        $this->artisan('monitor:reassess-scans')->assertSuccessful();
        $this->assertSame('high', $alert->fresh()->severity);
    }

    public function test_inconsistent_handshake_counts_do_not_imply_success(): void
    {
        $assessment = app(ScanAssessment::class)->assess(['tcp_attempts' => 100, 'synack_replies' => 101, 'max_ports_per_target' => 1]);
        $this->assertSame('high', $assessment['severity']);
        $this->assertNull($assessment['connection_analysis']['reply_ratio']);
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

    public function test_sparse_single_port_fanout_with_few_replies_remains_high_priority(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0] = array_replace($payload['metrics'][0], [
            'bytes_out' => 2097780, 'bytes_in' => 2142215,
            'tcp_attempts' => 103, 'unique_targets' => 102,
            'max_ports_per_target' => 1, 'max_attempts_per_target' => 2,
            'synack_replies' => 13,
        ]);
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $alert = Alert::where('kind', 'horizontal_scan')->firstOrFail();
        $this->assertSame('high', $alert->severity);
        $this->assertSame('behavioral', $alert->evidence['confidence']);
        $this->assertStringContainsString('13/103', $alert->evidence['note']);
    }

    public function test_scan_only_exclusion_preserves_other_alert_types_and_metrics(): void
    {
        $this->seed(MonitorSeeder::class);
        $node = $this->node();
        Exclusion::create([
            'node_id' => $node->id, 'cidr' => '203.0.113.10/32',
            'kind' => 'horizontal_scan', 'reason' => '业务复核', 'expires_at' => now()->addDays(30),
        ]);
        $payload = $this->payload();
        $payload['metrics'][0]['max_ports_per_target'] = 50;
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $this->assertDatabaseMissing('alerts', ['kind' => 'horizontal_scan']);
        $this->assertDatabaseHas('alerts', ['kind' => 'vertical_scan']);
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
}
