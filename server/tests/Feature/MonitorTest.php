<?php

namespace Tests\Feature;

use App\Filament\Resources\NodeResource;
use App\Filament\Resources\NodeResource\Pages\ManageNodes;
use App\Jobs\ProcessBatch;
use App\Models\Batch;
use App\Models\Alert;
use App\Models\Node;
use App\Models\ProtocolObservation;
use App\Models\Rule;
use App\Models\User;
use App\Models\Website;
use App\Services\ProbeQueue;
use Database\Seeders\MonitorSeeder;
use Filament\Facades\Filament;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Livewire\Livewire;
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

    public function test_panel_pages_render_and_viewer_cannot_mutate(): void
    {
        $n = $this->node();
        $this->upload($n, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $u = User::factory()->create();
        $u->role = 'admin';
        $u->save();
        $this->actingAs($u);
        foreach (['/admin', '/admin/nodes', '/admin/ip-assets', '/admin/websites', '/admin/alerts', '/admin/rules', '/admin/exclusions', '/admin/traffic-metrics', '/admin/probe-tasks', '/admin/audit-logs'] as $url) {
            $this->get($url)->assertOk();
        }
        $u->role = 'viewer';
        $u->save();
        $this->assertFalse(NodeResource::canCreate());
        $this->assertFalse(NodeResource::canEdit($this->node()));
        $this->get('/admin/nodes')->assertOk();
    }

    public function test_private_screenshots_require_login(): void
    {
        $this->get('/screenshots/1')->assertRedirect('/admin/login');
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

    public function test_alerts_can_be_filtered_and_handled_in_a_bounded_batch(): void
    {
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();
        $this->actingAs($admin);
        $alert = Alert::where('kind', 'new_website')->firstOrFail();
        $this->get('/admin/alerts?node='.$node->id.'&ip=203.0.113.10&severity=low')->assertOk()->assertSee($alert->title);
        $this->getJson(route('alerts.count', ['node' => $node->id, 'ip' => '203.0.113.10', 'severity' => 'low']))
            ->assertOk()->assertJsonPath('total', 1);
        $this->getJson(route('alerts.count', ['severity' => 'high']))
            ->assertOk()->assertJsonPath('total', 0);
        $this->post(route('alerts.bulk'), ['ids' => [$alert->id], 'status' => 'acknowledged', 'resolution' => '已核对资产'])->assertRedirect();
        $this->assertDatabaseHas('alerts', ['id' => $alert->id, 'status' => 'acknowledged', 'resolution' => '已核对资产']);
        $this->assertDatabaseHas('audit_logs', ['action' => 'alerts_bulk_handled']);
    }

    public function test_node_create_form_validates_cidrs_and_saves_settings(): void
    {
        $u = User::factory()->create();
        $u->role = 'admin';
        $u->save();
        $this->actingAs($u);
        Filament::setCurrentPanel(Filament::getPanel('admin'));
        $component = Livewire::test(ManageNodes::class);
        $component->callAction('create', data: ['name' => 'Bridge Host', 'enabled' => true, 'cidrs' => ['203.0.113.0/24'], 'settings' => ['interfaces' => ['eth0'], 'memory_soft_mib' => 2048, 'memory_hard_mib' => 4096, 'disk_limit_mib' => 2048, 'data_dir' => '/home/vm-monitor']])->assertHasNoActionErrors();
        $this->assertDatabaseHas('nodes', ['name' => 'Bridge Host']);
        $this->assertSame(['203.0.113.0/24'], Node::first()->cidrs);
        $component->callAction('create', data: ['name' => 'Invalid', 'enabled' => true, 'cidrs' => ['bad-cidr'], 'settings' => ['interfaces' => ['eth0'], 'data_dir' => '/home/vm-monitor']])->assertHasActionErrors();
        $this->assertDatabaseCount('nodes', 1);
    }

    public function test_node_evidence_is_loaded_independently_of_the_table(): void
    {
        $node = $this->node();
        $node->update(['health' => ['kernel_drops' => 2]]);
        $this->getJson(route('nodes.evidence', $node))->assertUnauthorized();

        $viewer = User::factory()->create();
        $viewer->role = 'viewer';
        $viewer->save();
        $this->actingAs($viewer)
            ->getJson(route('nodes.evidence', $node))
            ->assertOk()
            ->assertJsonPath('data.health.kernel_drops', 2)
            ->assertJsonMissingPath('data.token_hash');
    }

    public function test_admin_can_open_profile_to_change_email_and_password(): void
    {
        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();

        $this->actingAs($admin);
        $this->get(Filament::getPanel('admin')->getProfileUrl())->assertOk();
    }

    public function test_resolving_new_website_alert_does_not_reopen_it_on_next_observation(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $payload['sites'][0]['host'] = 'account.skrill.com';
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::firstOrFail()->id);
        $alert = Alert::where('kind', 'new_website')->firstOrFail();
        $alert->update(['status' => 'resolved']);

        $this->travel(1)->days();
        $payload['batch_id'] = Str::uuid()->toString();
        $payload['window_start'] = now()->subSeconds(30)->toIso8601String();
        $payload['window_end'] = now()->toIso8601String();
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
        $this->assertDatabaseCount('websites', 1);
        $this->assertSame(1, Alert::where('kind', 'new_website')->count());
        $this->assertSame('resolved', $alert->fresh()->status);
    }

    public function test_alert_list_excludes_evidence_and_detail_loads_only_requested_alert(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $payload['metrics'][0]['ports'] = [22, 443];
        $payload['metrics'][0]['target_endpoints'] = ['1.1.1.1:22', '1.1.1.1:443'];
        $this->seed(MonitorSeeder::class);
        $this->upload($node, $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $alert = Alert::where('kind', 'horizontal_scan')->firstOrFail();
        $this->assertSame([22, 443], $alert->evidence['sample']['ports']);

        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();
        $this->actingAs($admin);
        $list = $this->get('/admin/alerts?per_page=500')->assertOk();
        $this->assertStringNotContainsString('target_endpoints', $list->getContent());
        $this->get(route('alerts.evidence', $alert))->assertOk()->assertSee('1.1.1.1:22')->assertSee('443');
        $export = $this->get('/exports/alerts')->assertOk()->streamedContent();
        $this->assertStringNotContainsString('target_endpoints', $export);
    }

    public function test_website_description_export_and_domain_link(): void
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
            'lease_token' => $claim['lease_token'], 'status' => 'verified', 'title' => '测试网站',
            'description' => '这是一段网站描述', 'http_status' => 200,
        ])->assertOk();
        $this->assertSame('这是一段网站描述', $site->fresh()->description);

        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();
        $this->actingAs($admin);
        $this->get('/admin/websites')->assertOk()->assertSee('test.example');
        $this->post(route('websites.category', $site), ['manual_category' => '人工复核'])->assertRedirect();
        $this->assertSame('人工复核', $site->fresh()->manual_category);
        $this->post(route('websites.probe', $site))->assertRedirect();
        $this->post(route('websites.manual'), ['ip' => '203.0.113.10', 'port' => 18080, 'scheme' => 'http', 'host' => 'manual.example'])->assertRedirect();
        $this->assertDatabaseHas('websites', ['host' => 'manual.example', 'port' => 18080]);
        $this->get(route('websites.details', $site))->assertOk()->assertSee('这是一段网站描述');
        $export = $this->get('/exports/websites')->assertOk()->streamedContent();
        $this->assertStringContainsString('这是一段网站描述', $export);
    }

    public function test_large_lists_and_bulk_post_stay_small(): void
    {
        $node = $this->node();
        $now = now();
        $alerts = [];
        for ($i = 0; $i < 500; $i++) {
            $alerts[] = [
                'node_id' => $node->id, 'dedup_key' => hash('sha256', 'large-alert-'.$i),
                'kind' => 'horizontal_scan', 'severity' => 'high', 'title' => '扫描 '.$i,
                'status' => 'open', 'evidence' => json_encode(['large_private_evidence' => str_repeat('x', 10000)]),
                'first_seen_at' => $now, 'last_seen_at' => $now, 'created_at' => $now, 'updated_at' => $now,
            ];
        }
        Alert::insert($alerts);
        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();
        $this->actingAs($admin);
        $response = $this->get('/admin/alerts?per_page=500')->assertOk();
        $this->assertLessThan(1000000, strlen($response->getContent()));
        $this->assertStringNotContainsString('large_private_evidence', $response->getContent());
        $ids = Alert::query()->pluck('id')->all();
        $this->assertLessThan(10000, strlen(http_build_query(['ids' => $ids, 'status' => 'resolved', 'resolution' => '已复核'])));
        $this->post(route('alerts.bulk'), ['ids' => $ids, 'status' => 'resolved', 'resolution' => '已复核'])->assertRedirect();
        $this->assertSame(500, Alert::where('status', 'resolved')->count());
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
        $viewer = User::factory()->create();
        $viewer->role = 'viewer';
        $viewer->save();
        $this->actingAs($viewer)->get(route('protocol-observations.evidence', ProtocolObservation::firstOrFail()))
            ->assertOk()->assertJsonPath('evidence.protocol', 'wireguard');
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
        $viewer = User::factory()->create();
        $viewer->role = 'viewer';
        $viewer->save();
        $this->actingAs($viewer)->get(route('alerts.evidence', $alert))->assertOk()->assertSee('不能确认 SS');
        $this->get(route('protocol-observations.evidence', ProtocolObservation::firstOrFail()))
            ->assertOk()->assertJsonPath('evidence.transport', 'tls');
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

    public function test_website_cursor_pages_exclude_large_classification(): void
    {
        $node = $this->node();
        $this->upload($node, $this->payload())->assertOk();
        ProcessBatch::dispatchSync(Batch::first()->id);
        $assetId = Website::firstOrFail()->ip_asset_id;
        $now = now();
        $sites = [];
        for ($i = 0; $i < 500; $i++) {
            $sites[] = [
                'ip_asset_id' => $assetId, 'fingerprint' => hash('sha256', 'large-site-'.$i),
                'port' => 8000 + $i, 'scheme' => 'http', 'host' => 'site'.$i.'.example',
                'source' => 'manual', 'status' => 'verified', 'classification' => json_encode(['large_classification' => str_repeat('x', 10000)]),
                'first_seen_at' => $now, 'last_seen_at' => $now, 'created_at' => $now, 'updated_at' => $now,
            ];
        }
        Website::insert($sites);
        $admin = User::factory()->create();
        $admin->role = 'admin';
        $admin->save();
        $this->actingAs($admin);
        $response = $this->get('/admin/websites?per_page=500')->assertOk();
        $this->assertLessThan(1000000, strlen($response->getContent()));
        $this->assertStringNotContainsString('large_classification', $response->getContent());
        $cursor = Website::query()->orderByDesc('last_seen_at')->orderByDesc('id')->cursorPaginate(500)->nextCursor();
        $this->get('/admin/websites?per_page=500&cursor='.urlencode($cursor->encode()))->assertOk()->assertSee('本页 1 条');
    }
}
