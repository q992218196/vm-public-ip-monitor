<?php

namespace Tests\Feature;

use App\Filament\Resources\NodeResource;
use App\Filament\Resources\NodeResource\Pages\ManageNodes;
use App\Jobs\ProcessBatch;
use App\Models\Batch;
use App\Models\Node;
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
}
