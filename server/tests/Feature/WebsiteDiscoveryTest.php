<?php

namespace Tests\Feature;

use App\Jobs\ProcessBatch;
use App\Models\AuditLog;
use App\Models\Batch;
use App\Models\Node;
use App\Models\ProbeTask;
use App\Models\Website;
use App\Services\ProbeQueue;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

class WebsiteDiscoveryTest extends TestCase
{
    use RefreshDatabase;

    private string $token = 'website-discovery-token-abcdefghijklmnopqrstuvwxyz';

    private function upload(array $sites): void
    {
        $node = Node::firstOrCreate(['name' => 'Discovery node'], ['cidrs' => ['203.0.113.0/24'], 'token_hash' => hash('sha256', $this->token)]);
        $payload = ['batch_id' => (string) Str::uuid(), 'window_start' => now()->subSeconds(30)->toIso8601String(), 'window_end' => now()->toIso8601String(),
            'health' => ['version' => '1.5.0', 'kernel_drops' => 0], 'sites' => $sites,
            'metrics' => [['ip' => '203.0.113.10', 'bytes_out' => 100, 'bytes_in' => 100, 'packets_out' => 2, 'packets_in' => 2, 'tcp_attempts' => 1,
                'unique_targets' => 1, 'max_ports_per_target' => 1, 'max_attempts_per_target' => 1, 'auth_attempts' => 0, 'targets' => [], 'cardinality_capped' => false]]];
        $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $node->id])->postJson('/api/v1/agent/batches', $payload)->assertOk();
        ProcessBatch::dispatchSync(Batch::where('batch_id', $payload['batch_id'])->firstOrFail()->id);
    }

    private function hint(string $source = 'tls_sni', int $port = 3389, string $host = ''): array
    {
        return ['ip' => '203.0.113.10', 'port' => $port, 'scheme' => $source === 'http_host' ? 'http' : 'https', 'host' => $host, 'source' => $source];
    }

    public function test_pure_tls_and_rdp_clues_are_preserved_without_automatic_work(): void
    {
        $this->upload([$this->hint(), $this->hint('rdp_negotiation', 13389), $this->hint('tls_alpn', 23389), $this->hint('http_host', 3389)]);
        $this->assertSame('tls_unknown', Website::where('source', 'tls_sni')->firstOrFail()->discovery_kind);
        $this->assertSame('rdp', Website::where('source', 'rdp_negotiation')->firstOrFail()->discovery_kind);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertDatabaseCount('websites', 4);
        $this->assertDatabaseCount('probe_tasks', 2);
        foreach (Website::whereIn('discovery_kind', ['rdp', 'tls_unknown'])->get() as $site) {
            $this->assertNull(app(ProbeQueue::class)->enqueue($site, false));
        }
    }

    public function test_manual_verification_bypasses_admission_and_http_proof_promotes_service_clue(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $this->upload([$this->hint()]);
        $site = Website::firstOrFail();
        $task = ProbeTask::create(['website_id' => $site->id, 'status' => 'pending', 'available_at' => now(), 'request_source' => 'auto']);
        $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->assertJsonPath('task', null);
        app(ProbeQueue::class)->enqueue($site);
        $this->assertSame('manual', $task->fresh()->request_source);
        $claim = $this->postJson('/api/v1/worker/claim')->assertOk()->json('task');
        $this->assertSame('tls_unknown', $claim['discovery_kind']);
        $this->postJson('/api/v1/worker/tasks/'.$task->id.'/complete', ['lease_token' => $claim['lease_token'], 'status' => 'verified', 'http_status' => 403, 'classification' => ['method' => 'http_headers']])->assertOk();
        $this->assertSame('web_candidate', $site->fresh()->discovery_kind);
        $this->upload([$this->hint()]);
        $this->assertSame('web_candidate', $site->fresh()->discovery_kind);
    }

    public function test_ip_literal_and_empty_tls_clues_share_one_asset_and_stronger_evidence_is_retained(): void
    {
        $this->upload([$this->hint(), $this->hint('tls_sni', 3389, '203.0.113.10')]);
        $this->assertDatabaseCount('websites', 1);
        $this->upload([$this->hint('tls_alpn')]);
        $this->assertSame('web_candidate', Website::firstOrFail()->discovery_kind);
        $this->upload([$this->hint()]);
        $this->assertSame('tls_alpn', Website::firstOrFail()->source);
    }

    public function test_new_rdp_evidence_cancels_only_unexecuted_automatic_task(): void
    {
        $this->upload([$this->hint('tls_alpn'), $this->hint('tls_alpn', 13389)]);
        $auto = app(ProbeQueue::class)->enqueue(Website::where('port', 3389)->firstOrFail(), false);
        $manual = app(ProbeQueue::class)->enqueue(Website::where('port', 13389)->firstOrFail(), true);
        $this->upload([$this->hint('rdp_negotiation'), $this->hint('rdp_negotiation', 13389)]);
        $this->assertSame('skipped', $auto->fresh()->status);
        $this->assertSame('pending', $manual->fresh()->status);
        $this->assertSame('manual', $manual->fresh()->request_source);
    }

    public function test_failed_probe_cools_down_for_a_day_but_manual_retry_is_immediate(): void
    {
        $this->freezeTime();
        $this->upload([$this->hint('tls_alpn')]);
        $site = Website::firstOrFail();
        $task = app(ProbeQueue::class)->enqueue($site, false);
        $task->update(['status' => 'failed']);
        app(ProbeQueue::class)->enqueue($site, false);
        $this->assertSame('failed', $task->fresh()->status);
        app(ProbeQueue::class)->enqueue($site, true);
        $this->assertSame('pending', $task->fresh()->status);
        $this->assertSame('manual', $task->fresh()->request_source);
    }

    public function test_http_candidates_restore_skipped_task_and_manual_work_is_claimed_first(): void
    {
        config(['monitor.worker_token' => $this->token]);
        $this->upload([$this->hint('tls_alpn'), $this->hint('tls_alpn', 13389)]);
        $auto = app(ProbeQueue::class)->enqueue(Website::where('port', 3389)->firstOrFail(), false);
        $auto->update(['status' => 'skipped']);
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertSame('pending', $auto->fresh()->status);
        $manual = app(ProbeQueue::class)->enqueue(Website::where('port', 13389)->firstOrFail(), true);
        $this->withToken($this->token)->postJson('/api/v1/worker/claim')->assertOk()->assertJsonPath('task.id', $manual->id);
    }

    public function test_expired_service_leases_release_capacity_without_cancelling_running_or_manual_work(): void
    {
        $this->upload([$this->hint(), $this->hint('rdp_negotiation', 13389), $this->hint('tls_sni', 3389, 'manual.example')]);
        $sites = Website::orderBy('id')->get();
        foreach ($sites as $i => $site) {
            ProbeTask::create(['website_id' => $site->id, 'request_source' => $i === 2 ? 'manual' : 'auto', 'status' => 'leased', 'attempts' => 1,
                'available_at' => now(), 'lease_token' => str_repeat('a', 64), 'leased_until' => $i === 1 ? now()->addMinute() : now()->subMinute()]);
        }
        $this->artisan('monitor:maintain')->assertSuccessful();
        $this->assertSame('skipped', $sites[0]->task->status);
        $this->assertNull($sites[0]->task->lease_token);
        $this->assertSame('leased', $sites[1]->task->status);
        $this->assertSame('leased', $sites[2]->task->status);
    }

    public function test_upgrade_moves_only_unverified_tls_and_cancels_pending_normal_tasks(): void
    {
        $this->upload([$this->hint(), $this->hint('tls_sni', 3389, 'manual.example'), $this->hint('tls_sni', 3389, 'verified.example'), $this->hint('tls_sni', 3389, 'origin.example'), $this->hint('tls_sni', 3389, 'forced.example')]);
        $sites = Website::orderBy('id')->get();
        $sites[1]->update(['source' => 'manual', 'ownership_status' => 'manual']);
        $sites[2]->update(['http_status' => 200, 'status' => 'verified']);
        foreach ($sites as $i => $site) {
            ProbeTask::create(['website_id' => $site->id, 'status' => 'pending', 'mode' => $i === 3 ? 'origin_test' : 'normal', 'available_at' => now()]);
        }
        AuditLog::create(['action' => 'probe_queued', 'subject' => 'Website:'.$sites[4]->id, 'details' => [], 'created_at' => now()->addSecond()]);
        Schema::table('websites', function (Blueprint $table): void {
            $table->dropIndex('websites_discovery_kind_index');
            $table->dropColumn('discovery_kind');
        });
        Schema::table('probe_tasks', fn (Blueprint $table) => $table->dropColumn('request_source'));
        $migration = require database_path('migrations/2026_10_08_122147_classify_service_clues_before_web_probing.php');
        $migration->up();
        $this->assertSame('tls_unknown', $sites[0]->fresh()->discovery_kind);
        $this->assertSame('skipped', $sites[0]->task->status);
        foreach ([1, 2] as $i) {
            $this->assertSame('web_candidate', $sites[$i]->fresh()->discovery_kind);
            $this->assertSame('pending', $sites[$i]->task->status);
        }
        $this->assertSame('pending', $sites[3]->task->status);
        $this->assertSame('pending', $sites[4]->task->status);
        $this->assertSame('manual', $sites[4]->task->request_source);
        $this->assertDatabaseCount('websites', 5);
    }
}
