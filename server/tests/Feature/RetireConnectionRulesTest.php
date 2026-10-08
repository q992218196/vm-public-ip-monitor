<?php

namespace Tests\Feature;

use App\Models\AiAnalysis;
use App\Models\Alert;
use App\Models\Batch;
use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Models\PacketCapture;
use App\Models\Rule;
use App\Models\TrafficMetric;
use App\Services\RetireConnectionRules;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Tests\TestCase;

class RetireConnectionRulesTest extends TestCase
{
    use RefreshDatabase;

    private function event(array $kinds, array $attributes = []): MonitorEvent
    {
        $node = Node::firstOrCreate(['name' => 'Retirement test'], ['cidrs' => ['203.0.113.0/24']]);
        $ip = IpAsset::firstOrCreate(['ip' => '203.0.113.10'], ['version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);

        return MonitorEvent::create($attributes + ['node_id' => $node->id, 'ip_asset_id' => $ip->id, 'active_key' => hash('sha256', (string) Str::uuid()),
            'title' => '多端口连接（待复核）', 'severity' => 'high', 'assessment_category' => 'needs_review', 'kinds' => $kinds,
            'first_seen_at' => '2026-10-01 00:00:00', 'last_seen_at' => '2026-10-08 12:00:00', 'occurrences' => 99]);
    }

    private function alert(MonitorEvent $event, string $kind, array $attributes = []): Alert
    {
        return Alert::create($attributes + ['dedup_key' => hash('sha256', (string) Str::uuid()), 'event_id' => $event->id,
            'node_id' => $event->node_id, 'ip_asset_id' => $event->ip_asset_id, 'kind' => $kind, 'title' => $kind.' evidence',
            'severity' => 'medium', 'assessment_category' => 'needs_review', 'status' => 'open', 'evidence' => ['note' => 'Preserve original facts'],
            'first_seen_at' => '2026-10-08 10:00:00', 'last_seen_at' => '2026-10-08 10:01:00']);
    }

    private function capture(MonitorEvent $event, ?string $path = null): PacketCapture
    {
        $capture = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10',
            'status' => 'uploaded', 'path' => $path ?? 'packet-evidence/'.Str::uuid().'.pcap']);
        Storage::disk('local')->put($capture->path, 'pcap evidence');
        AiAnalysis::create(['event_id' => $event->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'status' => 'completed', 'config_snapshot' => [], 'report' => 'Keep manual analysis']);

        return $capture;
    }

    public function test_migration_removes_port_scan_rules_events_and_managed_files_without_deleting_raw_windows(): void
    {
        Storage::fake('local');
        $event = $this->event(['vertical_scan']);
        $this->alert($event, 'vertical_scan');
        $capture = $this->capture($event);
        $path = $capture->path;
        $batch = Batch::create(['node_id' => $event->node_id, 'batch_id' => (string) Str::uuid(), 'payload' => ['metrics' => []],
            'window_start' => now()->subSeconds(30), 'window_end' => now()]);
        TrafficMetric::create(['node_id' => $event->node_id, 'ip_asset_id' => $event->ip_asset_id, 'batch_id' => $batch->id,
            'window_start' => $batch->window_start, 'window_end' => $batch->window_end, 'evidence' => ['port_scan_targets' => [['peer_ip' => '192.0.2.10', 'ports' => [80, 443]]]]]);
        foreach (['vertical_scan', 'smb_connections'] as $kind) {
            Rule::create(['name' => $kind, 'kind' => $kind, 'threshold' => 50]);
            Exclusion::create(['node_id' => $event->node_id, 'cidr' => '203.0.113.10/32', 'kind' => $kind, 'reason' => 'Reviewed', 'expires_at' => now()->addMonth()]);
        }
        Exclusion::create(['node_id' => $event->node_id, 'cidr' => '203.0.113.10/32', 'kind' => null, 'reason' => 'General business scope', 'expires_at' => now()->addMonth()]);
        $legacyEvent = $this->event(['vertical_scan']);
        $legacyCapture = $this->capture($legacyEvent);
        $legacyPath = $legacyCapture->path;
        $unattached = $this->alert($event, 'vertical_scan');
        $unattached->update(['event_id' => null]);
        $migration = require database_path('migrations/2026_10_08_111410_retire_port_scan_and_service_connection_counts.php');
        $this->assertFalse($migration->withinTransaction);
        $migration->up();
        $migration->up();
        $this->assertDatabaseMissing('rules', ['kind' => 'vertical_scan']);
        $this->assertDatabaseMissing('alerts', ['kind' => 'vertical_scan']);
        $this->assertDatabaseMissing('exclusions', ['kind' => 'vertical_scan']);
        foreach (['monitor_events', 'alerts', 'packet_captures', 'ai_analyses'] as $table) {
            $this->assertDatabaseCount($table, 0);
        }
        foreach (['nodes', 'ip_assets', 'batches', 'traffic_metrics', 'rules'] as $table) {
            $this->assertDatabaseCount($table, 1);
        }
        $this->assertDatabaseCount('exclusions', 2);
        Storage::disk('local')->assertMissing($path);
        Storage::disk('local')->assertMissing($legacyPath);
    }

    public function test_mixed_events_retain_manual_reviews_other_alerts_and_evidence_with_recomputed_scope(): void
    {
        Storage::fake('local');
        $event = $this->event(['vertical_scan', 'smb_connections'], ['status' => 'normal', 'review_notes' => 'Authorized customer service',
            'behavior' => ['vertical_scan' => ['ports' => [80, 443]], 'smb_connections' => ['ports' => [445]]],
            'review_context' => ['vertical_scan' => ['ports' => [80, 443]], 'smb_connections' => ['ports' => [445]]]]);
        $activeKey = $event->active_key;
        $this->alert($event, 'vertical_scan', ['severity' => 'high', 'occurrences' => 50]);
        $first = $this->alert($event, 'smb_connections', ['title' => 'SMB evidence', 'status' => 'resolved', 'occurrences' => 4]);
        $second = $this->alert($event, 'smb_connections', ['title' => 'SMB stronger evidence', 'status' => 'resolved', 'severity' => 'high', 'assessment_category' => 'strong_anomaly',
            'occurrences' => 6, 'first_seen_at' => '2026-10-08 10:01:00', 'last_seen_at' => '2026-10-08 10:02:00']);
        $capture = $this->capture($event);
        $path = $capture->path;
        app(RetireConnectionRules::class)->run();
        app(RetireConnectionRules::class)->run();
        $event->refresh();
        $this->assertSame(['smb_connections'], $event->kinds);
        $this->assertSame('normal', $event->status);
        $this->assertSame('Authorized customer service', $event->review_notes);
        $this->assertSame($activeKey, $event->active_key);
        $this->assertSame(['smb_connections' => ['ports' => [445]]], $event->behavior);
        $this->assertSame(['smb_connections' => ['ports' => [445]]], $event->review_context);
        $this->assertSame('SMB stronger evidence', $event->title);
        $this->assertSame('high', $event->severity);
        $this->assertSame('strong_anomaly', $event->assessment_category);
        $this->assertSame(10, $event->occurrences);
        $this->assertSame('2026-10-08 10:00:00', $event->first_seen_at->format('Y-m-d H:i:s'));
        $this->assertSame('2026-10-08 10:02:00', $event->last_seen_at->format('Y-m-d H:i:s'));
        $this->assertSame(['note' => 'Preserve original facts'], $first->fresh()->evidence);
        $this->assertSame('resolved', $second->fresh()->status);
        $this->assertDatabaseCount('alerts', 2);
        $this->assertDatabaseCount('packet_captures', 1);
        $this->assertDatabaseCount('ai_analyses', 1);
        Storage::disk('local')->assertExists($path);
    }

    public function test_retired_service_counts_preserve_evidence_and_do_not_hide_remaining_anomalies(): void
    {
        Storage::fake('local');
        $event = $this->event(['vertical_scan', 'ssh_connections', 'rdp_connections', 'ftp_connections', 'smb_connections']);
        $this->alert($event, 'vertical_scan');
        foreach (['ssh_connections', 'rdp_connections', 'ftp_connections'] as $kind) {
            Rule::create(['name' => $kind, 'kind' => $kind, 'threshold' => 60]);
            $this->alert($event, $kind, ['severity' => 'high', 'status' => 'acknowledged', 'occurrences' => 20,
                'evidence' => ['sample' => ['tcp_attempts' => 317], 'connection_analysis' => ['category' => 'strong_anomaly', 'evidence_gaps' => ['TLS authentication unavailable']]]]);
        }
        $this->alert($event, 'smb_connections', ['title' => 'SMB needs review', 'severity' => 'medium', 'occurrences' => 7]);
        $capture = $this->capture($event);
        $path = $capture->path;
        $pure = $this->event(['rdp_connections']);
        $pureAlert = $this->alert($pure, 'rdp_connections');
        $pureCapture = $this->capture($pure);
        $purePath = $pureCapture->path;
        app(RetireConnectionRules::class)->run();
        $event->refresh();
        $this->assertSame('SMB needs review', $event->title);
        $this->assertSame('medium', $event->severity);
        $this->assertSame('needs_review', $event->assessment_category);
        $this->assertSame(7, $event->occurrences);
        $this->assertNotNull($event->active_key);
        $this->assertSame(['ssh_connections', 'rdp_connections', 'ftp_connections', 'smb_connections'], $event->kinds);
        foreach (Alert::whereIn('kind', ['ssh_connections', 'rdp_connections', 'ftp_connections'])->get() as $alert) {
            $this->assertSame('behavior_notice', $alert->assessment_category);
            $this->assertSame('behavior_notice', $alert->evidence['connection_analysis']['category']);
            if ($alert->id !== $pureAlert->id) {
                $this->assertSame(317, $alert->evidence['sample']['tcp_attempts']);
                $this->assertSame(['TLS authentication unavailable'], $alert->evidence['connection_analysis']['evidence_gaps']);
            }
        }
        $this->assertSame('behavior_notice', $pure->fresh()->assessment_category);
        $this->assertNull($pure->fresh()->active_key);
        $this->assertDatabaseCount('rules', 0);
        $this->assertDatabaseCount('packet_captures', 2);
        $this->assertDatabaseCount('ai_analyses', 2);
        Storage::disk('local')->assertExists($path);
        Storage::disk('local')->assertExists($purePath);
    }

    public function test_file_cleanup_rejects_unmanaged_paths_and_preserves_shared_references(): void
    {
        Storage::fake('local');
        $event = $this->event(['vertical_scan']);
        $this->capture($event, 'other/'.Str::uuid().'.pcap');
        $this->capture($event, 'packet-evidence/unmanaged.pcap');
        $retained = $this->event(['smb_connections']);
        $this->alert($retained, 'smb_connections');
        $shared = $this->capture($event);
        $sharedPath = $shared->path;
        $this->capture($retained, $sharedPath);
        $outsidePath = 'other/keep.txt';
        Storage::disk('local')->put($outsidePath, 'Keep outside packet directory');
        PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'uploaded', 'path' => 'packet-evidence/../other/keep.txt']);
        $paths = PacketCapture::where('event_id', $event->id)->whereNotNull('path')->pluck('path')->all();
        app(RetireConnectionRules::class)->run();
        $this->assertDatabaseMissing('monitor_events', ['id' => $event->id]);
        $this->assertDatabaseHas('monitor_events', ['id' => $retained->id]);
        foreach (array_filter($paths, fn ($path) => $path !== 'packet-evidence/../other/keep.txt') as $path) {
            Storage::disk('local')->assertExists($path);
        }
        Storage::disk('local')->assertExists($outsidePath);
        Storage::disk('local')->assertExists($sharedPath);
        $this->assertDatabaseCount('packet_captures', 1);
        $this->assertDatabaseCount('ai_analyses', 1);
    }

    public function test_historical_kinds_without_child_alerts_are_cleaned_without_removing_other_types(): void
    {
        $pure = $this->event(['vertical_scan'], ['behavior' => ['vertical_scan' => ['ports' => [80]]]]);
        $mixed = $this->event(['vertical_scan', 'vpn_protocol'], ['review_context' => ['vertical_scan' => ['ports' => [80]], 'vpn_protocol' => ['ports' => [51820]]]]);
        app(RetireConnectionRules::class)->run();
        $this->assertDatabaseMissing('monitor_events', ['id' => $pure->id]);
        $mixed->refresh();
        $this->assertSame(['vpn_protocol'], $mixed->kinds);
        $this->assertSame(['vpn_protocol' => ['ports' => [51820]]], $mixed->review_context);
        $this->assertSame('needs_review', $mixed->assessment_category);
        $this->assertNotNull($mixed->active_key);
    }

    public function test_managed_capture_symlinks_are_not_followed_or_deleted(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('File symlink creation requires Windows privileges; Linux CI covers this path.');
        }
        Storage::fake('local');
        $event = $this->event(['vertical_scan']);
        $disk = Storage::disk('local');
        $disk->put('other/keep.pcap', 'Unrelated file');
        $disk->makeDirectory('packet-evidence');
        $path = 'packet-evidence/'.Str::uuid().'.pcap';
        $this->assertTrue(symlink($disk->path('other/keep.pcap'), $disk->path($path)));
        PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'uploaded', 'path' => $path]);
        app(RetireConnectionRules::class)->run();
        $this->assertTrue(is_link($disk->path($path)));
        $this->assertSame('Unrelated file', $disk->get('other/keep.pcap'));
        $this->assertDatabaseMissing('monitor_events', ['id' => $event->id]);
    }
}
