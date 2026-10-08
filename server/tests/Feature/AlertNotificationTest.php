<?php

namespace Tests\Feature;

use App\Jobs\SendAlertEmail;
use App\Models\AiAnalysis;
use App\Models\Alert;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Models\PacketCapture;
use App\Models\Rule;
use App\Services\AlertNotificationPolicy;
use App\Services\Analyzer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Tests\TestCase;

class AlertNotificationTest extends TestCase
{
    use RefreshDatabase;

    private function node(): Node
    {
        return Node::create(['name' => 'UDP business', 'cidrs' => ['203.0.113.0/24'], 'health' => ['version' => '1.3.1'], 'token_hash' => hash('sha256', 'test-token')]);
    }

    private function ip(): IpAsset
    {
        return IpAsset::create(['ip' => '203.0.113.10', 'version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);
    }

    public function test_quantity_notices_never_create_alerts_events_email_or_captures(): void
    {
        Queue::fake();
        config(['monitor.auto_capture' => true, 'monitor.alert_email' => 'review@example.test']);
        $node = $this->node();
        $ip = $this->ip();
        foreach (['udp_flow_burst', 'udp_packet_rate', 'tcp_connection_burst', 'egress_mbps', 'vertical_scan'] as $kind) {
            $evidence = ['connection_analysis' => ['category' => 'behavior_notice'], 'value' => 1000000];
            $this->assertNull(app(Analyzer::class)->alert($node, $ip, $kind, 'high', 'Quantity only', $evidence, now()));
        }
        $this->assertNull(app(Analyzer::class)->alert($node, $ip, 'udp_packet_rate', 'high', 'Old UDP alert', ['connection_analysis' => ['category' => 'strong_anomaly']], now()));
        $this->assertNull(app(Analyzer::class)->alert($node, $ip, 'tcp_connection_burst', 'high', 'No assessment', [], now()));
        $this->assertDatabaseCount('alerts', 0);
        $this->assertDatabaseCount('monitor_events', 0);
        $this->assertDatabaseCount('packet_captures', 0);
        Queue::assertNotPushed(SendAlertEmail::class);
    }

    public function test_low_severity_anomalies_still_notify_and_notices_do_not_reopen_them(): void
    {
        Queue::fake();
        config(['monitor.alert_email' => 'review@example.test']);
        $node = $this->node();
        $ip = $this->ip();
        $alert = app(Analyzer::class)->alert($node, $ip, 'proxy_suspect', 'low', 'Suspected proxy', [], now());
        $event = MonitorEvent::findOrFail($alert->event_id);
        $event->update(['status' => 'normal', 'review_notes' => 'Reviewed business']);
        $this->assertNull(app(Analyzer::class)->alert($node, $ip, 'tcp_connection_burst', 'high', 'Quantity only', ['connection_analysis' => ['category' => 'behavior_notice']], now()->addSeconds(30)));
        $this->assertSame('normal', $event->fresh()->status);
        $this->assertSame(1, $event->fresh()->occurrences);
        app(Analyzer::class)->alert($node, $ip, 'smb_connections', 'high', 'New anomaly', ['connection_analysis' => ['category' => 'strong_anomaly']], now()->addMinute());
        $this->assertSame('open', $event->fresh()->status);
        $this->assertSame('New anomaly', $event->fresh()->title);
        $this->assertDatabaseCount('alerts', 2);
        $this->assertTrue(AlertNotificationPolicy::allows('capture_degraded', []));
        $this->assertTrue(AlertNotificationPolicy::allows('node_offline', []));
    }

    public function test_upgrade_hides_quantity_events_and_preserves_mixed_anomalies_reviews_and_evidence(): void
    {
        $node = $this->node();
        $ip = $this->ip();
        $events = [];
        foreach (['pure UDP', 'mixed', 'legacy TCP'] as $name) {
            $events[] = MonitorEvent::create(['node_id' => $node->id, 'ip_asset_id' => $ip->id, 'active_key' => hash('sha256', $name), 'title' => $name, 'severity' => 'high',
                'status' => 'acknowledged', 'review_notes' => 'Keep review', 'kinds' => ['udp_packet_rate'], 'assessment_category' => 'needs_review', 'first_seen_at' => now(), 'last_seen_at' => now()]);
        }
        foreach ($events as $index => $event) {
            Alert::create(['dedup_key' => hash('sha256', (string) $index), 'event_id' => $event->id, 'node_id' => $node->id, 'ip_asset_id' => $ip->id,
                'kind' => $index === 2 ? 'tcp_connection_burst' : 'udp_packet_rate', 'severity' => 'high', 'status' => 'open', 'title' => 'Count only', 'evidence' => ['value' => 50000], 'first_seen_at' => now(), 'last_seen_at' => now()]);
        }
        $events[1]->update(['kinds' => ['udp_packet_rate', 'proxy_suspect']]);
        Alert::create(['dedup_key' => hash('sha256', 'proxy'), 'event_id' => $events[1]->id, 'node_id' => $node->id, 'ip_asset_id' => $ip->id,
            'kind' => 'proxy_suspect', 'severity' => 'low', 'status' => 'open', 'title' => 'Proxy candidate', 'evidence' => [], 'first_seen_at' => now(), 'last_seen_at' => now()]);
        $capture = PacketCapture::create(['event_id' => $events[0]->id, 'node_id' => $node->id, 'ip' => $ip->ip, 'status' => 'uploaded', 'path' => 'packet-evidence/'.Str::uuid().'.pcap']);
        AiAnalysis::create(['event_id' => $events[0]->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'status' => 'completed', 'config_snapshot' => [], 'report' => 'Keep report']);
        foreach (AlertNotificationPolicy::RETIRED_UDP_RULES as $kind) {
            Rule::create(['name' => 'Retired UDP', 'kind' => $kind, 'threshold' => 1]);
        }
        $migration = require database_path('migrations/2026_10_04_092146_exclude_behavior_notices_from_notifications.php');
        $migration->up();
        $migration->up();
        foreach ([0, 2] as $index) {
            $this->assertSame('behavior_notice', $events[$index]->fresh()->assessment_category);
            $this->assertNull($events[$index]->fresh()->active_key);
        }
        $mixed = $events[1]->fresh();
        $this->assertSame('needs_review', $mixed->assessment_category);
        $this->assertSame('Proxy candidate', $mixed->title);
        $this->assertSame('low', $mixed->severity);
        $this->assertSame('acknowledged', $mixed->status);
        $this->assertSame('Keep review', $mixed->review_notes);
        $this->assertDatabaseCount('alerts', 4);
        $this->assertDatabaseCount('packet_captures', 1);
        $this->assertDatabaseCount('ai_analyses', 1);
        $this->assertDatabaseMissing('rules', ['kind' => 'udp_packet_rate']);
        $this->assertDatabaseMissing('rules', ['kind' => 'udp_flow_burst']);
        Alert::where('event_id', $mixed->id)->where('kind', 'udp_packet_rate')->update(['status' => 'acknowledged']);
        $mixed->update(['status' => 'open']);
        $this->artisan('monitor:reassess-connections')->assertSuccessful();
        $this->assertSame('Proxy candidate', $mixed->fresh()->title);
        $this->assertSame('needs_review', $mixed->fresh()->assessment_category);
    }

    public function test_previously_queued_notice_emails_are_skipped(): void
    {
        Mail::fake();
        config(['monitor.alert_email' => 'review@example.test']);
        $node = $this->node();
        $ip = $this->ip();
        $alert = Alert::create(['dedup_key' => hash('sha256', 'queued'), 'node_id' => $node->id, 'ip_asset_id' => $ip->id, 'kind' => 'udp_packet_rate',
            'severity' => 'high', 'title' => 'Count only', 'assessment_category' => 'needs_review', 'evidence' => [], 'first_seen_at' => now(), 'last_seen_at' => now()]);
        (new SendAlertEmail($alert->id))->handle();
        $alert->update(['kind' => 'smb_connections', 'evidence' => ['connection_analysis' => ['category' => 'behavior_notice']]]);
        (new SendAlertEmail($alert->id))->handle();
        Mail::assertNothingOutgoing();
    }

    public function test_retired_rules_do_not_notify_even_when_evidence_claims_strong_anomaly(): void
    {
        Queue::fake();
        Mail::fake();
        config(['monitor.auto_capture' => true, 'monitor.alert_email' => 'review@example.test']);
        $node = $this->node();
        $ip = $this->ip();
        foreach (AlertNotificationPolicy::RETIRED_RULES as $kind) {
            $evidence = ['connection_analysis' => ['category' => 'strong_anomaly'], 'value' => 1000000];
            $this->assertNull(app(Analyzer::class)->alert($node, $ip, $kind, 'high', 'Retired rule', $evidence, now()));
            $alert = Alert::create(['dedup_key' => hash('sha256', $kind), 'node_id' => $node->id, 'ip_asset_id' => $ip->id,
                'kind' => $kind, 'severity' => 'high', 'title' => 'Previously queued', 'assessment_category' => 'strong_anomaly',
                'evidence' => $evidence, 'first_seen_at' => now(), 'last_seen_at' => now()]);
            (new SendAlertEmail($alert->id))->handle();
        }
        $this->assertDatabaseCount('monitor_events', 0);
        $this->assertDatabaseCount('packet_captures', 0);
        $this->assertDatabaseCount('alerts', count(AlertNotificationPolicy::RETIRED_RULES));
        Queue::assertNotPushed(SendAlertEmail::class);
        Mail::assertNothingOutgoing();
    }
}
