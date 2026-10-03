<?php

namespace Tests\Feature;

use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Services\Analyzer;
use App\Services\ConnectionAssessment;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ConnectionAssessmentTest extends TestCase
{
    use RefreshDatabase;

    private function sample(): array
    {
        return ['connection_stats_version' => 1, 'tcp_attempts' => 120, 'synack_replies' => 0, 'completed_handshakes' => 0, 'rst_replies' => 90, 'mature_attempts' => 100, 'mature_no_reply' => 10,
            'unique_targets' => 120, 'max_ports_per_target' => 12, 'cardinality_capped' => false, 'ports' => [443], 'port_samples_truncated' => false,
            'capture_quality' => ['captured' => 10000, 'kernel_drops' => 0, 'decode_skipped' => 0, 'state_dropped' => 0]];
    }

    public function test_all_connection_rules_need_evidence_instead_of_count_for_high_risk(): void
    {
        $service = app(ConnectionAssessment::class);
        foreach (ConnectionAssessment::KINDS as $kind) {
            $result = $service->assess($kind, ['tcp_attempts' => 50000, 'unique_targets' => 200, 'max_ports_per_target' => 256], 100);
            $this->assertNotSame('high', $result['severity']);
            $this->assertNull($result['connection_analysis']['completion_ratio']);
        }
        $sample = $this->sample();
        $sample['rst_replies'] = 0;
        $sample['mature_no_reply'] = 100;
        $this->assertSame('medium', $service->assess('horizontal_scan', $sample, 100, 'high', [$sample, $sample])['severity']);
    }

    public function test_reply_ratio_requires_valid_paired_synack_counts(): void
    {
        $sample = $this->sample();
        $sample['synack_replies'] = 90;
        $assessment = app(ConnectionAssessment::class);
        $this->assertSame(0.75, $assessment->assess('tcp_connection_burst', $sample)['connection_analysis']['reply_ratio']);
        $sample['synack_replies'] = 121;
        $this->assertNull($assessment->assess('tcp_connection_burst', $sample)['connection_analysis']['reply_ratio']);
        unset($sample['synack_replies']);
        $this->assertNull($assessment->assess('tcp_connection_burst', $sample)['connection_analysis']['reply_ratio']);
        $sample['synack_replies'] = 90;
        unset($sample['connection_stats_version']);
        $this->assertNull($assessment->assess('tcp_connection_burst', $sample)['connection_analysis']['reply_ratio']);
    }

    public function test_strong_scan_needs_sustained_rejection_and_quality_and_respects_rule_ceiling(): void
    {
        $s = $this->sample();
        $service = app(ConnectionAssessment::class);
        foreach (['horizontal_scan' => 100, 'vertical_scan' => 10] as $kind => $threshold) {
            $this->assertSame('medium', $service->assess($kind, $s, $threshold, 'high', [$s])['severity']);
            $this->assertSame('high', $service->assess($kind, $s, $threshold, 'high', [$s, $s])['severity']);
            $this->assertSame('low', $service->assess($kind, $s, $threshold, 'low', [$s, $s])['severity']);
            $bad = $s;
            $bad['capture_quality']['state_dropped'] = 1;
            $this->assertSame('medium', $service->assess($kind, $bad, $threshold, 'high', [$bad, $bad])['severity']);
            $bad = $s;
            $bad['capture_quality']['kernel_drops'] = 500;
            $this->assertSame('medium', $service->assess($kind, $bad, $threshold, 'high', [$bad, $bad])['severity']);
        }
    }

    public function test_busy_successful_service_is_notice_and_auth_connections_do_not_prove_bruteforce(): void
    {
        $s = $this->sample();
        $s['completed_handshakes'] = 110;
        $s['rst_replies'] = 0;
        $service = app(ConnectionAssessment::class);
        $this->assertSame('low', $service->assess('tcp_connection_burst', $s, 100)['severity']);
        $this->assertSame('low', $service->assess('egress_mbps', $s, 100)['severity']);
        $this->assertSame('medium', $service->assess('suspected_bruteforce', $s, 100)['severity']);
        $s['completed_handshakes'] = 999;
        $this->assertNull($service->assess('horizontal_scan', $s, 100)['connection_analysis']['completion_ratio']);
    }

    public function test_reviewed_event_reopens_only_after_persistent_port_change_and_stale_data_cannot_replace_evidence(): void
    {
        config(['monitor.auto_capture' => false]);
        $node = Node::create(['name' => 'report test', 'cidrs' => ['203.0.113.0/24']]);
        $ip = IpAsset::create(['ip' => '203.0.113.10', 'version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);
        $analyzer = app(Analyzer::class);
        $at = now();
        $base = ['sample' => $this->sample(), 'connection_analysis' => ['category' => 'needs_review']];
        $alert = $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '连接', $base, $at);
        $event = MonitorEvent::find($alert->event_id);
        $event->update(['status' => 'normal', 'review_context' => $event->behavior]);
        $change = $base;
        $change['sample']['ports'] = [443, 22];
        $change['sample_window_end'] = $at->copy()->addSeconds(10)->toIso8601String();
        $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '连接', $change, $at->copy()->addSeconds(10));
        $this->assertSame('normal', $event->fresh()->status);
        $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '连接', $change, $at->copy()->addSeconds(15));
        $this->assertSame('normal', $event->fresh()->status);
        $change['sample_window_end'] = $at->copy()->addSeconds(20)->toIso8601String();
        $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '连接', $change, $at->copy()->addSeconds(20));
        $this->assertSame('open', $event->fresh()->status);
        $this->assertStringContainsString('新增认证', $event->fresh()->reopen_reason);
        $event->refresh()->update(['status' => 'normal', 'review_context' => $event->behavior]);
        $analyzer->alert($node, $ip, 'horizontal_scan', 'high', '旧数据', $base, $at->copy()->addSeconds(5));
        $this->assertSame('normal', $event->fresh()->status);
        $this->assertSame([443, 22], $alert->fresh()->evidence['sample']['ports']);
        $this->artisan('monitor:reassess-connections')->assertSuccessful();
        $this->assertSame('normal', $event->fresh()->status);
    }
}
