<?php

namespace Tests\Feature;

use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Services\Analyzer;
use App\Services\BehaviorWhitelist;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class BehaviorWhitelistTest extends TestCase
{
    use RefreshDatabase;

    private function scope(): array
    {
        return ['version' => 1, 'target_cidrs' => ['198.51.100.0/24'], 'ports' => [443], 'max_value' => 200, 'severity' => 'medium', 'reviewed_at' => now()->toIso8601String()];
    }

    private function evidence(): array
    {
        return ['value' => 100, 'sample' => ['targets' => ['198.51.100.1'], 'ports' => [443], 'unique_targets' => 1], 'assessed_severity' => 'medium'];
    }

    public function test_complete_approved_scope_matches_but_destination_port_intensity_and_quality_changes_do_not(): void
    {
        $entry = new Exclusion(['behavior_scope' => $this->scope()]);
        $checker = app(BehaviorWhitelist::class);
        $evidence = $this->evidence();
        $this->assertTrue($checker->evaluate($entry, $evidence)['match']);
        foreach ([
            ['sample' => ['targets' => ['192.0.2.1'], 'ports' => [443]]],
            ['sample' => ['targets' => ['198.51.100.1'], 'ports' => [22]]],
            ['sample' => ['targets' => ['198.51.100.1'], 'ports' => [443], 'capture_quality' => ['captured' => 100, 'kernel_drops' => 20]]],
            ['value' => 201],
            ['assessed_severity' => 'high'],
            ['connection_analysis' => ['category' => 'strong_anomaly']],
            ['sample' => ['targets' => ['198.51.100.1'], 'ports' => [443], 'unique_targets' => 10]],
            ['sample' => ['targets' => ['198.51.100.1'], 'ports' => [443], 'endpoint_samples_truncated' => true]],
            ['sample' => ['targets' => ['198.51.100.1'], 'ports' => [443], 'cardinality_capped' => true]],
        ] as $change) {
            $this->assertFalse($checker->evaluate($entry, array_replace($evidence, $change))['match']);
        }
        $this->assertFalse($checker->evaluate(new Exclusion, $evidence)['match']);
    }

    public function test_new_destination_reopens_reviewed_event_without_muting_other_nodes(): void
    {
        $node = Node::create(['name' => 'scope test', 'cidrs' => ['203.0.113.0/24'], 'token_hash' => hash('sha256', 'test-only-token')]);
        $ip = IpAsset::create(['ip' => '203.0.113.10', 'version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);
        $analyzer = app(Analyzer::class);
        $first = $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', 'test', $this->evidence(), now());
        $event = MonitorEvent::findOrFail($first->event_id);
        $event->refresh()->update(['status' => 'normal']);
        Exclusion::create(['node_id' => $node->id, 'cidr' => $ip->ip.'/32', 'kind' => 'horizontal_scan', 'reason' => 'approved business', 'expires_at' => now()->addDays(30), 'behavior_scope' => $this->scope()]);
        $this->assertNull($analyzer->alert($node, $ip, 'horizontal_scan', 'medium', 'test', $this->evidence(), now()->addSeconds(10)));
        $changed = $this->evidence();
        $changed['sample']['targets'] = ['192.0.2.1'];
        $alert = $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', 'test', $changed, now()->addSeconds(20));
        $this->assertTrue($alert->evidence['whitelist_review']['required']);
        $this->assertSame('open', $event->fresh()->status);
        $this->assertStringContainsString('未批准的目标 IP', $event->fresh()->reopen_reason);
        $event->refresh()->update(['status' => 'normal']);
        $changed['sample_window_end'] = now()->subMinute()->toIso8601String();
        $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', 'old queued window', $changed, now()->addSeconds(30));
        $this->assertSame('normal', $event->fresh()->status);
        $other = Node::create(['name' => 'other node', 'cidrs' => ['203.0.113.0/24'], 'token_hash' => hash('sha256', 'test-other-token')]);
        $this->assertNotNull($analyzer->alert($other, $ip, 'horizontal_scan', 'medium', 'test', $this->evidence(), now()));
    }

    public function test_ipv6_endpoint_scope_matches_explicitly_approved_range(): void
    {
        $entry = new Exclusion(['behavior_scope' => array_replace($this->scope(), ['target_cidrs' => ['2001:db8:1::/48']])]);
        $result = app(BehaviorWhitelist::class)->evaluate($entry, ['value' => 1, 'assessed_severity' => 'medium', 'sample' => ['target_endpoints' => ['[2001:db8:1::5]:443'], 'unique_targets' => 1]]);
        $this->assertTrue($result['match']);
    }
}
