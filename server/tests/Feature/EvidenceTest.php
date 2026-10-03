<?php

namespace Tests\Feature;

use App\Jobs\AnalyzeEvidence;
use App\Jobs\SummarizeCapture;
use App\Models\AiAnalysis;
use App\Models\Alert;
use App\Models\IpAsset;
use App\Models\MonitorEvent;
use App\Models\Node;
use App\Models\PacketCapture;
use App\Services\Analyzer;
use App\Services\EventCorrelation;
use App\Services\PcapSummary;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Tests\TestCase;

class EvidenceTest extends TestCase
{
    use RefreshDatabase;

    private string $token = 'test-only-node-token-abcdefghijklmnopqrstuvwxyz';

    private function event(): MonitorEvent
    {
        $node = Node::create(['name' => 'capture test', 'cidrs' => ['203.0.113.0/24'], 'health' => ['version' => '0.6.0'], 'token_hash' => hash('sha256', $this->token)]);
        $ip = IpAsset::create(['ip' => '203.0.113.10', 'version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);

        return app(EventCorrelation::class)->correlate($node, $ip, 'horizontal_scan', 'medium', '疑似扫描', now());
    }

    private function packet(string $src, string $dst, int $flags, int $sp = 20000, int $dp = 443, string $payload = ''): string
    {
        $ethernet = str_repeat("\0", 12).pack('n', 0x0800);
        $ip = "\x45\0".pack('n', 40 + strlen($payload)).str_repeat("\0", 5)."\x06".str_repeat("\0", 2).inet_pton($src).inet_pton($dst);
        $tcp = pack('nnNNCCnNN', $sp, $dp, $flags === 2 ? 100 : ($flags === 18 ? 200 : 101), $flags === 18 ? 101 : ($flags === 16 ? 201 : 0), 0x50, $flags, 1024, 0, 0);

        return $ethernet.$ip.substr($tcp, 0, 20).$payload;
    }

    private function pcap(array $packets): string
    {
        $data = pack('VvvVVVV', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1);
        foreach ($packets as $packet) {
            $data .= pack('VVVV', time(), 0, strlen($packet), strlen($packet)).$packet;
        }

        return $data;
    }

    public function test_continuous_ip_events_merge_rules_and_keep_review_until_behavior_changes(): void
    {
        $event = $this->event();
        $node = Node::find($event->node_id);
        $ip = IpAsset::find($event->ip_asset_id);
        $analyzer = app(Analyzer::class);
        $at = now();
        $first = $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '扫描', [], $at);
        $second = $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '扫描', [], $at->copy()->addMinutes(15));
        $this->assertSame($first->id, $second->id);
        $this->assertDatabaseCount('monitor_events', 1);
        $event->update(['status' => 'normal']);
        $analyzer->alert($node, $ip, 'horizontal_scan', 'medium', '扫描', [], $at->copy()->addMinutes(16));
        $this->assertSame('normal', $event->fresh()->status);
        $analyzer->alert($node, $ip, 'vertical_scan', 'high', '端口扫描', [], $at->copy()->addMinutes(17));
        $this->assertSame('open', $event->fresh()->status);
        $this->assertCount(2, $event->fresh()->kinds);
        $analyzer->alert($node, $ip, 'vertical_scan', 'high', '端口扫描', [], $at->copy()->addMinutes(48));
        $this->assertDatabaseCount('monitor_events', 2);
    }

    public function test_capture_is_node_scoped_lease_fenced_and_saved_without_ai(): void
    {
        Storage::fake('local');
        Http::preventStrayRequests();
        Queue::fake();
        $event = $this->event();
        $task = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10']);
        $this->getJson('/api/v1/agent/captures/claim')->assertUnauthorized();
        $headers = ['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $event->node_id];
        $reply = $this->withHeaders($headers)->getJson('/api/v1/agent/captures/claim')->assertOk()->json('task');
        $this->assertSame($task->id, $reply['id']);
        $this->getJson('/api/v1/agent/captures/claim')->assertJson(['task' => null]);
        $url = '/api/v1/agent/captures/'.$task->id.'/complete';
        $this->postJson($url)->assertStatus(409);
        $metadata = ['packets' => 1, 'queue_drops' => 0, 'snaplen_truncated' => 0, 'started_at' => now()->toIso8601String(), 'ended_at' => now()->toIso8601String(), 'stop_reason' => 'duration', 'interfaces' => ['eno1']];
        $data = $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 2)]);
        $this->call('POST', $url, [], [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$this->token, 'HTTP_X_NODE_ID' => $event->node_id, 'HTTP_X_CAPTURE_LEASE' => $reply['lease_token'], 'HTTP_X_CAPTURE_METADATA' => base64_encode(json_encode($metadata)), 'CONTENT_TYPE' => 'application/vnd.tcpdump.pcap'], $data)->assertOk();
        $task->refresh();
        $this->assertSame('uploaded', $task->status);
        $this->assertSame(hash('sha256', $data), $task->sha256);
        Storage::disk('local')->assertExists($task->path);
        $this->assertDatabaseCount('ai_analyses', 0);
        Http::assertNothingSent();
        $other = Node::create(['name' => 'other', 'cidrs' => ['203.0.113.0/24'], 'token_hash' => hash('sha256', $this->token)]);
        $this->withHeaders(['X-Node-ID' => $other->id])->postJson($url)->assertNotFound();
    }

    public function test_parser_distinguishes_replies_from_completed_handshakes_and_redacts_query_values(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'pcap-test');
        $data = $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 2), $this->packet('1.1.1.1', '203.0.113.10', 18, 443, 20000), $this->packet('203.0.113.10', '1.1.1.1', 16, 20000, 443, "GET /status?password=secret HTTP/1.1\r\nHost: example.test\r\nAuthorization: secret\r\n\r\n")]);
        file_put_contents($path, $data);
        try {
            $summary = app(PcapSummary::class)->summarize($path, '203.0.113.10');
            $this->assertSame(1, $summary['synack_flows']);
            $this->assertSame(1, $summary['completed_handshakes']);
            $this->assertSame('/status', $summary['flow_samples'][0]['http']['path']);
            $this->assertStringNotContainsString('secret', json_encode($summary));
            file_put_contents($path, $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 2), $this->packet('1.1.1.1', '203.0.113.10', 18, 443, 20000)]));
            $this->assertSame(0, app(PcapSummary::class)->summarize($path, '203.0.113.10')['completed_handshakes']);
        } finally {
            unlink($path);
        }
    }

    public function test_pcap_authentication_summary_pairs_ftp_replies_without_exporting_credentials(): void
    {
        $local = '203.0.113.10';
        $peer = '198.51.100.1';
        $banner = "220 ready\r\n";
        $command = "USER secret-user\r\n";
        $reply = "530 rejected\r\n";
        $packet = fn ($out, $payload, $seq) => substr_replace($this->packet($out ? $local : $peer, $out ? $peer : $local, 16, $out ? 20000 : 21, $out ? 21 : 20000, $payload), pack('N', $seq), 38, 4);
        $data = $this->pcap([$packet(false, $banner, 500), $packet(true, $command, 100), $packet(false, $reply, 500 + strlen($banner))]);
        $path = tempnam(sys_get_temp_dir(), 'auth-pcap');
        try {
            file_put_contents($path, $data);
            $summary = app(PcapSummary::class)->summarize($path, $local, true);
            $this->assertSame('FTP', $summary['authentication_groups'][0]['protocol']);
            $this->assertSame(1, $summary['authentication_groups'][0]['paired_failures']);
            $this->assertSame($peer, $summary['authentication_groups'][0]['peer_ip']);
            $this->assertStringNotContainsString('secret-user', json_encode($summary));
            $this->assertStringNotContainsString('_auth', json_encode($summary));
            $this->assertTrue($summary['packet_text']['complete']);
        } finally {
            unlink($path);
        }
    }

    public function test_ai_only_processes_manual_records_once_and_never_sends_pcap_binary(): void
    {
        Storage::fake('local');
        Http::fake(['api.deepseek.com/*' => Http::sequence()->push(['choices' => [['message' => ['content' => '证据不足，需要核查业务。']]], 'usage' => ['total_tokens' => 123]])->push(['error' => 'rate limit'], 429)]);
        $event = $this->event();
        $data = $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 2)]);
        $path = 'packet-evidence/'.Str::uuid().'.pcap';
        Storage::disk('local')->put($path, $data);
        $capture = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'uploaded', 'path' => $path, 'sha256' => hash('sha256', $data)]);
        config(['app.key' => 'base64:'.base64_encode(str_repeat('k', 32))]);
        DB::table('ai_settings')->insert(['id' => 1, 'enabled' => true]);
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt('test-only-api-key-123456789', 'aes-256-gcm', hash('sha256', str_repeat('k', 32), true), OPENSSL_RAW_DATA, $nonce, $tag, 'vm-monitor-ai-v1');
        $analysis = AiAnalysis::create(['event_id' => $event->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'config_snapshot' => ['endpoint' => 'https://api.deepseek.com/chat/completions', 'model' => 'deepseek-flash', 'api_key_cipher' => base64_encode($nonce.$tag.$cipher)]]);
        $job = new AnalyzeEvidence($analysis->id);
        $job->handle();
        $job->handle();
        Http::assertSentCount(1);
        Http::assertSent(fn ($request) => $request['messages'][1]['content'] && str_contains($request['messages'][1]['content'], 'pcap_summary') && ! str_contains($request->body(), base64_encode($data)));
        Http::assertSent(fn ($request) => str_contains($request['messages'][0]['content'], '第一节必须是“对外攻击结论”') && str_contains($request['messages'][0]['content'], 'authentication_groups') && json_decode($request['messages'][1]['content'], true)['analysis_question']['source_ip'] === '203.0.113.10');
        $this->assertSame('completed', $analysis->fresh()->status);
        $this->assertSame('open', $event->fresh()->status);
        $this->assertArrayNotHasKey('api_key_cipher', $analysis->fresh()->config_snapshot);
        $failed = AiAnalysis::create(['event_id' => $event->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'config_snapshot' => $analysis->config_snapshot]);
        $failedJob = new AnalyzeEvidence($failed->id);
        $failedJob->handle();
        $failedJob->handle();
        $this->assertSame('failed', $failed->fresh()->status);
        $this->assertStringContainsString('HTTP 429', $failed->fresh()->last_error);
        Http::assertSentCount(2);
    }

    public function test_full_packet_text_covers_every_frame_without_exporting_payload_secrets(): void
    {
        $packets = [];
        for ($i = 1; $i <= 40; $i++) {
            $packets[] = $this->packet('203.0.113.10', '198.51.100.'.$i, 2, 20000, 21088);
        }
        $packets[] = $this->packet('203.0.113.10', '1.1.1.1', 2);
        $packets[] = $this->packet('1.1.1.1', '203.0.113.10', 18, 443, 20000);
        $packets[] = $this->packet('203.0.113.10', '1.1.1.1', 16, 20000, 443, "POST /node/instance?password=secret HTTP/1.1\r\nHost: api.example.test\r\nCookie: secret\r\nAuthorization: secret\r\n\r\nsecret-body");
        $packets[] = $this->packet('192.0.2.1', '192.0.2.2', 2);
        $packets[] = str_repeat("\0", 14);
        $path = tempnam(sys_get_temp_dir(), 'full-text');
        try {
            $data = $this->pcap($packets);
            file_put_contents($path, $data);
            $summary = app(PcapSummary::class)->summarize($path, '203.0.113.10', true);
            $this->assertTrue($summary['pcap_fully_read']);
            $this->assertSame(strlen($data), $summary['file_bytes_read']);
            $this->assertTrue($summary['packet_text']['complete']);
            $this->assertSame(count($packets), $summary['packet_text']['frames']);
            $this->assertCount(count($packets) + 1, explode("\n", trim($summary['packet_text']['text'])));
            $this->assertTrue($summary['flow_samples_truncated']);
            $this->assertStringContainsString('198.51.100.40:21088', $summary['packet_text']['text']);
            $this->assertStringContainsString("unrelated\ttcp", $summary['packet_text']['text']);
            $this->assertStringContainsString("unknown\tunsupported", $summary['packet_text']['text']);
            $this->assertStringNotContainsString('secret', json_encode($summary));
            $this->assertSame(21088, $summary['port_groups'][0]['port']);
            $this->assertSame(40, $summary['port_groups'][0]['unique_targets']);
            $this->assertSame(40, $summary['port_groups'][0]['no_reply_observed_flows']);
            $this->assertSame(0, $summary['port_groups'][0]['completed_handshakes']);
            $this->assertSame(1, $summary['port_groups'][1]['completed_handshakes']);
        } finally {
            unlink($path);
        }
    }

    public function test_complete_packet_mode_sends_all_frames_once_and_retains_coverage(): void
    {
        Http::fake(['api.deepseek.com/*' => Http::response(['choices' => [['message' => ['content' => "# 报告\n\n## 观察事实\n\n仅证明当前窗口。"]]]])]);
        $packets = array_fill(0, 45, $this->packet('203.0.113.10', '1.1.1.1', 2));
        $analysis = $this->analysisForPackets($packets);
        $job = new AnalyzeEvidence($analysis->id);
        $job->handle();
        $job->handle();
        Http::assertSentCount(1);
        Http::assertSent(function ($request) {
            $evidence = json_decode($request['messages'][1]['content'], true);

            return $evidence['packet_text']['complete'] && $evidence['packet_text']['frames'] === 45 && $evidence['coverage']['mode'] === 'full_packets' && isset($evidence['pcap_summary']['port_groups']) && str_contains($request['messages'][0]['content'], '真实换行');
        });
        $analysis->refresh();
        $this->assertSame('completed', $analysis->status);
        $this->assertSame('full_packets', $analysis->config_snapshot['evidence_mode']);
        $this->assertArrayNotHasKey('api_key_cipher', $analysis->config_snapshot);
        $this->assertTrue($analysis->evidence['coverage']['packet_text_complete']);
    }

    public function test_over_limit_full_text_fails_without_any_ai_call_or_automatic_fallback(): void
    {
        Http::preventStrayRequests();
        $analysis = $this->analysisForPackets(array_fill(0, 40000, $this->packet('203.0.113.10', '1.1.1.1', 2)));
        $job = new AnalyzeEvidence($analysis->id);
        $job->handle();
        $job->handle();
        Http::assertNothingSent();
        $analysis->refresh();
        $this->assertSame('failed', $analysis->status);
        $this->assertStringContainsString('未调用 AI', $analysis->last_error);
        $this->assertSame('full_packets', $analysis->config_snapshot['evidence_mode']);
        $this->assertFalse($analysis->evidence['coverage']['packet_text_complete']);
        $this->assertArrayNotHasKey('packet_text', $analysis->evidence);
        $this->assertArrayNotHasKey('api_key_cipher', $analysis->config_snapshot);
    }

    public function test_complete_text_that_exceeds_json_budget_is_not_sent(): void
    {
        Http::preventStrayRequests();
        $analysis = $this->analysisForPackets(array_fill(0, 25000, $this->packet('203.0.113.10', '1.1.1.1', 2)));
        (new AnalyzeEvidence($analysis->id))->handle();
        Http::assertNothingSent();
        $analysis->refresh();
        $this->assertSame('failed', $analysis->status);
        $this->assertStringContainsString('发送上限', $analysis->last_error);
        $this->assertTrue($analysis->evidence['coverage']['packet_text_complete']);
        $this->assertFalse($analysis->evidence['coverage']['ai_call_attempted']);
        $this->assertArrayNotHasKey('packet_text', $analysis->evidence);
    }

    private function analysisForPackets(array $packets): AiAnalysis
    {
        Storage::fake('local');
        $event = $this->event();
        $data = $this->pcap($packets);
        $path = 'packet-evidence/'.Str::uuid().'.pcap';
        Storage::disk('local')->put($path, $data);
        $capture = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'uploaded', 'path' => $path, 'sha256' => hash('sha256', $data)]);
        config(['app.key' => 'base64:'.base64_encode(str_repeat('k', 32))]);
        DB::table('ai_settings')->insert(['id' => 1, 'enabled' => true]);
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt('test-only-api-key-123456789', 'aes-256-gcm', hash('sha256', str_repeat('k', 32), true), OPENSSL_RAW_DATA, $nonce, $tag, 'vm-monitor-ai-v1');

        return AiAnalysis::create(['event_id' => $event->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'config_snapshot' => ['endpoint' => 'https://api.deepseek.com/chat/completions', 'model' => 'deepseek-flash', 'api_key_cipher' => base64_encode($nonce.$tag.$cipher), 'evidence_mode' => 'full_packets']]);
    }

    public function test_parser_exposes_only_complete_visible_client_hello_sni(): void
    {
        $name = 'cdn.example.test';
        $serverName = "\0".pack('n', strlen($name)).$name;
        $serverName = pack('n', strlen($serverName)).$serverName;
        $extensions = pack('nn', 0, strlen($serverName)).$serverName;
        $hello = "\x03\x03".str_repeat("\0", 32)."\0".pack('n', 2)."\x13\x01\x01\0".pack('n', strlen($extensions)).$extensions;
        $handshake = "\x01".substr(pack('N', strlen($hello)), 1).$hello;
        $tls = "\x16\x03\x01".pack('n', strlen($handshake)).$handshake;
        $path = tempnam(sys_get_temp_dir(), 'sni-test');
        try {
            file_put_contents($path, $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 16, 20000, 443, $tls)]));
            $summary = app(PcapSummary::class)->summarize($path, '203.0.113.10');
            $this->assertSame($name, $summary['flow_samples'][0]['tls_client_hello_sni']);
            file_put_contents($path, $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 16, 20000, 443, substr($tls, 0, -1))]));
            $summary = app(PcapSummary::class)->summarize($path, '203.0.113.10');
            $this->assertArrayNotHasKey('tls_client_hello_sni', $summary['flow_samples'][0]);
        } finally {
            unlink($path);
        }
    }

    public function test_capture_summary_and_retention_never_dispatch_ai_without_manual_request(): void
    {
        Storage::fake('local');
        Http::preventStrayRequests();
        Queue::fake();
        $event = $this->event();
        $data = $this->pcap([$this->packet('203.0.113.10', '1.1.1.1', 2)]);
        $path = 'packet-evidence/'.Str::uuid().'.pcap';
        Storage::disk('local')->put($path, $data);
        $capture = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'uploaded', 'path' => $path, 'sha256' => hash('sha256', $data), 'created_at' => now()->subDays(8)]);
        (new SummarizeCapture($capture->id))->handle();
        $this->assertSame(1, $capture->fresh()->summary['matched_packets']);
        $this->artisan('monitor:evidence')->assertSuccessful();
        $this->assertSame('expired', $capture->fresh()->status);
        Storage::disk('local')->assertMissing($path);
        Queue::assertNotPushed(AnalyzeEvidence::class);
        Http::assertNothingSent();
    }

    public function test_historical_grouping_is_repeatable_and_preserves_rule_evidence(): void
    {
        $event = $this->event();
        foreach ([0, 10, 20] as $index => $minutes) {
            Alert::create(['dedup_key' => hash('sha256', 'history-'.$index), 'node_id' => $event->node_id, 'ip_asset_id' => $event->ip_asset_id, 'kind' => 'horizontal_scan', 'severity' => 'medium', 'title' => 'history', 'evidence' => ['sample' => ['ports' => [443]]], 'occurrences' => 20, 'first_seen_at' => now()->subMinutes(30)->addMinutes($minutes), 'last_seen_at' => now()->subMinutes(25)->addMinutes($minutes)]);
        }
        $this->artisan('monitor:group-events')->assertSuccessful();
        $this->artisan('monitor:group-events')->assertSuccessful();
        $this->assertDatabaseCount('monitor_events', 1);
        $this->assertSame(61, $event->fresh()->occurrences);
        $this->assertSame(0, Alert::whereNull('event_id')->count());
        $this->assertSame([443], Alert::first()->evidence['sample']['ports']);
    }

    public function test_ai_failure_is_not_automatically_retried(): void
    {
        Http::preventStrayRequests();
        $event = $this->event();
        $capture = PacketCapture::create(['event_id' => $event->id, 'node_id' => $event->node_id, 'ip' => '203.0.113.10', 'status' => 'expired']);
        $analysis = AiAnalysis::create(['event_id' => $event->id, 'capture_id' => $capture->id, 'requested_by' => 1, 'config_snapshot' => []]);
        $job = new AnalyzeEvidence($analysis->id);
        $job->handle();
        $job->handle();
        $this->assertSame('failed', $analysis->fresh()->status);
        Http::assertNothingSent();
    }

    public function test_tcp_retransmissions_tuple_reuse_and_peer_port_groups_are_distinct(): void
    {
        $rewrite = function (string $packet, int $seq, int $ack): string {
            return substr_replace($packet, pack('NN', $seq, $ack), 38, 8);
        };
        $local = '203.0.113.10';
        $peer = '198.51.100.1';
        $syn = $this->packet($local, $peer, 2, 20000, 443);
        $packets = [$syn, $syn, $this->packet($peer, $local, 18, 443, 20000), $this->packet($local, $peer, 16, 20000, 443)];
        $packets[] = $rewrite($syn, 500, 0);
        $packets[] = $rewrite($this->packet($peer, $local, 18, 443, 20000), 600, 501);
        $packets[] = $rewrite($this->packet($local, $peer, 16, 20000, 443), 501, 601);
        foreach (range(10000, 10009) as $port) {
            $packets[] = $this->packet($local, $peer, 2, 20001, $port);
        }
        $path = tempnam(sys_get_temp_dir(), 'pcap-groups');
        file_put_contents($path, $this->pcap($packets));
        try {
            $summary = app(PcapSummary::class)->summarize($path, $local);
            $this->assertSame(12, $summary['observed_outbound_flows']);
            $this->assertSame(13, $summary['syn_packets_out']);
            $this->assertSame(1, $summary['syn_retransmissions_observed']);
            $this->assertSame(2, $summary['completed_handshakes']);
            $this->assertSame(11, $summary['peer_groups'][0]['port_count']);
            $this->assertSame(10, $summary['peer_groups'][0]['no_reply_observed_flows']);
            $this->assertSame(2, $summary['sample_strata']['completed']);
            $this->assertSame(10, $summary['sample_strata']['no_reply']);
            $this->assertCount(12, $summary['flow_samples']);
        } finally {
            unlink($path);
        }
    }

    public function test_flow_samples_include_successful_and_unanswered_strata_without_claiming_population_proportions(): void
    {
        $packets = [];
        foreach (range(20000, 20079) as $port) {
            $packets[] = $this->packet('203.0.113.10', '198.51.100.1', 2, $port, 443);
            $packets[] = $this->packet('198.51.100.1', '203.0.113.10', 18, 443, $port);
            $packets[] = $this->packet('203.0.113.10', '198.51.100.1', 16, $port, 443);
        }
        foreach (range(30000, 30009) as $port) {
            foreach (range(1, 3) as $retry) {
                $packets[] = $this->packet('203.0.113.10', '198.51.100.2', 2, $port, 443);
            }
        }
        $path = tempnam(sys_get_temp_dir(), 'pcap-sampling');
        file_put_contents($path, $this->pcap($packets));
        try {
            $summary = app(PcapSummary::class)->summarize($path, '203.0.113.10');
            $this->assertSame(80, $summary['port_groups'][0]['completed_handshakes']);
            $this->assertSame(10, $summary['port_groups'][0]['no_reply_observed_flows']);
            $this->assertSame(20, $summary['syn_retransmissions_observed']);
            $this->assertCount(32, $summary['flow_samples']);
            $this->assertContains('completed', array_column($summary['flow_samples'], 'sample_group'));
            $this->assertContains('no_reply', array_column($summary['flow_samples'], 'sample_group'));
            $this->assertTrue($summary['flow_samples_truncated']);
        } finally {
            unlink($path);
        }
    }
}
