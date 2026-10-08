<?php

namespace Tests\Feature;

use App\Services\AuthenticationEvidence;
use App\Services\ConnectionAssessment;
use App\Services\ServiceConnectionRules;
use Tests\TestCase;

class AuthenticationEvidenceTest extends TestCase
{
    private function send(AuthenticationEvidence $parser, array &$flow, string $payload, bool $out, int $seq, int $frame): void
    {
        $parser->consume($flow, ['protocol' => 6, 'raw_payload' => $payload, 'payload_size' => strlen($payload), 'seq' => $seq, 'flags' => 16], $out, $frame);
    }

    private function smb(int $id, bool $response = false, int $status = 0, int $command = 1): string
    {
        $header = "\xfeSMB".pack('vvVvvVVVV', 64, 1, $status, $command, 1, (int) $response, 0, $id, 0).str_repeat("\0", 32);
        $header .= pack('v', $response ? 9 : 25).str_repeat("\0", $response ? 6 : 22);

        return "\0".substr(pack('N', strlen($header)), 1).$header;
    }

    public function test_ftp_pairs_only_authentication_replies_handles_segments_and_retransmissions_and_redacts_credentials(): void
    {
        $parser = new AuthenticationEvidence;
        $flow = ['peer_port' => 21];
        $banner = "220 FTP ready\r\n";
        $this->send($parser, $flow, $banner, false, 500, 1);
        $user = "USER private-user\r\n";
        $this->send($parser, $flow, substr($user, 0, 7), true, 100, 2);
        $this->send($parser, $flow, substr($user, 7), true, 107, 3);
        $challenge = "331 Password required\r\n";
        $this->send($parser, $flow, $challenge, false, 500 + strlen($banner), 4);
        $pass = "PASS private-password\r\n";
        $this->send($parser, $flow, $pass, true, 100 + strlen($user), 5);
        $this->send($parser, $flow, $pass, true, 100 + strlen($user), 6);
        $reject = "530 Not logged in\r\n";
        $this->send($parser, $flow, $reject, false, 500 + strlen($banner.$challenge), 7);
        $this->send($parser, $flow, "RETR /secret-file\r\n", true, 100 + strlen($user.$pass), 8);
        $this->send($parser, $flow, $reject, false, 500 + strlen($banner.$challenge.$reject), 9);
        $auth = $parser->finish($flow);
        $this->assertSame(2, $auth['requests_observed']);
        $this->assertSame(1, $auth['paired_failures']);
        $this->assertSame(1, $auth['challenges']);
        $this->assertSame('PASS', $auth['failure_samples'][0]['command']);
        $this->assertArrayNotHasKey('_auth', $flow);
        foreach (['private-user', 'private-password', 'secret-file'] as $secret) {
            $this->assertStringNotContainsString($secret, json_encode($flow));
        }
    }

    public function test_ftp_midstream_response_and_tls_transition_do_not_invent_failure_results(): void
    {
        $parser = new AuthenticationEvidence;
        $flow = ['peer_port' => 21];
        $this->send($parser, $flow, "530 rejected\r\n", false, 500, 1);
        $this->send($parser, $flow, "PASS unknown\r\n", true, 100, 2);
        $this->assertNull($parser->finish($flow));
        $flow = ['peer_port' => 21];
        $this->send($parser, $flow, "220 ready\r\n", false, 500, 1);
        $this->send($parser, $flow, "USER private\r\nAUTH TLS\r\n", true, 100, 2);
        $this->send($parser, $flow, "331 password\r\n234 start TLS\r\n", false, 511, 3);
        $this->send($parser, $flow, "530 forged\r\n", false, 540, 4);
        $auth = $parser->finish($flow);
        $this->assertTrue($auth['encrypted_observed']);
        $this->assertSame(0, $auth['paired_failures']);
    }

    public function test_smb2_matches_message_ids_and_does_not_count_authentication_challenges_or_other_command_errors_as_login_failure(): void
    {
        $parser = new AuthenticationEvidence;
        $flow = ['peer_port' => 445];
        $request = $this->smb(1);
        $this->send($parser, $flow, substr($request, 0, 20), true, 100, 1);
        $this->send($parser, $flow, substr($request, 20), true, 120, 2);
        $this->send($parser, $flow, $this->smb(1, true, 0xC0000016), false, 500, 3);
        $this->send($parser, $flow, $this->smb(2), true, 192, 4);
        $reply = $this->smb(2, true, 0xC000006D);
        $this->send($parser, $flow, $reply, false, 576, 5);
        $this->send($parser, $flow, $reply, false, 576, 6);
        $this->send($parser, $flow, $this->smb(99, true, 0xC000006D), false, 652, 7);
        $this->send($parser, $flow, $this->smb(3, true, 0xC000006D, 8), false, 728, 8);
        $auth = $parser->finish($flow);
        $this->assertSame(2, $auth['requests_observed']);
        $this->assertSame(1, $auth['paired_failures']);
        $this->assertSame(1, $auth['challenges']);
        $this->assertSame('0xC000006D', $auth['failure_samples'][0]['status']);
    }

    public function test_gaps_limits_and_encrypted_services_fail_closed(): void
    {
        $parser = new AuthenticationEvidence;
        $flow = ['peer_port' => 445];
        $this->send($parser, $flow, $this->smb(1), true, 100, 1);
        $this->send($parser, $flow, $this->smb(2), true, 193, 2);
        $this->send($parser, $flow, $this->smb(1, true, 0xC000006D), false, 500, 3);
        $auth = $parser->finish($flow);
        $this->assertSame(1, $auth['stream_gaps']);
        $this->assertSame(0, $auth['paired_failures']);
        $flow = ['peer_port' => 445];
        $this->send($parser, $flow, $this->smb(1), true, 100, 1);
        $this->send($parser, $flow, str_repeat('x', 8193), true, 192, 2);
        $this->assertTrue($parser->finish($flow)['analysis_capped']);
        foreach ([22, 3389, 990] as $port) {
            $flow = ['peer_port' => $port];
            $this->send($parser, $flow, "\x16\x03\x03encrypted", true, 100, 1);
            $this->assertNull($parser->finish($flow));
        }
    }

    public function test_service_rules_select_only_matching_target_connections_and_never_reuse_global_handshake_statistics(): void
    {
        $helper = new ServiceConnectionRules;
        $sample = $helper->sample('smb_connections', ['tcp_attempts' => 9999, 'completed_handshakes' => 9999, 'connection_stats_version' => 1, 'outbound_endpoints' => [
            ['peer_ip' => '192.0.2.1', 'peer_port' => 443, 'attempts' => 9900],
            ['peer_ip' => '2001:db8::1', 'peer_port' => 445, 'attempts' => 80, 'completed_handshakes' => 2],
            ['peer_ip' => '192.0.2.2', 'peer_port' => 445, 'attempts' => 19, 'completed_handshakes' => 19],
        ]]);
        $this->assertSame(80, $sample['tcp_attempts']);
        $this->assertSame(2, $sample['completed_handshakes']);
        $this->assertSame(['[2001:db8::1]:445'], $sample['target_endpoints']);
        $this->assertSame(0, $sample['connection_stats_version']);
        $this->assertNull($helper->sample('smb_connections', ['outbound_endpoints' => []]));
        $assessment = app(ConnectionAssessment::class)->assess('smb_connections', $sample, 60);
        $this->assertSame('medium', $assessment['severity']);
        $this->assertSame('limited_behavior', $assessment['confidence']);
        $this->assertStringContainsString('不代表已观察登录失败', $assessment['note']);
        $paired = $helper->sample('smb_connections', ['completed_handshakes' => 9999, 'connection_stats_version' => 1, 'outbound_endpoints' => [
            ['peer_ip' => '192.0.2.1', 'peer_port' => 443, 'attempts' => 9900, 'completed_handshakes' => 9900, 'synack_replies' => 9900, 'rst_replies' => 0],
            ['peer_ip' => '2001:db8::1', 'peer_port' => 445, 'attempts' => 80, 'completed_handshakes' => 2, 'synack_replies' => 3, 'rst_replies' => 1],
        ]]);
        $assessment = app(ConnectionAssessment::class)->assess('smb_connections', $paired, 60);
        $this->assertSame(2, $assessment['connection_analysis']['completed_handshakes']);
        $this->assertSame(0.025, $assessment['connection_analysis']['completion_ratio']);
        $this->assertNull($assessment['connection_analysis']['mature_no_reply']);
    }
}
