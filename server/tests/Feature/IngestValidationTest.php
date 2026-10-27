<?php

namespace Tests\Feature;

use App\Models\Batch;
use App\Models\Node;
use App\Support\IngestPayloadValidator;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class IngestValidationTest extends TestCase
{
    use RefreshDatabase;

    private string $token = 'ingest-validation-test-token';

    private function node(): Node
    {
        return Node::create(['name' => 'ingest validation', 'cidrs' => ['203.0.113.0/24', '2001:db8::/48'], 'token_hash' => hash('sha256', $this->token)]);
    }

    private function upload(Node $node, array $payload): TestResponse
    {
        return $this->withHeaders(['Authorization' => 'Bearer '.$this->token, 'X-Node-ID' => $node->id])->postJson('/api/v1/agent/batches', $payload);
    }

    private function payload(int $count = 1): array
    {
        $endpoint = ['peer_ip' => '1.1.1.1', 'peer_port' => 443, 'attempts' => 3, 'synack_replies' => 3, 'completed_handshakes' => 3, 'rst_replies' => 0, 'max_observed_span_ms' => 50, 'payload_out' => 50, 'payload_in' => 50, 'scheme' => 'https', 'host' => 'fixture.example', 'http_method' => 'GET', 'http_path' => '/status', 'query_keys' => ['page']];
        $udp = ['peer_ip' => '1.1.1.1', 'peer_port' => 443, 'flows' => 1, 'packets_out' => 3, 'packets_in' => 3, 'bytes_out' => 50, 'bytes_in' => 50];
        $metric = ['targets' => array_fill(0, 16, '1.1.1.1'), 'ports' => [22, 443, 3389], 'target_endpoints' => array_fill(0, 32, '1.1.1.1:443'), 'cardinality_capped' => false,
            'service_target_stats_version' => 1, 'service_targets' => [['service' => 'ssh', 'targets' => ['1.1.1.1', '8.8.8.8'], 'targets_capped' => false, 'attempts' => 3, 'ports' => [22]]],
            'udp_stats_version' => 1, 'udp_filter_version' => 1, 'udp_non_dns_endpoints' => array_fill(0, 8, $udp), 'udp_endpoints' => array_fill(0, 8, $udp), 'outbound_endpoints' => array_fill(0, 8, $endpoint),
            'connection_stats_version' => 1, 'synack_replies' => 50, 'completed_handshakes' => 50, 'rst_replies' => 0, 'mature_attempts' => 50, 'mature_no_reply' => 0];
        foreach (['bytes_out', 'bytes_in', 'packets_out', 'packets_in', 'tcp_attempts', 'unique_targets', 'max_ports_per_target', 'max_attempts_per_target', 'auth_attempts', 'udp_non_dns_flows_out', 'udp_non_dns_packets_out', 'udp_flows_out', 'udp_packets_out', 'udp_packets_in', 'udp_bytes_out', 'udp_bytes_in'] as $field) {
            $metric[$field] = 100;
        }
        $metrics = [];
        for ($index = 0; $index < $count; $index++) {
            $metrics[] = ['ip' => '2001:db8::'.dechex($index + 1)] + $metric;
        }

        return ['batch_id' => Str::uuid()->toString(), 'window_start' => now()->subSeconds(30)->toIso8601String(), 'window_end' => now()->toIso8601String(), 'health' => ['version' => '1.6.0', 'captured' => 12345, 'kernel_drops' => 0, 'interfaces' => ['eno1']], 'metrics' => $metrics,
            'sites' => [['ip' => '2001:db8::1', 'port' => 22, 'scheme' => 'http', 'host' => 'fixture.example', 'source' => 'http_response', 'http_status' => 403]],
            'vpn' => [['ip' => '2001:db8::1', 'peer_ip' => '2001:4860:4860::8888', 'local_port' => 51820, 'peer_port' => 43210, 'protocol' => 'wireguard', 'initiator' => 'peer', 'request_count' => 1, 'response_count' => 1, 'request_length' => 148, 'response_length' => 92, 'request_header' => '0100000000000000', 'response_header' => '0200000000000000']],
            'proxies' => [['ip' => '2001:db8::1', 'local_port' => 443, 'transport' => 'tls', 'peer_count' => 3, 'session_count' => 3, 'bytes_from_peers' => 300, 'bytes_to_peers' => 300, 'peer_samples' => ['2001:4860:4860::8888'], 'egress_target_count' => 5, 'egress_target_samples' => ['1.1.1.1']]]];
    }

    public function test_accepts_a_complex_500_row_batch_without_changing_evidence(): void
    {
        $node = $this->node();
        $payload = $this->payload(500);
        $this->upload($node, $payload)->assertOk()->assertJson(['accepted' => true, 'duplicate' => false]);
        $stored = Batch::firstOrFail()->payload;
        $this->assertCount(500, $stored['metrics']);
        $this->assertEquals($payload['metrics'][499], $stored['metrics'][499]);
        $this->assertSame($payload['sites'], $stored['sites']);
        $this->assertSame($payload['vpn'], $stored['vpn']);
        $this->assertEquals($payload['proxies'], $stored['proxies']);
        $this->assertSame(12345, $node->fresh()->health['captured']);
        $this->assertDatabaseCount('batches', 1);
    }

    public function test_container_limits_are_rejected_before_deep_row_validation(): void
    {
        $node = $this->node();
        foreach (['metrics' => 8192, 'sites' => 4096, 'vpn' => 2048, 'proxies' => 256] as $type => $limit) {
            $payload = $this->payload();
            $payload[$type] = array_fill(0, $limit + 1, ['ip' => 'invalid']);
            $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors($type)->assertJsonMissingValidationErrors($type.'.0.ip');
            $payload[$type] = 'not-an-array';
            $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors($type);
        }
        $this->assertDatabaseCount('batches', 0);
        $this->assertNull($node->fresh()->health);
    }

    public function test_second_and_last_rows_keep_the_original_nested_error_paths(): void
    {
        $node = $this->node();
        $payload = $this->payload(3);
        $payload['metrics'][1]['outbound_endpoints'][7]['peer_port'] = 65536;
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.1.outbound_endpoints.7.peer_port');
        $payload = $this->payload(3);
        $payload['metrics'] = [4 => $payload['metrics'][0], 99 => $payload['metrics'][1], 250 => $payload['metrics'][2]];
        $payload['metrics'][250]['service_targets'][0]['targets'][1] = 'invalid';
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.250.service_targets.0.targets.1');
        foreach (['sites' => 'http_status', 'vpn' => 'response_length', 'proxies' => 'local_port'] as $type => $field) {
            $payload = $this->payload();
            $payload[$type][] = $payload[$type][0];
            $payload[$type][1][$field] = 0;
            $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors($type.'.1.'.$field);
        }
        $this->assertDatabaseCount('batches', 0);
    }

    public function test_conditional_udp_fields_are_required_only_within_their_own_row(): void
    {
        $node = $this->node();
        $payload = $this->payload(2);
        foreach (array_keys($payload['metrics'][0]) as $field) {
            if (str_starts_with($field, 'udp_')) {
                unset($payload['metrics'][0][$field]);
            }
        }
        $this->upload($node, $payload)->assertOk();
        $payload['batch_id'] = Str::uuid()->toString();
        unset($payload['metrics'][1]['udp_packets_out']);
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.1.udp_packets_out')->assertJsonMissingValidationErrors('metrics.0.udp_packets_out');
        $this->assertDatabaseCount('batches', 1);
    }

    public function test_replayed_batch_is_acknowledged_without_revalidation_or_health_changes(): void
    {
        $this->freezeTime();
        $node = $this->node();
        $payload = $this->payload();
        $this->upload($node, $payload)->assertOk();
        $batch = Batch::firstOrFail();
        $node->update(['health' => ['version' => '1.7.0', 'captured' => 999], 'health_observed_at' => now()->addSeconds(5)]);
        $before = $node->fresh()->getAttributes();
        config(['monitor.pending_bytes_per_node' => 1]);
        $this->mock(IngestPayloadValidator::class)->shouldNotReceive('validate');
        $this->upload($node, ['batch_id' => $payload['batch_id'], 'window_start' => 'invalid', 'health' => ['version' => 'spoofed'], 'metrics' => 'invalid'])
            ->assertOk()->assertJson(['accepted' => true, 'duplicate' => true]);
        $this->assertSame($batch->getAttributes(), $batch->fresh()->getAttributes());
        $this->assertSame($before, $node->fresh()->getAttributes());
        $this->assertDatabaseCount('batches', 1);
        $this->withHeaders(['Authorization' => 'Bearer invalid'])->postJson('/api/v1/agent/batches', ['batch_id' => $payload['batch_id']])->assertUnauthorized();
    }

    public function test_transaction_rechecks_capacity_after_validation(): void
    {
        $node = $this->node();
        $payload = $this->payload();
        $capacity = strlen(json_encode($payload)) + 100;
        config(['monitor.pending_bytes_per_node' => $capacity]);
        $realValidator = new IngestPayloadValidator;
        $this->mock(IngestPayloadValidator::class)->shouldReceive('validate')->once()->andReturnUsing(function (array $input) use ($node, $realValidator, $capacity): array {
            $validated = $realValidator->validate($input);
            Batch::create(['node_id' => $node->id, 'batch_id' => Str::uuid()->toString(), 'payload' => [], 'payload_bytes' => $capacity, 'window_start' => now()->subSeconds(30), 'window_end' => now()]);

            return $validated;
        });
        $this->upload($node, $payload)->assertStatus(429);
        $this->assertDatabaseCount('batches', 1);
        $this->assertDatabaseMissing('batches', ['batch_id' => $payload['batch_id']]);
        $this->assertNull($node->fresh()->health);
    }

    public function test_concurrent_duplicate_cannot_replace_a_newer_health_report(): void
    {
        $this->freezeTime();
        $node = $this->node();
        $payload = $this->payload();
        $realValidator = new IngestPayloadValidator;
        $expectedHealth = ['version' => '1.7.0', 'captured' => 98765];
        $this->mock(IngestPayloadValidator::class)->shouldReceive('validate')->once()->andReturnUsing(function (array $input) use ($node, $realValidator, $expectedHealth): array {
            $validated = $realValidator->validate($input);
            Batch::create(['node_id' => $node->id, 'batch_id' => $input['batch_id'], 'payload' => $input, 'payload_bytes' => strlen(json_encode($input)), 'window_start' => $input['window_start'], 'window_end' => $input['window_end']]);
            $node->update(['health' => $expectedHealth, 'health_observed_at' => now()->addSeconds(5), 'last_seen_at' => now()->addSeconds(5)]);

            return $validated;
        });
        $this->upload($node, $payload)->assertOk()->assertJson(['duplicate' => true]);
        $this->assertSame($expectedHealth, $node->fresh()->health);
        $this->assertSame(now()->addSeconds(5)->timestamp, $node->fresh()->last_seen_at->timestamp);
        $this->assertDatabaseCount('batches', 1);
        $this->assertEquals($payload, Batch::firstOrFail()->payload);
    }

    public function test_nested_array_shapes_and_literal_keys_cannot_bypass_validation(): void
    {
        $node = $this->node();
        foreach (['bad.key', 'bad*key'] as $key) {
            $payload = $this->payload(2);
            $payload['metrics'][1]['targets'] = [$key => 'invalid'];
            $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.1.targets.'.$key);
        }
        $payload = $this->payload(2);
        $payload['metrics'][1]['outbound_endpoints'][0]['unexpected'] = true;
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.1.outbound_endpoints.0');
        $payload = $this->payload(2);
        $payload['metrics'][1] = 'invalid';
        $this->upload($node, $payload)->assertUnprocessable()->assertJsonValidationErrors('metrics.1');
        $this->assertDatabaseCount('batches', 0);
    }

    public function test_integer_fast_path_matches_original_laravel_constraints(): void
    {
        $subject = new IngestPayloadValidator;
        $values = [null, '', ' ', [], [1], false, true, 0, 1, -1, 1.0, 1.5, '1', '0', '-1', '+1', '01', ' 1 ', '1e2', '1.0', PHP_INT_MAX, (string) PHP_INT_MAX, 1000000000000000, 1000000000000001, '1000000000000000', '1000000000000001'];
        foreach (['auth_attempts' => 'required|integer|min:0|max:1000000000000000', 'synack_replies' => 'sometimes|integer|min:0|max:1000000000000000', 'udp_non_dns_packets_out' => 'required_with:udp_filter_version|integer|min:0|max:1000000000000000'] as $field => $originalRule) {
            foreach ($values as $value) {
                $expected = Validator::make([$field => $value, 'udp_filter_version' => 1], [$field => $originalRule])->passes();
                $payload = $this->payload();
                $payload['metrics'][0][$field] = $value;
                try {
                    $subject->validate($payload);
                    $actual = true;
                } catch (ValidationException $exception) {
                    $actual = ! array_key_exists('metrics.0.'.$field, $exception->errors());
                }
                $this->assertSame($expected, $actual, $field.' '.var_export($value, true));
            }
        }
        foreach ([0, 1, 65535, 65536, null, true, 1.0, '22', '22.0', ' 22 '] as $value) {
            $expected = Validator::make(['port' => $value], ['port' => 'required|integer|min:1|max:65535'])->passes();
            $payload = $this->payload();
            $payload['metrics'][0]['outbound_endpoints'][0]['peer_port'] = $value;
            try {
                $subject->validate($payload);
                $actual = true;
            } catch (ValidationException $exception) {
                $actual = ! array_key_exists('metrics.0.outbound_endpoints.0.peer_port', $exception->errors());
            }
            $this->assertSame($expected, $actual, 'peer_port '.var_export($value, true));
        }
    }
}
