<?php

namespace App\Support;

use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class IngestPayloadValidator
{
    public function validate(array $payload): array
    {
        $rules = $this->rules();
        $topRules = array_filter($rules, fn (string $field): bool => ! preg_match('/^(metrics|sites|vpn|proxies)\.\*\./', $field), ARRAY_FILTER_USE_KEY);
        $validated = Validator::make($payload, $topRules)->validate();
        foreach (['metrics', 'sites', 'vpn', 'proxies'] as $type) {
            $prefix = $type.'.*.';
            $rowRules = [];
            foreach ($rules as $field => $constraints) {
                if (str_starts_with($field, $prefix)) {
                    $rowRules['row.'.substr($field, strlen($prefix))] = is_string($constraints) ? str_replace($prefix, 'row.', $constraints) : $constraints;
                }
            }
            $validated[$type] = [];
            foreach ($payload[$type] ?? [] as $index => $row) {
                try {
                    $validator = Validator::make(['row' => $row], []);
                    $validator->setRules($this->expandRowRules($validator->getData(), ['row' => 'required|array', ...$rowRules]));
                    $record = $validator->validate();
                } catch (ValidationException $exception) {
                    $errors = [];
                    foreach ($exception->errors() as $field => $messages) {
                        $errors[$type.'.'.$index.substr($field, 3)] = $messages;
                    }
                    throw ValidationException::withMessages($errors);
                }
                $validated[$type][$index] = $record['row'];
            }
        }

        return $validated;
    }

    /**
     * Expand only the current row, retaining Laravel's escaped array keys.
     * Explicit paths avoid rebuilding wildcard indexes for every nested field.
     */
    private function expandRowRules(array $data, array $rules): array
    {
        $expanded = [];
        $missing = new \stdClass;
        foreach ($rules as $field => $constraints) {
            $boundedInteger = is_string($constraints) && preg_match('/^(?:(?:required|sometimes|required_with:[^|]+)\|)?integer\|min:([0-9]+)\|max:([0-9]+)$/', $constraints, $bounds);
            $paths = ['' => $data];
            foreach (explode('.', $field) as $segment) {
                $next = [];
                foreach ($paths as $path => $value) {
                    if ($segment === '*') {
                        foreach (is_array($value) ? $value : [] as $index => $item) {
                            $next[$path.'.'.$index] = $item;
                        }
                    } else {
                        $next[$path === '' ? $segment : $path.'.'.$segment] = is_array($value) && array_key_exists($segment, $value) ? $value[$segment] : $missing;
                    }
                }
                $paths = $next;
            }
            foreach ($paths as $path => $value) {
                if ($value === $missing && is_string($constraints) && str_starts_with($constraints, 'sometimes|')) {
                    continue;
                }
                // A present native integer within these fixed bounds satisfies
                // every constraint. Other values keep Laravel's original rules.
                $expanded[$path] = $boundedInteger && is_int($value) && $value >= (int) $bounds[1] && $value <= (int) $bounds[2] ? [] : $constraints;
            }
        }

        return $expanded;
    }

    private function rules(): array
    {
        return [
            'batch_id' => 'required|string|regex:/^[a-zA-Z0-9-]{16,64}$/',
            'window_start' => 'required|date', 'window_end' => 'required|date',
            'health' => 'required|array', 'health.version' => 'required|string|max:32',
            'health.update_error' => 'sometimes|string|max:255',
            'health.interfaces' => 'sometimes|array|max:8', 'health.interfaces.*' => 'string|max:64',
            'health.*' => ['nullable'],
            'metrics' => 'present|array|max:8192', 'sites' => 'present|array|max:4096', 'vpn' => 'sometimes|array|max:2048', 'proxies' => 'sometimes|array|max:256',
            'proxies.*.ip' => 'required|ip', 'proxies.*.local_port' => 'required|integer|min:1|max:65535',
            'proxies.*.transport' => 'required|in:opaque_tcp,opaque_udp,tls,quic',
            'proxies.*.peer_count' => 'required|integer|min:3|max:4096', 'proxies.*.session_count' => 'required|integer|min:3|max:4096',
            'proxies.*.bytes_from_peers' => 'required|integer|min:0|max:1000000000000000',
            'proxies.*.bytes_to_peers' => 'required|integer|min:0|max:1000000000000000',
            'proxies.*.peer_samples' => 'required|array|min:1|max:8', 'proxies.*.peer_samples.*' => 'ip',
            'proxies.*.egress_target_count' => 'required|integer|min:5|max:256',
            'proxies.*.egress_target_samples' => 'required|array|min:1|max:8', 'proxies.*.egress_target_samples.*' => 'ip',
            'vpn.*.ip' => 'required|ip', 'vpn.*.peer_ip' => 'required|ip',
            'vpn.*.local_port' => 'required|integer|min:1|max:65535', 'vpn.*.peer_port' => 'required|integer|min:1|max:65535',
            'vpn.*.protocol' => 'required|in:wireguard,openvpn,ikev2', 'vpn.*.initiator' => 'required|in:vm,peer',
            'vpn.*.request_count' => 'required|integer|min:1|max:1000000', 'vpn.*.response_count' => 'required|integer|min:1|max:1000000',
            'vpn.*.request_length' => 'required|integer|min:8|max:65535', 'vpn.*.response_length' => 'required|integer|min:8|max:65535',
            'vpn.*.request_header' => 'required|string|regex:/^[a-f0-9]{16}$/', 'vpn.*.response_header' => 'required|string|regex:/^[a-f0-9]{16}$/',
            'metrics.*.ip' => 'required|ip', 'metrics.*.targets' => 'present|array|max:16', 'metrics.*.targets.*' => 'ip',
            'metrics.*.ports' => 'sometimes|array|max:256', 'metrics.*.ports.*' => 'integer|min:1|max:65535',
            'metrics.*.target_endpoints' => 'sometimes|array|max:32', 'metrics.*.target_endpoints.*' => 'string|max:64',
            'metrics.*.port_samples_truncated' => 'sometimes|boolean', 'metrics.*.endpoint_samples_truncated' => 'sometimes|boolean',
            'metrics.*.cardinality_capped' => 'required|boolean',
            'metrics.*.service_target_stats_version' => 'sometimes|integer|in:1',
            'metrics.*.service_targets' => 'sometimes|array|max:3',
            'metrics.*.service_targets.*' => 'array:service,targets,targets_capped,attempts,ports',
            'metrics.*.service_targets.*.service' => 'required|in:ssh,rdp,ftp',
            'metrics.*.service_targets.*.targets' => 'required|array|min:1|max:128',
            'metrics.*.service_targets.*.targets.*' => 'required|ip',
            'metrics.*.service_targets.*.targets_capped' => 'required|boolean',
            'metrics.*.service_targets.*.attempts' => 'required|integer|min:1|max:1000000000000000',
            'metrics.*.service_targets.*.ports' => 'required|array|min:1|max:2',
            'metrics.*.service_targets.*.ports.*' => 'required|integer|in:21,22,990,3389',
            'metrics.*.udp_stats_version' => 'sometimes|integer|in:1',
            'metrics.*.udp_filter_version' => 'sometimes|integer|in:1',
            ...collect(['udp_non_dns_flows_out', 'udp_non_dns_packets_out'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'required_with:metrics.*.udp_filter_version|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.udp_non_dns_endpoints' => 'sometimes|array|max:8',
            'metrics.*.udp_non_dns_endpoints.*' => 'array:peer_ip,peer_port,flows,packets_out,packets_in,bytes_out,bytes_in',
            'metrics.*.udp_non_dns_endpoints.*.peer_ip' => 'required|ip',
            'metrics.*.udp_non_dns_endpoints.*.peer_port' => 'required|integer|min:0|max:65535|not_in:53',
            ...collect(['flows', 'packets_out', 'packets_in', 'bytes_out', 'bytes_in'])->mapWithKeys(fn ($f) => ["metrics.*.udp_non_dns_endpoints.*.$f" => 'required|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.udp_flows_capped' => 'sometimes|boolean', 'metrics.*.udp_endpoints_truncated' => 'sometimes|boolean',
            ...collect(['udp_flows_out', 'udp_packets_out', 'udp_packets_in', 'udp_bytes_out', 'udp_bytes_in'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'required_with:metrics.*.udp_stats_version|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.udp_endpoints' => 'sometimes|array|max:8',
            'metrics.*.udp_endpoints.*' => 'array:peer_ip,peer_port,flows,packets_out,packets_in,bytes_out,bytes_in',
            'metrics.*.udp_endpoints.*.peer_ip' => 'required|ip', 'metrics.*.udp_endpoints.*.peer_port' => 'required|integer|min:0|max:65535',
            ...collect(['flows', 'packets_out', 'packets_in', 'bytes_out', 'bytes_in'])->mapWithKeys(fn ($f) => ["metrics.*.udp_endpoints.*.$f" => 'required|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.synack_replies' => 'sometimes|integer|min:0|max:1000000000000000',
            'metrics.*.connection_stats_version' => 'sometimes|integer|in:1',
            ...collect(['completed_handshakes', 'rst_replies', 'mature_attempts', 'mature_no_reply'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'sometimes|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.port_scan_targets' => 'sometimes|array|max:8',
            'metrics.*.port_scan_targets.*' => 'array:peer_ip,port_count,ports,truncated',
            'metrics.*.port_scan_targets.*.peer_ip' => 'required|ip',
            'metrics.*.port_scan_targets.*.port_count' => 'required|integer|min:1|max:256',
            'metrics.*.port_scan_targets.*.ports' => 'required|array|max:128',
            'metrics.*.port_scan_targets.*.ports.*' => 'integer|min:1|max:65535',
            'metrics.*.port_scan_targets.*.truncated' => 'required|boolean',
            'metrics.*.outbound_samples_truncated' => 'sometimes|boolean',
            'metrics.*.outbound_endpoints' => 'sometimes|array|max:8',
            'metrics.*.outbound_endpoints.*' => 'array:peer_ip,peer_port,attempts,synack_replies,payload_out,payload_in,scheme,host,http_method,http_path,query_keys,completed_handshakes,rst_replies,max_observed_span_ms',
            ...collect(['completed_handshakes', 'rst_replies'])->mapWithKeys(fn ($f) => ["metrics.*.outbound_endpoints.*.$f" => 'sometimes|integer|min:0|max:1000000000000000'])->all(),
            'metrics.*.outbound_endpoints.*.max_observed_span_ms' => 'sometimes|integer|min:0|max:60000',
            'metrics.*.outbound_endpoints.*.peer_ip' => 'required|ip',
            'metrics.*.outbound_endpoints.*.peer_port' => 'required|integer|min:1|max:65535',
            'metrics.*.outbound_endpoints.*.attempts' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.synack_replies' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.payload_out' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.payload_in' => 'required|integer|min:0|max:1000000000000000',
            'metrics.*.outbound_endpoints.*.scheme' => 'sometimes|in:http,https',
            'metrics.*.outbound_endpoints.*.host' => 'sometimes|string|max:253',
            'metrics.*.outbound_endpoints.*.http_method' => 'sometimes|in:GET,HEAD,POST,PUT,OPTIONS,DELETE,PATCH',
            'metrics.*.outbound_endpoints.*.http_path' => 'sometimes|string|max:256',
            'metrics.*.outbound_endpoints.*.query_keys' => 'sometimes|array|max:8',
            'metrics.*.outbound_endpoints.*.query_keys.*' => 'string|max:32',
            'sites.*.ip' => 'required|ip', 'sites.*.port' => 'required|integer|min:1|max:65535',
            'sites.*.scheme' => 'required|in:http,https', 'sites.*.host' => ['present', 'nullable', 'string', 'max:253', 'regex:/^[a-zA-Z0-9.\-:\[\]]*$/'],
            'sites.*.source' => 'required|in:http_host,http_response,tls_sni,tls_alpn,rdp_negotiation',
            'sites.*.http_status' => 'sometimes|integer|min:100|max:599',
            ...collect(['bytes_out', 'bytes_in', 'packets_out', 'packets_in', 'tcp_attempts', 'unique_targets', 'max_ports_per_target', 'max_attempts_per_target', 'auth_attempts'])->mapWithKeys(fn ($f) => ["metrics.*.$f" => 'required|integer|min:0|max:1000000000000000'])->all(),
        ];
    }
}
