<?php

namespace App\Services;

class PcapSummary
{
    public const ANALYSIS_VERSION = 4;

    public const PACKET_TEXT_LIMIT = 2097152;

    public function summarize(string $path, string $ip, bool $includePackets = false): array
    {
        $packedIp = inet_pton($ip);
        if ($packedIp === false) {
            throw new \RuntimeException('Invalid capture IP');
        }
        $ip = inet_ntop($packedIp);
        if (! is_file($path) || filesize($path) > 33554432) {
            throw new \RuntimeException('PCAP missing or exceeds 32 MiB');
        }
        $size = filesize($path);
        $stream = fopen($path, 'rb');
        if (! $stream) {
            throw new \RuntimeException('PCAP missing or exceeds 32 MiB');
        }
        $summary = ['ip' => $ip, 'frames' => 0, 'matched_packets' => 0, 'skipped_frames' => 0, 'unrelated_frames' => 0, 'bytes_out' => 0, 'bytes_in' => 0, 'truncated_frames' => 0, 'summary_capped' => false];
        $flows = [];
        $authentication = new AuthenticationEvidence;
        $activeSequences = [];
        $summary['analysis_version'] = self::ANALYSIS_VERSION;
        $packetText = "frame\ttime_unix\tdirection\tprotocol\tsource\tdestination\tflags_hex\tseq\tack\twire_bytes\tcaptured_bytes\tpayload_bytes_advertised\tapplication_clue_json\n";
        $textFrames = 0;
        $textCapped = false;
        $summary['pcap_fully_read'] = false;
        $started = microtime(true);
        try {
            $header = $this->read($stream, 24);
            if (substr($header, 0, 4) !== "\xd4\xc3\xb2\xa1" || unpack('V', substr($header, 20, 4))[1] !== 1) {
                throw new \RuntimeException('Unsupported PCAP format');
            }
            while (! feof($stream)) {
                $record = fread($stream, 16);
                if ($record === '') {
                    break;
                }
                if (strlen($record) !== 16) {
                    throw new \RuntimeException('Incomplete PCAP record');
                }
                $r = unpack('Vsec/Vusec/Vincl/Vorig', $record);
                if ($r['incl'] > 65535 || $r['incl'] > $r['orig'] || $r['usec'] > 999999) {
                    throw new \RuntimeException('Invalid PCAP packet length');
                }
                $data = $this->read($stream, $r['incl']);
                $summary['frames']++;
                $summary['truncated_frames'] += (int) ($r['incl'] < $r['orig']);
                $packet = $this->decode($data);
                $timestamp = $r['sec'].'.'.str_pad((string) $r['usec'], 6, '0', STR_PAD_LEFT);
                $observedAt = gmdate('Y-m-d\TH:i:s', $r['sec']).'.'.str_pad((string) $r['usec'], 6, '0', STR_PAD_LEFT).'Z';
                $summary['first_frame_at'] ??= $observedAt;
                $summary['last_frame_at'] = $observedAt;
                if ($includePackets && ! $textCapped) {
                    $line = $this->packetLine($summary['frames'], $timestamp, $r, $packet, $ip);
                    if (strlen($packetText) + strlen($line) <= self::PACKET_TEXT_LIMIT) {
                        $packetText .= $line;
                        $textFrames++;
                    } else {
                        $textCapped = true;
                    }
                }
                if (! $packet) {
                    $summary['skipped_frames']++;
                } elseif ($packet['src'] !== $ip && $packet['dst'] !== $ip) {
                    $summary['unrelated_frames']++;
                } else {
                    $out = $packet['src'] === $ip;
                    $summary['matched_packets']++;
                    $summary[$out ? 'bytes_out' : 'bytes_in'] += $r['orig'];
                    $peer = $out ? $packet['dst'] : $packet['src'];
                    $remote = $out ? $packet['dp'] : $packet['sp'];
                    $local = $out ? $packet['sp'] : $packet['dp'];
                    $tuple = $peer.'|'.$remote.'|'.$local.'|'.$packet['protocol'];
                    if ($packet['protocol'] === 6 && $out && ($packet['flags'] & 0x16) === 0x02 && (isset($activeSequences[$tuple]) || count($activeSequences) < 4096)) {
                        $activeSequences[$tuple] = $packet['seq'];
                    }
                    $initialSequence = $activeSequences[$tuple] ?? 'midstream';
                    if ($packet['protocol'] === 6 && ! $out && ($packet['flags'] & 0x12) === 0x12) {
                        $initialSequence = ($packet['ack'] - 1) & 0xFFFFFFFF;
                    }
                    $key = $tuple.'|'.$initialSequence;
                    if (! isset($flows[$key]) && count($flows) < 4096) {
                        $flows[$key] = ['peer_ip' => $peer, 'peer_port' => $remote, 'local_port' => $local, 'transport' => $packet['protocol'] === 6 ? 'tcp' : 'udp', 'syn_out' => 0, 'synack_in' => false, 'handshake_completed' => false, 'rst_in' => false, 'payload_bytes_out' => 0, 'payload_bytes_in' => 0, 'local_syn_seq' => null, 'peer_syn_seq' => null];
                    }
                    if (isset($flows[$key])) {
                        $flow = &$flows[$key];
                        $flags = $packet['flags'];
                        if ($out && ($flags & 0x16) === 0x02) {
                            $flow['syn_out']++;
                            $flow['local_syn_seq'] = $packet['seq'];
                        }
                        if (! $out && ($flags & 0x12) === 0x12 && $flow['local_syn_seq'] !== null && $packet['ack'] === (($flow['local_syn_seq'] + 1) & 0xFFFFFFFF)) {
                            $flow['synack_in'] = true;
                            $flow['peer_syn_seq'] = $packet['seq'];
                        }
                        if ($out && ($flags & 0x12) === 0x10 && $flow['synack_in'] && ! ($flags & 0x04) && $packet['ack'] === (($flow['peer_syn_seq'] + 1) & 0xFFFFFFFF) && $packet['seq'] === (($flow['local_syn_seq'] + 1) & 0xFFFFFFFF)) {
                            $flow['handshake_completed'] = true;
                        }
                        if (! $out && ($flags & 0x04) && ($flow['handshake_completed'] || (($flags & 0x10) && $flow['local_syn_seq'] !== null && $packet['ack'] === (($flow['local_syn_seq'] + 1) & 0xFFFFFFFF)))) {
                            $flow['rst_in'] = true;
                        }
                        $flow[$out ? 'payload_bytes_out' : 'payload_bytes_in'] += $packet['payload_size'];
                        if ($out && $packet['tls_sni']) {
                            $flow['tls_client_hello_sni'] = $packet['tls_sni'];
                        }
                        if ($out && ! isset($flow['http']) && ($http = $this->httpClue($packet['payload']))) {
                            $flow['http'] = $http;
                        }
                        $authentication->consume($flow, $packet, $out, $summary['frames']);
                        unset($flow);
                    } else {
                        $summary['summary_capped'] = true;
                    }
                }
                if ($summary['frames'] >= 200000 || microtime(true) - $started > 8) {
                    $summary['summary_capped'] = $summary['summary_capped'] || ! feof($stream);
                    break;
                }
            }
            $summary['pcap_fully_read'] = ftell($stream) === $size;
            $summary['file_bytes_read'] = ftell($stream);
            $summary['file_bytes'] = $size;
        } finally {
            fclose($stream);
        }
        $authenticationGroups = [];
        foreach ($flows as &$flow) {
            $auth = $authentication->finish($flow);
            if (! $auth) {
                continue;
            }
            $groupKey = $auth['protocol'].'|'.$flow['peer_ip'].'|'.$flow['peer_port'];
            $authenticationGroups[$groupKey] ??= ['protocol' => $auth['protocol'], 'peer_ip' => $flow['peer_ip'], 'peer_port' => $flow['peer_port'], 'requests_observed' => 0, 'paired_failures' => 0, 'paired_successes' => 0, 'challenges' => 0, 'analysis_capped' => false, 'encrypted_observed' => false, 'stream_gaps' => 0, 'failure_samples' => []];
            $group = &$authenticationGroups[$groupKey];
            foreach (['requests_observed', 'paired_failures', 'paired_successes', 'challenges', 'stream_gaps'] as $field) {
                $group[$field] += $auth[$field];
            }
            $group['analysis_capped'] = $group['analysis_capped'] || $auth['analysis_capped'];
            $group['encrypted_observed'] = $group['encrypted_observed'] || $auth['encrypted_observed'];
            $group['failure_samples'] = array_slice([...$group['failure_samples'], ...$auth['failure_samples']], 0, 8);
            unset($group);
        }
        unset($flow, $group);
        uasort($authenticationGroups, fn ($a, $b) => $b['paired_failures'] <=> $a['paired_failures']);
        $summary['authentication_groups'] = array_values(array_slice($authenticationGroups, 0, 32));
        $summary['authentication_groups_truncated'] = count($authenticationGroups) > 32;
        $summary['authentication_limitations'] = 'Only paired visible FTP authentication replies and plaintext SMB2 SESSION_SETUP responses are counted. SSH and RDP/NLA login results, FTPS and encrypted SMB are unavailable; zero observed failures does not prove no failed logins or no attack.';
        $outbound = array_filter($flows, fn ($flow) => $flow['syn_out'] > 0);
        $summary['observed_outbound_flows'] = count($outbound);
        $summary['syn_packets_out'] = array_sum(array_column($outbound, 'syn_out'));
        $summary['syn_retransmissions_observed'] = $summary['syn_packets_out'] - count($outbound);
        $summary['counting_unit'] = 'TCP tuple plus initial SYN sequence; same-sequence SYN retransmissions do not create new initiations';
        $summary['synack_flows'] = count(array_filter($outbound, fn ($flow) => $flow['synack_in']));
        $summary['completed_handshakes'] = count(array_filter($outbound, fn ($flow) => $flow['handshake_completed']));
        $summary['rst_reply_flows'] = count(array_filter($outbound, fn ($flow) => $flow['rst_in']));
        $summary['no_reply_observed_flows'] = count(array_filter($outbound, fn ($flow) => ! $flow['synack_in'] && ! $flow['rst_in']));
        $targets = [];
        foreach ($outbound as $flow) {
            $targets[$flow['peer_ip']][$flow['peer_port']] = true;
        }
        $summary['unique_outbound_targets'] = count($targets);
        $summary['max_ports_per_target'] = $targets ? max(array_map('count', $targets)) : 0;
        $portGroups = [];
        $portTargets = [];
        foreach ($outbound as $flow) {
            $groupKey = $flow['transport'].':'.$flow['peer_port'];
            $portGroups[$groupKey] ??= ['transport' => $flow['transport'], 'port' => $flow['peer_port'], 'outbound_flows' => 0, 'syn_packets' => 0, 'synack_flows' => 0, 'completed_handshakes' => 0, 'rst_reply_flows' => 0, 'no_reply_observed_flows' => 0, 'payload_bytes_out' => 0, 'payload_bytes_in' => 0];
            $group = &$portGroups[$groupKey];
            $group['outbound_flows']++;
            $group['syn_packets'] += $flow['syn_out'];
            $group['synack_flows'] += (int) $flow['synack_in'];
            $group['completed_handshakes'] += (int) $flow['handshake_completed'];
            $group['rst_reply_flows'] += (int) $flow['rst_in'];
            $group['no_reply_observed_flows'] += (int) (! $flow['synack_in'] && ! $flow['rst_in']);
            $group['payload_bytes_out'] += $flow['payload_bytes_out'];
            $group['payload_bytes_in'] += $flow['payload_bytes_in'];
            $portTargets[$groupKey][$flow['peer_ip']] = true;
            unset($group);
        }
        foreach ($portGroups as $key => &$group) {
            $group['unique_targets'] = count($portTargets[$key]);
        }
        unset($group);
        uasort($portGroups, fn ($a, $b) => $b['outbound_flows'] <=> $a['outbound_flows']);
        $summary['port_groups'] = array_values(array_slice($portGroups, 0, 64));
        $summary['port_groups_truncated'] = count($portGroups) > 64;
        if ($includePackets) {
            $summary['packet_text'] = ['format' => 'tab-separated; one row per stored PCAP frame, including unsupported/unrelated frames', 'frames' => $textFrames, 'bytes' => strlen($packetText), 'complete' => ! $textCapped && $summary['pcap_fully_read'] && $textFrames === $summary['frames'], 'text' => $packetText, 'omitted' => 'raw payload, ciphertext hex, HTTP query/fragment values, cookies, authorization and bodies; no TCP reassembly; unknown frames retain timestamp and lengths only'];
        }
        $peerGroups = [];
        foreach ($outbound as $flow) {
            $peer = $flow['peer_ip'];
            $peerGroups[$peer] ??= ['peer_ip' => $peer, 'initiations' => 0, 'completed_handshakes' => 0, 'rst_reply_flows' => 0, 'no_reply_observed_flows' => 0, 'ports' => []];
            $peerGroups[$peer]['initiations']++;
            $peerGroups[$peer]['completed_handshakes'] += (int) $flow['handshake_completed'];
            $peerGroups[$peer]['rst_reply_flows'] += (int) $flow['rst_in'];
            $peerGroups[$peer]['no_reply_observed_flows'] += (int) (! $flow['synack_in'] && ! $flow['rst_in']);
            $peerGroups[$peer]['ports'][$flow['peer_port']] = true;
        }
        foreach ($peerGroups as &$group) {
            $group['port_count'] = count($group['ports']);
            $group['ports'] = array_slice(array_keys($group['ports']), 0, 32);
            sort($group['ports']);
            $group['ports_truncated'] = $group['port_count'] > 32;
        }
        unset($group);
        uasort($peerGroups, fn ($a, $b) => $b['initiations'] <=> $a['initiations']);
        $summary['peer_groups'] = array_values(array_slice($peerGroups, 0, 16));
        $summary['peer_groups_truncated'] = count($peerGroups) > 16;
        $chosen = [];
        $strata = ['completed' => fn ($flow) => $flow['handshake_completed'],
            'no_reply' => fn ($flow) => $flow['syn_out'] > 0 && ! $flow['synack_in'] && ! $flow['rst_in'],
            'reset' => fn ($flow) => $flow['rst_in'], 'midstream' => fn ($flow) => $flow['syn_out'] === 0];
        $summary['sample_strata'] = [];
        foreach ($strata as $name => $filter) {
            $pool = array_filter($flows, $filter);
            $summary['sample_strata'][$name] = count($pool);
            uasort($pool, fn ($a, $b) => ($b['payload_bytes_out'] + $b['payload_bytes_in']) <=> ($a['payload_bytes_out'] + $a['payload_bytes_in']));
            foreach (array_slice($pool, 0, 8, true) as $key => $flow) {
                $chosen[$key] = $flow + ['sample_group' => $name];
            }
        }
        foreach ($flows as $key => $flow) {
            if (count($chosen) >= 32) {
                break;
            }
            $chosen[$key] ??= $flow + ['sample_group' => 'other'];
        }
        $summary['flow_samples'] = array_values($chosen);
        $summary['flow_samples_truncated'] = count($flows) > count($chosen);
        $summary['sampling_note'] = 'Stratified examples include successful, unanswered, reset and pre-existing sessions; sample proportions are NOT population proportions. Use port_groups and peer_groups for conclusions.';
        $summary['limitations'] = ['Only the requested future capture interval is available; it does not reconstruct or disprove the original alert interval.', 'Outbound target and handshake counts require an outbound SYN in this capture; existing sessions are not counted as newly initiated flows.', 'Missing replies do not prove connection failure: loss, sampling, asymmetry and capture boundaries matter.', 'Multiple capture interfaces may include duplicate packets; retransmissions and tuple reuse affect counts.', 'HTTPS/TLS/QUIC payloads are encrypted; URL, request body, login result and actual proxy protocol cannot be recovered without keys or service logs. Visible SNI is only a single complete ClientHello clue, not ownership proof; ECH inner names are unavailable.', 'Flow and frame limits are conservative samples. HTTP header extraction has no TCP reassembly; query values, cookies, authorization and request bodies are omitted.'];

        $summary['limitations'][] = 'Port groups cover tracked outbound TCP flows, capped at 4096 tuples and 64 port groups. Advertised payload lengths are from IP headers and may exceed captured payload bytes when snaplen truncates a frame.';

        return $summary;
    }

    private function httpClue(string $payload): ?array
    {
        if (! preg_match('/^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) ([^\s]{1,2048}) HTTP\/1\.[01]\r\n/', $payload, $match)) {
            return null;
        }
        $host = preg_match('/\r\nHost: ([a-zA-Z0-9.\-_:\[\]]{1,253})\r\n/i', $payload, $hm) ? $hm[1] : null;
        $path = parse_url($match[2], PHP_URL_PATH);

        return ['method' => $match[1], 'host' => $host, 'path' => is_string($path) ? mb_substr($path, 0, 512) : null, 'path_truncated' => is_string($path) && mb_strlen($path) > 512, 'query_values' => 'not retained', 'source' => 'first captured plaintext request header; no TCP reassembly'];
    }

    private function packetLine(int $frame, string $timestamp, array $record, ?array $packet, string $ip): string
    {
        if (! $packet) {
            return implode("\t", [$frame, $timestamp, 'unknown', 'unsupported', '-', '-', '-', '-', '-', $record['orig'], $record['incl'], '-', '{}'])."\n";
        }
        $direction = $packet['src'] === $ip ? 'out' : ($packet['dst'] === $ip ? 'in' : 'unrelated');
        $endpoint = fn ($address, $port) => (str_contains($address, ':') ? '['.$address.']' : $address).':'.$port;
        $clue = [];
        if ($direction === 'out') {
            if ($packet['tls_sni']) {
                $clue['sni'] = $packet['tls_sni'];
            }
            if ($http = $this->httpClue($packet['payload'])) {
                $clue['http'] = $http;
            }
        }

        return implode("\t", [$frame, $timestamp, $direction, $packet['protocol'] === 6 ? 'tcp' : 'udp', $endpoint($packet['src'], $packet['sp']), $endpoint($packet['dst'], $packet['dp']), dechex($packet['flags']), $packet['seq'], $packet['ack'], $record['orig'], $record['incl'], $packet['payload_size'], json_encode($clue ?: new \stdClass, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR)])."\n";
    }

    private function read($stream, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && ! feof($stream)) {
            $part = fread($stream, $length - strlen($data));
            if ($part === false || $part === '') {
                break;
            }
            $data .= $part;
        }
        if (strlen($data) !== $length) {
            throw new \RuntimeException('Truncated PCAP file');
        }

        return $data;
    }

    private function decode(string $data): ?array
    {
        if (strlen($data) < 14) {
            return null;
        }
        $type = unpack('n', substr($data, 12, 2))[1];
        $offset = 14;
        for ($n = 0; in_array($type, [0x8100, 0x88A8], true); $n++) {
            if ($n >= 2 || strlen($data) < $offset + 4) {
                return null;
            }
            $type = unpack('n', substr($data, $offset + 2, 2))[1];
            $offset += 4;
        }
        if ($type === 0x0800 && strlen($data) >= $offset + 20) {
            $header = (ord($data[$offset]) & 15) * 4;
            if (ord($data[$offset]) >> 4 !== 4 || $header < 20 || unpack('n', substr($data, $offset + 6, 2))[1] & 0x3FFF) {
                return null;
            }
            $src = inet_ntop(substr($data, $offset + 12, 4));
            $dst = inet_ntop(substr($data, $offset + 16, 4));
            $protocol = ord($data[$offset + 9]);
            $total = unpack('n', substr($data, $offset + 2, 2))[1];
            if ($total < $header) {
                return null;
            }
            $end = $offset + $total;
            $offset += $header;
        } elseif ($type === 0x86DD && strlen($data) >= $offset + 40) {
            if (ord($data[$offset]) >> 4 !== 6) {
                return null;
            }
            $src = inet_ntop(substr($data, $offset + 8, 16));
            $dst = inet_ntop(substr($data, $offset + 24, 16));
            $protocol = ord($data[$offset + 6]);
            $end = $offset + 40 + unpack('n', substr($data, $offset + 4, 2))[1];
            $offset += 40;
            for ($n = 0; in_array($protocol, [0, 43, 60], true); $n++) {
                if ($n >= 8 || strlen($data) < $offset + 2) {
                    return null;
                }
                $next = ord($data[$offset]);
                $offset += (ord($data[$offset + 1]) + 1) * 8;
                $protocol = $next;
            }
        } else {
            return null;
        }
        if (! in_array($protocol, [6, 17], true) || strlen($data) < $offset + ($protocol === 6 ? 20 : 8)) {
            return null;
        }
        $ports = unpack('nsp/ndp', substr($data, $offset, 4));
        $header = $protocol === 6 ? (ord($data[$offset + 12]) >> 4) * 4 : 8;
        if ($header < ($protocol === 6 ? 20 : 8) || $offset + $header > min($end, strlen($data))) {
            return null;
        }
        $payload = substr($data, $offset + $header, max(0, min($end, strlen($data)) - $offset - $header));
        $sequence = $protocol === 6 ? unpack('Nseq/Nack', substr($data, $offset + 4, 8)) : ['seq' => 0, 'ack' => 0];

        return ['src' => $src, 'dst' => $dst, 'protocol' => $protocol, 'flags' => $protocol === 6 ? ord($data[$offset + 13]) : 0, 'payload_size' => max(0, $end - $offset - $header), 'tls_sni' => $protocol === 6 ? $this->tlsSni($payload) : null, 'raw_payload' => substr($payload, 0, 8192), 'payload' => mb_convert_encoding(substr($payload, 0, 2048), 'UTF-8', 'UTF-8')] + $ports + $sequence;
    }

    private function tlsSni(string $payload): ?string
    {
        if (strlen($payload) < 44 || ord($payload[0]) !== 22 || ord($payload[1]) !== 3 || ord($payload[5]) !== 1) {
            return null;
        }
        $end = 5 + unpack('n', substr($payload, 3, 2))[1];
        if ($end > strlen($payload)) {
            return null;
        }
        $handshakeEnd = 9 + (ord($payload[6]) << 16) + (ord($payload[7]) << 8) + ord($payload[8]);
        if ($handshakeEnd > $end) {
            return null;
        }
        $end = $handshakeEnd;
        $offset = 44 + ord($payload[43]);
        if ($offset + 2 > $end) {
            return null;
        }
        $offset += 2 + unpack('n', substr($payload, $offset, 2))[1];
        if ($offset + 1 > $end) {
            return null;
        }
        $offset += 1 + ord($payload[$offset]);
        if ($offset + 2 > $end) {
            return null;
        }
        $extEnd = $offset + 2 + unpack('n', substr($payload, $offset, 2))[1];
        $offset += 2;
        if ($extEnd > $end) {
            return null;
        }
        while ($offset + 4 <= $extEnd) {
            $extension = unpack('ntype/nlength', substr($payload, $offset, 4));
            $offset += 4;
            $next = $offset + $extension['length'];
            if ($next > $extEnd) {
                return null;
            }
            if ($extension['type'] === 0 && $extension['length'] >= 5) {
                $listEnd = $offset + 2 + unpack('n', substr($payload, $offset, 2))[1];
                if ($listEnd > $next) {
                    return null;
                }
                $pos = $offset + 2;
                while ($pos + 3 <= $listEnd) {
                    $type = ord($payload[$pos]);
                    $length = unpack('n', substr($payload, $pos + 1, 2))[1];
                    $pos += 3;
                    if ($pos + $length > $listEnd) {
                        return null;
                    }
                    if ($type === 0 && $length > 0 && $length <= 253) {
                        $host = strtolower(rtrim(substr($payload, $pos, $length), '.'));

                        return preg_match('/^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$/', $host) ? $host : null;
                    }
                    $pos += $length;
                }
            }
            $offset = $next;
        }

        return null;
    }
}
