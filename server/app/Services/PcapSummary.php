<?php

namespace App\Services;

class PcapSummary
{
    public function summarize(string $path, string $ip): array
    {
        $packedIp = inet_pton($ip);
        if ($packedIp === false) {
            throw new \RuntimeException('Invalid capture IP');
        }
        $ip = inet_ntop($packedIp);
        $stream = fopen($path, 'rb');
        if (! $stream || filesize($path) > 33554432) {
            throw new \RuntimeException('PCAP missing or exceeds 32 MiB');
        }
        $summary = ['ip' => $ip, 'frames' => 0, 'matched_packets' => 0, 'skipped_frames' => 0, 'unrelated_frames' => 0, 'bytes_out' => 0, 'bytes_in' => 0, 'truncated_frames' => 0, 'summary_capped' => false];
        $flows = [];
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
                    $key = $peer.'|'.$remote.'|'.$local.'|'.$packet['protocol'];
                    if (! isset($flows[$key]) && count($flows) < 4096) {
                        $flows[$key] = ['peer_ip' => $peer, 'peer_port' => $remote, 'local_port' => $local, 'transport' => $packet['protocol'] === 6 ? 'tcp' : 'udp', 'syn_out' => 0, 'synack_in' => false, 'handshake_completed' => false, 'rst_in' => false, 'payload_bytes_out' => 0, 'payload_bytes_in' => 0, 'local_syn_seq' => null, 'peer_syn_seq' => null];
                    }
                    if (isset($flows[$key])) {
                        $flow = &$flows[$key];
                        $flags = $packet['flags'];
                        if ($out && ($flags & 0x12) === 0x02) {
                            $flow['syn_out']++;
                            $flow['local_syn_seq'] = $packet['seq'];
                        }
                        if (! $out && ($flags & 0x12) === 0x12 && $flow['local_syn_seq'] !== null && $packet['ack'] === (($flow['local_syn_seq'] + 1) & 0xFFFFFFFF)) {
                            $flow['synack_in'] = true;
                            $flow['peer_syn_seq'] = $packet['seq'];
                        }
                        if ($out && ($flags & 0x12) === 0x10 && $flow['synack_in'] && ! ($flags & 0x04) && $packet['ack'] === (($flow['peer_syn_seq'] + 1) & 0xFFFFFFFF)) {
                            $flow['handshake_completed'] = true;
                        }
                        if (! $out && ($flags & 0x04)) {
                            $flow['rst_in'] = true;
                        }
                        $flow[$out ? 'payload_bytes_out' : 'payload_bytes_in'] += $packet['payload_size'];
                        if ($out && $packet['tls_sni']) {
                            $flow['tls_client_hello_sni'] = $packet['tls_sni'];
                        }
                        if ($out && ! isset($flow['http']) && preg_match('/^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) ([^\s]{1,2048}) HTTP\/1\.[01]\r\n/', $packet['payload'], $match)) {
                            $host = preg_match('/\r\nHost: ([^\r\n]{1,253})/i', $packet['payload'], $hm) ? $hm[1] : null;
                            $flow['http'] = ['method' => $match[1], 'host' => $host, 'path' => strtok($match[2], '?'), 'query_values' => 'not retained', 'source' => 'first captured plaintext request header; no TCP reassembly'];
                        }
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
        } finally {
            fclose($stream);
        }
        $outbound = array_filter($flows, fn ($flow) => $flow['syn_out'] > 0);
        $summary['observed_outbound_flows'] = count($outbound);
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
        uasort($flows, fn ($a, $b) => ($b['syn_out'] * 1024 + $b['payload_bytes_out'] + $b['payload_bytes_in']) <=> ($a['syn_out'] * 1024 + $a['payload_bytes_out'] + $a['payload_bytes_in']));
        $summary['flow_samples'] = array_values(array_slice($flows, 0, 32));
        $summary['flow_samples_truncated'] = count($flows) > 32;
        $summary['limitations'] = ['Only the requested future capture interval is available; it does not reconstruct or disprove the original alert interval.', 'Outbound target and handshake counts require an outbound SYN in this capture; existing sessions are not counted as newly initiated flows.', 'Missing replies do not prove connection failure: loss, sampling, asymmetry and capture boundaries matter.', 'Multiple capture interfaces may include duplicate packets; retransmissions and tuple reuse affect counts.', 'HTTPS/TLS/QUIC payloads are encrypted; URL, request body, login result and actual proxy protocol cannot be recovered without keys or service logs. Visible SNI is only a single complete ClientHello clue, not ownership proof; ECH inner names are unavailable.', 'Flow and frame limits are conservative samples. HTTP header extraction has no TCP reassembly; query values, cookies, authorization and request bodies are omitted.'];

        return $summary;
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

        return ['src' => $src, 'dst' => $dst, 'protocol' => $protocol, 'flags' => $protocol === 6 ? ord($data[$offset + 13]) : 0, 'payload_size' => max(0, $end - $offset - $header), 'tls_sni' => $protocol === 6 ? $this->tlsSni($payload) : null, 'payload' => mb_convert_encoding(substr($payload, 0, 2048), 'UTF-8', 'UTF-8')] + $ports + $sequence;
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
