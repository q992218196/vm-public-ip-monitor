<?php

namespace App\Services;

class AuthenticationEvidence
{
    public function consume(array &$flow, array $packet, bool $out, int $frame): void
    {
        $payload = $packet['raw_payload'] ?? '';
        if ($packet['protocol'] !== 6 || $payload === '' || ($flow['_auth']['stopped'] ?? false)) {
            return;
        }
        if (! isset($flow['_auth'])) {
            $smb = strlen($payload) >= 8 && substr($payload, 4, 4) === "\xfeSMB";
            $ftp = preg_match('/^(?:USER |PASS |ACCT |220[ -])/i', $payload) === 1;
            if (! $smb && ! $ftp && ! in_array($flow['peer_port'], [21, 139, 445], true)) {
                return;
            }
            $protocol = $smb || in_array($flow['peer_port'], [139, 445], true) ? 'SMB2' : 'FTP';
            $flow['_auth'] = ['protocol' => $protocol, 'pending' => [], 'failures' => 0, 'successes' => 0, 'challenges' => 0, 'requests' => 0, 'capped' => false, 'gaps' => 0, 'samples' => [], 'out' => ['next' => null, 'buffer' => ''], 'in' => ['next' => null, 'buffer' => '']];
        }
        $truncated = strlen($payload) < ($packet['payload_size'] ?? strlen($payload));
        $state = &$flow['_auth'];
        $stream = &$state[$out ? 'out' : 'in'];
        $seq = ($packet['seq'] + (int) (($packet['flags'] & 2) !== 0)) & 0xFFFFFFFF;
        if ($stream['next'] !== null) {
            $delta = ($seq - $stream['next']) & 0xFFFFFFFF;
            if ($delta > 0x7FFFFFFF) {
                $overlap = ($stream['next'] - $seq) & 0xFFFFFFFF;
                if ($overlap >= strlen($payload)) {
                    return;
                }
                $payload = substr($payload, $overlap);
                $seq = $stream['next'];
            } elseif ($delta > 0) {
                $state['gaps']++;
                $state['stopped'] = true;
                $state['pending'] = [];
                $stream['buffer'] = '';

                return;
            }
        }
        $stream['next'] = ($seq + strlen($payload)) & 0xFFFFFFFF;
        if (strlen($stream['buffer']) + strlen($payload) > 8192) {
            $state['capped'] = $state['stopped'] = true;
            $stream['buffer'] = '';

            return;
        }
        $stream['buffer'] .= $payload;
        if ($state['protocol'] === 'FTP') {
            $this->ftp($state, $stream, $out, $frame);
        } else {
            $this->smb($state, $stream, $out, $frame);
        }
        if ($truncated) {
            $state['capped'] = $state['stopped'] = true;
        }
        if ($state['requests'] >= 256) {
            $state['capped'] = $state['stopped'] = true;
        }
    }

    private function ftp(array &$state, array &$stream, bool $out, int $frame): void
    {
        while (($end = strpos($stream['buffer'], "\r\n")) !== false) {
            $line = substr($stream['buffer'], 0, $end);
            $stream['buffer'] = substr($stream['buffer'], $end + 2);
            if ($out) {
                if (! ($state['greeting_observed'] ?? false)) {
                    continue;
                }
                if (preg_match('/^([A-Z]{3,4})(?: |$)/i', $line, $match)) {
                    if (count($state['pending']) >= 16) {
                        $state['capped'] = $state['stopped'] = true;
                        break;
                    }
                    $command = strtoupper($match[1]);
                    $state['pending'][] = $command;
                    $state['requests'] += (int) in_array($command, ['USER', 'PASS', 'ACCT'], true);
                }
            } elseif (preg_match('/^(\d{3}) /', $line, $match)) {
                $code = (int) $match[1];
                if ($code === 220) {
                    $state['greeting_observed'] = true;

                    continue;
                }
                if ($code < 200) {
                    continue;
                }
                $command = array_shift($state['pending']);
                if ($command === 'AUTH' && $code === 234) {
                    $state['encrypted'] = $state['stopped'] = true;
                    break;
                }
                if (! in_array($command, ['USER', 'PASS', 'ACCT'], true)) {
                    continue;
                }
                if ($code === 530) {
                    $state['failures']++;
                    $this->sample($state, ['frame' => $frame, 'command' => $command, 'reply_code' => 530, 'meaning' => 'Not logged in in response to an authentication command']);
                } elseif ($code === 230) {
                    $state['successes']++;
                } elseif (in_array($code, [331, 332], true)) {
                    $state['challenges']++;
                }
            }
        }
    }

    private function smb(array &$state, array &$stream, bool $out, int $frame): void
    {
        while (strlen($stream['buffer']) >= 4) {
            $buffer = $stream['buffer'];
            $length = (ord($buffer[1]) << 16) | (ord($buffer[2]) << 8) | ord($buffer[3]);
            if (ord($buffer[0]) !== 0 || $length < 64 || $length > 8192) {
                $state['capped'] = $state['stopped'] = true;
                $stream['buffer'] = '';

                return;
            }
            if (strlen($buffer) < $length + 4) {
                return;
            }
            $message = substr($buffer, 4, $length);
            $stream['buffer'] = substr($buffer, $length + 4);
            if (substr($message, 0, 4) === "\xfdSMB") {
                $state['encrypted'] = true;

                continue;
            }
            if (substr($message, 0, 4) !== "\xfeSMB" || unpack('v', substr($message, 4, 2))[1] !== 64 || unpack('v', substr($message, 12, 2))[1] !== 1) {
                continue;
            }
            $response = (unpack('V', substr($message, 16, 4))[1] & 1) !== 0;
            if (strlen($message) < ($response ? 72 : 88) || unpack('v', substr($message, 64, 2))[1] !== ($response ? 9 : 25)) {
                continue;
            }
            $messageId = bin2hex(substr($message, 24, 8));
            if ($out && ! $response) {
                if (count($state['pending']) >= 128) {
                    $state['capped'] = $state['stopped'] = true;

                    return;
                }
                if (! isset($state['pending'][$messageId])) {
                    $state['requests']++;
                    $state['pending'][$messageId] = true;
                }
            } elseif (! $out && $response && isset($state['pending'][$messageId])) {
                $status = unpack('V', substr($message, 8, 4))[1];
                if ($status === 0x00000103) {
                    continue;
                }
                unset($state['pending'][$messageId]);
                if (in_array($status, [0xC000006D, 0xC000006A, 0xC0000064, 0xC0000234, 0xC0000072, 0xC0000071, 0xC0000193], true)) {
                    $state['failures']++;
                    $this->sample($state, ['frame' => $frame, 'command' => 'SESSION_SETUP', 'message_id_hex' => $messageId, 'status' => sprintf('0x%08X', $status), 'meaning' => 'Paired SMB2 session authentication rejected; not proof of password guessing']);
                } elseif ($status === 0) {
                    $state['successes']++;
                } elseif ($status === 0xC0000016) {
                    $state['challenges']++;
                }
            }
        }
    }

    private function sample(array &$state, array $sample): void
    {
        if (count($state['samples']) < 8) {
            $state['samples'][] = $sample;
        }
    }

    public function finish(array &$flow): ?array
    {
        $state = $flow['_auth'] ?? null;
        unset($flow['_auth']);
        if (! $state || $state['requests'] === 0) {
            return null;
        }

        return $flow['authentication'] = ['protocol' => $state['protocol'], 'requests_observed' => $state['requests'], 'paired_failures' => $state['failures'], 'paired_successes' => $state['successes'], 'challenges' => $state['challenges'], 'encrypted_observed' => $state['encrypted'] ?? false, 'analysis_capped' => $state['capped'], 'stream_gaps' => $state['gaps'], 'failure_samples' => $state['samples'],
            'limitations' => 'Bounded contiguous TCP parsing, no out-of-order repair; FTP greeting required; SMB2 first message only, no SMB1 parsing; captures can omit outcomes. No usernames/passwords or raw authentication payload retained. Repeated failures may be bad credentials/configuration and do not alone prove an attack.'];
    }
}
