<?php

namespace App\Services;

class AiKey
{
    public function decrypt(string $cipher): string
    {
        $packed = base64_decode($cipher, true);
        $secret = (string) config('app.key');
        $key = str_starts_with($secret, 'base64:') ? base64_decode(substr($secret, 7), true) : $secret;
        if (! $key || ! $packed || strlen($packed) < 29) {
            throw new \RuntimeException('AI credential is unavailable');
        }
        $plain = openssl_decrypt(substr($packed, 28), 'aes-256-gcm', hash('sha256', $key, true), OPENSSL_RAW_DATA, substr($packed, 0, 12), substr($packed, 12, 16), 'vm-monitor-ai-v1');
        if ($plain === false) {
            throw new \RuntimeException('AI credential cannot be decrypted');
        }

        return $plain;
    }
}
