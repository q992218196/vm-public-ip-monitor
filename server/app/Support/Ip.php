<?php

namespace App\Support;

final class Ip
{
    public static function normalize(string $ip): string
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            throw new \InvalidArgumentException('无效 IP 地址');
        }
        // A mapped IPv4 is the same address; don't create a second asset.
        if (strlen($binary) === 16 && substr($binary, 0, 12) === str_repeat("\0", 10)."\xff\xff") {
            $binary = substr($binary, 12);
        }

        return inet_ntop($binary);
    }

    public static function validCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2 || ! ctype_digit($parts[1])) {
            return false;
        }
        $b = @inet_pton($parts[0]);

        return $b !== false && (int) $parts[1] <= strlen($b) * 8;
    }

    public static function contains(string $cidr, string $ip): bool
    {
        if (! self::validCidr($cidr)) {
            return false;
        }
        [$network, $bits] = explode('/', $cidr);
        $a = @inet_pton($network);
        $b = @inet_pton($ip);
        if (! $b || strlen($a) !== strlen($b)) {
            return false;
        }
        $whole = intdiv((int) $bits, 8);
        $remaining = (int) $bits % 8;
        if (substr($a, 0, $whole) !== substr($b, 0, $whole)) {
            return false;
        }

        return ! $remaining || ((ord($a[$whole]) ^ ord($b[$whole])) & (255 << (8 - $remaining))) === 0;
    }

    public static function inRanges(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::contains($cidr, $ip)) {
                return true;
            }
        }

        return false;
    }
}
