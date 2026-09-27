<?php

namespace App\Services;

class Screenshots
{
    public function store(?string $encoded): ?string
    {
        if (! $encoded) {
            return null;
        }
        $bytes = base64_decode($encoded, true);
        if ($bytes === false || strlen($bytes) > 2 * 1024 * 1024) {
            throw new \InvalidArgumentException('截图最大 2 MiB');
        }
        $info = @getimagesizefromstring($bytes);
        if (! $info || $info[2] !== IMAGETYPE_PNG || $info[0] > 2000 || $info[1] > 4000) {
            throw new \InvalidArgumentException('仅允许尺寸受限的 PNG 截图');
        }
        $root = storage_path('app/private/screenshots');
        if (! is_dir($root)) {
            mkdir($root, 0700, true);
        }
        $lock = fopen($root.'/.budget.lock', 'c');
        flock($lock, LOCK_EX);
        try {
            $name = hash('sha256', $bytes).'.png';
            $path = $root.'/'.$name;
            if (is_file($path)) {
                return 'screenshots/'.$name;
            }
            $used = 0;
            foreach (glob($root.'/*.png') as $f) {
                $used += filesize($f);
            }
            if ($used + strlen($bytes) > (int) config('monitor.screenshots_bytes')) {
                return null;
            }
            if (file_put_contents($path.'.tmp', $bytes, LOCK_EX) === false || ! rename($path.'.tmp', $path)) {
                throw new \RuntimeException('截图写入失败');
            }

            return 'screenshots/'.$name;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
