<?php

namespace App\Services;

use App\Models\Website;
use FilesystemIterator;

class Screenshots
{
    private const PRUNE_BATCH_SIZE = 200;

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
        if ($lock === false || ! flock($lock, LOCK_EX)) {
            if ($lock !== false) {
                fclose($lock);
            }
            throw new \RuntimeException('截图存储锁获取失败');
        }
        try {
            $name = hash('sha256', $bytes).'.png';
            $path = $root.'/'.$name;
            if (is_file($path)) {
                if (! touch($path)) {
                    throw new \RuntimeException('截图复用时间更新失败');
                }

                return 'screenshots/'.$name;
            }
            $used = 0;
            foreach (new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS) as $file) {
                if (! $file->isLink() && $file->isFile() && $file->getExtension() === 'png') {
                    $used += $file->getSize();
                }
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

    public function prune(): int
    {
        $root = storage_path('app/private/screenshots');
        if (! is_dir($root)) {
            return 0;
        }
        $cutoff = time() - 86400;
        $candidates = [];
        $deleted = 0;
        foreach (new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS) as $file) {
            if (! preg_match('/\A[a-f0-9]{64}\.png\z/', $file->getFilename())) {
                continue;
            }
            $path = $file->getPathname();
            if (! $this->isExpiredRegularFile($path, $cutoff)) {
                continue;
            }
            $candidates['screenshots/'.$file->getFilename()] = $path;
            if (count($candidates) === self::PRUNE_BATCH_SIZE) {
                $deleted += $this->pruneBatch($root, $candidates, $cutoff);
                $candidates = [];
            }
        }

        return $deleted + ($candidates ? $this->pruneBatch($root, $candidates, $cutoff) : 0);
    }

    /**
     * @param  array<string, string>  $candidates
     */
    private function pruneBatch(string $root, array $candidates, int $cutoff): int
    {
        $lock = fopen($root.'/.budget.lock', 'c');
        if ($lock === false) {
            return 0;
        }
        if (! flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);

            return 0;
        }
        try {
            $referenced = array_fill_keys(Website::query()->whereNotNull('screenshot_path')
                ->whereIn('screenshot_path', array_keys($candidates))->distinct()->pluck('screenshot_path')->all(), true);
            $deleted = 0;
            foreach ($candidates as $reference => $path) {
                if (! isset($referenced[$reference]) && $this->isExpiredRegularFile($path, $cutoff) && unlink($path)) {
                    $deleted++;
                }
            }

            return $deleted;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function isExpiredRegularFile(string $path, int $cutoff): bool
    {
        clearstatcache(true, $path);
        $stat = @lstat($path);

        return $stat !== false && ($stat['mode'] & 0170000) === 0100000 && $stat['mtime'] < $cutoff;
    }
}
