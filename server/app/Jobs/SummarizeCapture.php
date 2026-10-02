<?php

namespace App\Jobs;

use App\Models\PacketCapture;
use App\Services\PcapSummary;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Storage;

class SummarizeCapture implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout = 30;

    public function __construct(public string $captureId)
    {
        $this->onQueue('evidence');
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $capture = PacketCapture::find($this->captureId);
        if (! $capture || $capture->status !== 'uploaded' || ! $capture->path || ($capture->summary['analysis_version'] ?? 0) >= PcapSummary::ANALYSIS_VERSION) {
            return;
        }
        try {
            $path = Storage::disk('local')->path($capture->path);
            if (! is_file($path) || ! hash_equals($capture->sha256, hash_file('sha256', $path))) {
                throw new \RuntimeException('PCAP integrity check failed');
            }
            $capture->update(['summary' => app(PcapSummary::class)->summarize($path, $capture->ip)]);
        } catch (\Throwable $error) {
            $capture->update(['last_error' => '抓包结构解析失败；原始文件仍可下载复核']);
        }
    }
}
