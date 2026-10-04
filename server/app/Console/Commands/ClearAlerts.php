<?php

namespace App\Console\Commands;

use App\Models\AiAnalysis;
use App\Models\Alert;
use App\Models\AuditLog;
use App\Models\MonitorEvent;
use App\Models\PacketCapture;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

#[Signature('monitor:clear-alerts {--force : 实际清空告警、事件、关联抓包和 AI 报告；默认只预览}')]
#[Description('预览或清空告警中心，保留节点、网站、规则、白名单和原始流量窗口')]
class ClearAlerts extends Command
{
    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $counts = ['alerts' => Alert::count(), 'events' => MonitorEvent::count(), 'captures' => PacketCapture::count(), 'ai_reports' => AiAnalysis::count()];
        $this->line('告警 '.$counts['alerts'].'；事件 '.$counts['events'].'；抓包 '.$counts['captures'].'；AI 报告 '.$counts['ai_reports']);
        if (! $this->option('force')) {
            $this->info('仅预览，未删除。实际执行前停止 app、queue、scheduler、ai-queue；加 --force 将永久清空上述记录及受管 PCAP 文件。');

            return self::SUCCESS;
        }
        DB::transaction(function () use ($counts) {
            AiAnalysis::query()->delete();
            PacketCapture::query()->delete();
            Alert::query()->delete();
            MonitorEvent::query()->delete();
            AuditLog::create(['user_id' => null, 'action' => 'alerts_cleared', 'subject' => 'MonitorEvent:all', 'details' => ['actor' => 'collector_cli', 'counts' => $counts]]);
        });
        $disk = Storage::disk('local');
        $root = $disk->path('packet-evidence');
        $failed = 0;
        if (is_dir($root)) {
            foreach (new \DirectoryIterator($root) as $file) {
                if (! $file->isFile() || $file->isLink() || ! preg_match('/^[a-f0-9-]{36}\.pcap$/i', $file->getFilename())) {
                    continue;
                }
                if (PacketCapture::where('path', 'packet-evidence/'.$file->getFilename())->exists()) {
                    continue;
                }
                try {
                    if (! $disk->delete('packet-evidence/'.$file->getFilename())) {
                        $failed++;
                    }
                } catch (\Throwable) {
                    $failed++;
                }
            }
        }
        $this->info('告警中心已清空；节点、网站、检测规则、白名单和流量窗口保留。恢复服务后，新规则命中会生成新告警。');
        if ($failed > 0) {
            $this->warn("$failed 个 PCAP 文件回收失败，可检查存储权限；定时证据清理会继续回收孤立文件。");
        }

        return self::SUCCESS;
    }
}
