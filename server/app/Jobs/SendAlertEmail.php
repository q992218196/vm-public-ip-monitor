<?php

namespace App\Jobs;

use App\Models\Alert;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Mail;

class SendAlertEmail implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public function __construct(public int $alertId) {}

    public function backoff(): array
    {
        return [30, 120, 300];
    }

    public function handle(): void
    {
        $to = config('monitor.alert_email');
        if (! $to) {
            return;
        }$a = Alert::with(['node', 'ipAsset'])->find($this->alertId);
        if (! $a) {
            return;
        }
        $body = "{$a->title}\n公网 IP：".($a->ipAsset?->ip ?? '—')."\n观察节点：{$a->node->name}\n级别：{$a->severity}\n时间：{$a->last_seen_at}\n证据：".json_encode($a->evidence, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)."\n后台：".rtrim(config('app.url'), '/').'/admin/alerts';
        Mail::raw($body, fn ($m) => $m->to($to)->subject('[VM监控] '.$a->title));
    }
}
