<?php

namespace App\Filament\Widgets;

use App\Models\Alert;
use App\Models\Batch;
use App\Models\IpAsset;
use App\Models\Node;
use App\Models\Website;
use Filament\Widgets\StatsOverviewWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use Illuminate\Support\Facades\Cache;

class Overview extends StatsOverviewWidget
{
    protected function getStats(): array
    {
        $counts = Cache::remember('monitor:overview:counts', 20, fn (): array => [
            'nodes' => Node::where('enabled', true)->where('last_seen_at', '>', now()->subMinutes(5))->count(),
            'ips' => IpAsset::count(),
            'websites' => Website::count(),
            'alerts' => Alert::where('status', 'open')->count(),
            'batches' => Batch::whereNull('processed_at')->count(),
        ]);

        return [
            Stat::make('在线采集节点', $counts['nodes'])->description('最近 5 分钟有上报'),
            Stat::make('公网 IP', $counts['ips'])->description('IPv4 / IPv6 独立建档'),
            Stat::make('网站资产', $counts['websites'])->description('含尚未验证的域名线索'),
            Stat::make('待处理告警', $counts['alerts'])->color('warning'),
            Stat::make('待分析批次', $counts['batches'])->description('持续增长时检查队列与调度器'),
        ];
    }
}
