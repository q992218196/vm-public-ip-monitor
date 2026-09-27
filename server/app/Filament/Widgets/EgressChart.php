<?php

namespace App\Filament\Widgets;

use App\Models\Node;
use App\Models\TrafficMetric;
use Filament\Widgets\ChartWidget;

class EgressChart extends ChartWidget
{
    protected ?string $heading = '单个观察节点的出站流量';

    protected ?string $description = '最近一小时；各节点分别观察，不相加推断全局 VM 流量。';

    protected static ?int $sort = 2;

    protected function getType(): string
    {
        return 'line';
    }

    protected function getFilters(): ?array
    {
        return Node::orderBy('name')->pluck('name', 'id')->all();
    }

    protected function getData(): array
    {
        $node = $this->filter ?: Node::orderBy('name')->value('id');
        $rows = TrafficMetric::where('node_id', $node)->where('window_start', '>=', now()->subHour())->selectRaw('window_start, window_end, SUM(bytes_out) AS total_bytes')->groupBy('window_start', 'window_end')->orderBy('window_end')->get();

        return ['datasets' => [['label' => '出站 Mbps', 'data' => $rows->map(fn ($r) => round($r->total_bytes * 8 / max(1, $r->window_start->diffInSeconds($r->window_end)) / 1000000, 3))->all(), 'borderColor' => '#0d9488', 'backgroundColor' => '#0d948833', 'fill' => true]], 'labels' => $rows->map(fn ($r) => $r->window_end->timezone(config('monitor.display_timezone'))->format('H:i:s'))->all()];
    }
}
