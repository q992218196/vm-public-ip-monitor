<?php

namespace App\Filament\Resources\AlertResource\Pages;

use App\Filament\Resources\AlertResource;
use App\Models\Alert;
use App\Models\Node;
use App\Support\Ip;
use Filament\Resources\Pages\Page;
use Illuminate\Database\Eloquent\Builder;

class ManageAlerts extends Page
{
    protected static string $resource = AlertResource::class;

    protected string $view = 'monitor.alert-list';

    public function getTitle(): string
    {
        return '告警中心';
    }

    protected function getViewData(): array
    {
        $filters = request()->validate([
            'node' => 'nullable|uuid',
            'ip' => 'nullable|ip',
            'severity' => 'nullable|in:low,medium,high',
            'status' => 'nullable|in:open,acknowledged,resolved',
            'per_page' => 'nullable|in:10,25,50,100,200,500',
            'cursor' => 'nullable|string|max:2048',
        ]);
        if (isset($filters['ip'])) {
            $filters['ip'] = Ip::normalize($filters['ip']);
        }
        $perPage = (int) ($filters['per_page'] ?? 25);
        $query = Alert::query()
            ->select(['id', 'node_id', 'ip_asset_id', 'kind', 'title', 'severity', 'status', 'occurrences', 'last_seen_at'])
            ->with(['node:id,name', 'ipAsset:id,ip'])
            ->when($filters['node'] ?? null, fn (Builder $query, string $node): Builder => $query->where('node_id', $node))
            ->when($filters['ip'] ?? null, fn (Builder $query, string $ip): Builder => $query->whereHas('ipAsset', fn (Builder $asset): Builder => $asset->where('ip', $ip)))
            ->when($filters['severity'] ?? null, fn (Builder $query, string $severity): Builder => $query->where('severity', $severity))
            ->when($filters['status'] ?? null, fn (Builder $query, string $status): Builder => $query->where('status', $status))
            ->orderByDesc('last_seen_at')->orderByDesc('id');

        return [
            'alerts' => $query->cursorPaginate($perPage)->withQueryString(),
            'nodes' => Node::query()->select(['id', 'name'])->orderBy('name')->get(),
            'filters' => $filters,
            'perPage' => $perPage,
        ];
    }
}
