<?php

namespace App\Filament\Resources\WebsiteResource\Pages;

use App\Filament\Resources\WebsiteResource;
use App\Models\Website;
use App\Support\Ip;
use Filament\Resources\Pages\Page;
use Illuminate\Database\Eloquent\Builder;

class ManageWebsites extends Page
{
    protected static string $resource = WebsiteResource::class;

    protected string $view = 'monitor.website-list';

    public function getTitle(): string
    {
        return '网站资产';
    }

    protected function getViewData(): array
    {
        $filters = request()->validate([
            'ip' => 'nullable|ip',
            'host' => ['nullable', 'string', 'max:253', 'regex:/^[a-zA-Z0-9.\-]*$/'],
            'status' => 'nullable|in:observed,candidate,verified,failed',
            'review' => 'nullable|in:1',
            'show_description' => 'nullable|in:1',
            'per_page' => 'nullable|in:10,25,50,100,200,500',
            'cursor' => 'nullable|string|max:2048',
        ]);
        if (isset($filters['ip'])) {
            $filters['ip'] = Ip::normalize($filters['ip']);
        }
        $perPage = (int) ($filters['per_page'] ?? 25);
        $columns = ['id', 'ip_asset_id', 'host', 'port', 'scheme', 'source', 'status', 'title', 'category', 'manual_category', 'last_probed_at', 'last_seen_at', 'screenshot_path'];
        if (isset($filters['show_description'])) {
            $columns[] = 'description';
        }
        $query = Website::query()
            ->select($columns)
            ->with('ipAsset:id,ip')
            ->when($filters['ip'] ?? null, fn (Builder $query, string $ip): Builder => $query->whereHas('ipAsset', fn (Builder $asset): Builder => $asset->where('ip', $ip)))
            ->when($filters['host'] ?? null, fn (Builder $query, string $host): Builder => $query->where('host', 'like', strtolower($host).'%'))
            ->when($filters['status'] ?? null, fn (Builder $query, string $status): Builder => $query->where('status', $status))
            ->when($filters['review'] ?? null, fn (Builder $query): Builder => $query->whereIn('category', ['疑似博彩', '疑似成人内容', '疑似诈骗引流', '支付平台线索', '贷款平台线索'])->whereNull('manual_category'))
            ->orderByDesc('last_seen_at')->orderByDesc('id');

        return [
            'websites' => $query->cursorPaginate($perPage)->withQueryString(),
            'filters' => $filters,
            'perPage' => $perPage,
        ];
    }
}
