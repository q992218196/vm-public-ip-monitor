<?php

namespace App\Support;

use Illuminate\Database\Eloquent\Builder;

class AlertFilters
{
    public static function apply(Builder $query, array $filters): Builder
    {
        return $query
            ->when($filters['node'] ?? null, fn (Builder $query, string $node): Builder => $query->where('node_id', $node))
            ->when($filters['ip'] ?? null, fn (Builder $query, string $ip): Builder => $query->whereHas('ipAsset', fn (Builder $asset): Builder => $asset->where('ip', Ip::normalize($ip))))
            ->when($filters['severity'] ?? null, fn (Builder $query, string $severity): Builder => $query->where('severity', $severity))
            ->when($filters['status'] ?? null, fn (Builder $query, string $status): Builder => $query->where('status', $status));
    }
}
