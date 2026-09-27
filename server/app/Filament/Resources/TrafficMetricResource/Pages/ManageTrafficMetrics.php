<?php

namespace App\Filament\Resources\TrafficMetricResource\Pages;

use App\Filament\Resources\TrafficMetricResource;
use Filament\Resources\Pages\ManageRecords;

class ManageTrafficMetrics extends ManageRecords
{
    protected static string $resource = TrafficMetricResource::class;

    protected function getHeaderActions(): array
    {
        return [];
    }
}
