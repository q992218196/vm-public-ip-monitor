<?php

namespace App\Filament\Resources\IpAssetResource\Pages;

use App\Filament\Resources\IpAssetResource;
use Filament\Resources\Pages\ManageRecords;

class ManageIpAssets extends ManageRecords
{
    protected static string $resource = IpAssetResource::class;

    protected function getHeaderActions(): array
    {
        return [];
    }
}
