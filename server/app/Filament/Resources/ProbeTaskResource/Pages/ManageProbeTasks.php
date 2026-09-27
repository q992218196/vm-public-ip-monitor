<?php

namespace App\Filament\Resources\ProbeTaskResource\Pages;

use App\Filament\Resources\ProbeTaskResource;
use Filament\Resources\Pages\ManageRecords;

class ManageProbeTasks extends ManageRecords
{
    protected static string $resource = ProbeTaskResource::class;

    protected function getHeaderActions(): array
    {
        return [];
    }
}
