<?php

namespace App\Filament\Resources\ExclusionResource\Pages;

use App\Filament\Resources\ExclusionResource;
use Filament\Actions\CreateAction;
use Filament\Resources\Pages\ManageRecords;

class ManageExclusions extends ManageRecords
{
    protected static string $resource = ExclusionResource::class;

    protected function getHeaderActions(): array
    {
        return [CreateAction::make()];
    }
}
