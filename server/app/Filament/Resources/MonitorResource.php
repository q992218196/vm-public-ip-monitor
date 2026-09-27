<?php

namespace App\Filament\Resources;

use Filament\Actions\Action;
use Filament\Resources\Resource;
use Illuminate\Database\Eloquent\Model;

abstract class MonitorResource extends Resource
{
    public static function canViewAny(): bool
    {
        return in_array(auth()->user()?->role, ['admin', 'viewer']);
    }

    public static function canCreate(): bool
    {
        return auth()->user()?->role === 'admin';
    }

    public static function canEdit(Model $record): bool
    {
        return auth()->user()?->role === 'admin';
    }

    public static function canDelete(Model $record): bool
    {
        return false;
    }

    public static function canDeleteAny(): bool
    {
        return false;
    }

    protected static function detailAction(): Action
    {
        return Action::make('detail')->label('详情')->modalHeading('记录与证据')->modalContent(fn (Model $record) => view('monitor.record', ['data' => $record->toArray()]))->modalSubmitAction(false);
    }
}
