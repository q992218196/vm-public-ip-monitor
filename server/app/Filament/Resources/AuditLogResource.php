<?php

namespace App\Filament\Resources;

use App\Models\AuditLog;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Model;

class AuditLogResource extends MonitorResource
{
    protected static ?string $model = AuditLog::class;

    protected static ?string $modelLabel = '操作审计';

    protected static ?string $pluralModelLabel = '操作审计';

    protected static ?int $navigationSort = 9;

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canEdit(Model $record): bool
    {
        return false;
    }

    public static function form(Schema $s): Schema
    {
        return $s->components([]);
    }

    public static function table(Table $t): Table
    {
        return $t->defaultSort('id', 'desc')->columns([TextColumn::make('user.email')->label('用户'), TextColumn::make('action')->label('操作')->searchable(), TextColumn::make('subject')->label('对象')->searchable(), TextColumn::make('created_at')->label('时间')->dateTime()->timezone(config('monitor.display_timezone'))])->recordActions([static::detailAction()]);
    }

    public static function getPages(): array
    {
        return ['index' => AuditLogResource\Pages\ManageAuditLogs::route('/')];
    }
}
