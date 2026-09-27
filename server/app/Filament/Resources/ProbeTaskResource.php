<?php

namespace App\Filament\Resources;

use App\Models\ProbeTask;
use App\Support\Labels;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Model;

class ProbeTaskResource extends MonitorResource
{
    protected static ?string $model = ProbeTask::class;

    protected static ?string $modelLabel = '网站探测任务';

    protected static ?string $pluralModelLabel = '网站探测任务';

    protected static ?int $navigationSort = 8;

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
        return $t->defaultSort('id', 'desc')->columns([TextColumn::make('website.ipAsset.ip')->label('公网 IP')->searchable(), TextColumn::make('website.host')->label('域名'), TextColumn::make('website.port')->label('端口'), TextColumn::make('status')->formatStateUsing(fn ($state) => Labels::get($state))->label('状态')->badge(), TextColumn::make('attempts')->label('尝试次数'), TextColumn::make('last_error')->label('错误')->limit(60)])->recordActions([static::detailAction()]);
    }

    public static function getPages(): array
    {
        return ['index' => ProbeTaskResource\Pages\ManageProbeTasks::route('/')];
    }
}
