<?php

namespace App\Filament\Resources;

use App\Models\IpAsset;
use Filament\Actions\Action;
use Filament\Actions\EditAction;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class IpAssetResource extends MonitorResource
{
    protected static ?string $model = IpAsset::class;

    protected static ?string $modelLabel = '公网 IP';

    protected static ?string $pluralModelLabel = '公网 IP';

    protected static ?int $navigationSort = 2;

    public static function canCreate(): bool
    {
        return false;
    }

    public static function form(Schema $s): Schema
    {
        return $s->components([TextInput::make('ip')->disabled(), TextInput::make('label')->label('归属标签')->maxLength(255), Textarea::make('notes')->label('查询备注')->maxLength(4000)]);
    }

    public static function table(Table $t): Table
    {
        return $t->columns([
            TextColumn::make('ip')->label('公网 IP')->searchable()->copyable(), TextColumn::make('version')->label('版本'), TextColumn::make('label')->label('标签')->searchable(), TextColumn::make('nodes.name')->label('观察节点')->badge(), TextColumn::make('websites_count')->counts('websites')->label('网站数'), TextColumn::make('last_seen_at')->label('最后观察')->dateTime()->timezone(config('monitor.display_timezone')),
        ])->headerActions([Action::make('export')->label('导出 IP')->url(route('exports', 'ips'))])->recordActions([static::detailAction(), EditAction::make()]);
    }

    public static function getPages(): array
    {
        return ['index' => IpAssetResource\Pages\ManageIpAssets::route('/')];
    }
}
