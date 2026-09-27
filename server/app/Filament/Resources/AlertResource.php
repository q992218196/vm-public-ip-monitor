<?php

namespace App\Filament\Resources;

use App\Models\Alert;
use App\Support\Labels;
use Filament\Actions\Action;
use Filament\Actions\EditAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;

class AlertResource extends MonitorResource
{
    protected static ?string $model = Alert::class;

    protected static ?string $modelLabel = '告警';

    protected static ?string $pluralModelLabel = '告警中心';

    protected static ?int $navigationSort = 4;

    public static function canCreate(): bool
    {
        return false;
    }

    public static function form(Schema $s): Schema
    {
        return $s->components([Select::make('status')->label('处理状态')->options(['open' => '待处理', 'acknowledged' => '已确认', 'resolved' => '已解决'])->required(), Textarea::make('resolution')->label('处理记录')->maxLength(4000)]);
    }

    public static function table(Table $t): Table
    {
        return $t->defaultSort('last_seen_at', 'desc')->columns([
            TextColumn::make('title')->label('告警')->searchable(), TextColumn::make('ipAsset.ip')->label('公网 IP')->searchable()->copyable(), TextColumn::make('node.name')->label('观察节点'), TextColumn::make('severity')->formatStateUsing(fn ($state) => Labels::get($state))->label('级别')->badge()->color(fn (string $state) => match ($state) {
                'high' => 'danger','medium' => 'warning',default => 'info'
            }), TextColumn::make('status')->formatStateUsing(fn ($state) => Labels::get($state))->label('状态')->badge(), TextColumn::make('occurrences')->label('次数'), TextColumn::make('last_seen_at')->label('最后触发')->dateTime()->timezone(config('monitor.display_timezone')),
        ])->filters([SelectFilter::make('status')->label('处理状态')->options(['open' => '待处理', 'acknowledged' => '已确认', 'resolved' => '已解决'])])->headerActions([Action::make('export')->label('导出告警')->url(route('exports', 'alerts'))])->recordActions([static::detailAction(), EditAction::make()->label('处理')]);
    }

    public static function getPages(): array
    {
        return ['index' => AlertResource\Pages\ManageAlerts::route('/')];
    }
}
