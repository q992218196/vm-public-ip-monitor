<?php

namespace App\Filament\Resources;

use App\Models\TrafficMetric;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Model;

class TrafficMetricResource extends MonitorResource
{
    protected static ?string $model = TrafficMetric::class;

    protected static ?string $modelLabel = '流量窗口';

    protected static ?string $pluralModelLabel = '流量窗口';

    protected static ?int $navigationSort = 7;

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
        return $t->defaultSort('id', 'desc')->columns([TextColumn::make('ipAsset.ip')->label('公网 IP')->searchable(), TextColumn::make('node.name')->label('观察节点'), TextColumn::make('bytes_out')->label('出站字节')->numeric(), TextColumn::make('bytes_in')->label('入站字节')->numeric(), TextColumn::make('tcp_attempts')->label('TCP 发起次数')->numeric(), TextColumn::make('window_end')->label('窗口结束')->dateTime()->timezone(config('monitor.display_timezone'))])->recordActions([static::detailAction()]);
    }

    public static function getPages(): array
    {
        return ['index' => TrafficMetricResource\Pages\ManageTrafficMetrics::route('/')];
    }
}
