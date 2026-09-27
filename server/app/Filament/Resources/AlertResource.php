<?php

namespace App\Filament\Resources;

use App\Models\Alert;
use App\Models\AuditLog;
use App\Support\Labels;
use Filament\Actions\Action;
use Filament\Actions\BulkAction;
use Filament\Actions\EditAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

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
        return $t->defaultSort('last_seen_at', 'desc')->selectCurrentPageOnly()->maxSelectableRecords(500)
            ->modifyQueryUsing(fn (Builder $query, bool $isResolvingRecord): Builder => $isResolvingRecord ? $query : $query->select(['id', 'node_id', 'ip_asset_id', 'kind', 'title', 'severity', 'status', 'occurrences', 'last_seen_at']))
            ->columns([
            TextColumn::make('title')->label('告警')->searchable(), TextColumn::make('ipAsset.ip')->label('公网 IP')->searchable()->copyable(), TextColumn::make('node.name')->label('观察节点'), TextColumn::make('severity')->formatStateUsing(fn ($state) => Labels::get($state))->label('级别')->badge()->color(fn (string $state) => match ($state) {
                'high' => 'danger','medium' => 'warning',default => 'info'
            }), TextColumn::make('status')->formatStateUsing(fn ($state) => Labels::get($state))->label('状态')->badge()->color(fn (string $state) => match ($state) {
                'open' => 'danger', 'acknowledged' => 'warning', 'resolved' => 'success', default => 'gray',
            }), TextColumn::make('occurrences')->label('次数'), TextColumn::make('last_seen_at')->label('最后触发')->dateTime()->timezone(config('monitor.display_timezone')),
        ])->filters([
            SelectFilter::make('status')->label('处理状态')->options(['open' => '待处理', 'acknowledged' => '已确认', 'resolved' => '已解决']),
            SelectFilter::make('node_id')->label('节点')->relationship('node', 'name')->searchable()->preload(),
            Filter::make('ip')->label('公网 IP')->schema([TextInput::make('ip')->label('公网 IP')->placeholder('输入完整 IPv4 或 IPv6 地址')])
                ->query(fn (Builder $query, array $data): Builder => $query->when(filled($data['ip'] ?? null), fn (Builder $query): Builder => $query->whereHas('ipAsset', fn (Builder $asset): Builder => $asset->where('ip', trim($data['ip']))))),
            SelectFilter::make('severity')->label('级别')->options(['high' => '高', 'medium' => '中', 'low' => '低']),
        ])->headerActions([Action::make('export')->label('导出告警')->url(route('exports', 'alerts'))])->recordActions([
            Action::make('detail')->label('详情')->url(fn (Alert $record): string => route('alerts.evidence', $record))->openUrlInNewTab(),
            EditAction::make()->label('处理'),
        ])->toolbarActions([
            BulkAction::make('handle')->label('批量处理')->visible(fn () => auth()->user()?->role === 'admin')->schema([
                Select::make('status')->label('处理状态')->options(['acknowledged' => '已确认', 'resolved' => '已解决', 'open' => '重新打开'])->required(),
                Textarea::make('resolution')->label('处理记录')->maxLength(4000)->required(),
            ])->requiresConfirmation()->action(function (Collection $records, array $data): void {
                abort_unless(auth()->user()?->role === 'admin', 403);
                $ids = $records->pluck('id')->all();
                abort_if(count($ids) > 500, 422);
                DB::transaction(function () use ($ids, $data): void {
                    Alert::whereKey($ids)->update(['status' => $data['status'], 'resolution' => $data['resolution']]);
                    AuditLog::create(['user_id' => auth()->id(), 'action' => 'alerts_bulk_handled', 'subject' => 'Alert:batch', 'details' => ['ids' => $ids, 'status' => $data['status'], 'resolution' => $data['resolution']]]);
                });
            })->deselectRecordsAfterCompletion(),
        ]);
    }

    public static function getPages(): array
    {
        return ['index' => AlertResource\Pages\ManageAlerts::route('/')];
    }
}
