<?php

namespace App\Filament\Resources;

use App\Models\AuditLog;
use App\Models\IpAsset;
use App\Models\Website;
use App\Services\ProbeQueue;
use App\Support\Labels;
use Filament\Actions\Action;
use Filament\Actions\EditAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class WebsiteResource extends MonitorResource
{
    protected static ?string $model = Website::class;

    protected static ?string $modelLabel = '网站资产';

    protected static ?string $pluralModelLabel = '网站资产';

    protected static ?int $navigationSort = 3;

    public static function canCreate(): bool
    {
        return false;
    }

    public static function form(Schema $s): Schema
    {
        return $s->components([TextInput::make('host')->disabled(), TextInput::make('manual_category')->label('人工分类')->maxLength(64)->helperText('保留自动分类证据，以人工分类为准。')]);
    }

    public static function table(Table $t): Table
    {
        return $t->columns([
            TextColumn::make('ipAsset.ip')->label('公网 IP')->searchable()->copyable(), TextColumn::make('host')->label('域名线索')->searchable()->placeholder('仅 IP'), TextColumn::make('port')->label('端口')->sortable(), TextColumn::make('scheme')->label('协议'), TextColumn::make('status')->formatStateUsing(fn ($state) => Labels::get($state))->label('验证状态')->badge(), TextColumn::make('title')->label('标题')->searchable()->limit(30), TextColumn::make('category')->label('自动分类')->badge(), TextColumn::make('manual_category')->label('人工分类'), TextColumn::make('last_probed_at')->label('最近验证')->since(),
        ])->headerActions([Action::make('add')->label('添加已知 IP 网站')->visible(fn () => auth()->user()?->role === 'admin')->schema([
            Select::make('ip_asset_id')->label('已发现的公网 IP')->options(fn () => IpAsset::limit(1000)->pluck('ip', 'id'))->searchable()->getSearchResultsUsing(fn (string $search) => IpAsset::where('ip', 'like', '%'.$search.'%')->limit(50)->pluck('ip', 'id'))->required(), TextInput::make('port')->label('端口')->numeric()->minValue(1)->maxValue(65535)->required(), Select::make('scheme')->options(['http' => 'HTTP', 'https' => 'HTTPS'])->required(), TextInput::make('host')->label('域名（可留空）')->maxLength(253)->regex('/^[a-zA-Z0-9.\-]*$/'),
        ])->action(function (array $data) {
            abort_unless(auth()->user()?->role === 'admin', 403);
            $asset = IpAsset::findOrFail($data['ip_asset_id']);
            $host = strtolower(rtrim($data['host'] ?? '', '.'));
            $key = hash('sha256', implode('|', [$asset->ip, $data['port'], $data['scheme'], $host]));
            $site = Website::firstOrCreate(['fingerprint' => $key], ['ip_asset_id' => $asset->id, 'host' => $host, 'port' => $data['port'], 'scheme' => $data['scheme'], 'source' => 'manual', 'first_seen_at' => now(), 'last_seen_at' => now()]);
            app(ProbeQueue::class)->enqueue($site);
        })])->recordActions([
            static::detailAction(), EditAction::make(), Action::make('probe')->label('验证／截图')->visible(fn () => auth()->user()?->role === 'admin')->action(function (Website $record) {
                abort_unless(auth()->user()?->role === 'admin', 403);
                app(ProbeQueue::class)->enqueue($record);
                AuditLog::record('probe_queued', $record);
            }), Action::make('screenshot')->label('查看截图')->url(fn (Website $record) => route('screenshots.show', $record))->openUrlInNewTab()->visible(fn (Website $record) => (bool) $record->screenshot_path),
        ]);
    }

    public static function getPages(): array
    {
        return ['index' => WebsiteResource\Pages\ManageWebsites::route('/')];
    }
}
