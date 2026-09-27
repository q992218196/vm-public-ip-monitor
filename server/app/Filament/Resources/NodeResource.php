<?php

namespace App\Filament\Resources;

use App\Models\AuditLog;
use App\Models\Node;
use App\Support\Ip;
use Filament\Actions\Action;
use Filament\Actions\EditAction;
use Filament\Forms\Components\TagsInput;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class NodeResource extends MonitorResource
{
    protected static ?string $model = Node::class;

    protected static ?string $modelLabel = '采集节点';

    protected static ?string $pluralModelLabel = '采集节点';

    protected static ?int $navigationSort = 1;

    public static function form(Schema $s): Schema
    {
        return $s->components([
            TextInput::make('name')->label('节点名称')->required()->maxLength(100), Toggle::make('enabled')->label('允许上报')->default(true),
            TagsInput::make('cidrs')->label('公网 CIDR 范围')->required()->nestedRecursiveRules([fn () => function ($attribute, $value, $fail) {
                if (! Ip::validCidr($value)) {
                    $fail('CIDR 格式无效');
                }
            }])->helperText('允许与其他节点重复；不是归属声明。'),
            TagsInput::make('settings.interfaces')->label('采集接口')->default(['monitor0'])->required(),
            TextInput::make('settings.memory_soft_mib')->label('工作内存 MiB')->numeric()->minValue(128)->maxValue(32768)->default(2048),
            TextInput::make('settings.memory_hard_mib')->label('服务硬限额 MiB')->numeric()->minValue(256)->maxValue(65536)->default(4096)->helperText('安装器应用；修改后需重新部署。'),
            TextInput::make('settings.disk_limit_mib')->label('Agent 目录预算 MiB')->numeric()->minValue(640)->maxValue(1048576)->default(2048),
            TextInput::make('settings.data_dir')->label('Agent 数据目录')->default('/home/vm-monitor')->required()->regex('#^/[a-zA-Z0-9/_-]+$#'),
            Textarea::make('notes')->label('备注')->maxLength(4000),
        ]);
    }

    public static function table(Table $t): Table
    {
        return $t->columns([
            TextColumn::make('name')->label('节点')->searchable(), TextColumn::make('id')->label('节点 ID')->copyable()->toggleable(), IconColumn::make('enabled')->label('启用')->boolean(),
            TextColumn::make('cidrs')->label('CIDR')->listWithLineBreaks()->limitList(3), TextColumn::make('last_seen_at')->label('最近上报')->since()->placeholder('尚未接入'),
            TextColumn::make('health.rss_bytes')->label('进程内存')->formatStateUsing(fn ($state) => round($state / 1048576).' MiB'), TextColumn::make('health.kernel_drops')->label('窗口丢包')->numeric(),
        ])->recordActions([static::detailAction(), EditAction::make(), Action::make('config')->label('下载接入配置')->visible(fn () => auth()->user()?->role === 'admin')->requiresConfirmation()->modalDescription('生成新凭据并撤销旧凭据。下载文件包含密钥，请以 0600 权限保存。')->action(function (Node $record) {
            abort_unless(auth()->user()?->role === 'admin', 403);
            $token = bin2hex(random_bytes(32));
            $record->update(['token_hash' => hash('sha256', $token)]);
            AuditLog::record('token_rotated', $record);
            $s = $record->settings ?? [];
            $data = ['node_id' => $record->id, 'server_url' => rtrim(config('app.url'), '/'), 'token' => $token, 'interfaces' => $s['interfaces'] ?? ['monitor0'], 'cidrs' => $record->cidrs, 'data_dir' => $s['data_dir'] ?? '/home/vm-monitor', 'memory_soft_mib' => (int) ($s['memory_soft_mib'] ?? 2048), 'memory_hard_mib' => (int) ($s['memory_hard_mib'] ?? 4096), 'disk_limit_mib' => (int) ($s['disk_limit_mib'] ?? 2048), 'spool_limit_mib' => 512, 'capture_buffer_mib' => 16, 'flush_seconds' => 30, 'max_ips' => 4096, 'max_flows' => 50000, 'max_reassembly' => 2048, 'max_sites' => 4096, 'allow_http_localhost' => false];

            return response()->streamDownload(fn () => print (json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)), 'agent.json');
        })]);
    }

    public static function getPages(): array
    {
        return ['index' => NodeResource\Pages\ManageNodes::route('/')];
    }
}
