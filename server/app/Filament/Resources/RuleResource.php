<?php

namespace App\Filament\Resources;

use App\Models\Rule;
use App\Support\Labels;
use Filament\Actions\EditAction;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class RuleResource extends MonitorResource
{
    protected static ?string $model = Rule::class;

    protected static ?string $modelLabel = '检测规则';

    protected static ?string $pluralModelLabel = '检测规则';

    protected static ?int $navigationSort = 5;

    public static function form(Schema $s): Schema
    {
        return $s->components([TextInput::make('name')->label('规则名称')->required()->maxLength(100), Select::make('kind')->label('检测类型')->options(['horizontal_scan' => '横向扫描', 'vertical_scan' => '端口扫描', 'suspected_bruteforce' => '疑似爆破', 'egress_mbps' => '出站 Mbps'])->required(), TextInput::make('threshold')->label('阈值')->numeric()->minValue(1)->required(), TextInput::make('window_seconds')->label('评估窗口秒')->numeric()->minValue(30)->maxValue(3600)->default(60)->required(), TextInput::make('cooldown_seconds')->label('告警合并窗口秒')->numeric()->minValue(60)->maxValue(86400)->default(600)->required(), Select::make('severity')->label('级别')->options(['low' => '低', 'medium' => '中', 'high' => '高'])->default('medium')->required(), Select::make('node_id')->label('适用节点，留空为全部')->relationship('node', 'name')->searchable(), Toggle::make('enabled')->label('启用')->default(true)]);
    }

    public static function table(Table $t): Table
    {
        return $t->defaultSort('id', 'desc')->columns([TextColumn::make('name')->label('规则')->searchable(), TextColumn::make('kind')->formatStateUsing(fn ($state) => Labels::get($state))->label('类型'), TextColumn::make('threshold')->label('阈值'), TextColumn::make('window_seconds')->label('窗口秒'), TextColumn::make('node.name')->label('节点')->placeholder('全部'), IconColumn::make('enabled')->label('启用')->boolean()])->recordActions([static::detailAction(), EditAction::make()]);
    }

    public static function getPages(): array
    {
        return ['index' => RuleResource\Pages\ManageRules::route('/')];
    }
}
