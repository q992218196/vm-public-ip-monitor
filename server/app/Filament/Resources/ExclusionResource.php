<?php

namespace App\Filament\Resources;

use App\Models\Exclusion;
use App\Support\Ip;
use Filament\Actions\EditAction;
use Filament\Forms\Components\DateTimePicker;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class ExclusionResource extends MonitorResource
{
    protected static ?string $model = Exclusion::class;

    protected static ?string $modelLabel = '维护与白名单';

    protected static ?string $pluralModelLabel = '维护与白名单';

    protected static ?int $navigationSort = 6;

    public static function form(Schema $s): Schema
    {
        return $s->components([TextInput::make('cidr')->label('源公网 IP/CIDR')->required()->rules([fn () => function ($attribute, $value, $fail) {
            if (! Ip::validCidr($value)) {
                $fail('请输入 CIDR，例如 /32 或 /128');
            }
        }]), TextInput::make('reason')->label('原因')->required()->maxLength(255), DateTimePicker::make('expires_at')->label('失效时间')->required(), Select::make('node_id')->label('适用节点，留空为全部')->relationship('node', 'name')->searchable()]);
    }

    public static function table(Table $t): Table
    {
        return $t->defaultSort('id', 'desc')->columns([TextColumn::make('cidr')->label('CIDR')->searchable(), TextColumn::make('reason')->label('原因'), TextColumn::make('node.name')->label('节点')->placeholder('全部'), TextColumn::make('expires_at')->label('失效时间')->dateTime()->timezone(config('monitor.display_timezone'))])->recordActions([static::detailAction(), EditAction::make()]);
    }

    public static function getPages(): array
    {
        return ['index' => ExclusionResource\Pages\ManageExclusions::route('/')];
    }
}
