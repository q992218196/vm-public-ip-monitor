<?php

namespace App\Providers;

use App\Models\Alert;
use App\Models\AuditLog;
use App\Models\Exclusion;
use App\Models\IpAsset;
use App\Models\Node;
use App\Models\Rule;
use App\Models\Website;
use Filament\Forms\Components\Select;
use Filament\Tables\Columns\SelectColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Select::configureUsing(fn (Select $select) => $select->native(false));
        SelectFilter::configureUsing(fn (SelectFilter $filter) => $filter->native(false));
        SelectColumn::configureUsing(fn (SelectColumn $column) => $column->native(false));
        Table::configureUsing(fn (Table $table) => $table
            ->stackedOnMobile()
            ->paginationPageOptions([10, 25, 50, 100, 200, 500])
            ->defaultPaginationPageOption(25));
        if (app()->environment('production') && str_starts_with(config('app.url'), 'https://')) {
            URL::forceScheme('https');
        }
        RateLimiter::for('agent', fn (Request $r) => Limit::perMinute(120)->by($r->attributes->get('node')?->id ?? $r->ip()));
        RateLimiter::for('worker', fn () => Limit::perMinute(600)->by('workers'));
        foreach ([Node::class, Rule::class, Exclusion::class, IpAsset::class, Website::class, Alert::class] as $model) {
            $model::saved(function ($record) {
                if (auth()->check()) {
                    AuditLog::record($record->wasRecentlyCreated ? 'created' : 'updated', $record, ['fields' => array_values(array_diff(array_keys($record->getChanges()), ['token_hash']))]);
                }
            });
        }
    }
}
