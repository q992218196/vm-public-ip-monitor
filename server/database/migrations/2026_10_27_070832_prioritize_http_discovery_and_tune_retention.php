<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public $withinTransaction = false;

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            DB::statement('ALTER TABLE traffic_metrics SET (autovacuum_vacuum_scale_factor=0.02, autovacuum_vacuum_threshold=5000, autovacuum_analyze_scale_factor=0.02, autovacuum_analyze_threshold=5000)');
            DB::statement('ALTER TABLE websites SET (autovacuum_vacuum_scale_factor=0.02, autovacuum_vacuum_threshold=1000, autovacuum_analyze_scale_factor=0.02, autovacuum_analyze_threshold=1000)');
        }
        $candidates = DB::table('websites')->whereIn('source', ['tls_sni', 'tls_alpn'])->where('discovery_kind', 'web_candidate')
            ->where(fn (Builder $query) => $query->whereNull('status')->orWhere('status', '<>', 'verified'))
            ->where(fn (Builder $query) => $query->whereNull('ownership_status')->orWhere('ownership_status', '<>', 'manual'))
            ->whereNull('http_status')->whereNull('manual_category')->whereNull('screenshot_path');
        (clone $candidates)->select('id')->chunkById(1000, function ($rows) use ($candidates): void {
            $ids = $rows->pluck('id');
            (clone $candidates)->whereIn('id', $ids)->update(['discovery_kind' => 'tls_unknown']);
            DB::table('probe_tasks')->whereIn('website_id', DB::table('websites')->select('id')->whereIn('id', $ids)->where('discovery_kind', 'tls_unknown'))
                ->where('status', 'pending')->where('mode', 'normal')
                ->whereIn('request_source', ['auto', 'legacy'])->update(['status' => 'skipped', 'lease_token' => null, 'leased_until' => null,
                    'last_error' => '仅有 TLS 线索，已移出自动网页验证队列；可手动验证', 'updated_at' => now()]);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            foreach (['traffic_metrics', 'websites'] as $table) {
                DB::statement('ALTER TABLE '.$table.' RESET (autovacuum_vacuum_scale_factor,autovacuum_vacuum_threshold,autovacuum_analyze_scale_factor,autovacuum_analyze_threshold)');
            }
        }
        DB::table('websites')->whereIn('source', ['tls_sni', 'tls_alpn'])->where('discovery_kind', 'tls_unknown')
            ->where(fn (Builder $query) => $query->where('source', 'tls_alpn')->orWhere('port', '<>', 3389))
            ->update(['discovery_kind' => 'web_candidate']);
    }
};
