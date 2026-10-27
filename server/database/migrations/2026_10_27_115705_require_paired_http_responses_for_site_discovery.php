<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public $withinTransaction = false;

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (! Schema::hasColumn('websites', 'observed_http_status')) {
            Schema::table('websites', fn (Blueprint $table) => $table->unsignedSmallInteger('observed_http_status')->nullable());
        }
        if (! Schema::hasColumn('websites', 'observed_http_at')) {
            Schema::table('websites', fn (Blueprint $table) => $table->timestamp('observed_http_at')->nullable());
        }
        $candidates = DB::table('websites')->where('source', 'http_host')->where('discovery_kind', 'web_candidate')
            ->where(fn (Builder $query) => $query->whereNull('status')->orWhere('status', '<>', 'verified'))
            ->where(fn (Builder $query) => $query->whereNull('ownership_status')->orWhere('ownership_status', '<>', 'manual'))
            ->whereNull('http_status')->whereNull('manual_category')->whereNull('screenshot_path');
        (clone $candidates)->select('id')->chunkById(1000, function ($rows) use ($candidates): void {
            $ids = $rows->pluck('id');
            (clone $candidates)->whereIn('id', $ids)->update(['discovery_kind' => 'http_request']);
        });
        $tasks = DB::table('probe_tasks')->where('status', 'pending')->where('mode', 'normal')->whereIn('request_source', ['auto', 'legacy'])
            ->whereIn('website_id', DB::table('websites')->select('id')->where('discovery_kind', 'http_request'));
        (clone $tasks)->select('id')->chunkById(1000, function ($rows) use ($tasks): void {
            (clone $tasks)->whereIn('id', $rows->pluck('id'))
                ->update(['status' => 'skipped', 'lease_token' => null, 'leased_until' => null, 'last_error' => '仅观察到客户端 HTTP 请求，未见服务端响应；不自动验证', 'updated_at' => now()]);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        DB::table('websites')->where('source', 'http_host')->where('discovery_kind', 'http_request')->update(['discovery_kind' => 'web_candidate']);
        Schema::table('websites', fn (Blueprint $table) => $table->dropColumn(['observed_http_status', 'observed_http_at']));
    }
};
