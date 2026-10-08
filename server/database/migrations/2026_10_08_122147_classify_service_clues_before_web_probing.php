<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('websites', function (Blueprint $table): void {
            $table->string('discovery_kind', 24)->default('web_candidate')->index();
        });
        Schema::table('probe_tasks', function (Blueprint $table): void {
            $table->string('request_source', 16)->default('legacy');
        });
        DB::table('probe_tasks')->where('status', 'pending')->whereExists(function ($query): void {
            $query->selectRaw('1')->from('audit_logs')->where('action', 'probe_queued')
                ->whereRaw("audit_logs.subject = 'Website:' || CAST(probe_tasks.website_id AS TEXT)")
                ->whereColumn('audit_logs.created_at', '>=', 'probe_tasks.created_at');
        })->update(['request_source' => 'manual']);
        DB::table('websites')->where('port', 3389)->where('scheme', 'https')->where('source', 'tls_sni')
            ->where('status', '<>', 'verified')->whereNull('http_status')->whereNull('manual_category')->whereNull('screenshot_path')
            ->where('ownership_status', '<>', 'manual')->update(['discovery_kind' => 'tls_unknown']);
        DB::table('probe_tasks')->where('status', 'pending')->where('mode', 'normal')->where('request_source', '<>', 'manual')
            ->whereIn('website_id', DB::table('websites')->select('id')->where('discovery_kind', 'tls_unknown'))
            ->update(['status' => 'skipped', 'lease_token' => null, 'leased_until' => null, 'last_error' => '3389 仅有 TLS 线索，不自动探测；需要时可手动验证', 'updated_at' => now()]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('probe_tasks', fn (Blueprint $table) => $table->dropColumn('request_source'));
        Schema::table('websites', function (Blueprint $table): void {
            $table->dropIndex('websites_discovery_kind_index');
            $table->dropColumn('discovery_kind');
        });
    }
};
