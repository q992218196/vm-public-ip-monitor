<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public $withinTransaction = false;

    public function up(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            foreach ([
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_recent_idx ON alerts (last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_status_recent_idx ON alerts (status, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_node_recent_idx ON alerts (node_id, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_asset_recent_idx ON alerts (ip_asset_id, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_severity_recent_idx ON alerts (severity, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_recent_idx ON websites (last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_status_recent_idx ON websites (status, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_asset_recent_idx ON websites (ip_asset_id, last_seen_at DESC, id DESC)',
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_host_idx ON websites (host varchar_pattern_ops)',
            ] as $statement) {
                DB::statement($statement);
            }

            return;
        }
        Schema::table('alerts', function (Blueprint $table): void {
            $table->index(['last_seen_at', 'id'], 'alerts_recent_idx');
            $table->index(['status', 'last_seen_at', 'id'], 'alerts_status_recent_idx');
            $table->index(['node_id', 'last_seen_at', 'id'], 'alerts_node_recent_idx');
            $table->index(['ip_asset_id', 'last_seen_at', 'id'], 'alerts_asset_recent_idx');
            $table->index(['severity', 'last_seen_at', 'id'], 'alerts_severity_recent_idx');
        });
        Schema::table('websites', function (Blueprint $table): void {
            $table->index(['last_seen_at', 'id'], 'websites_recent_idx');
            $table->index(['status', 'last_seen_at', 'id'], 'websites_status_recent_idx');
            $table->index(['ip_asset_id', 'last_seen_at', 'id'], 'websites_asset_recent_idx');
            $table->index('host', 'websites_host_idx');
        });
    }

    public function down(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            foreach (['alerts_recent_idx', 'alerts_status_recent_idx', 'alerts_node_recent_idx', 'alerts_asset_recent_idx', 'alerts_severity_recent_idx', 'websites_recent_idx', 'websites_status_recent_idx', 'websites_asset_recent_idx', 'websites_host_idx'] as $index) {
                DB::statement('DROP INDEX CONCURRENTLY IF EXISTS '.$index);
            }

            return;
        }
        Schema::table('alerts', function (Blueprint $table): void {
            $table->dropIndex('alerts_recent_idx');
            $table->dropIndex('alerts_status_recent_idx');
            $table->dropIndex('alerts_node_recent_idx');
            $table->dropIndex('alerts_asset_recent_idx');
            $table->dropIndex('alerts_severity_recent_idx');
        });
        Schema::table('websites', function (Blueprint $table): void {
            $table->dropIndex('websites_recent_idx');
            $table->dropIndex('websites_status_recent_idx');
            $table->dropIndex('websites_asset_recent_idx');
            $table->dropIndex('websites_host_idx');
        });
    }
};
