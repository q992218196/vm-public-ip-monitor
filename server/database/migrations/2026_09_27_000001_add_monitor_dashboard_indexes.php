<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('alerts', function (Blueprint $table) {
            $table->index(['status', 'last_seen_at'], 'alerts_status_last_seen');
            $table->index(['node_id', 'last_seen_at'], 'alerts_node_last_seen');
            $table->index(['severity', 'last_seen_at'], 'alerts_severity_last_seen');
            $table->index(['ip_asset_id', 'last_seen_at'], 'alerts_ip_last_seen');
        });
        Schema::table('websites', fn (Blueprint $table) => $table->index(['last_probed_at', 'status'], 'websites_probe_status'));
    }

    public function down(): void
    {
        Schema::table('websites', fn (Blueprint $table) => $table->dropIndex('websites_probe_status'));
        Schema::table('alerts', function (Blueprint $table) {
            $table->dropIndex('alerts_status_last_seen');
            $table->dropIndex('alerts_node_last_seen');
            $table->dropIndex('alerts_severity_last_seen');
            $table->dropIndex('alerts_ip_last_seen');
        });
    }
};
