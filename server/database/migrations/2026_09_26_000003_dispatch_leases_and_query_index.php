<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('batches', fn (Blueprint $t) => $t->timestamp('dispatched_at')->nullable()->index());
        Schema::table('traffic_metrics', fn (Blueprint $t) => $t->index(['node_id', 'ip_asset_id', 'window_end'], 'metrics_node_ip_time'));
    }

    public function down(): void
    {
        Schema::table('traffic_metrics', fn (Blueprint $t) => $t->dropIndex('metrics_node_ip_time'));
        Schema::table('batches', fn (Blueprint $t) => $t->dropColumn('dispatched_at'));
    }
};
