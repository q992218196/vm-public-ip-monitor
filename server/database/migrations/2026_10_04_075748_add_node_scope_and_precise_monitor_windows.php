<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('rules', function (Blueprint $table) {
            $table->json('node_ids')->nullable();
        });
        foreach (['batches', 'traffic_metrics'] as $name) {
            Schema::table($name, function (Blueprint $table) {
                $table->timestamp('window_start', 6)->change();
                $table->timestamp('window_end', 6)->change();
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('rules', function (Blueprint $table) {
            $table->dropColumn('node_ids');
        });
        // Retain recorded microseconds: narrowing on rollback would destroy window evidence.
    }
};
