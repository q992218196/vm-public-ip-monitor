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
        Schema::table('monitor_events', function (Blueprint $table) {
            $table->json('behavior')->nullable();
            $table->json('review_context')->nullable();
            $table->text('reopen_reason')->nullable();
            $table->string('assessment_category', 32)->default('needs_review');
            $table->index(['assessment_category', 'status', 'last_seen_at'], 'events_category_status_time');
        });
        Schema::table('alerts', fn (Blueprint $table) => $table->string('assessment_category', 32)->default('needs_review'));
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('monitor_events', function (Blueprint $table) {
            $table->dropIndex('events_category_status_time');
            $table->dropColumn(['behavior', 'review_context', 'reopen_reason', 'assessment_category']);
        });
        Schema::table('alerts', fn (Blueprint $table) => $table->dropColumn('assessment_category'));
    }
};
