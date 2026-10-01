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
        Schema::create('monitor_events', function (Blueprint $table) {
            $table->id();
            $table->foreignUuid('node_id')->constrained('nodes')->cascadeOnDelete();
            $table->foreignId('ip_asset_id')->nullable()->constrained('ip_assets')->nullOnDelete();
            $table->string('active_key', 64)->nullable()->unique();
            $table->string('title');
            $table->string('severity', 16);
            $table->string('status', 24)->default('open');
            $table->json('kinds');
            $table->json('quality')->nullable();
            $table->unsignedBigInteger('occurrences')->default(1);
            $table->text('review_notes')->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at')->index();
            $table->timestamps();
            $table->index(['node_id', 'ip_asset_id', 'status']);
            $table->index(['status', 'last_seen_at', 'id']);
        });
        Schema::table('alerts', function (Blueprint $table) {
            $table->foreignId('event_id')->nullable()->constrained('monitor_events')->nullOnDelete();
            $table->index(['event_id', 'kind', 'id']);
        });
        Schema::create('packet_captures', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('event_id')->constrained('monitor_events')->cascadeOnDelete();
            $table->foreignUuid('node_id')->constrained('nodes')->cascadeOnDelete();
            $table->string('ip', 45);
            $table->string('status', 24)->default('pending')->index();
            $table->string('source', 16)->default('manual');
            $table->string('lease_token', 64)->nullable();
            $table->timestamp('lease_until')->nullable();
            $table->unsignedInteger('duration_seconds')->default(60);
            $table->unsignedInteger('max_bytes')->default(33554432);
            $table->unsignedInteger('snaplen')->default(2048);
            $table->string('path')->nullable();
            $table->string('sha256', 64)->nullable();
            $table->unsignedBigInteger('bytes')->default(0);
            $table->json('metadata')->nullable();
            $table->json('summary')->nullable();
            $table->string('last_error')->nullable();
            $table->timestamps();
            $table->index(['node_id', 'status', 'created_at']);
            $table->index(['event_id', 'created_at']);
        });
        Schema::create('ai_settings', function (Blueprint $table) {
            $table->unsignedInteger('id')->primary();
            $table->string('endpoint')->default('https://api.deepseek.com/chat/completions');
            $table->string('model')->default('deepseek-flash');
            $table->text('api_key_cipher')->nullable();
            $table->boolean('enabled')->default(false);
            $table->timestamps();
        });
        Schema::create('ai_analyses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('event_id')->constrained('monitor_events')->cascadeOnDelete();
            $table->foreignUuid('capture_id')->constrained('packet_captures')->cascadeOnDelete();
            $table->unsignedBigInteger('requested_by');
            $table->string('status', 24)->default('pending')->index();
            $table->json('config_snapshot');
            $table->json('evidence')->nullable();
            $table->text('report')->nullable();
            $table->json('usage')->nullable();
            $table->string('last_error')->nullable();
            $table->timestamp('dispatched_at')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
            $table->index(['event_id', 'id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ai_analyses');
        Schema::dropIfExists('ai_settings');
        Schema::dropIfExists('packet_captures');
        Schema::table('alerts', function (Blueprint $table) {
            $table->dropConstrainedForeignId('event_id');
        });
        Schema::dropIfExists('monitor_events');
    }
};
