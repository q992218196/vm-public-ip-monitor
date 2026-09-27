<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', fn (Blueprint $t) => $t->string('role')->default('viewer'));
        Schema::create('nodes', function (Blueprint $t) {
            $t->uuid('id')->primary();
            $t->string('name');
            $t->string('token_hash', 64)->nullable();
            $t->json('cidrs');
            $t->boolean('enabled')->default(true);
            $t->json('settings')->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->json('health')->nullable();
            $t->timestamp('health_observed_at')->nullable();
            $t->text('notes')->nullable();
            $t->timestamps();
        });
        Schema::create('ip_assets', function (Blueprint $t) {
            $t->id();
            $t->string('ip', 45)->unique();
            $t->unsignedSmallInteger('version');
            $t->string('label')->nullable();
            $t->text('notes')->nullable();
            $t->timestamp('first_seen_at');
            $t->timestamp('last_seen_at');
            $t->timestamps();
        });
        Schema::create('ip_observations', function (Blueprint $t) {
            $t->id();
            $t->foreignId('ip_asset_id')->constrained()->cascadeOnDelete();
            $t->foreignUuid('node_id')->constrained()->cascadeOnDelete();
            $t->timestamp('first_seen_at');
            $t->timestamp('last_seen_at');
            $t->unique(['ip_asset_id', 'node_id']);
        });
        Schema::create('batches', function (Blueprint $t) {
            $t->id();
            $t->foreignUuid('node_id')->constrained()->cascadeOnDelete();
            $t->string('batch_id', 64);
            $t->json('payload')->nullable();
            $t->timestamp('window_start');
            $t->timestamp('window_end');
            $t->timestamp('processed_at')->nullable()->index();
            $t->timestamps();
            $t->unique(['node_id', 'batch_id']);
        });
        Schema::create('traffic_metrics', function (Blueprint $t) {
            $t->id();
            $t->foreignUuid('node_id')->constrained()->cascadeOnDelete();
            $t->foreignId('batch_id')->constrained()->cascadeOnDelete();
            $t->foreignId('ip_asset_id')->constrained()->cascadeOnDelete();
            $t->timestamp('window_start')->index();
            $t->timestamp('window_end');
            foreach (['bytes_out', 'bytes_in', 'packets_out', 'packets_in', 'tcp_attempts'] as $f) {
                $t->unsignedBigInteger($f)->default(0);
            }
            $t->json('evidence');
            $t->unique(['batch_id', 'ip_asset_id']);
        });
        Schema::create('websites', function (Blueprint $t) {
            $t->id();
            $t->foreignId('ip_asset_id')->constrained()->cascadeOnDelete();
            $t->string('fingerprint', 64)->unique();
            $t->unsignedInteger('port');
            $t->string('scheme', 8);
            $t->string('host', 253)->default('');
            $t->string('source');
            $t->string('status')->default('observed');
            $t->string('title')->nullable();
            $t->unsignedInteger('http_status')->nullable();
            $t->text('final_url')->nullable();
            $t->string('category')->nullable();
            $t->string('manual_category')->nullable();
            $t->json('classification')->nullable();
            $t->string('content_hash', 64)->nullable();
            $t->string('screenshot_path')->nullable();
            $t->text('last_error')->nullable();
            $t->timestamp('first_seen_at');
            $t->timestamp('last_seen_at');
            $t->timestamp('last_probed_at')->nullable();
            $t->timestamps();
        });
        Schema::create('rules', function (Blueprint $t) {
            $t->id();
            $t->string('name');
            $t->string('kind');
            $t->boolean('enabled')->default(true);
            $t->string('severity')->default('medium');
            $t->unsignedInteger('threshold');
            $t->unsignedInteger('window_seconds')->default(60);
            $t->unsignedInteger('cooldown_seconds')->default(600);
            $t->foreignUuid('node_id')->nullable()->constrained()->cascadeOnDelete();
            $t->timestamps();
        });
        Schema::create('exclusions', function (Blueprint $t) {
            $t->id();
            $t->string('cidr');
            $t->string('reason');
            $t->timestamp('expires_at');
            $t->foreignUuid('node_id')->nullable()->constrained()->cascadeOnDelete();
            $t->timestamps();
        });
        Schema::create('alerts', function (Blueprint $t) {
            $t->id();
            $t->string('dedup_key', 64)->unique();
            $t->foreignUuid('node_id')->constrained()->cascadeOnDelete();
            $t->foreignId('ip_asset_id')->nullable()->constrained()->nullOnDelete();
            $t->string('kind');
            $t->string('severity');
            $t->string('title');
            $t->string('status')->default('open');
            $t->json('evidence');
            $t->unsignedInteger('occurrences')->default(1);
            $t->timestamp('first_seen_at');
            $t->timestamp('last_seen_at');
            $t->text('resolution')->nullable();
            $t->timestamps();
        });
        Schema::create('probe_tasks', function (Blueprint $t) {
            $t->id();
            $t->foreignId('website_id')->unique()->constrained()->cascadeOnDelete();
            $t->string('status')->default('pending')->index();
            $t->unsignedInteger('attempts')->default(0);
            $t->string('lease_token', 64)->nullable();
            $t->timestamp('leased_until')->nullable();
            $t->timestamp('available_at');
            $t->text('last_error')->nullable();
            $t->timestamps();
        });
        Schema::create('audit_logs', function (Blueprint $t) {
            $t->id();
            $t->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $t->string('action');
            $t->string('subject');
            $t->json('details')->nullable();
            $t->timestamp('created_at')->useCurrent();
        });
    }

    public function down(): void
    {
        foreach (['audit_logs', 'probe_tasks', 'alerts', 'exclusions', 'rules', 'websites', 'traffic_metrics', 'batches', 'ip_observations', 'ip_assets', 'nodes'] as $name) {
            Schema::dropIfExists($name);
        }
        Schema::table('users', fn (Blueprint $t) => $t->dropColumn('role'));
    }
};
