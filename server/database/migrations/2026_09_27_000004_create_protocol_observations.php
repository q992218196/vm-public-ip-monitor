<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('protocol_observations', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('batch_id');
            $table->foreignUuid('node_id')->constrained()->cascadeOnDelete();
            $table->foreignId('ip_asset_id')->constrained()->cascadeOnDelete();
            $table->string('protocol', 16);
            $table->string('peer_ip', 45);
            $table->unsignedSmallInteger('local_port');
            $table->unsignedSmallInteger('peer_port');
            $table->timestamp('window_start');
            $table->timestamp('window_end')->index();
            $table->json('evidence');
            $table->index(['ip_asset_id', 'window_end']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('protocol_observations');
    }
};
