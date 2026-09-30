<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nodes', function (Blueprint $table) {
            $table->string('agent_desired_version', 32)->nullable();
            $table->string('agent_desired_sha256', 64)->nullable();
            $table->timestamp('agent_update_requested_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('nodes', function (Blueprint $table) {
            $table->dropColumn(['agent_desired_version', 'agent_desired_sha256', 'agent_update_requested_at']);
        });
    }
};
