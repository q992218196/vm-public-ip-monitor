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
        Schema::table('exclusions', function (Blueprint $table) {
            $table->json('behavior_scope')->nullable();
        });
        Schema::table('websites', function (Blueprint $table) {
            $table->string('ownership_status', 24)->default('unverified')->index();
            $table->json('ownership_evidence')->nullable();
        });
        DB::table('websites')->where('source', 'manual')->update(['ownership_status' => 'manual']);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('exclusions', fn (Blueprint $table) => $table->dropColumn('behavior_scope'));
        Schema::table('websites', fn (Blueprint $table) => $table->dropColumn(['ownership_status', 'ownership_evidence']));
    }
};
