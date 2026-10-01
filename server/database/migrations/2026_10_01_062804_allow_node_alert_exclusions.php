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
            $table->string('cidr')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::table('exclusions')->whereNull('cidr')->exists()) {
            throw new RuntimeException('仍有节点级白名单，无法恢复 CIDR 非空约束；请先处理这些白名单。');
        }
        Schema::table('exclusions', function (Blueprint $table) {
            $table->string('cidr')->nullable(false)->change();
        });
    }
};
