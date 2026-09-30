<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('exclusions', function (Blueprint $table) {
            $table->string('kind')->nullable();
            $table->unique(['node_id', 'cidr', 'kind'], 'exclusions_scope_unique');
        });

        DB::table('alerts')->where('kind', 'new_website')->delete();
    }

    public function down(): void
    {
        Schema::table('exclusions', function (Blueprint $table) {
            $table->dropUnique('exclusions_scope_unique');
            $table->dropColumn('kind');
        });
    }
};
