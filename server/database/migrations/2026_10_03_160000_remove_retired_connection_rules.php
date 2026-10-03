<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        DB::table('rules')->whereIn('kind', ['horizontal_scan', 'suspected_bruteforce'])->delete();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Retired rule configurations are intentionally not restored. Historical evidence is retained.
    }
};
