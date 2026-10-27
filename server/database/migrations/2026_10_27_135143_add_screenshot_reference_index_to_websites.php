<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public $withinTransaction = false;

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            $existing = DB::selectOne('SELECT CASE WHEN indisvalid THEN 1 ELSE 0 END AS is_valid FROM pg_index WHERE indexrelid = to_regclass(?)', ['websites_screenshot_path_idx']);
            if ($existing && (int) $existing->is_valid !== 1) {
                DB::statement('DROP INDEX CONCURRENTLY IF EXISTS websites_screenshot_path_idx');
            }
            DB::statement('CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_screenshot_path_idx ON websites (screenshot_path) WHERE screenshot_path IS NOT NULL');

            return;
        }
        if (DB::getDriverName() === 'sqlite') {
            DB::statement('CREATE INDEX IF NOT EXISTS websites_screenshot_path_idx ON websites (screenshot_path) WHERE screenshot_path IS NOT NULL');

            return;
        }
        Schema::table('websites', fn (Blueprint $table) => $table->index('screenshot_path', 'websites_screenshot_path_idx'));
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::getDriverName() === 'pgsql') {
            DB::statement('DROP INDEX CONCURRENTLY IF EXISTS websites_screenshot_path_idx');

            return;
        }
        Schema::table('websites', fn (Blueprint $table) => $table->dropIndex('websites_screenshot_path_idx'));
    }
};
