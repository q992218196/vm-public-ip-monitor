<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Mockery;
use Tests\TestCase;

class ScreenshotReferenceIndexTest extends TestCase
{
    public function test_postgres_migration_retries_an_invalid_concurrent_index_in_order(): void
    {
        $this->assertPostgresIndexMigration((object) ['is_valid' => 0], true);
    }

    public function test_postgres_migration_keeps_a_valid_existing_index(): void
    {
        $this->assertPostgresIndexMigration((object) ['is_valid' => 1], false);
    }

    public function test_postgres_migration_creates_a_missing_index_without_a_drop(): void
    {
        $this->assertPostgresIndexMigration(null, false);
    }

    private function assertPostgresIndexMigration(?object $existing, bool $dropInvalid): void
    {
        $manager = DB::getFacadeRoot();
        $connection = Mockery::mock();
        $connection->shouldReceive('getDriverName')->once()->andReturn('pgsql');
        $connection->shouldReceive('selectOne')->once()->with('SELECT CASE WHEN indisvalid THEN 1 ELSE 0 END AS is_valid FROM pg_index WHERE indexrelid = to_regclass(?)', ['websites_screenshot_path_idx'])->ordered()->andReturn($existing);
        if ($dropInvalid) {
            $connection->shouldReceive('statement')->once()->with('DROP INDEX CONCURRENTLY IF EXISTS websites_screenshot_path_idx')->ordered()->andReturn(true);
        }
        $connection->shouldReceive('statement')->once()->with('CREATE INDEX CONCURRENTLY IF NOT EXISTS websites_screenshot_path_idx ON websites (screenshot_path) WHERE screenshot_path IS NOT NULL')->ordered()->andReturn(true);
        DB::swap($connection);
        try {
            $migration = require database_path('migrations/2026_10_27_135143_add_screenshot_reference_index_to_websites.php');
            $this->assertFalse($migration->withinTransaction);
            $migration->up();
        } finally {
            DB::swap($manager);
        }
    }
}
