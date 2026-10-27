<?php

namespace Tests\Feature;

use App\Models\IpAsset;
use App\Models\Website;
use App\Services\Screenshots;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

class ScreenshotRetentionTest extends TestCase
{
    use RefreshDatabase;

    private string $originalStorage;

    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalStorage = storage_path();
        $this->directory = storage_path('framework/testing/screenshots-'.Str::uuid());
        File::ensureDirectoryExists($this->directory.'/app/private/screenshots');
        $this->app->useStoragePath($this->directory);
    }

    protected function tearDown(): void
    {
        $this->app->useStoragePath($this->originalStorage);
        File::deleteDirectory($this->directory);
        parent::tearDown();
    }

    private function image(string $name, int $ageSeconds = 172800): string
    {
        $path = storage_path('app/private/screenshots/'.hash('sha256', $name).'.png');
        file_put_contents($path, $name);
        touch($path, time() - $ageSeconds);

        return $path;
    }

    private function reference(string $path): void
    {
        $asset = IpAsset::create(['ip' => '203.0.113.10', 'version' => 4, 'first_seen_at' => now(), 'last_seen_at' => now()]);
        Website::create(['ip_asset_id' => $asset->id, 'fingerprint' => hash('sha256', $path), 'port' => 80, 'scheme' => 'http',
            'source' => 'http_response', 'screenshot_path' => 'screenshots/'.basename($path), 'first_seen_at' => now(), 'last_seen_at' => now()]);
    }

    public function test_prune_deletes_only_old_unreferenced_generated_png_files(): void
    {
        $used = $this->image('used');
        $this->reference($used);
        $orphan = $this->image('orphan');
        $recent = $this->image('recent', 60);
        $boundary = $this->image('boundary', 86399);
        $root = storage_path('app/private/screenshots');
        $other = $root.'/other.png';
        file_put_contents($other, 'unknown file');
        touch($other, time() - 172800);
        $directory = $root.'/'.hash('sha256', 'directory').'.png';
        mkdir($directory);
        touch($directory, time() - 172800);

        $this->assertSame(1, app(Screenshots::class)->prune());
        $this->assertFileDoesNotExist($orphan);
        foreach ([$used, $recent, $boundary, $other] as $retained) {
            $this->assertFileExists($retained);
        }
        $this->assertDirectoryExists($directory);
    }

    public function test_prune_looks_up_references_in_bounded_batches_instead_of_per_file(): void
    {
        for ($i = 0; $i < 401; $i++) {
            $path = $this->image('batch-'.$i);
            if ($i === 0) {
                $this->reference($path);
            }
        }
        $lookups = [];
        DB::listen(function (QueryExecuted $query) use (&$lookups): void {
            if (str_contains($query->sql, 'screenshot_path') && str_contains($query->sql, 'select')) {
                $lookups[] = $query;
            }
        });

        $this->assertSame(400, app(Screenshots::class)->prune());
        $this->assertCount(3, $lookups);
        $this->assertSame([200, 200, 1], array_map(fn (QueryExecuted $query) => count($query->bindings), $lookups));
        foreach ($lookups as $query) {
            $this->assertStringContainsString(' in (', $query->sql);
            $this->assertStringNotContainsString('exists(', $query->sql);
        }
    }

    public function test_reusing_old_png_refreshes_grace_before_its_reference_is_committed(): void
    {
        $encoded = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/f9sAAAAASUVORK5CYII=';
        $screenshots = app(Screenshots::class);
        $reference = $screenshots->store($encoded);
        $path = storage_path('app/private/'.$reference);
        $oldTime = time() - 172800;
        touch($path, $oldTime);
        clearstatcache(true, $path);
        $this->assertSame($oldTime, filemtime($path));

        $this->assertSame($reference, $screenshots->store($encoded));
        clearstatcache(true, $path);
        $this->assertGreaterThan($oldTime, filemtime($path));
        $this->assertSame(0, $screenshots->prune());
        $this->assertFileExists($path);
    }

    public function test_prune_rechecks_mtime_after_the_reference_lookup(): void
    {
        $path = $this->image('refreshed-during-lookup');
        DB::listen(function (QueryExecuted $query) use ($path): void {
            if (str_contains($query->sql, 'screenshot_path')) {
                touch($path);
            }
        });

        $this->assertSame(0, app(Screenshots::class)->prune());
        $this->assertFileExists($path);
    }

    public function test_failed_database_lookup_keeps_the_entire_batch_and_releases_its_lock(): void
    {
        $paths = [$this->image('failure-1'), $this->image('failure-2')];
        DB::connection()->beforeExecuting(function (string $query): void {
            if (str_contains($query, 'screenshot_path')) {
                throw new RuntimeException('Screenshot reference lookup unavailable');
            }
        });
        try {
            app(Screenshots::class)->prune();
            $this->fail('The database failure must abort the cleanup batch');
        } catch (RuntimeException $error) {
            $this->assertSame('Screenshot reference lookup unavailable', $error->getMessage());
        }
        foreach ($paths as $path) {
            $this->assertFileExists($path);
        }
        $lock = fopen(storage_path('app/private/screenshots/.budget.lock'), 'c');
        try {
            $this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function test_busy_store_lock_defers_cleanup_without_deleting_files(): void
    {
        $path = $this->image('busy');
        $lock = fopen(storage_path('app/private/screenshots/.budget.lock'), 'c');
        flock($lock, LOCK_EX);
        try {
            $this->assertSame(0, app(Screenshots::class)->prune());
            $this->assertFileExists($path);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function test_prune_does_not_follow_a_hash_named_symbolic_link(): void
    {
        $target = $this->directory.'/external.png';
        file_put_contents($target, 'outside screenshot directory');
        touch($target, time() - 172800);
        $link = storage_path('app/private/screenshots/'.hash('sha256', 'link').'.png');
        if (! @symlink($target, $link)) {
            $this->markTestSkipped('Symbolic links are unavailable for this test user');
        }

        $this->assertSame(0, app(Screenshots::class)->prune());
        $this->assertTrue(is_link($link));
        $this->assertFileExists($target);
    }

    public function test_screenshot_reference_index_exists_and_postgres_predicate_is_valid(): void
    {
        $this->assertTrue(Schema::hasIndex('websites', 'websites_screenshot_path_idx'));
        if (DB::getDriverName() === 'pgsql') {
            $index = DB::selectOne("SELECT indisvalid, pg_get_indexdef(indexrelid) AS definition, pg_get_expr(indpred, indrelid) AS predicate FROM pg_index WHERE indexrelid = 'websites_screenshot_path_idx'::regclass");
            $this->assertTrue((bool) $index->indisvalid);
            $this->assertStringContainsString('(screenshot_path)', $index->definition);
            $this->assertStringContainsString('screenshot_path IS NOT NULL', $index->predicate);
        }
    }
}
