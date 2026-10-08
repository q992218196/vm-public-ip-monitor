<?php

use App\Services\RetireConnectionRules;
use Illuminate\Database\Migrations\Migration;

return new class extends Migration
{
    public $withinTransaction = false;

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        app(RetireConnectionRules::class)->run();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // User-requested evidence deletion cannot be reversed.
    }
};
