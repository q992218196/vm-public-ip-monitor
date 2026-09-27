<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('batches', fn (Blueprint $t) => $t->unsignedInteger('payload_bytes')->default(0));
    }

    public function down(): void
    {
        Schema::table('batches', fn (Blueprint $t) => $t->dropColumn('payload_bytes'));
    }
};
