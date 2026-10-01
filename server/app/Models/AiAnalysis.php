<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AiAnalysis extends Model
{
    protected $guarded = [];

    protected $hidden = ['config_snapshot'];

    protected function casts(): array
    {
        return ['config_snapshot' => 'array', 'evidence' => 'array', 'usage' => 'array', 'started_at' => 'datetime', 'dispatched_at' => 'datetime'];
    }
}
