<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MonitorEvent extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['kinds' => 'array', 'quality' => 'array', 'behavior' => 'array', 'review_context' => 'array', 'first_seen_at' => 'datetime', 'last_seen_at' => 'datetime'];
    }
}
