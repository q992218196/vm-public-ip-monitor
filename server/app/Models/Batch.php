<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Batch extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['payload' => 'array', 'processed_at' => 'datetime', 'dispatched_at' => 'datetime', 'window_start' => 'datetime', 'window_end' => 'datetime'];
    }

    public function node()
    {
        return $this->belongsTo(Node::class);
    }
}
