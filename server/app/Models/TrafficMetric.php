<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class TrafficMetric extends Model
{
    public $timestamps = false;

    protected $guarded = [];

    protected function casts(): array
    {
        return ['evidence' => 'array', 'window_start' => 'datetime', 'window_end' => 'datetime'];
    }

    public function node()
    {
        return $this->belongsTo(Node::class);
    }

    public function ipAsset()
    {
        return $this->belongsTo(IpAsset::class);
    }
}
