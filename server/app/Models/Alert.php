<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['evidence' => 'array', 'first_seen_at' => 'datetime', 'last_seen_at' => 'datetime'];
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
