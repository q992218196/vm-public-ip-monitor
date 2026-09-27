<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Website extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['classification' => 'array', 'last_probed_at' => 'datetime', 'first_seen_at' => 'datetime', 'last_seen_at' => 'datetime'];
    }

    public function ipAsset()
    {
        return $this->belongsTo(IpAsset::class);
    }

    public function task()
    {
        return $this->hasOne(ProbeTask::class);
    }
}
