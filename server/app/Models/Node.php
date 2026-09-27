<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Node extends Model
{
    use HasUuids;

    protected $guarded = [];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return ['cidrs' => 'array', 'settings' => 'array', 'health' => 'array', 'enabled' => 'boolean', 'last_seen_at' => 'datetime', 'health_observed_at' => 'datetime'];
    }

    public function observations()
    {
        return $this->hasMany(IpObservation::class);
    }
}
