<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class IpAsset extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['first_seen_at' => 'datetime', 'last_seen_at' => 'datetime'];
    }

    public function observations()
    {
        return $this->hasMany(IpObservation::class);
    }

    public function websites()
    {
        return $this->hasMany(Website::class);
    }

    public function nodes()
    {
        return $this->belongsToMany(Node::class, 'ip_observations');
    }
}
