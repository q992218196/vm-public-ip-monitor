<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ProbeTask extends Model
{
    protected $guarded = [];

    protected $hidden = ['lease_token'];

    protected function casts(): array
    {
        return ['available_at' => 'datetime', 'leased_until' => 'datetime'];
    }

    public function website()
    {
        return $this->belongsTo(Website::class);
    }
}
