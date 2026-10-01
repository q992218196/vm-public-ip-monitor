<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class PacketCapture extends Model
{
    use HasUuids;

    protected $guarded = [];

    protected $hidden = ['lease_token', 'path'];

    protected function casts(): array
    {
        return ['metadata' => 'array', 'summary' => 'array', 'lease_until' => 'datetime'];
    }
}
