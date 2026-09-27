<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class IpObservation extends Model
{
    public $timestamps = false;

    protected $guarded = [];

    public function node()
    {
        return $this->belongsTo(Node::class);
    }

    public function ipAsset()
    {
        return $this->belongsTo(IpAsset::class);
    }
}
