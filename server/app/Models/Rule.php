<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Rule extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return ['enabled' => 'boolean', 'node_ids' => 'array'];
    }

    public function node()
    {
        return $this->belongsTo(Node::class);
    }
}
