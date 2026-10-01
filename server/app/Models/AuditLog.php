<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    public $timestamps = false;

    protected $guarded = [];

    protected function casts(): array
    {
        return ['details' => 'array', 'created_at' => 'datetime'];
    }

    public static function record(string $action, Model $subject, array $details = []): void
    {
        self::create(['user_id' => null, 'action' => $action, 'subject' => class_basename($subject).':'.$subject->getKey(), 'details' => ['actor' => 'collector_cli'] + $details]);
    }
}
