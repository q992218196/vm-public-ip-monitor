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

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public static function record(string $action, Model $subject, array $details = []): void
    {
        self::create(['user_id' => auth()->id(), 'action' => $action, 'subject' => class_basename($subject).':'.$subject->getKey(), 'details' => $details]);
    }
}
