<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Website extends Model
{
    protected $guarded = [];

    public function publicUrl(): ?string
    {
        $host = strtolower(rtrim($this->host, '.'));
        if (! in_array($this->scheme, ['http', 'https'], true)
            || ! filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
            || ! str_contains($host, '.')
            || preg_match('/\.(local|internal|invalid|test)$/', $host)
            || $this->port < 1 || $this->port > 65535) {
            return null;
        }

        return "{$this->scheme}://{$host}:{$this->port}/";
    }

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
