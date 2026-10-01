<?php

namespace App\Services;

/** Compatibility entry point; all connection rules use the same evidence policy. */
class ScanAssessment
{
    public function assess(array $sample, string $severity = 'high'): array
    {
        return app(ConnectionAssessment::class)->assess('horizontal_scan', $sample, 100, $severity);
    }
}
