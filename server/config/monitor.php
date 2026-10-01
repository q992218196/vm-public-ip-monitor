<?php

return [
    'worker_token' => env('MONITOR_WORKER_TOKEN', ''),
    'auto_probe' => env('MONITOR_AUTO_PROBE', true),
    'alert_email' => env('MONITOR_ALERT_EMAIL'),
    'metrics_days' => (int) env('MONITOR_METRICS_DAYS', 7),
    'protocol_days' => (int) env('MONITOR_PROTOCOL_DAYS', 30),
    'alerts_days' => (int) env('MONITOR_ALERTS_DAYS', 180),
    'screenshots_bytes' => (int) env('MONITOR_SCREENSHOTS_BYTES', 5368709120),
    'offline_minutes' => (int) env('MONITOR_OFFLINE_MINUTES', 5),
    'pending_bytes_per_node' => (int) env('MONITOR_PENDING_BYTES_PER_NODE', 67108864),
    'auto_capture' => (bool) env('MONITOR_AUTO_CAPTURE', true),
    'capture_bytes' => (int) env('MONITOR_CAPTURE_BYTES', 21474836480),
    'capture_days' => (int) env('MONITOR_CAPTURE_DAYS', 7),
];
