<?php

declare(strict_types=1);

// Run after BuildAdmin migrations. Existing Laravel hashes remain valid for password_verify().
if (PHP_SAPI !== 'cli') {
    exit(1);
}

$required = ['BUILDADMIN_DB_PASSWORD', 'MONITOR_DB_PASSWORD'];
foreach ($required as $name) {
    if (!getenv($name)) {
        fwrite(STDERR, "$name is required\n");
        exit(1);
    }
}

try {
    $monitor = new PDO(
        sprintf('pgsql:host=%s;port=%s;dbname=%s', getenv('MONITOR_DB_HOST') ?: 'postgres', getenv('MONITOR_DB_PORT') ?: '5432', getenv('MONITOR_DB_DATABASE') ?: 'monitor'),
        getenv('MONITOR_DB_USERNAME') ?: 'monitor',
        getenv('MONITOR_DB_PASSWORD'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    $admin = new PDO(
        sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', getenv('BUILDADMIN_DB_HOST') ?: 'buildadmin-db', getenv('BUILDADMIN_DB_PORT') ?: '3306', getenv('BUILDADMIN_DB_DATABASE') ?: 'buildadmin'),
        getenv('BUILDADMIN_DB_USERNAME') ?: 'buildadmin',
        getenv('BUILDADMIN_DB_PASSWORD'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    $viewerGroup = (int)$admin->query("SELECT id FROM ba_admin_group WHERE name = '监控只读' LIMIT 1")->fetchColumn();
    if (!$viewerGroup) throw new RuntimeException('Run BuildAdmin migrations before importing users');

    $demo = $admin->prepare("UPDATE ba_admin SET status = 'disable' WHERE username = 'admin' AND password = ''");
    $demo->execute();
    $users = $monitor->query("SELECT id, name, email, password, role FROM users WHERE role IN ('admin', 'viewer') ORDER BY id");
    $find = $admin->prepare('SELECT id FROM ba_admin WHERE username = ? OR email = ? LIMIT 1');
    $insert = $admin->prepare("INSERT INTO ba_admin (username, nickname, email, password, status, create_time, update_time) VALUES (?, ?, ?, ?, 'enable', ?, ?)");
    $assign = $admin->prepare('INSERT INTO ba_admin_group_access (uid, group_id) VALUES (?, ?)');
    $counts = ['imported' => 0, 'existing' => 0];
    while ($user = $users->fetch(PDO::FETCH_ASSOC)) {
        $username = 'vm_' . $user['id'];
        $find->execute([$username, $user['email']]);
        if ($find->fetchColumn()) {
            $counts['existing']++;
            continue;
        }
        if (!str_starts_with($user['password'], '$') || strlen($user['email']) > 255) {
            throw new RuntimeException('Unsupported password hash or email length for Laravel user ' . $user['id']);
        }
        $admin->beginTransaction();
        try {
            $now = time();
            $insert->execute([$username, mb_substr($user['name'], 0, 50), $user['email'], $user['password'], $now, $now]);
            $assign->execute([(int)$admin->lastInsertId(), $user['role'] === 'admin' ? 1 : $viewerGroup]);
            $admin->commit();
            $counts['imported']++;
        } catch (Throwable $e) {
            $admin->rollBack();
            throw $e;
        }
    }
    printf("Imported %d accounts; %d already present. Default empty-password account disabled.\n", $counts['imported'], $counts['existing']);
} catch (Throwable $e) {
    fwrite(STDERR, "Import failed: " . $e->getMessage() . "\n");
    exit(1);
}
