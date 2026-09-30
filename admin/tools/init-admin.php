<?php

declare(strict_types=1);

// Initialize only the unused administrator account created by BuildAdmin migrations.
if (PHP_SAPI !== 'cli') {
    exit(1);
}

$email = $argv[1] ?? '';
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
    fwrite(STDERR, "Provide a valid administrator email.\n");
    exit(1);
}
if (!getenv('BUILDADMIN_DB_PASSWORD')) {
    fwrite(STDERR, "BUILDADMIN_DB_PASSWORD is required.\n");
    exit(1);
}

function readSecret(string $prompt): string
{
    fwrite(STDERR, $prompt);
    $tty = stream_isatty(STDIN);
    if ($tty) {
        system('stty -echo');
    }
    try {
        return rtrim((string)fgets(STDIN), "\r\n");
    } finally {
        if ($tty) {
            system('stty echo');
            fwrite(STDERR, "\n");
        }
    }
}

$password = readSecret('Password (at least 12 characters): ');
$confirmation = readSecret('Confirm password: ');
if (strlen($password) < 12 || !hash_equals($password, $confirmation)) {
    fwrite(STDERR, "Password is too short or does not match.\n");
    exit(1);
}

try {
    $db = new PDO(
        sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', getenv('BUILDADMIN_DB_HOST') ?: 'buildadmin-db', getenv('BUILDADMIN_DB_PORT') ?: '3306', getenv('BUILDADMIN_DB_DATABASE') ?: 'buildadmin'),
        getenv('BUILDADMIN_DB_USERNAME') ?: 'buildadmin',
        getenv('BUILDADMIN_DB_PASSWORD'),
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
    $db->beginTransaction();
    $seeded = $db->query('SELECT id, password FROM ba_admin WHERE id = 1 FOR UPDATE')->fetch(PDO::FETCH_ASSOC);
    $existing = (int)$db->query("SELECT COUNT(*) FROM ba_admin WHERE status = 'enable' AND password <> ''")->fetchColumn();
    if (!$seeded || $seeded['password'] !== '' || $existing > 0) {
        throw new RuntimeException('An administrator is already configured; use the BuildAdmin account page.');
    }
    $check = $db->prepare('SELECT id FROM ba_admin WHERE email = ? AND id <> 1 LIMIT 1');
    $check->execute([$email]);
    if ($check->fetchColumn()) {
        throw new RuntimeException('The email is already in use.');
    }
    $update = $db->prepare("UPDATE ba_admin SET email = ?, nickname = '管理员', password = ?, salt = '', status = 'enable', update_time = ? WHERE id = 1 AND password = ''");
    $update->execute([$email, password_hash($password, PASSWORD_DEFAULT), time()]);
    if ($update->rowCount() !== 1) {
        throw new RuntimeException('Administrator initialization failed.');
    }
    $db->commit();
    fwrite(STDOUT, "BuildAdmin administrator initialized. Sign in with the email and password you entered.\n");
} catch (Throwable $error) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    fwrite(STDERR, 'Initialization failed: '.$error->getMessage()."\n");
    exit(1);
}
