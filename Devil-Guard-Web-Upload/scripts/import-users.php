<?php
declare(strict_types=1);

/**
 * Imports basic account data from a CSV export. Passwords are deliberately not imported because
 * historic password formats cannot be trusted. Imported users are pending and must reset a password.
 * CSV columns: username,email,display_name
 */
use DevilGuard\Web\Database;

require_once dirname(__DIR__) . '/src/bootstrap.php';
if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

$file = $argv[1] ?? '';
if (!is_file($file)) {
    exit("Usage: php scripts/import-users.php users.csv\n");
}

$handle = fopen($file, 'rb');
$header = fgetcsv($handle);
if ($header !== ['username', 'email', 'display_name']) {
    exit("Unexpected CSV header.\n");
}

$db = Database::connection();
$count = 0;
while (($row = fgetcsv($handle)) !== false) {
    if (count($row) !== 3 || !filter_var($row[1], FILTER_VALIDATE_EMAIL)) {
        continue;
    }

    try {
        devil_guard_insert(
            $db,
            'users',
            "INSERT INTO users (uid,username,email,display_name,password_hash,role,status,created_at,updated_at)
             VALUES (:uid,:username,:email,:display_name,:password_hash,'user','pending',UTC_TIMESTAMP(),UTC_TIMESTAMP())",
            [
                'username' => substr(trim($row[0]), 0, 50),
                'email' => substr(trim($row[1]), 0, 190),
                'display_name' => substr(trim($row[2]), 0, 100),
                'password_hash' => password_hash(bin2hex(random_bytes(32)), PASSWORD_ARGON2ID),
            ]
        );
        $count++;
    } catch (PDOException $exception) {
        if ($exception->getCode() !== '23000') {
            throw $exception;
        }
    }
}

fclose($handle);
echo "Imported {$count} pending users.\n";
