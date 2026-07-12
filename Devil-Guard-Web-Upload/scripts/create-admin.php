<?php
declare(strict_types=1);

use DevilGuard\Web\Database;

require_once dirname(__DIR__) . '/src/bootstrap.php';
if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

[$script, $username, $email, $displayName] = array_pad($argv, 4, null);
if (!$username || !$email || !$displayName) {
    exit("Usage: php scripts/create-admin.php <username> <email> <display-name>\n");
}
if (!preg_match('/^[A-Za-z0-9_.-]{3,50}$/', $username) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit("Supply a valid username and email address.\n");
}

$password = readline('Password: ');
if (strlen($password) < 12) {
    exit("Password must contain at least 12 characters.\n");
}

$db = Database::connection();
$uid = devil_guard_insert(
    $db,
    'users',
    "INSERT INTO users (uid,username,email,display_name,password_hash,role,status,created_at,updated_at)
     VALUES (:uid,:username,:email,:display_name,:password_hash,'admin','active',UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    [
        'username' => $username,
        'email' => $email,
        'display_name' => substr($displayName, 0, 100),
        'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
    ]
);

echo "Administrator created with UID {$uid}.\n";
