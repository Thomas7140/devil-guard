<?php
declare(strict_types=1);

use DevilGuard\Web\Database;
use DevilGuard\Web\ServerAuth;

require_once dirname(__DIR__) . '/src/bootstrap.php';

if (PHP_SAPI !== 'cli') {
    exit("CLI only.\n");
}

$name = trim((string)($argv[1] ?? ''));
$gameName = trim((string)($argv[2] ?? 'dfbhd')) ?: 'dfbhd';
if ($name === '') {
    exit("Usage: php scripts/create-server.php \"Server name\" [game-name]\n");
}

$database = Database::connection();
$serverUid = devil_guard_insert(
    $database,
    'servers',
    'INSERT INTO servers
        (uid, public_id, name, game_name, status, deny_on_any_signal,
         max_report_age_seconds, created_at, updated_at)
     VALUES
        (:uid, :public_id, :name, :game_name, \'active\', 1, 120,
         UTC_TIMESTAMP(), UTC_TIMESTAMP())',
    [
        'public_id' => ServerAuth::uuidV4(),
        'name' => substr($name, 0, 120),
        'game_name' => substr($gameName, 0, 100),
    ]
);
$token = ServerAuth::issueToken($serverUid, 'primary');

echo "Server UID: {$serverUid}\n";
echo "Server token (shown once): {$token['token']}\n";
