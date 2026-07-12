<?php
declare(strict_types=1);

use DevilGuard\Web\Database;

require_once dirname(__DIR__) . '/src/bootstrap.php';
if (PHP_SAPI !== 'cli') { exit("CLI only.\n"); }
$db = Database::connection();
$db->exec("DELETE FROM login_attempts WHERE attempted_at < UTC_TIMESTAMP() - INTERVAL 7 DAY");
$db->exec("DELETE FROM api_tokens WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 30 DAY OR revoked_at < UTC_TIMESTAMP() - INTERVAL 30 DAY");
$db->exec("DELETE FROM heartbeats WHERE received_at < UTC_TIMESTAMP() - INTERVAL 90 DAY");
try {
    $db->exec("DELETE FROM server_tokens WHERE revoked_at IS NOT NULL AND revoked_at < UTC_TIMESTAMP() - INTERVAL 90 DAY");
    $db->exec("DELETE FROM attestation_reports WHERE received_at < UTC_TIMESTAMP() - INTERVAL 180 DAY");
} catch (PDOException $exception) {
    // The integration migration may not have been imported yet.
    error_log('[Devil-Guard] Integration pruning skipped: ' . $exception->getMessage());
}
echo "Maintenance complete.\n";
