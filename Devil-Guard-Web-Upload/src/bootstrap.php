<?php
declare(strict_types=1);

use DevilGuard\Web\Env;
use DevilGuard\Web\Http;

$root = dirname(__DIR__);
require_once $root . '/assets/uid.php';
require_once $root . '/src/Env.php';
require_once $root . '/src/Database.php';
require_once $root . '/src/Http.php';
require_once $root . '/src/Auth.php';
require_once $root . '/src/ServerAuth.php';
require_once $root . '/src/Attestation.php';

$externalEnv = '/home/devilishservices/connections/devil_guard/.env';
Env::load(is_file($externalEnv) ? $externalEnv : $root . '/config/.env');
date_default_timezone_set(Env::get('APP_TIMEZONE', 'UTC') ?? 'UTC');
Http::securityHeaders(false);

set_exception_handler(static function (Throwable $exception): never {
    error_log('[Devil-Guard] ' . $exception);
    if (str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/')) {
        Http::json(['ok' => false, 'error' => 'server_error'], 500);
    }
    http_response_code(500);
    echo 'The service encountered an error.';
    exit;
});
