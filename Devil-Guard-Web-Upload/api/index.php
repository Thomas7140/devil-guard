<?php
declare(strict_types=1);

use DevilGuard\Web\Attestation;
use DevilGuard\Web\Auth;
use DevilGuard\Web\Database;
use DevilGuard\Web\Env;
use DevilGuard\Web\Http;
use DevilGuard\Web\ServerAuth;

require_once dirname(__DIR__) . '/src/bootstrap.php';

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = array_filter(array_map('trim', explode(',', Env::get('CORS_ALLOWED_ORIGINS', '') ?? '')));
if ($origin !== '' && in_array($origin, $allowed, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, X-DevilGuard-Token');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$route = trim((string)($_GET['route'] ?? ''), '/');
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$db = Database::connection();

/*
|--------------------------------------------------------------------------
| Gatekeeper-compatible attestation API
|--------------------------------------------------------------------------
|
| These routes intentionally match the existing .NET Sentinel and
| Gatekeeper contract. Authentication is performed with an opaque server
| token in the X-DevilGuard-Token header. Tokens are stored only as hashes.
|
*/
if ($method === 'POST' && $route === 'attestation/report') {
    $server = ServerAuth::requireServer();
    $body = Http::jsonBody(131072);

    try {
        $report = Attestation::normalise($body);
    } catch (InvalidArgumentException $exception) {
        Http::json(['ok' => false, 'error' => 'invalid_report', 'message' => $exception->getMessage()], 400);
    }

    Http::json(Attestation::receive($db, $server, $report));
}

if ($method === 'GET' && preg_match('#^attestation/decision/([^/]+)$#', $route, $matches) === 1) {
    $server = ServerAuth::requireServer();
    $machineId = substr(trim(rawurldecode($matches[1])), 0, 190);
    if ($machineId === '') {
        Http::json(['ok' => false, 'error' => 'machine_id_required'], 400);
    }

    $decision = Attestation::latestDecision($db, $server, $machineId);
    if ($decision === null) {
        Http::json([
            'machineId' => $machineId,
            'allowJoin' => false,
            'reason' => 'No attestation report found for this machine.',
            'decisionAtUtc' => gmdate('Y-m-d\\TH:i:s\\Z'),
        ], 404);
    }

    Http::json($decision);
}

if ($method === 'GET' && $route === 'attestation/recent') {
    $server = ServerAuth::requireServer();
    $limit = max(1, min(200, (int)($_GET['limit'] ?? 200)));
    Http::json(Attestation::recent($db, $server, $limit));
}

if ($method === 'GET' && $route === 'status') {
    $settings = $db->query(
        "SELECT setting_key, setting_value
         FROM settings
         WHERE setting_key IN ('service_status','minimum_client_version','maintenance_message')"
    )->fetchAll(PDO::FETCH_KEY_PAIR);

    Http::json([
        'ok' => true,
        'service' => 'Devil-Guard',
        'status' => $settings['service_status'] ?? 'online',
        'minimumClientVersion' => $settings['minimum_client_version'] ?? '1.0.0',
        'message' => $settings['maintenance_message'] ?? '',
        'serverTime' => gmdate(DATE_ATOM),
        'apiVersion' => 'v1',
    ]);
}

if ($method === 'POST' && $route === 'auth/login') {
    $body = Http::jsonBody(32768);
    $login = trim((string)($body['login'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $installationPublicId = strtolower(trim((string)($body['installationId'] ?? '')));

    if ($login === '' || $password === '' || !preg_match('/^[A-Za-z0-9._:-]{16,128}$/', $installationPublicId)) {
        Http::json(['ok' => false, 'error' => 'invalid_credentials'], 422);
    }

    $cutoff = gmdate('Y-m-d H:i:s', time() - 900);
    $attempts = $db->prepare(
        'SELECT COUNT(*) FROM login_attempts
         WHERE ip_address = :ip AND succeeded = 0 AND attempted_at >= :cutoff'
    );
    $attempts->execute(['ip' => Http::clientIp(), 'cutoff' => $cutoff]);
    if ((int)$attempts->fetchColumn() >= 8) {
        Http::json(['ok' => false, 'error' => 'rate_limited'], 429);
    }

    $statement = $db->prepare(
        'SELECT uid, username, email, display_name, password_hash, role, status
         FROM users
         WHERE username = :username OR email = :email
         LIMIT 1'
    );
    $statement->execute([
        'username' => $login,
        'email' => $login,
    ]);
    $user = $statement->fetch();
    $valid = $user && $user['status'] === 'active' && password_verify($password, $user['password_hash']);

    devil_guard_insert(
        $db,
        'login_attempts',
        'INSERT INTO login_attempts (uid, login_value, ip_address, succeeded, attempted_at)
         VALUES (:uid, :login, :ip, :succeeded, UTC_TIMESTAMP())',
        [
            'login' => substr($login, 0, 190),
            'ip' => Http::clientIp(),
            'succeeded' => $valid ? 1 : 0,
        ]
    );

    if (!$valid) {
        usleep(random_int(150000, 350000));
        Http::json(['ok' => false, 'error' => 'invalid_credentials'], 401);
    }

    $clientVersion = substr(trim((string)($body['clientVersion'] ?? 'unknown')), 0, 40);
    $osVersion = substr(trim((string)($body['osVersion'] ?? '')), 0, 190);
    $runtimeVersion = substr(trim((string)($body['runtimeVersion'] ?? '')), 0, 100);

    $installStatement = $db->prepare('SELECT uid FROM installations WHERE public_id = :public_id LIMIT 1');
    $installStatement->execute(['public_id' => $installationPublicId]);
    $installationUid = (string)($installStatement->fetchColumn() ?: '');

    if ($installationUid === '') {
        try {
            $installationUid = devil_guard_insert(
                $db,
                'installations',
                'INSERT INTO installations
                    (uid, user_uid, public_id, client_version, os_version, runtime_version, first_seen_at, last_seen_at)
                 VALUES
                    (:uid, :user_uid, :public_id, :client_version, :os_version, :runtime_version, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
                [
                    'user_uid' => $user['uid'],
                    'public_id' => $installationPublicId,
                    'client_version' => $clientVersion,
                    'os_version' => $osVersion,
                    'runtime_version' => $runtimeVersion,
                ]
            );
        } catch (PDOException $exception) {
            $duplicateKey = $exception->getCode() === '23000'
                && (int)($exception->errorInfo[1] ?? 0) === 1062;
            if (!$duplicateKey) {
                throw $exception;
            }

            $installStatement->execute(['public_id' => $installationPublicId]);
            $installationUid = (string)($installStatement->fetchColumn() ?: '');
            if ($installationUid === '') {
                throw $exception;
            }
        }
    }

    $db->prepare(
        'UPDATE installations
         SET user_uid = :user_uid,
             client_version = :client_version,
             os_version = :os_version,
             runtime_version = :runtime_version,
             last_seen_at = UTC_TIMESTAMP()
         WHERE uid = :uid'
    )->execute([
        'user_uid' => $user['uid'],
        'client_version' => $clientVersion,
        'os_version' => $osVersion,
        'runtime_version' => $runtimeVersion,
        'uid' => $installationUid,
    ]);

    $token = Auth::issueToken((string)$user['uid'], $installationUid);
    $db->prepare(
        'UPDATE users SET last_login_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() WHERE uid = :uid'
    )->execute(['uid' => $user['uid']]);

    Http::json([
        'ok' => true,
        'token' => $token['token'],
        'expiresAt' => $token['expiresAt'],
        'user' => [
            'id' => $user['uid'],
            'uid' => $user['uid'],
            'username' => $user['username'],
            'displayName' => $user['display_name'],
            'role' => $user['role'],
        ],
    ]);
}

if ($method === 'POST' && $route === 'auth/logout') {
    Auth::requireApiUser();
    Auth::revokeCurrentToken();
    Http::json(['ok' => true]);
}

if ($method === 'GET' && $route === 'me') {
    $user = Auth::requireApiUser();
    Http::json([
        'ok' => true,
        'user' => [
            'id' => $user['uid'],
            'uid' => $user['uid'],
            'username' => $user['username'],
            'displayName' => $user['display_name'],
            'role' => $user['role'],
        ],
    ]);
}

if ($method === 'POST' && $route === 'heartbeat') {
    $user = Auth::requireApiUser();
    $body = Http::jsonBody(65536);
    $heartbeatValues = [
        'user_uid' => $user['uid'],
        'installation_uid' => $user['installation_uid'],
        'client_version' => substr((string)($body['clientVersion'] ?? ''), 0, 40),
        'game_running' => !empty($body['gameRunning']) ? 1 : 0,
        'in_game' => !empty($body['inGame']) ? 1 : 0,
        'player_name' => substr((string)($body['playerName'] ?? ''), 0, 80),
        'server_name' => substr((string)($body['serverName'] ?? ''), 0, 120),
        'server_ip' => substr((string)($body['serverIp'] ?? ''), 0, 45),
        'process_hash' => preg_match('/^[a-fA-F0-9]{64}$/', (string)($body['processHash'] ?? ''))
            ? strtolower((string)$body['processHash'])
            : null,
        'os_version' => substr((string)($body['osVersion'] ?? ''), 0, 190),
        'runtime_version' => substr((string)($body['runtimeVersion'] ?? ''), 0, 100),
    ];

    $updateHeartbeat = $db->prepare(
        'UPDATE heartbeats SET
            user_uid = :user_uid,
            client_version = :client_version,
            game_running = :game_running,
            in_game = :in_game,
            player_name = :player_name,
            server_name = :server_name,
            server_ip = :server_ip,
            process_hash = :process_hash,
            os_version = :os_version,
            runtime_version = :runtime_version,
            received_at = UTC_TIMESTAMP()
         WHERE installation_uid = :installation_uid'
    );
    $updateHeartbeat->execute($heartbeatValues);

    if ($updateHeartbeat->rowCount() === 0) {
        try {
            devil_guard_insert(
                $db,
                'heartbeats',
                'INSERT INTO heartbeats
                    (uid, user_uid, installation_uid, client_version, game_running, in_game, player_name,
                     server_name, server_ip, process_hash, os_version, runtime_version, received_at)
                 VALUES
                    (:uid, :user_uid, :installation_uid, :client_version, :game_running, :in_game, :player_name,
                     :server_name, :server_ip, :process_hash, :os_version, :runtime_version, UTC_TIMESTAMP())',
                $heartbeatValues
            );
        } catch (PDOException $exception) {
            $duplicateKey = $exception->getCode() === '23000'
                && (int)($exception->errorInfo[1] ?? 0) === 1062;
            if (!$duplicateKey) {
                throw $exception;
            }
            $updateHeartbeat->execute($heartbeatValues);
        }
    }

    if (!empty($user['installation_uid'])) {
        $db->prepare(
            'UPDATE installations
             SET last_seen_at = UTC_TIMESTAMP(), client_version = :version
             WHERE uid = :uid'
        )->execute([
            'version' => $heartbeatValues['client_version'],
            'uid' => $user['installation_uid'],
        ]);
    }

    Http::json(['ok' => true, 'nextHeartbeatSeconds' => 30, 'serverTime' => gmdate(DATE_ATOM)]);
}

if ($method === 'POST' && $route === 'events') {
    $user = Auth::requireApiUser();
    $body = Http::jsonBody(65536);
    $eventType = substr(trim((string)($body['eventType'] ?? 'client')), 0, 50);
    $severity = strtolower(substr(trim((string)($body['severity'] ?? 'info')), 0, 20));
    if (!in_array($severity, ['info', 'warning', 'error', 'security'], true)) {
        $severity = 'info';
    }

    $message = substr(trim((string)($body['message'] ?? '')), 0, 2000);
    if ($message === '') {
        Http::json(['ok' => false, 'error' => 'message_required'], 422);
    }

    $context = $body['context'] ?? null;
    devil_guard_insert(
        $db,
        'client_events',
        'INSERT INTO client_events
            (uid, user_uid, installation_uid, event_type, severity, message, context_json, created_at)
         VALUES
            (:uid, :user_uid, :installation_uid, :event_type, :severity, :message, :context_json, UTC_TIMESTAMP())',
        [
            'user_uid' => $user['uid'],
            'installation_uid' => $user['installation_uid'],
            'event_type' => $eventType,
            'severity' => $severity,
            'message' => $message,
            'context_json' => $context === null
                ? null
                : json_encode($context, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
        ]
    );

    Http::json(['ok' => true], 202);
}

if ($method === 'GET' && $route === 'announcements') {
    $rows = $db->query(
        "SELECT uid, uid AS id, title, body, starts_at AS startsAt, ends_at AS endsAt
         FROM announcements
         WHERE is_active = 1
           AND (starts_at IS NULL OR starts_at <= UTC_TIMESTAMP())
           AND (ends_at IS NULL OR ends_at >= UTC_TIMESTAMP())
         ORDER BY created_at DESC
         LIMIT 20"
    )->fetchAll();
    Http::json(['ok' => true, 'announcements' => $rows]);
}

if ($method === 'GET' && $route === 'releases/latest') {
    $channel = preg_replace('/[^a-z0-9_-]/i', '', (string)($_GET['channel'] ?? 'stable')) ?: 'stable';
    $statement = $db->prepare(
        'SELECT uid, uid AS id, version, package_url AS packageUrl, sha256,
                file_name AS fileName, notes, min_windows_build AS minWindowsBuild
         FROM releases
         WHERE channel = :channel AND is_active = 1
         ORDER BY published_at DESC, uid DESC
         LIMIT 1'
    );
    $statement->execute(['channel' => $channel]);
    $release = $statement->fetch();
    if (!$release) {
        Http::json(['ok' => false, 'error' => 'release_not_found'], 404);
    }
    Http::json($release);
}

if ($method === 'GET' && $route === 'bans') {
    $statement = $db->query(
        "SELECT uid, uid AS id, player_name AS playerName, player_id AS playerId,
                reason, starts_at AS startsAt, ends_at AS endsAt, status
         FROM bans
         WHERE status IN ('active','expired')
         ORDER BY starts_at DESC
         LIMIT 250"
    );
    Http::json(['ok' => true, 'bans' => $statement->fetchAll()]);
}

Http::json(['ok' => false, 'error' => 'not_found'], 404);
