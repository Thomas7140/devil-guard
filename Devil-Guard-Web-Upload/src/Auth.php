<?php
declare(strict_types=1);

namespace DevilGuard\Web;

final class Auth
{
    /** @return array<string,mixed>|null */
    public static function apiUser(): ?array
    {
        $token = Http::bearerToken();
        if ($token === null || strlen($token) < 32) {
            return null;
        }

        $hash = hash('sha256', $token);
        $db = Database::connection();
        $statement = $db->prepare(
            'SELECT u.uid, u.username, u.email, u.display_name, u.role, u.status,
                    t.uid AS token_uid, t.installation_uid
             FROM api_tokens t
             INNER JOIN users u ON u.uid = t.user_uid
             WHERE t.token_hash = :hash
               AND t.revoked_at IS NULL
               AND t.expires_at > UTC_TIMESTAMP()
             LIMIT 1'
        );
        $statement->execute(['hash' => $hash]);
        $user = $statement->fetch();

        if (!$user || $user['status'] !== 'active') {
            return null;
        }

        $db->prepare('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP() WHERE uid = :uid')
            ->execute(['uid' => $user['token_uid']]);

        return $user;
    }

    /** @return array<string,mixed> */
    public static function requireApiUser(): array
    {
        $user = self::apiUser();
        if ($user === null) {
            Http::json(['ok' => false, 'error' => 'unauthorized'], 401);
        }
        return $user;
    }

    /** @return array{token:string,expiresAt:string} */
    public static function issueToken(string $userUid, ?string $installationUid): array
    {
        $plain = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $hash = hash('sha256', $plain);
        $hours = max(1, min(2160, Env::int('TOKEN_TTL_HOURS', 168)));
        $expires = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $expires = $expires->modify('+' . $hours . ' hours');
        $db = Database::connection();

        \devil_guard_insert(
            $db,
            'api_tokens',
            'INSERT INTO api_tokens
                (uid, user_uid, installation_uid, token_hash, created_ip, expires_at, created_at)
             VALUES
                (:uid, :user_uid, :installation_uid, :token_hash, :created_ip, :expires_at, UTC_TIMESTAMP())',
            [
                'user_uid' => $userUid,
                'installation_uid' => $installationUid,
                'token_hash' => $hash,
                'created_ip' => Http::clientIp(),
                'expires_at' => $expires->format('Y-m-d H:i:s'),
            ]
        );

        return ['token' => $plain, 'expiresAt' => $expires->format(DATE_ATOM)];
    }

    public static function revokeCurrentToken(): void
    {
        $token = Http::bearerToken();
        if ($token === null) {
            return;
        }

        Database::connection()
            ->prepare('UPDATE api_tokens SET revoked_at = UTC_TIMESTAMP() WHERE token_hash = :hash')
            ->execute(['hash' => hash('sha256', $token)]);
    }

    public static function startWebSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        session_name(Env::get('SESSION_NAME', 'devil_guard_session') ?? 'devil_guard_session');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }

    /** @return array<string,mixed>|null */
    public static function webUser(): ?array
    {
        self::startWebSession();
        $uid = strtoupper(trim((string)($_SESSION['admin_user_uid'] ?? '')));
        if (!preg_match('/^[A-HJ-NP-Z2-9]{4}$/', $uid)) {
            return null;
        }

        $statement = Database::connection()->prepare(
            'SELECT uid, username, email, display_name, role, status
             FROM users WHERE uid = :uid LIMIT 1'
        );
        $statement->execute(['uid' => $uid]);
        $user = $statement->fetch();

        return $user && $user['role'] === 'admin' && $user['status'] === 'active' ? $user : null;
    }

    /** @return array<string,mixed> */
    public static function requireAdmin(): array
    {
        $user = self::webUser();
        if ($user === null) {
            header('Location: ./?page=login');
            exit;
        }
        return $user;
    }

    public static function csrfToken(): string
    {
        self::startWebSession();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return (string)$_SESSION['csrf'];
    }

    public static function verifyCsrf(): void
    {
        self::startWebSession();
        $provided = (string)($_POST['csrf'] ?? '');
        $expected = (string)($_SESSION['csrf'] ?? '');
        if ($provided === '' || $expected === '' || !hash_equals($expected, $provided)) {
            http_response_code(419);
            exit('Session validation failed. Refresh the page and try again.');
        }
    }
}
