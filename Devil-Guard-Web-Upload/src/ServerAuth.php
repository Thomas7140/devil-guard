<?php
declare(strict_types=1);

namespace DevilGuard\Web;

final class ServerAuth
{
    /** @return array<string,mixed>|null */
    public static function server(): ?array
    {
        $token = trim((string)($_SERVER['HTTP_X_DEVILGUARD_TOKEN'] ?? ''));
        if (strlen($token) < 24 || strlen($token) > 512) {
            return null;
        }

        $database = Database::connection();
        $statement = $database->prepare(
            'SELECT s.uid, s.public_id, s.name, s.game_name, s.status,
                    s.deny_on_any_signal, s.max_report_age_seconds,
                    t.uid AS token_uid
             FROM server_tokens t
             INNER JOIN servers s ON s.uid = t.server_uid
             WHERE t.token_hash = :token_hash
               AND t.revoked_at IS NULL
               AND s.status = \'active\'
             LIMIT 1'
        );
        $statement->execute(['token_hash' => hash('sha256', $token)]);
        $server = $statement->fetch();

        if (!$server) {
            return null;
        }

        $database->prepare(
            'UPDATE server_tokens SET last_used_at = UTC_TIMESTAMP() WHERE uid = :token_uid'
        )->execute(['token_uid' => $server['token_uid']]);

        $database->prepare(
            'UPDATE servers SET last_seen_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() WHERE uid = :server_uid'
        )->execute(['server_uid' => $server['uid']]);

        return $server;
    }

    /** @return array<string,mixed> */
    public static function requireServer(): array
    {
        try {
            $server = self::server();
        } catch (\PDOException $exception) {
            error_log('[Devil-Guard] Server token authentication failed: ' . $exception->getMessage());
            Http::json(['ok' => false, 'error' => 'integration_schema_unavailable'], 503);
        }

        if ($server === null) {
            Http::json(['ok' => false, 'error' => 'unauthorized'], 401);
        }

        return $server;
    }

    /** @return array{token:string,tokenUid:string} */
    public static function issueToken(string $serverUid, string $label = 'primary'): array
    {
        $plain = 'dg_srv_' . rtrim(strtr(base64_encode(random_bytes(42)), '+/', '-_'), '=');
        $database = Database::connection();
        $tokenUid = \devil_guard_insert(
            $database,
            'server_tokens',
            'INSERT INTO server_tokens
                (uid, server_uid, token_hash, label, created_at)
             VALUES
                (:uid, :server_uid, :token_hash, :label, UTC_TIMESTAMP())',
            [
                'server_uid' => $serverUid,
                'token_hash' => hash('sha256', $plain),
                'label' => substr(trim($label), 0, 100) ?: 'primary',
            ]
        );

        return ['token' => $plain, 'tokenUid' => $tokenUid];
    }

    public static function revokeTokens(string $serverUid): void
    {
        Database::connection()->prepare(
            'UPDATE server_tokens
             SET revoked_at = UTC_TIMESTAMP()
             WHERE server_uid = :server_uid AND revoked_at IS NULL'
        )->execute(['server_uid' => $serverUid]);
    }

    public static function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        $hex = bin2hex($data);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }
}
