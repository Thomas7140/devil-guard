<?php
declare(strict_types=1);

/*
 * Devil-Guard four-character UID helpers.
 *
 * The database uses CHAR(4) primary keys, so every INSERT must supply a UID.
 * These functions use an unambiguous 32-character alphabet and retry safely
 * if a generated UID already exists.
 */

if (realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    http_response_code(404);
    exit;
}

if (!function_exists('devil_guard_random_uid')) {
    function devil_guard_random_uid(): string
    {
        static $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $uid = '';

        for ($i = 0; $i < 4; $i++) {
            $uid .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return $uid;
    }
}

if (!function_exists('devil_guard_uid_table')) {
    function devil_guard_uid_table(string $table): string
    {
        static $allowedTables = [
            'users',
            'installations',
            'api_tokens',
            'login_attempts',
            'heartbeats',
            'client_events',
            'announcements',
            'releases',
            'bans',
            'servers',
            'server_tokens',
            'attestation_reports',
            'attestation_decisions',
        ];

        if (!in_array($table, $allowedTables, true)) {
            throw new \InvalidArgumentException('UID generation is not enabled for this table.');
        }

        return $table;
    }
}

if (!function_exists('devil_guard_uid')) {
    function devil_guard_uid(\PDO $database, string $table): string
    {
        $table = devil_guard_uid_table($table);
        $statement = $database->prepare("SELECT 1 FROM `{$table}` WHERE `uid` = :uid LIMIT 1");

        for ($attempt = 0; $attempt < 128; $attempt++) {
            $uid = devil_guard_random_uid();
            $statement->execute(['uid' => $uid]);

            if ($statement->fetchColumn() === false) {
                return $uid;
            }
        }

        throw new \RuntimeException("Unable to allocate a unique UID for {$table}.");
    }
}

if (!function_exists('devil_guard_insert')) {
    /**
     * Executes an INSERT containing a :uid placeholder and returns the UID.
     *
     * @param array<string,mixed> $parameters
     */
    function devil_guard_insert(\PDO $database, string $table, string $sql, array $parameters = []): string
    {
        $table = devil_guard_uid_table($table);
        $statement = $database->prepare($sql);
        $collisionCheck = $database->prepare("SELECT 1 FROM `{$table}` WHERE `uid` = :uid LIMIT 1");

        for ($attempt = 0; $attempt < 128; $attempt++) {
            $uid = devil_guard_random_uid();

            try {
                $statement->execute(['uid' => $uid] + $parameters);
                return $uid;
            } catch (\PDOException $exception) {
                $duplicateKey = $exception->getCode() === '23000'
                    && (int)($exception->errorInfo[1] ?? 0) === 1062;

                if (!$duplicateKey) {
                    throw $exception;
                }

                $collisionCheck->execute(['uid' => $uid]);
                if ($collisionCheck->fetchColumn() === false) {
                    // Another UNIQUE key, such as username or public_id, failed.
                    throw $exception;
                }
            }
        }

        throw new \RuntimeException("Unable to insert a unique UID into {$table}.");
    }
}
