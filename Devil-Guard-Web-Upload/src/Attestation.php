<?php
declare(strict_types=1);

namespace DevilGuard\Web;

final class Attestation
{
    /** @param array<string,mixed> $body
     *  @return array<string,mixed>
     */
    public static function normalise(array $body): array
    {
        $machineId = self::text(self::value($body, ['MachineId', 'machineId']), 190);
        if ($machineId === '' || preg_match('/[\x00-\x1F\x7F]/', $machineId) === 1) {
            throw new \InvalidArgumentException('MachineId is required.');
        }

        $signalsRaw = self::value($body, ['Signals', 'signals']);
        $signals = [];
        if (is_array($signalsRaw)) {
            foreach (array_slice($signalsRaw, 0, 50) as $signal) {
                if (!is_scalar($signal)) {
                    continue;
                }
                $clean = self::text($signal, 200);
                if ($clean !== '') {
                    $signals[] = $clean;
                }
            }
        }
        $signals = array_values(array_unique($signals));

        $reported = self::text(self::value($body, ['ReportedAtUtc', 'reportedAtUtc']), 80);
        $reportedAt = gmdate('Y-m-d H:i:s');
        if ($reported !== '') {
            try {
                $date = new \DateTimeImmutable($reported);
                $reportedAt = $date->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
            } catch (\Throwable) {
                // Keep the receipt time when the client timestamp is malformed.
            }
        }

        return [
            'machine_id' => $machineId,
            'player_name' => self::text(self::value($body, ['PlayerName', 'playerName']), 100),
            'game_name' => self::text(self::value($body, ['GameName', 'gameName']), 100),
            'game_directory' => self::text(self::value($body, ['GameDirectory', 'gameDirectory']), 1000),
            'process_id' => max(0, min(4294967295, (int)(self::value($body, ['ProcessId', 'processId']) ?? 0))),
            'game_running' => self::boolean(self::value($body, ['GameRunning', 'gameRunning'])),
            'hook_detected' => self::boolean(self::value($body, ['HookDetected', 'hookDetected'])),
            'suspicious_modules_detected' => self::boolean(self::value($body, ['SuspiciousModulesDetected', 'suspiciousModulesDetected'])),
            'directory_integrity_changed' => self::boolean(self::value($body, ['DirectoryIntegrityChanged', 'directoryIntegrityChanged'])),
            'signals' => $signals,
            'reported_at' => $reportedAt,
        ];
    }

    /** @param array<string,mixed> $server
     *  @param array<string,mixed> $report
     *  @return array<string,mixed>
     */
    public static function receive(\PDO $database, array $server, array $report): array
    {
        $decision = self::evaluate($database, $server, $report);
        $database->beginTransaction();

        try {
            $lookup = $database->prepare(
                'SELECT uid FROM attestation_reports
                 WHERE server_uid = :server_uid AND machine_id = :machine_id
                 LIMIT 1'
            );
            $lookup->execute([
                'server_uid' => $server['uid'],
                'machine_id' => $report['machine_id'],
            ]);
            $reportUid = (string)($lookup->fetchColumn() ?: '');

            $reportValues = [
                'server_uid' => $server['uid'],
                'machine_id' => $report['machine_id'],
                'player_name' => $report['player_name'],
                'game_name' => $report['game_name'],
                'game_directory' => $report['game_directory'],
                'process_id' => $report['process_id'],
                'game_running' => $report['game_running'] ? 1 : 0,
                'hook_detected' => $report['hook_detected'] ? 1 : 0,
                'suspicious_modules_detected' => $report['suspicious_modules_detected'] ? 1 : 0,
                'directory_integrity_changed' => $report['directory_integrity_changed'] ? 1 : 0,
                'signals_json' => json_encode($report['signals'], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
                'reported_at' => $report['reported_at'],
                'source_ip' => Http::clientIp(),
            ];

            if ($reportUid === '') {
                try {
                    $reportUid = \devil_guard_insert(
                        $database,
                        'attestation_reports',
                        'INSERT INTO attestation_reports
                            (uid, server_uid, machine_id, player_name, game_name, game_directory, process_id,
                             game_running, hook_detected, suspicious_modules_detected, directory_integrity_changed,
                             signals_json, reported_at, received_at, source_ip)
                         VALUES
                            (:uid, :server_uid, :machine_id, :player_name, :game_name, :game_directory, :process_id,
                             :game_running, :hook_detected, :suspicious_modules_detected, :directory_integrity_changed,
                             :signals_json, :reported_at, UTC_TIMESTAMP(), :source_ip)',
                        $reportValues
                    );
                } catch (\PDOException $exception) {
                    $duplicateKey = $exception->getCode() === '23000'
                        && (int)($exception->errorInfo[1] ?? 0) === 1062;
                    if (!$duplicateKey) {
                        throw $exception;
                    }
                    $lookup->execute([
                        'server_uid' => $server['uid'],
                        'machine_id' => $report['machine_id'],
                    ]);
                    $reportUid = (string)($lookup->fetchColumn() ?: '');
                    if ($reportUid === '') {
                        throw $exception;
                    }
                }
            }

            if ($reportUid !== '') {
                $database->prepare(
                    'UPDATE attestation_reports SET
                        player_name = :player_name,
                        game_name = :game_name,
                        game_directory = :game_directory,
                        process_id = :process_id,
                        game_running = :game_running,
                        hook_detected = :hook_detected,
                        suspicious_modules_detected = :suspicious_modules_detected,
                        directory_integrity_changed = :directory_integrity_changed,
                        signals_json = :signals_json,
                        reported_at = :reported_at,
                        received_at = UTC_TIMESTAMP(),
                        source_ip = :source_ip
                     WHERE uid = :report_uid'
                )->execute([
                    'player_name' => $reportValues['player_name'],
                    'game_name' => $reportValues['game_name'],
                    'game_directory' => $reportValues['game_directory'],
                    'process_id' => $reportValues['process_id'],
                    'game_running' => $reportValues['game_running'],
                    'hook_detected' => $reportValues['hook_detected'],
                    'suspicious_modules_detected' => $reportValues['suspicious_modules_detected'],
                    'directory_integrity_changed' => $reportValues['directory_integrity_changed'],
                    'signals_json' => $reportValues['signals_json'],
                    'reported_at' => $reportValues['reported_at'],
                    'source_ip' => $reportValues['source_ip'],
                    'report_uid' => $reportUid,
                ]);
            }

            $decisionLookup = $database->prepare(
                'SELECT uid FROM attestation_decisions WHERE report_uid = :report_uid LIMIT 1'
            );
            $decisionLookup->execute(['report_uid' => $reportUid]);
            $decisionUid = (string)($decisionLookup->fetchColumn() ?: '');
            $decisionValues = [
                'report_uid' => $reportUid,
                'server_uid' => $server['uid'],
                'machine_id' => $report['machine_id'],
                'allow_join' => $decision['allowJoin'] ? 1 : 0,
                'reason' => $decision['reason'],
            ];

            if ($decisionUid === '') {
                try {
                    $decisionUid = \devil_guard_insert(
                        $database,
                        'attestation_decisions',
                        'INSERT INTO attestation_decisions
                            (uid, report_uid, server_uid, machine_id, allow_join, reason, decided_at)
                         VALUES
                            (:uid, :report_uid, :server_uid, :machine_id, :allow_join, :reason, UTC_TIMESTAMP())',
                        $decisionValues
                    );
                } catch (\PDOException $exception) {
                    $duplicateKey = $exception->getCode() === '23000'
                        && (int)($exception->errorInfo[1] ?? 0) === 1062;
                    if (!$duplicateKey) {
                        throw $exception;
                    }
                    $decisionLookup->execute(['report_uid' => $reportUid]);
                    $decisionUid = (string)($decisionLookup->fetchColumn() ?: '');
                    if ($decisionUid === '') {
                        throw $exception;
                    }
                }
            }

            if ($decisionUid !== '') {
                $database->prepare(
                    'UPDATE attestation_decisions SET
                        server_uid = :server_uid,
                        machine_id = :machine_id,
                        allow_join = :allow_join,
                        reason = :reason,
                        decided_at = UTC_TIMESTAMP()
                     WHERE uid = :decision_uid'
                )->execute([
                    'server_uid' => $decisionValues['server_uid'],
                    'machine_id' => $decisionValues['machine_id'],
                    'allow_join' => $decisionValues['allow_join'],
                    'reason' => $decisionValues['reason'],
                    'decision_uid' => $decisionUid,
                ]);
            }

            $database->commit();
        } catch (\Throwable $exception) {
            if ($database->inTransaction()) {
                $database->rollBack();
            }
            throw $exception;
        }

        return self::decisionPayload(
            (string)$report['machine_id'],
            (bool)$decision['allowJoin'],
            (string)$decision['reason']
        );
    }

    /** @param array<string,mixed> $server
     *  @return array<string,mixed>|null
     */
    public static function latestDecision(\PDO $database, array $server, string $machineId): ?array
    {
        $statement = $database->prepare(
            'SELECT r.machine_id, r.player_name, r.received_at,
                    d.allow_join, d.reason, d.decided_at
             FROM attestation_reports r
             INNER JOIN attestation_decisions d ON d.report_uid = r.uid
             WHERE r.server_uid = :server_uid AND r.machine_id = :machine_id
             LIMIT 1'
        );
        $statement->execute([
            'server_uid' => $server['uid'],
            'machine_id' => $machineId,
        ]);
        $row = $statement->fetch();
        if (!$row) {
            return null;
        }

        $ban = self::activeBan($database, (string)$row['player_name'], $machineId);
        if ($ban !== null) {
            return self::decisionPayload($machineId, false, 'Active restriction: ' . $ban['reason']);
        }

        $receivedAt = strtotime((string)$row['received_at'] . ' UTC');
        $maxAge = max(10, min(86400, (int)$server['max_report_age_seconds']));
        if ($receivedAt === false || (time() - $receivedAt) > $maxAge) {
            return self::decisionPayload($machineId, false, 'Latest attestation is stale.');
        }

        return self::decisionPayload(
            $machineId,
            (bool)$row['allow_join'],
            (string)$row['reason'],
            self::atom((string)$row['decided_at'])
        );
    }

    /** @param array<string,mixed> $server
     *  @return array<int,array<string,mixed>>
     */
    public static function recent(\PDO $database, array $server, int $limit = 200): array
    {
        $limit = max(1, min(200, $limit));
        $statement = $database->prepare(
            'SELECT r.machine_id, r.player_name, r.game_name, r.reported_at, r.received_at,
                    r.signals_json, d.allow_join, d.reason
             FROM attestation_reports r
             INNER JOIN attestation_decisions d ON d.report_uid = r.uid
             WHERE r.server_uid = :server_uid
             ORDER BY r.received_at DESC
             LIMIT ' . $limit
        );
        $statement->execute(['server_uid' => $server['uid']]);

        $rows = [];
        foreach ($statement->fetchAll() as $row) {
            $signals = json_decode((string)($row['signals_json'] ?? '[]'), true);
            $rows[] = [
                'machineId' => $row['machine_id'],
                'playerName' => $row['player_name'],
                'gameName' => $row['game_name'],
                'allowJoin' => (bool)$row['allow_join'],
                'reason' => $row['reason'],
                'reportedAtUtc' => self::atom((string)$row['reported_at']),
                'receivedAtUtc' => self::atom((string)$row['received_at']),
                'signals' => is_array($signals) ? $signals : [],
            ];
        }

        return $rows;
    }

    /** @param array<string,mixed> $server
     *  @param array<string,mixed> $report
     *  @return array{allowJoin:bool,reason:string}
     */
    private static function evaluate(\PDO $database, array $server, array $report): array
    {
        $ban = self::activeBan(
            $database,
            (string)$report['player_name'],
            (string)$report['machine_id']
        );
        if ($ban !== null) {
            return ['allowJoin' => false, 'reason' => 'Active restriction: ' . $ban['reason']];
        }

        if (!$report['game_running']) {
            return ['allowJoin' => false, 'reason' => 'Game process is not running on client.'];
        }

        $signals = $report['signals'];
        $dockerDetected = false;
        foreach ($signals as $signal) {
            if (strcasecmp((string)$signal, 'environment:docker') === 0) {
                $dockerDetected = true;
                break;
            }
        }
        if ($dockerDetected) {
            return ['allowJoin' => false, 'reason' => 'Docker runtime detected on client.'];
        }

        $hasSignals = (bool)$report['hook_detected']
            || (bool)$report['suspicious_modules_detected']
            || (bool)$report['directory_integrity_changed']
            || count($signals) > 0;

        if ((bool)$server['deny_on_any_signal'] && $hasSignals) {
            return ['allowJoin' => false, 'reason' => 'Suspicious anti-cheat signal present.'];
        }

        return ['allowJoin' => true, 'reason' => 'Attestation accepted.'];
    }

    /** @return array{uid:string,reason:string}|null */
    private static function activeBan(\PDO $database, string $playerName, string $machineId): ?array
    {
        $clauses = [];
        $parameters = [];
        if ($playerName !== '') {
            $clauses[] = 'player_name = :player_name';
            $parameters['player_name'] = $playerName;
        }
        if ($machineId !== '') {
            $clauses[] = 'player_id = :machine_id';
            $parameters['machine_id'] = $machineId;
        }
        if ($clauses === []) {
            return null;
        }

        $statement = $database->prepare(
            "SELECT uid, reason
             FROM bans
             WHERE status = 'active'
               AND starts_at <= UTC_TIMESTAMP()
               AND (ends_at IS NULL OR ends_at >= UTC_TIMESTAMP())
               AND (" . implode(' OR ', $clauses) . ")
             ORDER BY created_at DESC
             LIMIT 1"
        );
        $statement->execute($parameters);
        $ban = $statement->fetch();

        return $ban ?: null;
    }

    /** @return array<string,mixed> */
    private static function decisionPayload(string $machineId, bool $allowJoin, string $reason, ?string $decisionAt = null): array
    {
        return [
            'machineId' => $machineId,
            'allowJoin' => $allowJoin,
            'reason' => $reason,
            'decisionAtUtc' => $decisionAt ?? gmdate('Y-m-d\TH:i:s\Z'),
        ];
    }

    /** @param array<string,mixed> $body
     *  @param array<int,string> $keys
     */
    private static function value(array $body, array $keys): mixed
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $body)) {
                return $body[$key];
            }
        }
        return null;
    }

    private static function text(mixed $value, int $maxLength): string
    {
        if (!is_scalar($value) && $value !== null) {
            return '';
        }
        return substr(trim((string)$value), 0, $maxLength);
    }

    private static function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return (int)$value !== 0;
        }
        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? false;
    }

    private static function atom(string $databaseDate): string
    {
        $timestamp = strtotime($databaseDate . ' UTC');
        return $timestamp === false ? gmdate('Y-m-d\TH:i:s\Z') : gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }
}
