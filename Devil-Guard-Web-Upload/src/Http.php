<?php
declare(strict_types=1);

namespace DevilGuard\Web;

final class Http
{
    /** @return array<string,mixed> */
    public static function jsonBody(int $maxBytes = 131072): array
    {
        $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > $maxBytes) {
            self::json(['ok' => false, 'error' => 'request_too_large'], 413);
        }
        $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
        if ($raw === false || strlen($raw) > $maxBytes) {
            self::json(['ok' => false, 'error' => 'request_too_large'], 413);
        }
        if ($raw === '') {
            return [];
        }
        try {
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            self::json(['ok' => false, 'error' => 'invalid_json'], 400);
        }
        if (!is_array($decoded)) {
            self::json(['ok' => false, 'error' => 'invalid_json'], 400);
        }
        return $decoded;
    }

    /** @param array<string,mixed> $payload */
    public static function json(array $payload, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, max-age=0');
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function bearerToken(): ?string
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/^Bearer\s+([A-Za-z0-9._~-]+)$/i', $header, $matches) !== 1) {
            return null;
        }
        return $matches[1];
    }

    public static function clientIp(): string
    {
        return substr((string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'), 0, 45);
    }

    public static function securityHeaders(bool $html = false): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        if ($html) {
            header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
        }
    }
}
