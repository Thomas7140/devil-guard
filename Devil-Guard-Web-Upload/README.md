# Devil-Guard web portal

PHP 8.2+ administration, update, client API and persistent Gatekeeper service for the supplied Devil-Guard .NET software.

## Requirements

- PHP 8.2 or later with PDO MySQL and Argon2 support
- MySQL 8.0 or MariaDB 10.6+
- Apache with `mod_rewrite`, or the supplied Nginx route configuration
- HTTPS with a valid certificate

## Fresh installation

1. Upload the entire `Devil-Guard-Web-Upload/` directory.
2. Copy `config/.env.example` to `/home/devilishservices/connections/devil_guard/.env` and enter the real database credentials and a random `APP_KEY`.
3. Import `database/schema.sql` in phpMyAdmin.
4. Create an administrator with `php scripts/create-admin.php ...` or use the supplied administrator SQL if already prepared.
5. Sign in at `/admin/`, open **Servers**, and issue a Sentinel server token.
6. Follow `CLIENT-SERVER-INTEGRATION.md` to configure the Windows service.
7. Add a daily cron entry for `php scripts/prune.php`.

## Existing database upgrade

Upload the new files, select the existing Devil-Guard database in phpMyAdmin, and import only:

`database/integration-migration.sql`

The admin panel remains usable before migration and displays a migration notice. Attestation routes return a service-unavailable response until the integration tables exist.

## API contract

User/client API:

- `GET /api/v1/status`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/me`
- `POST /api/v1/heartbeat`
- `POST /api/v1/events`
- `GET /api/v1/announcements`
- `GET /api/v1/releases/latest?channel=stable`
- `GET /api/v1/bans`

Gatekeeper-compatible API used by the current Sentinel:

- `POST /api/attestation/report`
- `GET /api/attestation/decision/{machineId}`
- `GET /api/attestation/recent`

The user/client API uses bearer tokens. Gatekeeper routes use an opaque `X-DevilGuard-Token`; only its SHA-256 hash is stored.

## Four-character UIDs

All keyed tables use `uid CHAR(4)`. Heartbeats and attestations are current-state tables: they update one row per installation or server/machine rather than allocating a new UID on every report.
