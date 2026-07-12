CREATE DATABASE IF NOT EXISTS devil_guard
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE devil_guard;

CREATE TABLE users (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(190) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','admin') NOT NULL DEFAULT 'user',
    status ENUM('pending','active','suspended') NOT NULL DEFAULT 'pending',
    last_login_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE installations (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_id VARCHAR(128) NOT NULL,
    label VARCHAR(100) NULL,
    client_version VARCHAR(40) NOT NULL DEFAULT '',
    os_version VARCHAR(190) NOT NULL DEFAULT '',
    runtime_version VARCHAR(100) NOT NULL DEFAULT '',
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_installations_public_id (public_id),
    KEY ix_installations_user (user_uid),
    CONSTRAINT fk_installations_user
        FOREIGN KEY (user_uid) REFERENCES users(uid)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE api_tokens (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    installation_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    token_hash CHAR(64) NOT NULL,
    created_ip VARCHAR(45) NOT NULL,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_api_tokens_hash (token_hash),
    KEY ix_api_tokens_user (user_uid),
    KEY ix_api_tokens_installation (installation_uid),
    CONSTRAINT fk_api_tokens_user
        FOREIGN KEY (user_uid) REFERENCES users(uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_api_tokens_installation
        FOREIGN KEY (installation_uid) REFERENCES installations(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE login_attempts (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    login_value VARCHAR(190) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    succeeded TINYINT(1) NOT NULL DEFAULT 0,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    KEY ix_login_attempts_ip_time (ip_address, attempted_at),
    KEY ix_login_attempts_login_time (login_value, attempted_at)
) ENGINE=InnoDB;

CREATE TABLE heartbeats (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    installation_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    client_version VARCHAR(40) NOT NULL,
    game_running TINYINT(1) NOT NULL DEFAULT 0,
    in_game TINYINT(1) NOT NULL DEFAULT 0,
    player_name VARCHAR(80) NOT NULL DEFAULT '',
    server_name VARCHAR(120) NOT NULL DEFAULT '',
    server_ip VARCHAR(45) NOT NULL DEFAULT '',
    process_hash CHAR(64) NULL,
    os_version VARCHAR(190) NOT NULL DEFAULT '',
    runtime_version VARCHAR(100) NOT NULL DEFAULT '',
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_heartbeats_installation (installation_uid),
    KEY ix_heartbeats_user_time (user_uid, received_at),
    KEY ix_heartbeats_installation_time (installation_uid, received_at),
    CONSTRAINT fk_heartbeats_user
        FOREIGN KEY (user_uid) REFERENCES users(uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_heartbeats_installation
        FOREIGN KEY (installation_uid) REFERENCES installations(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE client_events (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    installation_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    event_type VARCHAR(50) NOT NULL,
    severity ENUM('info','warning','error','security') NOT NULL DEFAULT 'info',
    message VARCHAR(2000) NOT NULL,
    context_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    KEY ix_events_created (created_at),
    KEY ix_events_severity (severity),
    KEY ix_events_user (user_uid),
    KEY ix_events_installation (installation_uid),
    CONSTRAINT fk_events_user
        FOREIGN KEY (user_uid) REFERENCES users(uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_events_installation
        FOREIGN KEY (installation_uid) REFERENCES installations(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE announcements (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    title VARCHAR(160) NOT NULL,
    body TEXT NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    starts_at DATETIME NULL,
    ends_at DATETIME NULL,
    created_by_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    KEY ix_announcements_active_dates (is_active, starts_at, ends_at),
    KEY ix_announcements_created_by (created_by_uid),
    CONSTRAINT fk_announcements_user
        FOREIGN KEY (created_by_uid) REFERENCES users(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE releases (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version VARCHAR(40) NOT NULL,
    channel VARCHAR(30) NOT NULL DEFAULT 'stable',
    file_name VARCHAR(255) NOT NULL,
    package_url VARCHAR(1000) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    min_windows_build INT UNSIGNED NOT NULL DEFAULT 17763,
    notes TEXT NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    published_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_releases_version_channel (version, channel),
    KEY ix_releases_active_channel (is_active, channel, published_at)
) ENGINE=InnoDB;

CREATE TABLE bans (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    player_name VARCHAR(100) NOT NULL,
    player_id VARCHAR(100) NOT NULL DEFAULT '',
    reason VARCHAR(1000) NOT NULL,
    evidence_url VARCHAR(1000) NULL,
    starts_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ends_at DATETIME NULL,
    status ENUM('active','expired','overturned') NOT NULL DEFAULT 'active',
    created_by_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    KEY ix_bans_player_name (player_name),
    KEY ix_bans_player_id (player_id),
    KEY ix_bans_status (status),
    KEY ix_bans_created_by (created_by_uid),
    CONSTRAINT fk_bans_user
        FOREIGN KEY (created_by_uid) REFERENCES users(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE servers (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name VARCHAR(120) NOT NULL,
    game_name VARCHAR(100) NOT NULL DEFAULT 'dfbhd',
    status ENUM('active','disabled') NOT NULL DEFAULT 'active',
    deny_on_any_signal TINYINT(1) NOT NULL DEFAULT 1,
    max_report_age_seconds INT UNSIGNED NOT NULL DEFAULT 120,
    last_seen_at DATETIME NULL,
    created_by_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_servers_public_id (public_id),
    KEY ix_servers_status (status),
    KEY ix_servers_created_by (created_by_uid),
    CONSTRAINT fk_servers_created_by
        FOREIGN KEY (created_by_uid) REFERENCES users(uid)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE server_tokens (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    server_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    label VARCHAR(100) NOT NULL DEFAULT 'primary',
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_server_tokens_hash (token_hash),
    KEY ix_server_tokens_server (server_uid),
    CONSTRAINT fk_server_tokens_server
        FOREIGN KEY (server_uid) REFERENCES servers(uid)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE attestation_reports (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    server_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    machine_id VARCHAR(190) NOT NULL,
    player_name VARCHAR(100) NOT NULL DEFAULT '',
    game_name VARCHAR(100) NOT NULL DEFAULT '',
    game_directory VARCHAR(1000) NOT NULL DEFAULT '',
    process_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    game_running TINYINT(1) NOT NULL DEFAULT 0,
    hook_detected TINYINT(1) NOT NULL DEFAULT 0,
    suspicious_modules_detected TINYINT(1) NOT NULL DEFAULT 0,
    directory_integrity_changed TINYINT(1) NOT NULL DEFAULT 0,
    signals_json JSON NULL,
    reported_at DATETIME NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL DEFAULT '',
    PRIMARY KEY (uid),
    UNIQUE KEY uq_attestation_reports_server_machine (server_uid, machine_id),
    KEY ix_attestation_reports_received (received_at),
    KEY ix_attestation_reports_player (player_name),
    CONSTRAINT fk_attestation_reports_server
        FOREIGN KEY (server_uid) REFERENCES servers(uid)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE attestation_decisions (
    uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    report_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    server_uid CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    machine_id VARCHAR(190) NOT NULL,
    allow_join TINYINT(1) NOT NULL DEFAULT 0,
    reason VARCHAR(1000) NOT NULL,
    decided_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (uid),
    UNIQUE KEY uq_attestation_decisions_report (report_uid),
    KEY ix_attestation_decisions_server_machine (server_uid, machine_id),
    KEY ix_attestation_decisions_decided (decided_at),
    CONSTRAINT fk_attestation_decisions_report
        FOREIGN KEY (report_uid) REFERENCES attestation_reports(uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_attestation_decisions_server
        FOREIGN KEY (server_uid) REFERENCES servers(uid)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE settings (
    setting_key VARCHAR(100) NOT NULL,
    setting_value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (setting_key)
) ENGINE=InnoDB;

INSERT INTO settings (setting_key, setting_value) VALUES
    ('service_status', 'online'),
    ('minimum_client_version', '1.0.0'),
    ('maintenance_message', '')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);
