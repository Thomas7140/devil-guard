-- Devil-Guard client/server integration migration.
-- Import this file into the existing Devil-Guard database selected in phpMyAdmin.

ALTER TABLE installations
    MODIFY public_id VARCHAR(128) NOT NULL;

CREATE TABLE IF NOT EXISTS servers (
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

CREATE TABLE IF NOT EXISTS server_tokens (
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

CREATE TABLE IF NOT EXISTS attestation_reports (
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

CREATE TABLE IF NOT EXISTS attestation_decisions (
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
