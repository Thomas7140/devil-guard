-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Jul 12, 2026 at 10:57 AM
-- Server version: 10.11.18-MariaDB
-- PHP Version: 8.4.22

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `devilishservices_devil_guard`
--

-- --------------------------------------------------------

--
-- Table structure for table `announcements`
--

CREATE TABLE `announcements` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `title` varchar(160) NOT NULL,
  `body` text NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `starts_at` datetime DEFAULT NULL,
  `ends_at` datetime DEFAULT NULL,
  `created_by_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `api_tokens`
--

CREATE TABLE `api_tokens` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `installation_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `token_hash` char(64) NOT NULL,
  `created_ip` varchar(45) NOT NULL,
  `expires_at` datetime NOT NULL,
  `last_used_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `attestation_decisions`
--

CREATE TABLE `attestation_decisions` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `report_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `server_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `machine_id` varchar(190) NOT NULL,
  `allow_join` tinyint(1) NOT NULL DEFAULT 0,
  `reason` varchar(1000) NOT NULL,
  `decided_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `attestation_reports`
--

CREATE TABLE `attestation_reports` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `server_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `machine_id` varchar(190) NOT NULL,
  `player_name` varchar(100) NOT NULL DEFAULT '',
  `game_name` varchar(100) NOT NULL DEFAULT '',
  `game_directory` varchar(1000) NOT NULL DEFAULT '',
  `process_id` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `game_running` tinyint(1) NOT NULL DEFAULT 0,
  `hook_detected` tinyint(1) NOT NULL DEFAULT 0,
  `suspicious_modules_detected` tinyint(1) NOT NULL DEFAULT 0,
  `directory_integrity_changed` tinyint(1) NOT NULL DEFAULT 0,
  `signals_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`signals_json`)),
  `reported_at` datetime NOT NULL,
  `received_at` datetime NOT NULL DEFAULT current_timestamp(),
  `source_ip` varchar(45) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `bans`
--

CREATE TABLE `bans` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `player_name` varchar(100) NOT NULL,
  `player_id` varchar(100) NOT NULL DEFAULT '',
  `reason` varchar(1000) NOT NULL,
  `evidence_url` varchar(1000) DEFAULT NULL,
  `starts_at` datetime NOT NULL DEFAULT current_timestamp(),
  `ends_at` datetime DEFAULT NULL,
  `status` enum('active','expired','overturned') NOT NULL DEFAULT 'active',
  `created_by_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_events`
--

CREATE TABLE `client_events` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `installation_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `event_type` varchar(50) NOT NULL,
  `severity` enum('info','warning','error','security') NOT NULL DEFAULT 'info',
  `message` varchar(2000) NOT NULL,
  `context_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`context_json`)),
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `heartbeats`
--

CREATE TABLE `heartbeats` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `installation_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `client_version` varchar(40) NOT NULL,
  `game_running` tinyint(1) NOT NULL DEFAULT 0,
  `in_game` tinyint(1) NOT NULL DEFAULT 0,
  `player_name` varchar(80) NOT NULL DEFAULT '',
  `server_name` varchar(120) NOT NULL DEFAULT '',
  `server_ip` varchar(45) NOT NULL DEFAULT '',
  `process_hash` char(64) DEFAULT NULL,
  `os_version` varchar(190) NOT NULL DEFAULT '',
  `runtime_version` varchar(100) NOT NULL DEFAULT '',
  `received_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `installations`
--

CREATE TABLE `installations` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `public_id` varchar(128) NOT NULL,
  `label` varchar(100) DEFAULT NULL,
  `client_version` varchar(40) NOT NULL DEFAULT '',
  `os_version` varchar(190) NOT NULL DEFAULT '',
  `runtime_version` varchar(100) NOT NULL DEFAULT '',
  `first_seen_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_seen_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `login_value` varchar(190) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `succeeded` tinyint(1) NOT NULL DEFAULT 0,
  `attempted_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `releases`
--

CREATE TABLE `releases` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `version` varchar(40) NOT NULL,
  `channel` varchar(30) NOT NULL DEFAULT 'stable',
  `file_name` varchar(255) NOT NULL,
  `package_url` varchar(1000) NOT NULL,
  `sha256` char(64) NOT NULL,
  `min_windows_build` int(10) UNSIGNED NOT NULL DEFAULT 17763,
  `notes` text NOT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `published_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE `servers` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `public_id` char(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `name` varchar(120) NOT NULL,
  `game_name` varchar(100) NOT NULL DEFAULT 'dfbhd',
  `status` enum('active','disabled') NOT NULL DEFAULT 'active',
  `deny_on_any_signal` tinyint(1) NOT NULL DEFAULT 1,
  `max_report_age_seconds` int(10) UNSIGNED NOT NULL DEFAULT 120,
  `last_seen_at` datetime DEFAULT NULL,
  `created_by_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `server_tokens`
--

CREATE TABLE `server_tokens` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `server_uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `token_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `label` varchar(100) NOT NULL DEFAULT 'primary',
  `last_used_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `settings`
--

CREATE TABLE `settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text NOT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `settings`
--

INSERT INTO `settings` (`setting_key`, `setting_value`, `updated_at`) VALUES
('maintenance_message', '', '2026-07-12 09:00:41'),
('minimum_client_version', '1.0.0', '2026-07-12 09:00:41'),
('service_status', 'online', '2026-07-12 09:00:41');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `uid` char(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(190) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('user','admin') NOT NULL DEFAULT 'user',
  `status` enum('pending','active','suspended') NOT NULL DEFAULT 'pending',
  `last_login_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`uid`, `username`, `email`, `display_name`, `password_hash`, `role`, `status`, `last_login_at`, `created_at`, `updated_at`) VALUES
('THMS', 'Devilish', 'thomas@devilishservices.com', 'Devilish', '$argon2id$v=19$m=65536,t=4,p=1$Wkg2QjNBbW5JY3gydlQxVw$mL7aNI2ef6jkHAXBuOpfK+IkZOLQZd6X6+U1PwAgNCg', 'admin', 'active', NULL, '2026-07-12 00:10:13', '2026-07-12 00:10:13');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `announcements`
--
ALTER TABLE `announcements`
  ADD PRIMARY KEY (`uid`),
  ADD KEY `ix_announcements_active_dates` (`is_active`,`starts_at`,`ends_at`),
  ADD KEY `ix_announcements_created_by` (`created_by_uid`);

--
-- Indexes for table `api_tokens`
--
ALTER TABLE `api_tokens`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_api_tokens_hash` (`token_hash`),
  ADD KEY `ix_api_tokens_user` (`user_uid`),
  ADD KEY `ix_api_tokens_installation` (`installation_uid`);

--
-- Indexes for table `attestation_decisions`
--
ALTER TABLE `attestation_decisions`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_attestation_decisions_report` (`report_uid`),
  ADD KEY `ix_attestation_decisions_server_machine` (`server_uid`,`machine_id`),
  ADD KEY `ix_attestation_decisions_decided` (`decided_at`);

--
-- Indexes for table `attestation_reports`
--
ALTER TABLE `attestation_reports`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_attestation_reports_server_machine` (`server_uid`,`machine_id`),
  ADD KEY `ix_attestation_reports_received` (`received_at`),
  ADD KEY `ix_attestation_reports_player` (`player_name`);

--
-- Indexes for table `bans`
--
ALTER TABLE `bans`
  ADD PRIMARY KEY (`uid`),
  ADD KEY `ix_bans_player_name` (`player_name`),
  ADD KEY `ix_bans_player_id` (`player_id`),
  ADD KEY `ix_bans_status` (`status`),
  ADD KEY `ix_bans_created_by` (`created_by_uid`);

--
-- Indexes for table `client_events`
--
ALTER TABLE `client_events`
  ADD PRIMARY KEY (`uid`),
  ADD KEY `ix_events_created` (`created_at`),
  ADD KEY `ix_events_severity` (`severity`),
  ADD KEY `ix_events_user` (`user_uid`),
  ADD KEY `ix_events_installation` (`installation_uid`);

--
-- Indexes for table `heartbeats`
--
ALTER TABLE `heartbeats`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_heartbeats_installation` (`installation_uid`),
  ADD KEY `ix_heartbeats_user_time` (`user_uid`,`received_at`),
  ADD KEY `ix_heartbeats_installation_time` (`installation_uid`,`received_at`);

--
-- Indexes for table `installations`
--
ALTER TABLE `installations`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_installations_public_id` (`public_id`),
  ADD KEY `ix_installations_user` (`user_uid`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`uid`),
  ADD KEY `ix_login_attempts_ip_time` (`ip_address`,`attempted_at`),
  ADD KEY `ix_login_attempts_login_time` (`login_value`,`attempted_at`);

--
-- Indexes for table `releases`
--
ALTER TABLE `releases`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_releases_version_channel` (`version`,`channel`),
  ADD KEY `ix_releases_active_channel` (`is_active`,`channel`,`published_at`);

--
-- Indexes for table `servers`
--
ALTER TABLE `servers`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_servers_public_id` (`public_id`),
  ADD KEY `ix_servers_status` (`status`),
  ADD KEY `ix_servers_created_by` (`created_by_uid`);

--
-- Indexes for table `server_tokens`
--
ALTER TABLE `server_tokens`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_server_tokens_hash` (`token_hash`),
  ADD KEY `ix_server_tokens_server` (`server_uid`);

--
-- Indexes for table `settings`
--
ALTER TABLE `settings`
  ADD PRIMARY KEY (`setting_key`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`uid`),
  ADD UNIQUE KEY `uq_users_username` (`username`),
  ADD UNIQUE KEY `uq_users_email` (`email`);

--
-- Constraints for dumped tables
--

--
-- Constraints for table `announcements`
--
ALTER TABLE `announcements`
  ADD CONSTRAINT `fk_announcements_user` FOREIGN KEY (`created_by_uid`) REFERENCES `users` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `api_tokens`
--
ALTER TABLE `api_tokens`
  ADD CONSTRAINT `fk_api_tokens_installation` FOREIGN KEY (`installation_uid`) REFERENCES `installations` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_api_tokens_user` FOREIGN KEY (`user_uid`) REFERENCES `users` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `attestation_decisions`
--
ALTER TABLE `attestation_decisions`
  ADD CONSTRAINT `fk_attestation_decisions_report` FOREIGN KEY (`report_uid`) REFERENCES `attestation_reports` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_attestation_decisions_server` FOREIGN KEY (`server_uid`) REFERENCES `servers` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `attestation_reports`
--
ALTER TABLE `attestation_reports`
  ADD CONSTRAINT `fk_attestation_reports_server` FOREIGN KEY (`server_uid`) REFERENCES `servers` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `bans`
--
ALTER TABLE `bans`
  ADD CONSTRAINT `fk_bans_user` FOREIGN KEY (`created_by_uid`) REFERENCES `users` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `client_events`
--
ALTER TABLE `client_events`
  ADD CONSTRAINT `fk_events_installation` FOREIGN KEY (`installation_uid`) REFERENCES `installations` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_events_user` FOREIGN KEY (`user_uid`) REFERENCES `users` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `heartbeats`
--
ALTER TABLE `heartbeats`
  ADD CONSTRAINT `fk_heartbeats_installation` FOREIGN KEY (`installation_uid`) REFERENCES `installations` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_heartbeats_user` FOREIGN KEY (`user_uid`) REFERENCES `users` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `installations`
--
ALTER TABLE `installations`
  ADD CONSTRAINT `fk_installations_user` FOREIGN KEY (`user_uid`) REFERENCES `users` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `servers`
--
ALTER TABLE `servers`
  ADD CONSTRAINT `fk_servers_created_by` FOREIGN KEY (`created_by_uid`) REFERENCES `users` (`uid`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `server_tokens`
--
ALTER TABLE `server_tokens`
  ADD CONSTRAINT `fk_server_tokens_server` FOREIGN KEY (`server_uid`) REFERENCES `servers` (`uid`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
