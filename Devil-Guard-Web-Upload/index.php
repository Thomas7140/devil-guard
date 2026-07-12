<?php
declare(strict_types=1);

use DevilGuard\Web\Database;
use DevilGuard\Web\Env;
use DevilGuard\Web\Http;

require_once __DIR__ . '/src/bootstrap.php';
Http::securityHeaders(true);
$db = Database::connection();
$announcements = $db->query("SELECT title, body, created_at FROM announcements WHERE is_active = 1 AND (starts_at IS NULL OR starts_at <= UTC_TIMESTAMP()) AND (ends_at IS NULL OR ends_at >= UTC_TIMESTAMP()) ORDER BY created_at DESC LIMIT 3")->fetchAll();
$release = $db->query("SELECT version, notes, published_at FROM releases WHERE channel='stable' AND is_active=1 ORDER BY published_at DESC LIMIT 1")->fetch();
$activeUsers = (int)$db->query("SELECT COUNT(*) FROM users WHERE status='active'")->fetchColumn();
$onlineClients = (int)$db->query("SELECT COUNT(DISTINCT installation_uid) FROM heartbeats WHERE received_at >= UTC_TIMESTAMP() - INTERVAL 2 MINUTE")->fetchColumn();
$activeBans = (int)$db->query("SELECT COUNT(*) FROM bans WHERE status='active' AND (ends_at IS NULL OR ends_at > UTC_TIMESTAMP())")->fetchColumn();
$appName = htmlspecialchars(Env::get('APP_NAME', 'Devil-Guard') ?? 'Devil-Guard', ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en-AU">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= $appName ?> · Delta Warzone protection service</title>
<link rel="stylesheet" href="assets/css/app.css?v=20260712-4">
<script defer src="assets/js/app.js"></script>
</head>
<body>
<header class="topbar"><div class="shell nav">
<a class="brand" href="./"><img class="brand-mark" src="/images/logo.png" alt="Devil-Guard logo"><span>Devil-Guard</span></a>
<nav class="navlinks"><a class="active" href="#status">Status</a><a href="#announcements">Announcements</a><a href="api/v1/releases/latest">Latest release</a><a href="api/v1/bans">Bans API</a><a href="admin/">Administration</a></nav>
</div></header>
<main>
<section class="hero"><div class="shell">
<div class="eyebrow">Delta Warzone · Windows protection client</div>
<p>Devil-Guard connects the Windows 10/11 Sentry client to a modern HTTPS service for account authentication, client health, controlled update delivery, announcements and evidence-aware administration.</p>
<div class="actions"><a class="btn" href="api/v1/releases/latest">View current release</a><a class="btn secondary" href="admin/">Open control centre</a></div>
</div></section>
<section id="status" class="section"><div class="shell">
<div class="section-title"><div><div class="eyebrow">Operational picture</div><h2>Service status</h2></div><p><span class="status-dot"></span>API <span data-api-status>checking</span></p></div>
<div class="grid">
<article class="card"><h3>Registered operators</h3><div class="metric"><?= number_format($activeUsers) ?></div><p>Approved accounts able to authenticate through the desktop client.</p></article>
<article class="card"><h3>Connected clients</h3><div class="metric"><?= number_format($onlineClients) ?></div><p>Installations that reported a heartbeat during the last two minutes.</p></article>
<article class="card"><h3>Active restrictions</h3><div class="metric"><?= number_format($activeBans) ?></div><p>Current server restrictions recorded by authorised administrators.</p></article>
</div></div></section>
<section id="announcements" class="section"><div class="shell">
<div class="section-title"><div><div class="eyebrow">Command brief</div><h2>Announcements</h2></div></div>
<div class="grid">
<?php if (!$announcements): ?><article class="card"><h3>System ready</h3><p>No active announcements have been published.</p></article><?php endif; ?>
<?php foreach ($announcements as $item): ?><article class="card"><h3><?= htmlspecialchars($item['title'], ENT_QUOTES, 'UTF-8') ?></h3><p><?= nl2br(htmlspecialchars($item['body'], ENT_QUOTES, 'UTF-8')) ?></p></article><?php endforeach; ?>
<article class="card"><h3>Stable release</h3><div class="metric"><?= htmlspecialchars($release['version'] ?? 'Not published', ENT_QUOTES, 'UTF-8') ?></div><p><?= htmlspecialchars($release['notes'] ?? 'Publish the first signed Windows package from the control centre.', ENT_QUOTES, 'UTF-8') ?></p></article>
</div></div></section>
</main>
<footer class="footer"><div class="shell">Devil-Guard · A Devilish Services project for the Delta Warzone community. Client telemetry is limited to service health, installation identity and configured game-session fields.</div></footer>
</body></html>
