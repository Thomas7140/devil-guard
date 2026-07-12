<?php
declare(strict_types=1);

use DevilGuard\Web\Auth;
use DevilGuard\Web\Database;
use DevilGuard\Web\Env;
use DevilGuard\Web\Http;
use DevilGuard\Web\ServerAuth;

require_once dirname(__DIR__) . '/src/bootstrap.php';
Http::securityHeaders(true);
Auth::startWebSession();
$db = Database::connection();

/** Check integration tables without breaking the existing admin panel before migration. */
function devil_guard_admin_table_exists(PDO $database, string $table): bool
{
    $statement = $database->prepare(
        'SELECT COUNT(*)
         FROM information_schema.tables
         WHERE table_schema = DATABASE() AND table_name = :table_name'
    );
    $statement->execute(['table_name' => $table]);
    return (int)$statement->fetchColumn() > 0;
}

$page = preg_replace('/[^a-z]/', '', (string)($_GET['page'] ?? 'dashboard')) ?: 'dashboard';
$allowedPages = ['dashboard', 'users', 'events', 'servers', 'attestations', 'releases', 'bans', 'login', 'logout'];
if (!in_array($page, $allowedPages, true)) {
    $page = 'dashboard';
}

$error = '';
$message = '';
$issuedServerToken = '';
$issuedServerName = '';

if ($page === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: ./?page=login');
    exit;
}

if ($page === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::verifyCsrf();
    $login = trim((string)($_POST['login'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $statement = $db->prepare(
        "SELECT uid, password_hash
         FROM users
         WHERE (username = :username OR email = :email)
           AND role = 'admin'
           AND status = 'active'
         LIMIT 1"
    );
    $statement->execute([
        'username' => $login,
        'email' => $login,
    ]);
    $user = $statement->fetch();
    if ($user && password_verify($password, $user['password_hash'])) {
        session_regenerate_id(true);
        $_SESSION['admin_user_uid'] = (string)$user['uid'];
        header('Location: ./');
        exit;
    }
    $error = 'The supplied administrator credentials were not accepted.';
}

if ($page === 'login' && Auth::webUser() === null) {
    ?>
<!doctype html>
<html lang="en-AU">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Devil-Guard login</title>
    <link rel="stylesheet" href="../assets/css/app.css?v=20260712-6">
</head>
<body class="admin-login-page">
<main class="login-shell">
    <a class="brand" href="../"><img class="brand-mark" src="/images/logo.png" alt="Devil-Guard logo"><span>Devil-Guard</span></a>
    <div class="panel login-panel">
        <div class="eyebrow">Restricted access</div>
        <h2 class="login-title">Control centre</h2>
        <?php if ($error): ?><div class="notice error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
            <label>Username or email<input name="login" autocomplete="username" required></label>
            <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
            <button class="btn" type="submit">Authenticate</button>
        </form>
    </div>
</main>
</body>
</html>
<?php
    exit;
}

$admin = Auth::requireAdmin();
$integrationReady = devil_guard_admin_table_exists($db, 'servers')
    && devil_guard_admin_table_exists($db, 'server_tokens')
    && devil_guard_admin_table_exists($db, 'attestation_reports')
    && devil_guard_admin_table_exists($db, 'attestation_decisions');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::verifyCsrf();
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'add_release') {
        $version = trim((string)($_POST['version'] ?? ''));
        $url = trim((string)($_POST['package_url'] ?? ''));
        $sha = strtolower(trim((string)($_POST['sha256'] ?? '')));
        if (!preg_match('/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/', $version)
            || !filter_var($url, FILTER_VALIDATE_URL)
            || !str_starts_with($url, 'https://')
            || !preg_match('/^[a-f0-9]{64}$/', $sha)) {
            $error = 'Release version, HTTPS package URL, or SHA-256 value is invalid.';
        } else {
            $channel = substr(trim((string)($_POST['channel'] ?? 'stable')), 0, 30) ?: 'stable';
            $releaseValues = [
                'version' => $version,
                'channel' => $channel,
                'file_name' => basename((string)($_POST['file_name'] ?? '')),
                'url' => $url,
                'sha' => $sha,
                'build' => max(0, (int)($_POST['min_windows_build'] ?? 17763)),
                'notes' => trim((string)($_POST['notes'] ?? '')),
            ];
            $existingRelease = $db->prepare(
                'SELECT uid FROM releases WHERE version = :version AND channel = :channel LIMIT 1'
            );
            $existingRelease->execute(['version' => $version, 'channel' => $channel]);
            $releaseUid = (string)($existingRelease->fetchColumn() ?: '');
            if ($releaseUid !== '') {
                $db->prepare(
                    'UPDATE releases SET
                        file_name = :file_name,
                        package_url = :url,
                        sha256 = :sha,
                        min_windows_build = :build,
                        notes = :notes,
                        is_active = 1,
                        published_at = UTC_TIMESTAMP()
                     WHERE uid = :release_uid'
                )->execute([
                    'file_name' => $releaseValues['file_name'],
                    'url' => $releaseValues['url'],
                    'sha' => $releaseValues['sha'],
                    'build' => $releaseValues['build'],
                    'notes' => $releaseValues['notes'],
                    'release_uid' => $releaseUid,
                ]);
            } else {
                devil_guard_insert(
                    $db,
                    'releases',
                    'INSERT INTO releases
                        (uid, version, channel, file_name, package_url, sha256,
                         min_windows_build, notes, is_active, published_at)
                     VALUES
                        (:uid, :version, :channel, :file_name, :url, :sha,
                         :build, :notes, 1, UTC_TIMESTAMP())',
                    $releaseValues
                );
            }
            $message = 'Release manifest saved.';
        }
    } elseif ($action === 'add_announcement') {
        devil_guard_insert(
            $db,
            'announcements',
            'INSERT INTO announcements
                (uid, title, body, is_active, created_by_uid, created_at)
             VALUES
                (:uid, :title, :body, 1, :created_by_uid, UTC_TIMESTAMP())',
            [
                'title' => substr(trim((string)($_POST['title'] ?? '')), 0, 160),
                'body' => trim((string)($_POST['body'] ?? '')),
                'created_by_uid' => $admin['uid'],
            ]
        );
        $message = 'Announcement published.';
    } elseif ($action === 'add_ban') {
        $endsAt = trim((string)($_POST['ends_at'] ?? ''));
        if ($endsAt !== '') {
            $endsAt = str_replace('T', ' ', $endsAt) . (strlen($endsAt) === 16 ? ':00' : '');
        }
        devil_guard_insert(
            $db,
            'bans',
            "INSERT INTO bans
                (uid, player_name, player_id, reason, evidence_url, starts_at,
                 ends_at, status, created_by_uid, created_at)
             VALUES
                (:uid, :player_name, :player_id, :reason, :evidence_url,
                 UTC_TIMESTAMP(), :ends_at, 'active', :created_by_uid, UTC_TIMESTAMP())",
            [
                'player_name' => substr(trim((string)($_POST['player_name'] ?? '')), 0, 100),
                'player_id' => substr(trim((string)($_POST['player_id'] ?? '')), 0, 100),
                'reason' => substr(trim((string)($_POST['reason'] ?? '')), 0, 1000),
                'evidence_url' => trim((string)($_POST['evidence_url'] ?? '')) ?: null,
                'ends_at' => $endsAt ?: null,
                'created_by_uid' => $admin['uid'],
            ]
        );
        $message = 'Restriction recorded. Use the Sentinel machine name in Player ID to block one machine.';
    } elseif ($action === 'add_user') {
        $username = trim((string)($_POST['username'] ?? ''));
        $email = trim((string)($_POST['email'] ?? ''));
        $displayName = trim((string)($_POST['display_name'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $role = in_array($_POST['role'] ?? '', ['user', 'admin'], true) ? (string)$_POST['role'] : 'user';
        if (!preg_match('/^[A-Za-z0-9_.-]{3,50}$/', $username)
            || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || $displayName === ''
            || strlen($password) < 12) {
            $error = 'Use a valid username and email, a display name, and a password of at least 12 characters.';
        } else {
            try {
                devil_guard_insert(
                    $db,
                    'users',
                    "INSERT INTO users
                        (uid, username, email, display_name, password_hash, role,
                         status, created_at, updated_at)
                     VALUES
                        (:uid, :username, :email, :display_name, :password_hash,
                         :role, 'active', UTC_TIMESTAMP(), UTC_TIMESTAMP())",
                    [
                        'username' => $username,
                        'email' => $email,
                        'display_name' => substr($displayName, 0, 100),
                        'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
                        'role' => $role,
                    ]
                );
                $message = 'Account created.';
            } catch (PDOException) {
                $error = 'That username or email address is already in use.';
            }
        }
    } elseif ($action === 'user_status') {
        $status = in_array($_POST['status'] ?? '', ['active', 'pending', 'suspended'], true)
            ? (string)$_POST['status']
            : 'pending';
        $db->prepare('UPDATE users SET status = :status WHERE uid = :user_uid')
            ->execute([
                'status' => $status,
                'user_uid' => strtoupper(trim((string)($_POST['user_uid'] ?? ''))),
            ]);
        $message = 'User status updated.';
    } elseif ($action === 'add_server') {
        if (!$integrationReady) {
            $error = 'Import database/integration-migration.sql before creating a server.';
        } else {
            $name = substr(trim((string)($_POST['name'] ?? '')), 0, 120);
            $gameName = substr(trim((string)($_POST['game_name'] ?? 'dfbhd')), 0, 100) ?: 'dfbhd';
            $maxAge = max(10, min(86400, (int)($_POST['max_report_age_seconds'] ?? 120)));
            $denyOnAnySignal = isset($_POST['deny_on_any_signal']) ? 1 : 0;
            if ($name === '') {
                $error = 'A server name is required.';
            } else {
                $serverUid = devil_guard_insert(
                    $db,
                    'servers',
                    'INSERT INTO servers
                        (uid, public_id, name, game_name, status, deny_on_any_signal,
                         max_report_age_seconds, created_by_uid, created_at, updated_at)
                     VALUES
                        (:uid, :public_id, :name, :game_name, \'active\',
                         :deny_on_any_signal, :max_report_age_seconds,
                         :created_by_uid, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
                    [
                        'public_id' => ServerAuth::uuidV4(),
                        'name' => $name,
                        'game_name' => $gameName,
                        'deny_on_any_signal' => $denyOnAnySignal,
                        'max_report_age_seconds' => $maxAge,
                        'created_by_uid' => $admin['uid'],
                    ]
                );
                $issued = ServerAuth::issueToken($serverUid, 'primary');
                $issuedServerToken = $issued['token'];
                $issuedServerName = $name;
                $message = 'Server created. Copy the token now; only its hash is stored.';
            }
        }
    } elseif ($action === 'rotate_server_token') {
        if (!$integrationReady) {
            $error = 'Integration tables are unavailable.';
        } else {
            $serverUid = strtoupper(trim((string)($_POST['server_uid'] ?? '')));
            $lookup = $db->prepare('SELECT name FROM servers WHERE uid = :server_uid LIMIT 1');
            $lookup->execute(['server_uid' => $serverUid]);
            $serverName = (string)($lookup->fetchColumn() ?: '');
            if ($serverName === '') {
                $error = 'Server not found.';
            } else {
                ServerAuth::revokeTokens($serverUid);
                $issued = ServerAuth::issueToken($serverUid, 'rotated');
                $issuedServerToken = $issued['token'];
                $issuedServerName = $serverName;
                $message = 'Server token rotated. The previous token is now revoked.';
            }
        }
    } elseif ($action === 'server_policy') {
        if (!$integrationReady) {
            $error = 'Integration tables are unavailable.';
        } else {
            $serverUid = strtoupper(trim((string)($_POST['server_uid'] ?? '')));
            $status = ($_POST['status'] ?? '') === 'disabled' ? 'disabled' : 'active';
            $denyOnAnySignal = isset($_POST['deny_on_any_signal']) ? 1 : 0;
            $maxAge = max(10, min(86400, (int)($_POST['max_report_age_seconds'] ?? 120)));
            $db->prepare(
                'UPDATE servers SET
                    status = :status,
                    deny_on_any_signal = :deny_on_any_signal,
                    max_report_age_seconds = :max_report_age_seconds,
                    updated_at = UTC_TIMESTAMP()
                 WHERE uid = :server_uid'
            )->execute([
                'status' => $status,
                'deny_on_any_signal' => $denyOnAnySignal,
                'max_report_age_seconds' => $maxAge,
                'server_uid' => $serverUid,
            ]);
            $message = 'Server policy updated.';
        }
    }
}

$counts = [
    'users' => (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn(),
    'online' => (int)$db->query(
        'SELECT COUNT(DISTINCT installation_uid)
         FROM heartbeats
         WHERE received_at >= UTC_TIMESTAMP() - INTERVAL 2 MINUTE'
    )->fetchColumn(),
    'events' => (int)$db->query(
        'SELECT COUNT(*) FROM client_events WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR'
    )->fetchColumn(),
    'bans' => (int)$db->query("SELECT COUNT(*) FROM bans WHERE status = 'active'")->fetchColumn(),
    'servers' => 0,
    'denied' => 0,
];
if ($integrationReady) {
    $counts['servers'] = (int)$db->query("SELECT COUNT(*) FROM servers WHERE status = 'active'")->fetchColumn();
    $counts['denied'] = (int)$db->query(
        'SELECT COUNT(*)
         FROM attestation_decisions
         WHERE allow_join = 0 AND decided_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR'
    )->fetchColumn();
}

$users = $page === 'users'
    ? $db->query(
        'SELECT uid, username, email, display_name, role, status, last_login_at, created_at
         FROM users ORDER BY created_at DESC LIMIT 250'
    )->fetchAll()
    : [];
$events = $page === 'events'
    ? $db->query(
        'SELECT e.uid, u.username, e.event_type, e.severity, e.message, e.created_at
         FROM client_events e
         JOIN users u ON u.uid = e.user_uid
         ORDER BY e.created_at DESC LIMIT 300'
    )->fetchAll()
    : [];
$releases = $page === 'releases'
    ? $db->query('SELECT * FROM releases ORDER BY published_at DESC LIMIT 100')->fetchAll()
    : [];
$bans = $page === 'bans'
    ? $db->query('SELECT * FROM bans ORDER BY created_at DESC LIMIT 250')->fetchAll()
    : [];
$servers = ($page === 'servers' && $integrationReady)
    ? $db->query(
        'SELECT s.*,
                (SELECT COUNT(*) FROM server_tokens t
                 WHERE t.server_uid = s.uid AND t.revoked_at IS NULL) AS active_tokens
         FROM servers s
         ORDER BY s.created_at DESC LIMIT 250'
    )->fetchAll()
    : [];
$attestations = ($page === 'attestations' && $integrationReady)
    ? $db->query(
        'SELECT r.uid, r.machine_id, r.player_name, r.game_name, r.game_running,
                r.hook_detected, r.suspicious_modules_detected,
                r.directory_integrity_changed, r.signals_json, r.reported_at,
                r.received_at, r.source_ip, s.name AS server_name,
                d.allow_join, d.reason, d.decided_at
         FROM attestation_reports r
         INNER JOIN servers s ON s.uid = r.server_uid
         INNER JOIN attestation_decisions d ON d.report_uid = r.uid
         ORDER BY r.received_at DESC LIMIT 300'
    )->fetchAll()
    : [];

$appUrl = rtrim((string)(Env::get('APP_URL', 'https://devil-guard.devilishservices.com') ?? ''), '/');
?>
<!doctype html>
<html lang="en-AU">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Devil-Guard control centre</title>
    <link rel="stylesheet" href="../assets/css/app.css?v=20260712-6">
    <script defer src="../assets/js/app.js"></script>
</head>
<body class="admin-page">
<header class="topbar">
    <div class="shell nav">
        <a class="brand" href="./"><img class="brand-mark" src="/images/logo.png" alt="Devil-Guard logo"><span>Devil-Guard Control</span></a>
        <nav class="navlinks">
            <a href="../">Home</a>
            <a href="./" class="<?= $page === 'dashboard' ? 'active' : '' ?>">Dashboard</a>
            <a href="?page=users" class="<?= $page === 'users' ? 'active' : '' ?>">Users</a>
            <a href="?page=events" class="<?= $page === 'events' ? 'active' : '' ?>">Events</a>
            <a href="?page=servers" class="<?= $page === 'servers' ? 'active' : '' ?>">Servers</a>
            <a href="?page=attestations" class="<?= $page === 'attestations' ? 'active' : '' ?>">Attestations</a>
            <a href="?page=releases" class="<?= $page === 'releases' ? 'active' : '' ?>">Releases</a>
            <a href="?page=bans" class="<?= $page === 'bans' ? 'active' : '' ?>">Bans</a>
            <a href="?page=logout">Logout</a>
        </nav>
    </div>
</header>
<main class="section">
<div class="shell admin-shell">
    <div class="section-title">
        <div>
            <div class="eyebrow">Authenticated as <?= htmlspecialchars((string)$admin['display_name']) ?></div>
            <h2><?= htmlspecialchars(ucfirst($page)) ?></h2>
        </div>
    </div>

    <?php if (!$integrationReady): ?>
        <div class="notice warning-notice">Client/server integration is not installed yet. Import <span class="code">database/integration-migration.sql</span> into the existing database.</div>
    <?php endif; ?>
    <?php if ($message): ?><div class="notice"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="notice error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($issuedServerToken !== ''): ?>
        <div class="panel token-panel">
            <div class="eyebrow">Token issued for <?= htmlspecialchars($issuedServerName) ?></div>
            <h3>Copy this server token now</h3>
            <p class="muted-copy">It will not be displayed again. Store it as the Windows Sentinel service token.</p>
            <pre class="token-box"><?= htmlspecialchars($issuedServerToken) ?></pre>
            <pre class="command-box">setx /M DEVILGUARD_GATEKEEPER_URL "<?= htmlspecialchars($appUrl) ?>"
setx /M DEVILGUARD_GATEKEEPER_TOKEN "<?= htmlspecialchars($issuedServerToken) ?>"
sc stop DevilGuardSentinel
sc start DevilGuardSentinel</pre>
        </div>
    <?php endif; ?>

    <?php if ($page === 'dashboard'): ?>
        <div class="grid">
            <article class="card"><h3>Accounts</h3><div class="metric"><?= $counts['users'] ?></div></article>
            <article class="card"><h3>Clients online</h3><div class="metric"><?= $counts['online'] ?></div></article>
            <article class="card"><h3>24-hour events</h3><div class="metric"><?= $counts['events'] ?></div></article>
            <article class="card"><h3>Active restrictions</h3><div class="metric"><?= $counts['bans'] ?></div></article>
            <article class="card"><h3>Active servers</h3><div class="metric"><?= $counts['servers'] ?></div></article>
            <article class="card"><h3>Denied attestations</h3><div class="metric"><?= $counts['denied'] ?></div><p>Current machine decisions updated in the last 24 hours.</p></article>
            <article class="card dashboard-announcement">
                <h3>Publish announcement</h3>
                <form method="post">
                    <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                    <input type="hidden" name="action" value="add_announcement">
                    <label>Title<input name="title" maxlength="160" required></label>
                    <label>Message<textarea name="body" required></textarea></label>
                    <button class="btn" type="submit">Publish</button>
                </form>
            </article>
        </div>
    <?php endif; ?>

    <?php if ($page === 'users'): ?>
        <div class="admin-split admin-split-users">
            <div class="panel admin-form-panel">
                <h3>Create account</h3>
                <form method="post" class="admin-form">
                    <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                    <input type="hidden" name="action" value="add_user">
                    <label>Username<input name="username" minlength="3" maxlength="50" pattern="[A-Za-z0-9_.-]+" required></label>
                    <label>Email<input type="email" name="email" required></label>
                    <label>Display name<input name="display_name" maxlength="100" required></label>
                    <label>Temporary password<input type="password" name="password" minlength="12" autocomplete="new-password" required></label>
                    <label>Role<select name="role"><option value="user">User</option><option value="admin">Administrator</option></select></label>
                    <button class="btn" type="submit">Create account</button>
                </form>
            </div>
            <div class="panel table-wrap admin-table-panel users-table-panel">
                <table>
                    <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th>Action</th></tr></thead>
                    <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= htmlspecialchars((string)$user['display_name']) ?><br><span class="code"><?= htmlspecialchars((string)$user['username']) ?></span></td>
                            <td><?= htmlspecialchars((string)$user['email']) ?></td>
                            <td><?= htmlspecialchars((string)$user['role']) ?></td>
                            <td><span class="badge"><?= htmlspecialchars((string)$user['status']) ?></span></td>
                            <td><?= htmlspecialchars((string)($user['last_login_at'] ?? 'Never')) ?></td>
                            <td>
                                <form method="post" class="inline-action-form">
                                    <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                                    <input type="hidden" name="action" value="user_status">
                                    <input type="hidden" name="user_uid" value="<?= htmlspecialchars((string)$user['uid']) ?>">
                                    <select name="status">
                                        <option value="active" <?= $user['status'] === 'active' ? 'selected' : '' ?>>active</option>
                                        <option value="pending" <?= $user['status'] === 'pending' ? 'selected' : '' ?>>pending</option>
                                        <option value="suspended" <?= $user['status'] === 'suspended' ? 'selected' : '' ?>>suspended</option>
                                    </select>
                                    <button class="btn" type="submit">Save</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($page === 'events'): ?>
        <div class="panel table-wrap">
            <table>
                <thead><tr><th>Time</th><th>User</th><th>Type</th><th>Severity</th><th>Message</th></tr></thead>
                <tbody>
                <?php foreach ($events as $event): ?>
                    <tr>
                        <td><?= htmlspecialchars((string)$event['created_at']) ?></td>
                        <td><?= htmlspecialchars((string)$event['username']) ?></td>
                        <td><?= htmlspecialchars((string)$event['event_type']) ?></td>
                        <td><span class="badge <?= in_array($event['severity'], ['error', 'security'], true) ? 'danger' : '' ?>"><?= htmlspecialchars((string)$event['severity']) ?></span></td>
                        <td><?= htmlspecialchars((string)$event['message']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>

    <?php if ($page === 'servers'): ?>
        <?php if ($integrationReady): ?>
            <div class="admin-split admin-split-servers">
                <div class="panel admin-form-panel">
                    <h3>Register server</h3>
                    <p class="muted-copy">This creates the shared token used by the current Sentinel software.</p>
                    <form method="post" class="admin-form">
                        <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                        <input type="hidden" name="action" value="add_server">
                        <label>Server name<input name="name" maxlength="120" placeholder="Delta Warzone DFBHD" required></label>
                        <label>Game/process name<input name="game_name" maxlength="100" value="dfbhd" required></label>
                        <label>Maximum report age in seconds<input type="number" name="max_report_age_seconds" min="10" max="86400" value="120" required></label>
                        <label class="checkbox-row"><input type="checkbox" name="deny_on_any_signal" value="1" checked> Deny when any anti-cheat signal is present</label>
                        <button class="btn" type="submit">Register and issue token</button>
                    </form>
                </div>
                <div class="panel table-wrap admin-table-panel servers-table-panel">
                    <table>
                        <thead><tr><th>Server</th><th>Game</th><th>Status</th><th>Policy</th><th>Last used</th><th>Token</th></tr></thead>
                        <tbody>
                        <?php foreach ($servers as $server): ?>
                            <tr>
                                <td><?= htmlspecialchars((string)$server['name']) ?><br><span class="code"><?= htmlspecialchars((string)$server['uid']) ?></span></td>
                                <td><?= htmlspecialchars((string)$server['game_name']) ?></td>
                                <td><span class="badge <?= $server['status'] === 'disabled' ? 'danger' : '' ?>"><?= htmlspecialchars((string)$server['status']) ?></span></td>
                                <td>
                                    <form method="post" class="server-policy-form">
                                        <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                                        <input type="hidden" name="action" value="server_policy">
                                        <input type="hidden" name="server_uid" value="<?= htmlspecialchars((string)$server['uid']) ?>">
                                        <select name="status"><option value="active" <?= $server['status'] === 'active' ? 'selected' : '' ?>>active</option><option value="disabled" <?= $server['status'] === 'disabled' ? 'selected' : '' ?>>disabled</option></select>
                                        <input type="number" name="max_report_age_seconds" min="10" max="86400" value="<?= (int)$server['max_report_age_seconds'] ?>" aria-label="Maximum report age seconds">
                                        <label class="checkbox-row compact"><input type="checkbox" name="deny_on_any_signal" value="1" <?= (int)$server['deny_on_any_signal'] === 1 ? 'checked' : '' ?>> Deny signals</label>
                                        <button class="btn" type="submit">Save</button>
                                    </form>
                                </td>
                                <td><?= htmlspecialchars((string)($server['last_seen_at'] ?? 'Never')) ?></td>
                                <td>
                                    <div><?= (int)$server['active_tokens'] ?> active</div>
                                    <form method="post" class="compact-action-form">
                                        <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                                        <input type="hidden" name="action" value="rotate_server_token">
                                        <input type="hidden" name="server_uid" value="<?= htmlspecialchars((string)$server['uid']) ?>">
                                        <button class="btn danger" type="submit">Rotate token</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <?php if ($page === 'attestations'): ?>
        <?php if ($integrationReady): ?>
            <div class="panel table-wrap attestation-table-panel">
                <table>
                    <thead><tr><th>Received</th><th>Server</th><th>Machine</th><th>Player</th><th>Game</th><th>Signals</th><th>Decision</th><th>Reason</th></tr></thead>
                    <tbody>
                    <?php foreach ($attestations as $attestation): ?>
                        <?php
                        $signals = json_decode((string)($attestation['signals_json'] ?? '[]'), true);
                        $signalText = is_array($signals) && $signals !== [] ? implode(', ', array_map('strval', $signals)) : 'None';
                        ?>
                        <tr>
                            <td><?= htmlspecialchars((string)$attestation['received_at']) ?><br><span class="code"><?= htmlspecialchars((string)$attestation['source_ip']) ?></span></td>
                            <td><?= htmlspecialchars((string)$attestation['server_name']) ?></td>
                            <td><span class="code"><?= htmlspecialchars((string)$attestation['machine_id']) ?></span></td>
                            <td><?= htmlspecialchars((string)$attestation['player_name']) ?></td>
                            <td><?= htmlspecialchars((string)$attestation['game_name']) ?></td>
                            <td><?= htmlspecialchars($signalText) ?></td>
                            <td><span class="badge <?= (int)$attestation['allow_join'] === 1 ? '' : 'danger' ?>"><?= (int)$attestation['allow_join'] === 1 ? 'allow' : 'deny' ?></span></td>
                            <td><?= htmlspecialchars((string)$attestation['reason']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <?php if ($page === 'releases'): ?>
        <div class="admin-split admin-split-releases">
            <div class="panel admin-form-panel">
                <h3>Publish release manifest</h3>
                <form method="post" class="admin-form">
                    <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                    <input type="hidden" name="action" value="add_release">
                    <div class="form-grid"><label>Version<input name="version" placeholder="1.0.1" required></label><label>Channel<input name="channel" value="stable" required></label></div>
                    <label>File name<input name="file_name" placeholder="Devil-Guard-1.0.1-win-x86.zip" required></label>
                    <label>HTTPS package URL<input type="url" name="package_url" required></label>
                    <label>SHA-256<input class="code" name="sha256" minlength="64" maxlength="64" required></label>
                    <label>Minimum Windows build<input type="number" name="min_windows_build" value="17763" required></label>
                    <label>Release notes<textarea name="notes" required></textarea></label>
                    <button class="btn" type="submit">Publish manifest</button>
                </form>
            </div>
            <div class="panel table-wrap admin-table-panel releases-table-panel">
                <table><thead><tr><th>Version</th><th>Channel</th><th>Published</th><th>Package</th></tr></thead><tbody>
                <?php foreach ($releases as $release): ?><tr><td><?= htmlspecialchars((string)$release['version']) ?></td><td><?= htmlspecialchars((string)$release['channel']) ?></td><td><?= htmlspecialchars((string)$release['published_at']) ?></td><td><a href="<?= htmlspecialchars((string)$release['package_url']) ?>"><?= htmlspecialchars((string)$release['file_name']) ?></a></td></tr><?php endforeach; ?>
                </tbody></table>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($page === 'bans'): ?>
        <div class="admin-split admin-split-bans">
            <div class="panel admin-form-panel">
                <h3>Record restriction</h3>
                <form method="post" class="admin-form">
                    <input type="hidden" name="csrf" value="<?= Auth::csrfToken() ?>">
                    <input type="hidden" name="action" value="add_ban">
                    <label>Player name<input name="player_name" required></label>
                    <label>Player or machine ID<input name="player_id"><span class="field-help">Use the Sentinel MachineId here to block a specific computer.</span></label>
                    <label>Reason<textarea name="reason" required></textarea></label>
                    <label>Evidence URL<input type="url" name="evidence_url"></label>
                    <label>Ends at (UTC)<input type="datetime-local" name="ends_at"></label>
                    <button class="btn" type="submit">Record</button>
                </form>
            </div>
            <div class="panel table-wrap admin-table-panel bans-table-panel">
                <table><thead><tr><th>Player</th><th>Reason</th><th>Status</th><th>Started</th></tr></thead><tbody>
                <?php foreach ($bans as $ban): ?><tr><td><?= htmlspecialchars((string)$ban['player_name']) ?><br><span class="code"><?= htmlspecialchars((string)$ban['player_id']) ?></span></td><td><?= htmlspecialchars((string)$ban['reason']) ?></td><td><span class="badge"><?= htmlspecialchars((string)$ban['status']) ?></span></td><td><?= htmlspecialchars((string)$ban['starts_at']) ?></td></tr><?php endforeach; ?>
                </tbody></table>
            </div>
        </div>
    <?php endif; ?>
</div>
</main>
<footer class="footer"><div class="shell">Server tokens are stored as SHA-256 hashes. Use HTTPS and rotate a token if it is exposed.</div></footer>
</body>
</html>
