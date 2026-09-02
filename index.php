<?php
/* bouncer.php — password-gated file drop. All requests route through here. */
declare(strict_types=1);

// Never leak server internals into the page (5: error hardening)
ini_set('display_errors', '0');
ini_set('log_errors', '1');

const PASS_HASH = '$2y$10$VrZgUtUlLYmttKZ9hUrYYOUkEwFTIb5KdZoIOOx8cLVKnMn2iB9TO'; // "exchange-demo" — replace: password_hash('yourpass', PASSWORD_DEFAULT)
const FILES_DIR = __DIR__ . '/files';
const INLINE_EXT = ['mp3','wav','ogg','m4a','flac','mp4','mkv','webm','mov','pdf','jpg','jpeg','png','gif','webp','svg']; // played/rendered in browser
const MAX_FAILS = 5;      // failed logins per IP before lockout
const LOCKOUT_SEC = 900;  // lockout duration (15 min)
const FAIL_FILE = FILES_DIR . '/.fails.json';

// (6) auto-provision the drop folder with direct-access protection
if (!is_dir(FILES_DIR)) {
    mkdir(FILES_DIR, 0755, true);
    file_put_contents(FILES_DIR . '/.htaccess', "Require all denied\n");
}

// (4) SameSite=Strict: session cookie never leaves this origin
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();

// (1) CSRF token for the login form (timing-safe compare via hash_equals)
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

// --- brute-force lockout (per IP, stored in files/.fails.json) ---
$ip = $_SERVER['REMOTE_ADDR'] ?? '?';
$fails = is_file(FAIL_FILE) ? (json_decode(file_get_contents(FAIL_FILE), true) ?: []) : [];
$locked = ($fails[$ip]['n'] ?? 0) >= MAX_FAILS && time() - $fails[$ip]['t'] < LOCKOUT_SEC;

// --- requested path ---
$req = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$req = str_replace('\0', '', rawurldecode($req)); // decode %XX, strip null bytes
if (empty($_SESSION['ok']) && $req !== '' && $req !== 'index.php') $_SESSION['want'] = $req; // remember target across login

// --- login ---
$err = $locked ? 'Too many attempts. Try again later.' : '';
if (!$locked && isset($_POST['pw'])) {
    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        http_response_code(403);
        exit('Invalid request.'); // CSRF mismatch: not counted as a password guess
    }
    if (password_verify($_POST['pw'], PASS_HASH)) {
        unset($fails[$ip]);
        file_put_contents(FAIL_FILE, json_encode($fails), LOCK_EX);
        session_regenerate_id(true);
        $_SESSION['ok'] = true;
        $next = $_SESSION['want'] ?? '';
        unset($_SESSION['want']);
        header('Location: ./' . $next); // back to the requested file -> download starts
        exit;
    }
    $fails[$ip] = ['n' => ($fails[$ip]['n'] ?? 0) + 1, 't' => time()];
    file_put_contents(FAIL_FILE, json_encode($fails), LOCK_EX);
    sleep(2); // slow down brute force
    $err = 'Wrong password.';
}
$authed = !empty($_SESSION['ok']);

// --- download (authed + file requested) ---
if ($authed && $req !== '' && $req !== 'index.php') {
    $path = realpath(FILES_DIR . '/' . $req); // resolves .. and symlinks; false if missing
    if ($path && str_starts_with($path, realpath(FILES_DIR) . '/') && is_file($path)
        && !str_starts_with(basename($path), '.')) { // never serve dotfiles (.fails.json, .htaccess)
        header('Content-Type: ' . (mime_content_type($path) ?: 'application/octet-stream'));
        $disp = in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), INLINE_EXT) ? 'inline' : 'attachment';
        // (3) sanitize filename for the header: strip control chars, quotes, backslashes (response-splitting safe)
        $fname = substr(preg_replace('/[\x00-\x1F\x7F"\\]/', '', basename($path)), 0, 255) ?: 'file';
        header('Content-Disposition: ' . $disp . '; filename="' . $fname . '"');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('Accept-Ranges: bytes');
        $size = filesize($path);
        $start = 0; $end = $size - 1;
        // HTTP Range support: browsers stream/seek video in byte chunks (206 Partial Content)
        if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
            if ($m[1] !== '') { $start = (int)$m[1]; if ($m[2] !== '') $end = min((int)$m[2], $end); }
            else { $start = max(0, $size - (int)$m[2]); } // suffix range: last N bytes
            if ($start > $end || $start >= $size) { http_response_code(416); header("Content-Range: bytes */$size"); exit; }
            http_response_code(206);
            header("Content-Range: bytes $start-$end/$size");
        }
        header('Content-Length: ' . ($end - $start + 1));
        $fp = fopen($path, 'rb');
        fseek($fp, $start);
        $left = $end - $start + 1;
        while ($left > 0 && !feof($fp)) { // chunked: no memory spike, survives long streams
            $chunk = fread($fp, min(8192, $left));
            if ($chunk === false) break;
            echo $chunk;
            $left -= strlen($chunk);
            flush();
        }
        fclose($fp);
        exit;
    }
    http_response_code(404);
    exit('Not found.');
}

// (2) security headers for the HTML gate page (self-contained: no external resources needed)
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:");
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>bouncer</title>
<style>
  * { box-sizing: border-box; margin: 0 }
  body { min-height: 100vh; display: grid; place-items: center; font: 15px/1.5 system-ui, sans-serif;
         background: #0f1115; color: #e8eaf0 }
  .card { width: min(92vw, 340px); padding: 2.2rem; border-radius: 14px;
          background: #181b22; border: 1px solid #262b36; box-shadow: 0 20px 60px #0008 }
  .lock { font-size: 1.6rem; text-align: center }
  h1 { font-size: 1.05rem; font-weight: 600; text-align: center; margin: .6rem 0 1.4rem; letter-spacing: .02em }
  input { width: 100%; padding: .7rem .9rem; border-radius: 8px; border: 1px solid #333a47;
          background: #0f1115; color: inherit; outline: none }
  input:focus { border-color: #6d8dff }
  button { width: 100%; margin-top: .8rem; padding: .7rem; border: 0; border-radius: 8px; cursor: pointer;
           background: #6d8dff; color: #0b0d12; font-weight: 600 }
  button:hover { background: #86a0ff }
  .err { color: #ff7b72; font-size: .85rem; text-align: center; margin-top: .8rem; min-height: 1.2em }
  .hint { color: #8b93a5; font-size: .78rem; text-align: center; margin-top: .4rem }
  .ok  { text-align: center }
</style>
</head>
<body>
<div class="card">
  <div class="lock">🔒</div>
  <?php if (!$authed): ?>
    <h1>Restricted area</h1>
    <form method="post">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">
      <input type="password" name="pw" placeholder="Password" autofocus required>
      <button>Unlock</button>
    </form>
    <div class="err"><?= htmlspecialchars($err) ?></div>
    <p class="hint">Enter the password you were given with the link.</p>
  <?php else: ?>
    <h1 class="ok">Access granted</h1>
    <p class="ok">Access ends when you close the browser.</p>
  <?php endif; ?>
</div>
</body>
</html>
