<?php
/* bouncer.php test suite — black-box HTTP tests against a throwaway app copy.
 * Usage: php tests/run.php   (requires PHP CLI with the built-in web server)
 * Exit code 0 = all passed, 1 = failures. No external dependencies. */
declare(strict_types=1);

const APP = __DIR__ . '/../index.php';
const HOST = '127.0.0.1';
const DEMO_PW = 'exchange-demo'; // must match the default PASS_HASH in index.php

// random high port per run: avoids collisions with leaked/stale test servers
$port = random_int(20000, 60000);
while (@fsockopen(HOST, $port)) $port = random_int(20000, 60000);
define('PORT', $port);
define('BASE', 'http://' . HOST . ':' . PORT);

$passed = 0; $failed = 0; $failures = [];

function check(string $name, mixed $got, mixed $want): void {
    global $passed, $failed, $failures;
    if ($got === $want) { $passed++; echo "ok   - $name\n"; }
    else { $failed++; $failures[] = "$name (got: " . var_export($got, true) . ", want: " . var_export($want, true) . ")"; echo "FAIL - $name\n"; }
}

// --- minimal curl helpers (cookie-jar aware) ---
function req(string $method, string $url, ?string $cookieFile = null, array $post = [], array $headers = []): array {
    $ch = curl_init(BASE . $url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_NOBODY => $method === 'HEAD',
    ]);
    if ($cookieFile) {
        curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieFile);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieFile);
    }
    if ($post) curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return ['code' => $code, 'head' => substr((string)$raw, 0, $hsize), 'body' => substr((string)$raw, $hsize)];
}
function csrf(string $cookieFile): string {
    $r = req('GET', '/', $cookieFile);
    preg_match('/name="csrf" value="([a-f0-9]+)"/', $r['body'], $m);
    return $m[1] ?? '';
}
function login(string $cookieFile, string $pw = DEMO_PW, string $url = '/'): array {
    return req('POST', $url, $cookieFile, ['pw' => $pw, 'csrf' => csrf($cookieFile)]);
}

// --- sandbox: throwaway copy of the app so real files/ are never touched ---
$sandbox = sys_get_temp_dir() . '/bouncer-test-' . getmypid();
mkdir("$sandbox/files", 0755, true);
copy(APP, "$sandbox/index.php");
file_put_contents("$sandbox/router.php", "<?php require __DIR__ . '/index.php';");
file_put_contents("$sandbox/files/photos.zip", 'zipdata');
file_put_contents("$sandbox/files/song.mp3", 'audiodata');
mkdir("$sandbox/files/Videos/Birthday", 0755, true);
file_put_contents("$sandbox/files/Videos/Birthday/1.mp4", str_repeat('0123456789', 1024)); // 10KB
mkdir("$sandbox/files/Videos/Nice.RG[TGx]", 0755, true);
file_put_contents("$sandbox/files/Videos/Nice.RG[TGx]/vid.mkv", 'mkvdata');
file_put_contents("$sandbox/files/evil\"onload=x\".jpg", 'evil');

$server = proc_open(
    sprintf('%s -S %s:%d -t %s %s', PHP_BINARY, HOST, PORT, escapeshellarg($sandbox), escapeshellarg("$sandbox/router.php")),
    [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'a'], 2 => ['file', '/dev/null', 'a']],
    $pipes
);

// always tear down, even on Ctrl-C / kill
$teardown = function () use ($server, $sandbox) {
    if (is_resource($server)) { @proc_terminate($server); @proc_close($server); }
    if (is_dir($sandbox)) exec('rm -rf ' . escapeshellarg($sandbox));
};
register_shutdown_function($teardown);
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGINT, fn() => exit(130));
    pcntl_signal(SIGTERM, fn() => exit(143));
}
// wait for OUR server to answer HTTP (not just any listener on the port)
$up = false;
for ($i = 0; $i < 40; $i++) {
    $r = @file_get_contents(BASE . '/', false, stream_context_create(['http' => ['timeout' => 1]]));
    if ($r !== false && str_contains($r, 'Restricted area')) { $up = true; break; }
    usleep(100_000);
}
if (!$up) {
    proc_terminate($server);
    proc_close($server);
    exec('rm -rf ' . escapeshellarg($sandbox));
    fwrite(STDERR, "FATAL: test server did not start on " . BASE . " (port busy?)\n");
    exit(2);
}
$cj = "$sandbox/cookies.txt";

echo "== bouncer.php test suite ==\n";

// ---------- gate & auth ----------
$r = req('GET', '/', $cj);
check('unauth / shows gate', str_contains($r['body'], 'Restricted area'), true);
check('unauth file request leaks no bytes', str_contains(req('GET', '/photos.zip')['body'], 'zipdata'), false);
check('gate page has noindex meta', str_contains($r['body'], 'noindex,nofollow'), true);
check('hint text present', str_contains($r['body'], 'password you were given'), true);

// ---------- security headers on gate ----------
check('CSP default-src none', str_contains($r['head'], "Content-Security-Policy: default-src 'none'"), true);
check('X-Frame-Options DENY', str_contains($r['head'], 'X-Frame-Options: DENY'), true);
check('Referrer-Policy no-referrer', str_contains($r['head'], 'Referrer-Policy: no-referrer'), true);
check('nosniff on gate', str_contains($r['head'], 'X-Content-Type-Options: nosniff'), true);
check('session cookie SameSite=Strict + HttpOnly', (bool)preg_match('/Set-Cookie:.*HttpOnly; SameSite=Strict/i', $r['head']), true);

// ---------- CSRF ----------
check('CSRF token rendered (32 hex chars)', strlen(csrf($cj)), 32);
check('POST without CSRF -> 403', req('POST', '/', null, ['pw' => DEMO_PW])['code'], 403);
check('POST with wrong CSRF -> 403', req('POST', '/', $cj, ['pw' => DEMO_PW, 'csrf' => 'deadbeef'])['code'], 403);

// ---------- login & download flow ----------
$cj2 = "$sandbox/cookies2.txt";
$r = req('GET', '/photos.zip', $cj2); // stash want
check('unauth file req shows gate', str_contains($r['body'], 'Restricted area'), true);
$r = login($cj2, DEMO_PW, '/photos.zip');
check('login -> 302 redirect', $r['code'], 302);
check('redirect points back to file', str_contains($r['head'], 'Location: ./photos.zip'), true);
$r = req('GET', '/photos.zip', $cj2);
check('authed download serves file', $r['body'], 'zipdata');
check('zip -> attachment', str_contains($r['head'], 'Content-Disposition: attachment'), true);
check('download has no-store', str_contains($r['head'], 'Cache-Control: no-store'), true);
check('download has nosniff', str_contains($r['head'], 'X-Content-Type-Options: nosniff'), true);
check('Accept-Ranges bytes', str_contains($r['head'], 'Accept-Ranges: bytes'), true);

// ---------- inline vs attachment ----------
$r = req('GET', '/song.mp3', $cj2);
check('mp3 -> inline', str_contains($r['head'], 'Content-Disposition: inline'), true);
check('mkv -> inline', str_contains(req('GET', '/Videos/Nice.RG%5BTGx%5D/vid.mkv', $cj2)['head'], 'Content-Disposition: inline'), true);

// ---------- nested & encoded paths ----------
check('nested path serves file', req('GET', '/Videos/Birthday/1.mp4', $cj2)['code'], 200);
check('URL-encoded brackets resolve', req('GET', '/Videos/Nice.RG%5BTGx%5D/vid.mkv', $cj2)['body'], 'mkvdata');
check('filename header is basename', str_contains(req('GET', '/Videos/Birthday/1.mp4', $cj2)['head'], 'filename="1.mp4"'), true);

// ---------- range requests ----------
$r = req('GET', '/Videos/Birthday/1.mp4', $cj2, [], ['Range: bytes=1000-1999']);
check('range request -> 206', $r['code'], 206);
check('range serves exact bytes', strlen($r['body']), 1000);
check('Content-Range header', str_contains($r['head'], 'Content-Range: bytes 1000-1999/10240'), true);
check('suffix range (last 100)', strlen(req('GET', '/Videos/Birthday/1.mp4', $cj2, [], ['Range: bytes=-100'])['body']), 100);
check('invalid range -> 416', req('GET', '/Videos/Birthday/1.mp4', $cj2, [], ['Range: bytes=999999-'])['code'], 416);

// ---------- traversal & dotfiles ----------
check('.. traversal -> 404', req('GET', '/../../etc/passwd', $cj2)['code'], 404);
check('encoded traversal -> 404', req('GET', '/%2e%2e/%2e%2e/etc/passwd', $cj2)['code'], 404);
check('.fails.json not served', req('GET', '/.fails.json', $cj2)['code'], 404);
check('missing file -> 404', req('GET', '/nope.zip', $cj2)['code'], 404);
check('directory request -> 404', req('GET', '/Videos/Birthday/', $cj2)['code'], 404);

// ---------- filename sanitization (response-splitting) ----------
$r = req('GET', '/evil%22onload%3Dx%22.jpg', $cj2);
check('quotes stripped from filename header', str_contains($r['head'], 'filename="evilonload=x.jpg"'), true);

// ---------- lockout ----------
$readFails = fn(): array => json_decode(@file_get_contents("$sandbox/files/.fails.json") ?: '[]', true) ?: [];
$cj3 = "$sandbox/cookies3.txt";
$token = csrf($cj3);
for ($i = 0; $i < 5; $i++) req('POST', '/', $cj3, ['pw' => 'wrong', 'csrf' => $token]);
check('5 wrong logins recorded', $readFails()['127.0.0.1']['n'] ?? 0, 5);
$r = req('POST', '/', $cj3, ['pw' => DEMO_PW, 'csrf' => $token]);
check('6th attempt (correct pw) locked out', str_contains($r['body'], 'Too many attempts'), true);
// CSRF-less attempts must not increment the counter
req('POST', '/', $cj3, ['pw' => 'wrong']);
check('CSRF-blocked attempt not counted', $readFails()['127.0.0.1']['n'] ?? null, 5);
// expire lockout and confirm recovery
$f = $readFails();
$f['127.0.0.1']['t'] = time() - 901;
file_put_contents("$sandbox/files/.fails.json", json_encode($f));
$r = login($cj3);
check('login works after lockout expiry', $r['code'], 302);
check('counter cleared on success', isset($readFails()['127.0.0.1']), false);

// ---------- static source checks ----------
$src = file_get_contents(APP);
check('source has no plaintext demo password outside the comment', substr_count($src, DEMO_PW) <= 1, true);
check('PASS_HASH is a bcrypt hash', (bool)preg_match("/const PASS_HASH = '\\\$2y\\\$/", $src), true);
check('display_errors disabled', str_contains($src, "ini_set('display_errors', '0')"), true);

// ---------- teardown (also registered as shutdown function) ----------
$teardown();

echo "== $passed passed, $failed failed ==\n";
if ($failures) { echo "Failures:\n - " . implode("\n - ", $failures) . "\n"; }
exit($failed ? 1 : 0);
