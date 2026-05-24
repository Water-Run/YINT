<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Yint.php';

use Yint\Yint;
use Yint\YintException;

$pass = 0;
$fail = 0;

function check(string $name, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) {
        ++$pass;
        echo "[PASS] $name\n";
        return;
    }
    ++$fail;
    echo "[FAIL] $name\n";
    if ($detail !== '') {
        echo "       $detail\n";
    }
}

function expectStatus(string $name, int $status, callable $fn): void
{
    try {
        $fn();
        check($name, false, 'no exception');
    } catch (YintException $exception) {
        check($name, $exception->status === $status, 'status=' . $exception->status);
    }
}

$master = hex2bin('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
$core = dirname(__DIR__, 3) . '/core/bin/yint';
$y = new Yint($master ?: '', $core);

check('derive K_enc', $y->kEncHex === '82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5');
check('derive K_mac', $y->kMacHex === 'ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50');

$req = $y->buildRequest('post', '/api/echo?x=1&x=2', 'hello yint');
check('open request', $y->openRequest('POST', '/api/echo?x=1&x=2', $req->headers, $req->body) === 'hello yint');
expectStatus('replay rejected', 401, fn() => $y->openRequest('POST', '/api/echo?x=1&x=2', $req->headers, $req->body));

$resp = $y->buildResponse(200, $req->nonce, 'world');
check('open response', $y->openResponse(200, $req->nonce, $resp->headers, $resp->body) === 'world');
expectStatus('response req nonce binding', 401, fn() => $y->openResponse(200, str_repeat('0', 32), $resp->headers, $resp->body));

$bad = $req->headers;
$bad['X-Yint-Extra'] = '1';
expectStatus('unknown request x-yint header', 400, fn() => $y->openRequest('POST', '/api/echo?x=1&x=2', $bad, $req->body));

echo "\npass=$pass fail=$fail\n";
exit($fail === 0 ? 0 : 1);
