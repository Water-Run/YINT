<?php
require_once dirname(__FILE__) . '/Yint.php';

$pass = 0;
$fail = 0;

function yint_test_check($name, $ok, $detail)
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "[PASS] " . $name . "\n";
    } else {
        $fail++;
        echo "[FAIL] " . $name . "\n";
        if ($detail !== null && $detail !== '') {
            echo "       " . $detail . "\n";
        }
    }
}

function yint_test_eq($name, $got, $want)
{
    yint_test_check($name, $got === $want, "got=" . var_export($got, true) . " want=" . var_export($want, true));
}

function yint_test_expect_exception_status($name, $status, $fn)
{
    try {
        call_user_func($fn);
        yint_test_check($name, false, "no exception");
    } catch (YintException $e) {
        yint_test_check($name, intval($e->status) === intval($status), "status=" . $e->status);
    }
}

$core = null;
if (isset($argv) && isset($argv[1])) {
    $core = $argv[1];
}

$master_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
$master = pack('H*', $master_hex);
$y = new Yint($master, $core, 300);

yint_test_eq("derive K_enc",
    $y->k_enc_hex,
    "82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5");
yint_test_eq("derive K_mac",
    $y->k_mac_hex,
    "ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50");

$req = $y->build_request("POST", "/api/echo?x=1&x=2", "hello yint");
yint_test_check("request has timestamp", isset($req['headers']['X-Yint-Timestamp']), null);
yint_test_check("request nonce format", preg_match('/^[0-9a-f]{32}$/', $req['headers']['X-Yint-Nonce']) === 1, null);
yint_test_check("request sign format", preg_match('/^[0-9a-f]{64}$/', $req['headers']['X-Yint-Sign']) === 1, null);
yint_test_check("request body encrypted", $req['body'] !== "hello yint" && strlen($req['body']) >= 32, null);

$plain = $y->open_request("POST", "/api/echo?x=1&x=2", $req['headers'], $req['body']);
yint_test_eq("open request", $plain, "hello yint");

yint_test_expect_exception_status("replay rejected", 401, array(new YintReplayCase($y, $req), 'run'));

$resp = $y->build_response(200, $req['nonce'], "world");
$resp_plain = $y->open_response(200, $req['nonce'], $resp['headers'], $resp['body']);
yint_test_eq("open response", $resp_plain, "world");

yint_test_expect_exception_status("response req nonce binding", 401, array(new YintBadRespNonceCase($y, $resp), 'run'));

$bad = $req;
$bad['headers']['X-Yint-Extra'] = '1';
yint_test_expect_exception_status("unknown request x-yint header", 400, array(new YintBadHeaderCase($y, $bad), 'run'));

$bad_resp = $resp;
$bad_resp['headers']['X-Yint-Extra'] = '1';
yint_test_expect_exception_status("unknown response x-yint header", 400, array(new YintBadResponseHeaderCase($y, $req, $bad_resp), 'run'));

class YintReplayCase
{
    var $y;
    var $req;
    function __construct($y, $req) { $this->YintReplayCase($y, $req); }
    function YintReplayCase($y, $req) { $this->y = $y; $this->req = $req; }
    function run() { $this->y->open_request("POST", "/api/echo?x=1&x=2", $this->req['headers'], $this->req['body']); }
}

class YintBadRespNonceCase
{
    var $y;
    var $resp;
    function __construct($y, $resp) { $this->YintBadRespNonceCase($y, $resp); }
    function YintBadRespNonceCase($y, $resp) { $this->y = $y; $this->resp = $resp; }
    function run() { $this->y->open_response(200, str_repeat('0', 32), $this->resp['headers'], $this->resp['body']); }
}

class YintBadHeaderCase
{
    var $y;
    var $req;
    function __construct($y, $req) { $this->YintBadHeaderCase($y, $req); }
    function YintBadHeaderCase($y, $req) { $this->y = $y; $this->req = $req; }
    function run() { $this->y->open_request("POST", "/api/echo?x=1&x=2", $this->req['headers'], $this->req['body']); }
}

class YintBadResponseHeaderCase
{
    var $y;
    var $req;
    var $resp;
    function __construct($y, $req, $resp) { $this->YintBadResponseHeaderCase($y, $req, $resp); }
    function YintBadResponseHeaderCase($y, $req, $resp) { $this->y = $y; $this->req = $req; $this->resp = $resp; }
    function run() { $this->y->open_response(200, $this->req['nonce'], $this->resp['headers'], $this->resp['body']); }
}

echo "\n";
echo "pass=" . $pass . " fail=" . $fail . "\n";
exit($fail ? 1 : 0);
?>
