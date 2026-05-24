<?php
/*
 * PHP 5.2 wrapper for the yint core CLI.
 *
 * This file intentionally keeps the PHP layer small.  The byte-level
 * protocol operations live in core/bin/yint; PHP owns configuration,
 * HTTP header validation, timestamp checks and the in-process nonce table.
 */

class YintException extends Exception
{
    var $status;

    function __construct($message, $status)
    {
        $this->YintException($message, $status);
    }

    function YintException($message, $status)
    {
        parent::__construct($message);
        $this->status = $status;
    }
}

class Yint
{
    var $core_path;
    var $time_window;
    var $k_enc_hex;
    var $k_mac_hex;
    var $nonces;

    function __construct($master_key, $core_path = null, $time_window = null)
    {
        $this->Yint($master_key, $core_path, $time_window);
    }

    function Yint($master_key, $core_path = null, $time_window = null)
    {
        if ($core_path === null || $core_path === '') {
            $core_path = dirname(__FILE__) . '/../../core/bin/yint';
            if (!is_file($core_path) && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && is_file($core_path . '.exe')) {
                $core_path .= '.exe';
            }
        }
        if ($time_window === null) {
            $time_window = 300;
        }

        $this->core_path = $core_path;
        $this->time_window = intval($time_window);
        $this->nonces = array();

        if ($this->time_window < 1) {
            throw new YintException('bad time window', 400);
        }
        if (!is_file($this->core_path)) {
            throw new YintException('core not found: ' . $this->core_path, 500);
        }

        $out = $this->_run(array('derive', bin2hex($master_key)), null);
        $parts = preg_split('/\s+/', trim($out));
        if (count($parts) != 2 || !$this->_is_lower_hex($parts[0], 64) || !$this->_is_lower_hex($parts[1], 64)) {
            throw new YintException('bad derive output', 500);
        }
        $this->k_enc_hex = $parts[0];
        $this->k_mac_hex = $parts[1];
    }

    function build_request($method, $uri, $plaintext)
    {
        $method = strtoupper($method);
        $timestamp = strval(time());
        $nonce = $this->_random_hex(16);
        $iv = $this->_random_hex(16);
        $body_hex = $this->_run(array('build-body', $this->k_enc_hex, $iv, '-'), bin2hex($plaintext));
        $body_hex = trim($body_hex);
        $sign = trim($this->_run(array('sign-req', $this->k_mac_hex, $method, $uri, $timestamp, $nonce, '-'), $body_hex));

        return array(
            'headers' => array(
                'X-Yint-Timestamp' => $timestamp,
                'X-Yint-Nonce' => $nonce,
                'X-Yint-Sign' => $sign
            ),
            'body' => $this->_hex_to_bin($body_hex),
            'nonce' => $nonce
        );
    }

    function open_request($method, $uri, $headers, $body)
    {
        $method = strtoupper($method);
        $h = $this->_normalize_headers($headers);
        $this->_reject_unknown_yint_headers($h);

        $timestamp = $this->_required_header($h, 'x-yint-timestamp');
        $nonce = $this->_required_header($h, 'x-yint-nonce');
        $sign = $this->_required_header($h, 'x-yint-sign');

        if (!preg_match('/^[0-9]+$/', $timestamp) ||
            !$this->_is_lower_hex($nonce, 32) ||
            !$this->_is_lower_hex($sign, 64)) {
            throw new YintException('bad yint headers', 400);
        }

        $now = time();
        $ts = intval($timestamp);
        if (abs($now - $ts) > $this->time_window) {
            throw new YintException('unauthorized', 401);
        }

        $this->_cleanup_nonces($now);
        if (isset($this->nonces[$nonce])) {
            throw new YintException('unauthorized', 401);
        }

        $body_hex = bin2hex($body);
        $out = trim($this->_run(array('verify-req', $this->k_mac_hex, $method, $uri, $timestamp, $nonce, $sign, '-'), $body_hex, true));
        if ($out !== 'OK') {
            throw new YintException('unauthorized', 401);
        }

        $this->nonces[$nonce] = $ts + $this->time_window;
        return $this->decrypt_body($body);
    }

    function build_response($status, $req_nonce, $plaintext)
    {
        $status = strval(intval($status));
        $timestamp = strval(time());
        $nonce = $this->_random_hex(16);
        $iv = $this->_random_hex(16);
        $body_hex = trim($this->_run(array('build-body', $this->k_enc_hex, $iv, '-'), bin2hex($plaintext)));
        $sign = trim($this->_run(array('sign-resp', $this->k_mac_hex, $status, $timestamp, $nonce, $req_nonce, '-'), $body_hex));

        return array(
            'headers' => array(
                'X-Yint-Timestamp' => $timestamp,
                'X-Yint-Nonce' => $nonce,
                'X-Yint-Sign' => $sign
            ),
            'body' => $this->_hex_to_bin($body_hex)
        );
    }

    function open_response($status, $req_nonce, $headers, $body)
    {
        $status = strval(intval($status));
        $h = $this->_normalize_headers($headers);
        $this->_reject_unknown_yint_headers($h);

        $timestamp = $this->_required_header($h, 'x-yint-timestamp');
        $nonce = $this->_required_header($h, 'x-yint-nonce');
        $sign = $this->_required_header($h, 'x-yint-sign');

        if (!preg_match('/^[0-9]+$/', $timestamp) ||
            !$this->_is_lower_hex($nonce, 32) ||
            !$this->_is_lower_hex($sign, 64) ||
            !$this->_is_lower_hex($req_nonce, 32)) {
            throw new YintException('bad yint headers', 400);
        }

        if (abs(time() - intval($timestamp)) > $this->time_window) {
            throw new YintException('unauthorized', 401);
        }

        $body_hex = bin2hex($body);
        $out = trim($this->_run(array('verify-resp', $this->k_mac_hex, $status, $timestamp, $nonce, $req_nonce, $sign, '-'), $body_hex, true));
        if ($out !== 'OK') {
            throw new YintException('unauthorized', 401);
        }

        return $this->decrypt_body($body);
    }

    function decrypt_body($body)
    {
        $plain_hex = trim($this->_run(array('decrypt-body', $this->k_enc_hex, '-'), bin2hex($body), true));
        return $this->_hex_to_bin($plain_hex);
    }

    function response_error_status($e)
    {
        if (is_object($e) && isset($e->status)) {
            return intval($e->status);
        }
        return 500;
    }

    function collect_headers_from_server($server)
    {
        $headers = array();
        foreach ($server as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $name = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = $value;
            }
        }
        if (isset($server['CONTENT_TYPE'])) {
            $headers['content-type'] = $server['CONTENT_TYPE'];
        }
        if (isset($server['CONTENT_LENGTH'])) {
            $headers['content-length'] = $server['CONTENT_LENGTH'];
        }
        return $headers;
    }

    function request_uri_from_server($server)
    {
        if (isset($server['REQUEST_URI'])) {
            $uri = $server['REQUEST_URI'];
            $p = strpos($uri, '#');
            if ($p !== false) {
                $uri = substr($uri, 0, $p);
            }
            return $uri;
        }
        $uri = isset($server['SCRIPT_NAME']) ? $server['SCRIPT_NAME'] : '/';
        if (isset($server['QUERY_STRING']) && $server['QUERY_STRING'] !== '') {
            $uri .= '?' . $server['QUERY_STRING'];
        }
        return $uri;
    }

    function send_headers($headers)
    {
        foreach ($headers as $name => $value) {
            header($name . ': ' . $value);
        }
    }

    function _random_hex($nbytes)
    {
        return trim($this->_run(array('random', strval($nbytes)), null));
    }

    function _run($args, $stdin, $allow_sign_error = false)
    {
        $cmd = escapeshellarg($this->core_path);
        for ($i = 0; $i < count($args); $i++) {
            $cmd .= ' ' . escapeshellarg($args[$i]);
        }

        $desc = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w')
        );
        $pipes = array();
        $proc = proc_open($cmd, $desc, $pipes);
        if (!is_resource($proc)) {
            throw new YintException('cannot run core', 500);
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);

        $out = $this->_read_all($pipes[1]);
        $err = $this->_read_all($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($proc);

        if ($rc !== 0) {
            $tag = trim($err !== '' ? $err : $out);
            if ($allow_sign_error && ($tag == 'ERR_SIGN' || $tag == 'ERR_PADDING')) {
                return $tag;
            }
            throw new YintException('core failed: ' . $tag, 500);
        }
        return $out;
    }

    function _read_all($fp)
    {
        $s = '';
        while (!feof($fp)) {
            $s .= fread($fp, 8192);
        }
        return $s;
    }

    function _normalize_headers($headers)
    {
        $out = array();
        foreach ($headers as $k => $v) {
            $out[strtolower($k)] = $v;
        }
        return $out;
    }

    function _reject_unknown_yint_headers($headers)
    {
        foreach ($headers as $k => $v) {
            if (substr($k, 0, 7) == 'x-yint-' &&
                $k != 'x-yint-timestamp' &&
                $k != 'x-yint-nonce' &&
                $k != 'x-yint-sign') {
                throw new YintException('bad yint headers', 400);
            }
        }
    }

    function _required_header($headers, $name)
    {
        if (!isset($headers[$name])) {
            throw new YintException('missing yint header', 400);
        }
        return strval($headers[$name]);
    }

    function _cleanup_nonces($now)
    {
        foreach ($this->nonces as $nonce => $expire_at) {
            if ($expire_at < $now) {
                unset($this->nonces[$nonce]);
            }
        }
    }

    function _is_lower_hex($s, $len)
    {
        return is_string($s) && strlen($s) == $len && preg_match('/^[0-9a-f]+$/', $s);
    }

    function _hex_to_bin($hex)
    {
        if ($hex === '') {
            return '';
        }
        return pack('H*', $hex);
    }
}
?>
