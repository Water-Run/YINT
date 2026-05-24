<?php

declare(strict_types=1);

namespace Yint;

final class YintException extends \RuntimeException
{
    public function __construct(string $message, public readonly int $status)
    {
        parent::__construct($message);
    }
}

final readonly class RequestPackage
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public array $headers,
        public string $body,
        public string $nonce,
    ) {
    }
}

final readonly class ResponsePackage
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public array $headers,
        public string $body,
    ) {
    }
}

final class Yint
{
    private const array YINT_HEADERS = [
        'x-yint-timestamp' => true,
        'x-yint-nonce' => true,
        'x-yint-sign' => true,
    ];

    public readonly string $corePath;
    public readonly int $timeWindow;
    public readonly string $kEncHex;
    public readonly string $kMacHex;

    /** @var array<string, int> */
    private array $nonces = [];

    public function __construct(
        string $masterKey,
        ?string $corePath = null,
        int $timeWindow = 300,
    ) {
        if ($timeWindow < 1) {
            throw new YintException('bad time window', 400);
        }
        $this->corePath = $corePath ?: dirname(__DIR__, 3) . '/core/bin/yint';
        $this->timeWindow = $timeWindow;
        if (!is_file($this->corePath)) {
            throw new YintException('core not found: ' . $this->corePath, 500);
        }

        $parts = preg_split('/\s+/', $this->run(['derive', bin2hex($masterKey)]));
        if (
            !is_array($parts) ||
            count($parts) !== 2 ||
            !$this->isLowerHex($parts[0], 64) ||
            !$this->isLowerHex($parts[1], 64)
        ) {
            throw new YintException('bad derive output', 500);
        }
        $this->kEncHex = $parts[0];
        $this->kMacHex = $parts[1];
    }

    public function buildRequest(string $method, string $uri, string $plaintext): RequestPackage
    {
        $method = strtoupper($method);
        $timestamp = (string) time();
        $nonce = $this->randomHex(16);
        $iv = $this->randomHex(16);
        $bodyHex = $this->run(['build-body', $this->kEncHex, $iv, '-'], bin2hex($plaintext));
        $sign = $this->run(['sign-req', $this->kMacHex, $method, $uri, $timestamp, $nonce, '-'], $bodyHex);

        return new RequestPackage(
            [
                'X-Yint-Timestamp' => $timestamp,
                'X-Yint-Nonce' => $nonce,
                'X-Yint-Sign' => $sign,
            ],
            hex2bin($bodyHex) ?: '',
            $nonce,
        );
    }

    /**
     * @param array<string, string|int> $headers
     */
    public function openRequest(string $method, string $uri, array $headers, string $body): string
    {
        $method = strtoupper($method);
        $h = $this->normalizeHeaders($headers);
        $this->rejectUnknownYintHeaders($h);
        $timestamp = $this->requiredHeader($h, 'x-yint-timestamp');
        $nonce = $this->requiredHeader($h, 'x-yint-nonce');
        $sign = $this->requiredHeader($h, 'x-yint-sign');

        if (!preg_match('/^[0-9]+$/', $timestamp) || !$this->isLowerHex($nonce, 32) || !$this->isLowerHex($sign, 64)) {
            throw new YintException('bad yint headers', 400);
        }

        $now = time();
        $ts = (int) $timestamp;
        if (abs($now - $ts) > $this->timeWindow) {
            throw new YintException('unauthorized', 401);
        }
        $this->cleanupNonces($now);
        if (isset($this->nonces[$nonce])) {
            throw new YintException('unauthorized', 401);
        }

        $this->verify(['verify-req', $this->kMacHex, $method, $uri, $timestamp, $nonce, $sign, '-'], bin2hex($body));
        $this->nonces[$nonce] = $ts + $this->timeWindow;
        return $this->decryptBody($body);
    }

    public function buildResponse(int $status, string $reqNonce, string $plaintext): ResponsePackage
    {
        $statusText = (string) $status;
        $timestamp = (string) time();
        $nonce = $this->randomHex(16);
        $iv = $this->randomHex(16);
        $bodyHex = $this->run(['build-body', $this->kEncHex, $iv, '-'], bin2hex($plaintext));
        $sign = $this->run(['sign-resp', $this->kMacHex, $statusText, $timestamp, $nonce, $reqNonce, '-'], $bodyHex);

        return new ResponsePackage(
            [
                'X-Yint-Timestamp' => $timestamp,
                'X-Yint-Nonce' => $nonce,
                'X-Yint-Sign' => $sign,
            ],
            hex2bin($bodyHex) ?: '',
        );
    }

    /**
     * @param array<string, string|int> $headers
     */
    public function openResponse(int $status, string $reqNonce, array $headers, string $body): string
    {
        $h = $this->normalizeHeaders($headers);
        $this->rejectUnknownYintHeaders($h);
        $timestamp = $this->requiredHeader($h, 'x-yint-timestamp');
        $nonce = $this->requiredHeader($h, 'x-yint-nonce');
        $sign = $this->requiredHeader($h, 'x-yint-sign');

        if (
            !preg_match('/^[0-9]+$/', $timestamp) ||
            !$this->isLowerHex($nonce, 32) ||
            !$this->isLowerHex($sign, 64) ||
            !$this->isLowerHex($reqNonce, 32)
        ) {
            throw new YintException('bad yint headers', 400);
        }
        if (abs(time() - (int) $timestamp) > $this->timeWindow) {
            throw new YintException('unauthorized', 401);
        }

        $this->verify(['verify-resp', $this->kMacHex, (string) $status, $timestamp, $nonce, $reqNonce, $sign, '-'], bin2hex($body));
        return $this->decryptBody($body);
    }

    public function decryptBody(string $body): string
    {
        $plainHex = $this->run(['decrypt-body', $this->kEncHex, '-'], bin2hex($body));
        return hex2bin($plainHex) ?: '';
    }

    private function randomHex(int $nbytes): string
    {
        return $this->run(['random', (string) $nbytes]);
    }

    /**
     * @param list<string> $args
     */
    private function run(array $args, ?string $stdin = null): string
    {
        $descriptor = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open([$this->corePath, ...$args], $descriptor, $pipes);
        if (!is_resource($process)) {
            throw new YintException('cannot run core', 500);
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]) ?: '';
        $err = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        if ($code !== 0) {
            $tag = trim($err !== '' ? $err : $out);
            throw new YintException('core failed: ' . $tag, 500);
        }
        return trim($out);
    }

    /**
     * @param list<string> $args
     */
    private function verify(array $args, string $stdin): void
    {
        try {
            $out = $this->run($args, $stdin);
        } catch (YintException $exception) {
            if (str_contains($exception->getMessage(), 'ERR_SIGN')) {
                throw new YintException('unauthorized', 401);
            }
            throw $exception;
        }
        if ($out !== 'OK') {
            throw new YintException('unauthorized', 401);
        }
    }

    /**
     * @param array<string, string|int> $headers
     * @return array<string, string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $out[strtolower((string) $name)] = (string) $value;
        }
        return $out;
    }

    /**
     * @param array<string, string> $headers
     */
    private function rejectUnknownYintHeaders(array $headers): void
    {
        foreach ($headers as $name => $_) {
            if (str_starts_with($name, 'x-yint-') && !isset(self::YINT_HEADERS[$name])) {
                throw new YintException('bad yint headers', 400);
            }
        }
    }

    /**
     * @param array<string, string> $headers
     */
    private function requiredHeader(array $headers, string $name): string
    {
        return $headers[$name] ?? throw new YintException('missing yint header', 400);
    }

    private function cleanupNonces(int $now): void
    {
        foreach ($this->nonces as $nonce => $expireAt) {
            if ($expireAt < $now) {
                unset($this->nonces[$nonce]);
            }
        }
    }

    private function isLowerHex(string $value, int $length): bool
    {
        return strlen($value) === $length && preg_match('/^[0-9a-f]+$/', $value) === 1;
    }
}
