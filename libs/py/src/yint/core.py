from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import time
from collections.abc import Mapping

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TS = re.compile(r"^[0-9]+$")
_YINT_HEADERS = {"x-yint-timestamp", "x-yint-nonce", "x-yint-sign"}


class YintError(RuntimeError):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True, slots=True)
class RequestPackage:
    headers: dict[str, str]
    body: bytes
    nonce: str


@dataclass(frozen=True, slots=True)
class ResponsePackage:
    headers: dict[str, str]
    body: bytes


class Yint:
    def __init__(
        self,
        master_key: bytes,
        *,
        core_path: str | Path | None = None,
        time_window: int = 300,
    ) -> None:
        if time_window < 1:
            raise YintError("bad time window", 400)
        self.core_path = Path(core_path) if core_path is not None else self._default_core_path()
        if not self.core_path.is_file():
            raise YintError(f"core not found: {self.core_path}", 500)
        self.time_window = time_window
        self._nonces: dict[str, int] = {}

        parts = self._run("derive", master_key.hex()).split()
        if len(parts) != 2 or not _HEX64.match(parts[0]) or not _HEX64.match(parts[1]):
            raise YintError("bad derive output", 500)
        self.k_enc_hex, self.k_mac_hex = parts

    @staticmethod
    def _default_core_path() -> Path:
        return Path(__file__).resolve().parents[4] / "core" / "bin" / "yint"

    def build_request(self, method: str, uri: str, plaintext: bytes) -> RequestPackage:
        method = method.upper()
        timestamp = str(int(time.time()))
        nonce = self._random_hex(16)
        iv = self._random_hex(16)
        body_hex = self._run("build-body", self.k_enc_hex, iv, "-", stdin=plaintext.hex())
        sign = self._run("sign-req", self.k_mac_hex, method, uri, timestamp, nonce, "-", stdin=body_hex)
        return RequestPackage(
            headers={
                "X-Yint-Timestamp": timestamp,
                "X-Yint-Nonce": nonce,
                "X-Yint-Sign": sign,
            },
            body=bytes.fromhex(body_hex),
            nonce=nonce,
        )

    def open_request(
        self,
        method: str,
        uri: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> bytes:
        method = method.upper()
        h = self._normalize_headers(headers)
        self._reject_unknown_yint_headers(h)
        timestamp = self._required_header(h, "x-yint-timestamp")
        nonce = self._required_header(h, "x-yint-nonce")
        sign = self._required_header(h, "x-yint-sign")
        if not _TS.match(timestamp) or not _HEX32.match(nonce) or not _HEX64.match(sign):
            raise YintError("bad yint headers", 400)

        now = int(time.time())
        ts = int(timestamp)
        if abs(now - ts) > self.time_window:
            raise YintError("unauthorized", 401)
        self._cleanup_nonces(now)
        if nonce in self._nonces:
            raise YintError("unauthorized", 401)

        self._verify(
            "verify-req",
            self.k_mac_hex,
            method,
            uri,
            timestamp,
            nonce,
            sign,
            "-",
            stdin=body.hex(),
        )
        self._nonces[nonce] = ts + self.time_window
        return self.decrypt_body(body)

    def build_response(self, status: int, req_nonce: str, plaintext: bytes) -> ResponsePackage:
        status_s = str(int(status))
        timestamp = str(int(time.time()))
        nonce = self._random_hex(16)
        iv = self._random_hex(16)
        body_hex = self._run("build-body", self.k_enc_hex, iv, "-", stdin=plaintext.hex())
        sign = self._run(
            "sign-resp",
            self.k_mac_hex,
            status_s,
            timestamp,
            nonce,
            req_nonce,
            "-",
            stdin=body_hex,
        )
        return ResponsePackage(
            headers={
                "X-Yint-Timestamp": timestamp,
                "X-Yint-Nonce": nonce,
                "X-Yint-Sign": sign,
            },
            body=bytes.fromhex(body_hex),
        )

    def open_response(
        self,
        status: int,
        req_nonce: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> bytes:
        status_s = str(int(status))
        h = self._normalize_headers(headers)
        self._reject_unknown_yint_headers(h)
        timestamp = self._required_header(h, "x-yint-timestamp")
        nonce = self._required_header(h, "x-yint-nonce")
        sign = self._required_header(h, "x-yint-sign")
        if (
            not _TS.match(timestamp)
            or not _HEX32.match(nonce)
            or not _HEX64.match(sign)
            or not _HEX32.match(req_nonce)
        ):
            raise YintError("bad yint headers", 400)
        if abs(int(time.time()) - int(timestamp)) > self.time_window:
            raise YintError("unauthorized", 401)
        self._verify(
            "verify-resp",
            self.k_mac_hex,
            status_s,
            timestamp,
            nonce,
            req_nonce,
            sign,
            "-",
            stdin=body.hex(),
        )
        return self.decrypt_body(body)

    def decrypt_body(self, body: bytes) -> bytes:
        return bytes.fromhex(self._run("decrypt-body", self.k_enc_hex, "-", stdin=body.hex()))

    def _random_hex(self, nbytes: int) -> str:
        return self._run("random", str(nbytes))

    def _run(self, *args: str, stdin: str | None = None) -> str:
        proc = subprocess.run(
            [str(self.core_path), *args],
            input=stdin,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            tag = (proc.stderr or proc.stdout).strip()
            raise YintError(f"core failed: {tag}", 500)
        return proc.stdout.strip()

    def _verify(self, *args: str, stdin: str) -> None:
        try:
            out = self._run(*args, stdin=stdin)
        except YintError as exc:
            if "ERR_SIGN" in str(exc):
                raise YintError("unauthorized", 401) from exc
            raise
        if out != "OK":
            raise YintError("unauthorized", 401)

    @staticmethod
    def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
        return {key.lower(): str(value) for key, value in headers.items()}

    @staticmethod
    def _reject_unknown_yint_headers(headers: Mapping[str, str]) -> None:
        for key in headers:
            if key.startswith("x-yint-") and key not in _YINT_HEADERS:
                raise YintError("bad yint headers", 400)

    @staticmethod
    def _required_header(headers: Mapping[str, str], name: str) -> str:
        try:
            return headers[name]
        except KeyError as exc:
            raise YintError("missing yint header", 400) from exc

    def _cleanup_nonces(self, now: int) -> None:
        self._nonces = {nonce: expire_at for nonce, expire_at in self._nonces.items() if expire_at >= now}
