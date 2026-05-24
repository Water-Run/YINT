from __future__ import annotations

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yint import Yint, YintError


MASTER = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
CORE = Path(__file__).resolve().parents[3] / "core" / "bin" / "yint"


class YintTests(unittest.TestCase):
    def test_round_trip_and_replay(self) -> None:
        y = Yint(MASTER, core_path=CORE)
        self.assertEqual(y.k_enc_hex, "82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5")
        self.assertEqual(y.k_mac_hex, "ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50")

        req = y.build_request("post", "/api/echo?x=1&x=2", b"hello yint")
        self.assertEqual(y.open_request("POST", "/api/echo?x=1&x=2", req.headers, req.body), b"hello yint")
        with self.assertRaises(YintError) as replay:
            y.open_request("POST", "/api/echo?x=1&x=2", req.headers, req.body)
        self.assertEqual(replay.exception.status, 401)

        resp = y.build_response(200, req.nonce, b"world")
        self.assertEqual(y.open_response(200, req.nonce, resp.headers, resp.body), b"world")
        with self.assertRaises(YintError) as bad_resp:
            y.open_response(200, "0" * 32, resp.headers, resp.body)
        self.assertEqual(bad_resp.exception.status, 401)

    def test_unknown_yint_header(self) -> None:
        y = Yint(MASTER, core_path=CORE)
        req = y.build_request("GET", "/api/ping", b"")
        headers = dict(req.headers)
        headers["X-Yint-Extra"] = "1"
        with self.assertRaises(YintError) as bad:
            y.open_request("GET", "/api/ping", headers, req.body)
        self.assertEqual(bad.exception.status, 400)


if __name__ == "__main__":
    unittest.main()
