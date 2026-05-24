--[[
  yint-test.lua -- portable Lua regression tests for the yint CLI.

  Drives the yint binary via io.popen / os.execute. Works on Lua 5.1,
  5.2, 5.3, 5.4, 5.5 and LuaJIT, on Linux / macOS / Windows.

  Usage: lua yint-test.lua [path/to/yint]
         (default: ./yint  -- on Windows: .\yint.exe)
]]

----------------------------------------------------------------
-- Config & portability shims
----------------------------------------------------------------

local IS_WIN = (package.config:sub(1, 1) == "\\")
local YINT   = arg and arg[1]
if not YINT then
    YINT = IS_WIN and ".\\yint.exe" or "./yint"
end

-- POSIX single-quote shell quoting / cmd.exe double-quote quoting.
local function shellquote(s)
    s = tostring(s)
    if IS_WIN then
        -- cmd.exe: wrap in quotes, double internal quotes.
        return '"' .. s:gsub('"', '""') .. '"'
    end
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

local function build_cmd(args)
    local parts = { shellquote(YINT) }
    for i = 1, #args do parts[#parts + 1] = shellquote(args[i]) end
    return table.concat(parts, " ")
end

-- Run, return (stdout, exit_code). 2>&1 merges stderr.
local function run(args)
    local cmd = build_cmd(args) .. " 2>&1"
    local pipe = assert(io.popen(cmd, "r"))
    local out = pipe:read("*a") or ""
    local ok, what, code = pipe:close()
    -- Lua versions handle close differently; normalise.
    local rc
    if type(ok) == "number" then
        rc = ok
    elseif ok == true then
        rc = 0
    else
        rc = (type(code) == "number" and code) or 1
    end
    -- strip trailing newline(s)
    out = out:gsub("[\r\n]+$", "")
    return out, rc
end

local function run_ok(args)
    local out, rc = run(args)
    if rc ~= 0 then
        error(string.format("CLI failed (rc=%d) cmd=%s\noutput:%s",
                            rc, build_cmd(args), out))
    end
    return out
end

----------------------------------------------------------------
-- Test harness
----------------------------------------------------------------

local PASS, FAIL = 0, 0
local function check(name, ok_v, detail)
    if ok_v then
        PASS = PASS + 1
        io.write(string.format("  [PASS] %s\n", name))
    else
        FAIL = FAIL + 1
        io.write(string.format("  [FAIL] %s\n", name))
        if detail then io.write("         " .. tostring(detail) .. "\n") end
    end
end

local function eq(name, got, want)
    return check(name, got == want,
                 string.format("got=%q want=%q", tostring(got), tostring(want)))
end

local function group(title)
    io.write(string.format("\n[%s]\n", title))
end

----------------------------------------------------------------
-- A: SHA-256 / HMAC vectors (NIST + RFC 4231)
----------------------------------------------------------------
group("A. SHA-256 / HMAC-SHA256 standard vectors")

-- empty
eq("sha256 of empty",
   run_ok({ "sha256", "" }),
   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

-- "abc"
eq("sha256(\"abc\")",
   run_ok({ "sha256", "616263" }),
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

-- 448-bit message
eq("sha256(56-byte msg)",
   run_ok({ "sha256",
       "6162636462636465636465666465666765666768666768696768696a"
    .. "68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071" }),
   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

-- RFC 4231 test case 1
eq("hmac case 1 (key=0b*20, data='Hi There')",
   run_ok({ "hmac",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265" }),
   "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

-- RFC 4231 test case 2
eq("hmac case 2 (key='Jefe')",
   run_ok({ "hmac", "4a656665",
            "7768617420646f2079612077616e74"
         .. "20666f72206e6f7468696e673f" }),
   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

-- RFC 4231 test case 3 (key 0xaa*20, data 0xdd*50)
do
    local k = string.rep("aa", 20)
    local d = string.rep("dd", 50)
    eq("hmac case 3", run_ok({ "hmac", k, d }),
       "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
end

-- RFC 4231 test case 4 (long key 0xaa*131, data 'Test Using Larger Than ...')
do
    local k = string.rep("aa", 131)
    local d = "54657374205573696e67204c6172676572205468616e20426c6f63"
           .. "6b2d53697a65204b6579202d2048617368204b6579204669727374"
    eq("hmac case 6 (long key)", run_ok({ "hmac", k, d }),
       "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
end

----------------------------------------------------------------
-- B: AES-256-CBC NIST F.2.5 vectors + PKCS#7 boundaries
----------------------------------------------------------------
group("B. AES-256-CBC + PKCS#7 boundaries")

local NIST_KEY = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
local NIST_IV  = "000102030405060708090a0b0c0d0e0f"
-- Plaintext is 4 NIST blocks (no PKCS#7 added yet); we test raw 4-block CBC by
-- letting our CLI add a 5th padding block.
local NIST_PT4 =
    "6bc1bee22e409f96e93d7e117393172a"
 .. "ae2d8a571e03ac9c9eb76fac45af8e51"
 .. "30c81c46a35ce411e5fbc1191a0a52ef"
 .. "f69f2445df4f9b17ad2b417be66c3710"
-- Expected NIST ciphertext for the 4 blocks alone:
local NIST_CT4 =
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
 .. "9cfc4e967edb808d679f777bc6702c7d"
 .. "39f23369a9d9bacfa530e26304231461"
 .. "b2eb05e2c39be9fcda6c19078c6a9d1b"

do
    local out = run_ok({ "aes-enc", NIST_KEY, NIST_IV, NIST_PT4 })
    -- our output includes one extra full pad block after the 4 NIST blocks
    eq("NIST F.2.5 first 4 blocks match",
       out:sub(1, #NIST_CT4), NIST_CT4)
    -- round-trip
    eq("NIST round-trip dec",
       run_ok({ "aes-dec", NIST_KEY, NIST_IV, out }),
       NIST_PT4)
end

-- Plaintext length boundaries: 0, 15, 16, 17, 31, 32 bytes
do
    local sizes = { 0, 15, 16, 17, 31, 32 }
    for _, n in ipairs(sizes) do
        local pt = string.rep("ab", n)
        local key = string.rep("11", 32)
        local iv  = string.rep("22", 16)
        local ct  = run_ok({ "aes-enc", key, iv, pt })
        local back = run_ok({ "aes-dec", key, iv, ct })
        eq(string.format("PKCS#7 boundary plen=%d round-trip", n), back, pt)
        eq(string.format("PKCS#7 boundary plen=%d ciphertext is multiple of 16", n),
           (#ct) % 32, 0)  -- hex chars, so 32 = 16 bytes
    end
end

----------------------------------------------------------------
-- C: Key derivation
----------------------------------------------------------------
group("C. Key derivation (yint/enc, yint/mac)")

local MASTER_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
local KENC_HEX   = "82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5"
local KMAC_HEX   = "ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50"

do
    local out  = run_ok({ "derive", MASTER_HEX })
    local a, b = out:match("^(%x+)%s+(%x+)$")
    eq("derive K_enc", a, KENC_HEX)
    eq("derive K_mac", b, KMAC_HEX)

    -- Cross-check against direct HMAC
    eq("HMAC(master,'yint/enc') == K_enc",
       run_ok({ "hmac", MASTER_HEX, "79696e742f656e63" }), KENC_HEX)
    eq("HMAC(master,'yint/mac') == K_mac",
       run_ok({ "hmac", MASTER_HEX, "79696e742f6d6163" }), KMAC_HEX)
end

----------------------------------------------------------------
-- D: build-body byte layout
----------------------------------------------------------------
group("D. build-body == IV || AES-CBC(K_enc, IV, plain)")

do
    local iv = "000102030405060708090a0b0c0d0e0f"
    -- empty plaintext: body must be 32 bytes (IV + one full PKCS#7 block)
    local body = run_ok({ "build-body", KENC_HEX, iv, "" })
    eq("empty body length (hex chars)", #body, 64)
    eq("empty body starts with IV", body:sub(1, 32), iv)
    -- non-empty plaintext: IV prefix + AES-CBC ciphertext
    local pt   = "48656c6c6f2c20796e74"  -- "Hello, ynt"
    local body2 = run_ok({ "build-body", KENC_HEX, iv, pt })
    eq("non-empty body starts with IV", body2:sub(1, 32), iv)
    local ct = run_ok({ "aes-enc", KENC_HEX, iv, pt })
    eq("non-empty body suffix == aes-enc(plain)", body2:sub(33), ct)
    -- decrypt-body recovers plaintext
    eq("decrypt-body recovers plain",
       run_ok({ "decrypt-body", KENC_HEX, body2 }), pt)
    -- decrypt-body of empty body returns ""
    eq("decrypt-body empty",
       run_ok({ "decrypt-body", KENC_HEX, body }), "")
end

----------------------------------------------------------------
-- E: sign-request regression vectors
----------------------------------------------------------------
group("E. sign-request regression vectors")

-- Case E1: empty body GET /api/ping
do
    local IV    = "000102030405060708090a0b0c0d0e0f"
    local NONCE = "00112233445566778899aabbccddeeff"
    local TS    = "1732464000"
    local BODY  = "000102030405060708090a0b0c0d0e0fa88d903ece1f8a99b6a5ef59da7296bd"
    local SIG   = "c034f6790b0f9b5326ed9150151167571aec2dc4a63226b979eb193ab94285a7"
    eq("E1 build-body", run_ok({ "build-body", KENC_HEX, IV, "" }), BODY)
    eq("E1 sign-req",
       run_ok({ "sign-req", KMAC_HEX, "GET", "/api/ping", TS, NONCE, BODY }),
       SIG)
    eq("E1 verify-req OK",
       run_ok({ "verify-req", KMAC_HEX, "GET", "/api/ping", TS, NONCE, SIG, BODY }),
       "OK")
end

-- Case E2: query string preserved verbatim
do
    local IV    = "101112131415161718191a1b1c1d1e1f"
    local NONCE = "ffeeddccbbaa99887766554433221100"
    local TS    = "1732464100"
    local URI   = "/api/v2/items?since=2024-01-01&order=asc"
    local BODY  = "101112131415161718191a1b1c1d1e1f1395806adfe3cbfc72db9454e29a1eb0"
    local SIG   = "791a2916974f25be4b1de67a4ef91c70063362b8a057d110e3226bc3b1cc7e6e"
    eq("E2 build-body", run_ok({ "build-body", KENC_HEX, IV, "" }), BODY)
    eq("E2 sign-req with query",
       run_ok({ "sign-req", KMAC_HEX, "GET", URI, TS, NONCE, BODY }),
       SIG)
    eq("E2 verify-req OK",
       run_ok({ "verify-req", KMAC_HEX, "GET", URI, TS, NONCE, SIG, BODY }),
       "OK")
end

-- Case E3: POST with UTF-8 body
local E3 = {
    IV    = "2021222324252627282930313233a4a5",
    NONCE = "cafebabedeadbeef0123456789abcdef",
    TS    = "1732464200",
    URI   = "/api/echo",
    PT    = "e4bda0e5a5bd2c2079696e7421",  -- "你好, yint!"
    BODY  = "2021222324252627282930313233a4a593d4c71c7ad3c262a02f9408b9d155d3",
    SIG   = "03854da6f3186a9f6ec30126673f562a9392b5ae4a0c1d79d2c1f44465cc2c1f",
}
do
    eq("E3 build-body POST UTF-8",
       run_ok({ "build-body", KENC_HEX, E3.IV, E3.PT }), E3.BODY)
    eq("E3 sign-req",
       run_ok({ "sign-req", KMAC_HEX, "POST", E3.URI, E3.TS, E3.NONCE, E3.BODY }),
       E3.SIG)
    eq("E3 verify-req OK",
       run_ok({ "verify-req", KMAC_HEX, "POST", E3.URI, E3.TS, E3.NONCE, E3.SIG, E3.BODY }),
       "OK")
end

-- Case E4: URI not normalised (//)
do
    local IV    = "3031323334353637383940414243a4a5"
    local NONCE = "0102030405060708090a0b0c0d0e0f10"
    local TS    = "1732464300"
    local URI   = "/a//b"
    local BODY  = "3031323334353637383940414243a4a5e7cf5618351286ab36d47ec8efbce765"
    local SIG   = "94fecdf9cf1a8972f98b02e24665587142a642d8fa3374bcdf5153be1c280486"
    eq("E4 build-body", run_ok({ "build-body", KENC_HEX, IV, "" }), BODY)
    eq("E4 sign-req URI=/a//b",
       run_ok({ "sign-req", KMAC_HEX, "GET", URI, TS, NONCE, BODY }),
       SIG)
    -- Negative: /a/b must not equal /a//b
    do
        local out, rc = run({
            "verify-req", KMAC_HEX, "GET", "/a/b", TS, NONCE, SIG, BODY })
        check("E4 verify-req with normalised URI rejects",
              rc ~= 0 and out:find("ERR_SIGN", 1, true),
              "out=" .. out)
    end
end

----------------------------------------------------------------
-- F: sign-response binds REQ_NONCE
----------------------------------------------------------------
group("F. sign-response and REQ_NONCE binding")

do
    local RESP_TS    = "1732464205"
    local RESP_NONCE = "aabbccddeeff00112233445566778899"
    local RESP_IV    = "4041424344454647484950515253a4a5"
    local RESP_PT    = "4f4b"
    local RESP_BODY  = "4041424344454647484950515253a4a5423c5b3ce27ead7fea66503ae4777e21"
    local RESP_SIG   = "ae2f4e54a35dd768a5ba35ab48a08bf0ebea207022a92967c4ff9c1c1fd4ec3d"

    eq("F build response body",
       run_ok({ "build-body", KENC_HEX, RESP_IV, RESP_PT }), RESP_BODY)
    eq("F sign-resp",
       run_ok({ "sign-resp", KMAC_HEX, "200", RESP_TS, RESP_NONCE,
                E3.NONCE, RESP_BODY }), RESP_SIG)
    eq("F verify-resp OK",
       run_ok({ "verify-resp", KMAC_HEX, "200", RESP_TS, RESP_NONCE,
                E3.NONCE, RESP_SIG, RESP_BODY }),
       "OK")
    -- REQ_NONCE substitution must fail
    do
        local bogus = string.rep("ff", 16)
        local out, rc = run({
            "verify-resp", KMAC_HEX, "200", RESP_TS, RESP_NONCE,
            bogus, RESP_SIG, RESP_BODY })
        check("F verify-resp with wrong REQ_NONCE rejects",
              rc ~= 0 and out:find("ERR_SIGN", 1, true),
              "out=" .. out)
    end
end

----------------------------------------------------------------
-- G: end-to-end client/server round-trip
----------------------------------------------------------------
group("G. End-to-end client/server round-trip")

do
    local METHOD = "POST"
    local URI    = "/api/round-trip?x=1"
    local TS     = "1732464500"

    -- client: random IV/NONCE, build body, sign request
    local NONCE = run_ok({ "random", "16" })
    local IV    = run_ok({ "random", "16" })
    local PT    = "7468652071756963"  -- "the quic"
    local BODY  = run_ok({ "build-body", KENC_HEX, IV, PT })
    local SIG   = run_ok({ "sign-req", KMAC_HEX, METHOD, URI, TS, NONCE, BODY })

    -- server: verify request, decrypt, build response
    eq("G server verifies request",
       run_ok({ "verify-req", KMAC_HEX, METHOD, URI, TS, NONCE, SIG, BODY }),
       "OK")
    eq("G server decrypts plaintext",
       run_ok({ "decrypt-body", KENC_HEX, BODY }), PT)

    local RTS    = "1732464505"
    local RNONCE = run_ok({ "random", "16" })
    local RIV    = run_ok({ "random", "16" })
    local RPT    = "70696e672d706f6e67"  -- "ping-pong"
    local RBODY  = run_ok({ "build-body", KENC_HEX, RIV, RPT })
    local RSIG   = run_ok({ "sign-resp", KMAC_HEX, "200",
                            RTS, RNONCE, NONCE, RBODY })

    -- client: verify response and decrypt
    eq("G client verifies response",
       run_ok({ "verify-resp", KMAC_HEX, "200",
                RTS, RNONCE, NONCE, RSIG, RBODY }),
       "OK")
    eq("G client decrypts response plaintext",
       run_ok({ "decrypt-body", KENC_HEX, RBODY }), RPT)
end

----------------------------------------------------------------
-- H: negative tests
----------------------------------------------------------------
group("H. Negative / error-path tests")

local function expect_fail(name, args, token)
    local out, rc = run(args)
    check(name, rc ~= 0 and (token == nil or out:find(token, 1, true)),
          string.format("rc=%d out=%q", rc, out))
end

-- bad hex (odd length)
expect_fail("odd-length hex rejected",
            { "sha256", "abc" }, "ERR_FORMAT")
-- bad hex (non-hex char)
expect_fail("non-hex character rejected",
            { "sha256", "zz" }, "ERR_FORMAT")
-- AES key wrong length
expect_fail("aes-enc with 31-byte key rejected",
            { "aes-enc", string.rep("00", 31), string.rep("00", 16), "" },
            "ERR_FORMAT")
-- AES IV wrong length
expect_fail("aes-enc with 15-byte IV rejected",
            { "aes-enc", string.rep("00", 32), string.rep("00", 15), "" },
            "ERR_FORMAT")
-- decrypt-body with too-short body
expect_fail("decrypt-body with body=16B rejected",
            { "decrypt-body", KENC_HEX, string.rep("00", 16) },
            "ERR_FORMAT")
-- decrypt-body with non-multiple-of-16 body
expect_fail("decrypt-body with 33B body rejected",
            { "decrypt-body", KENC_HEX, string.rep("00", 33) },
            "ERR_FORMAT")
-- corrupt PKCS#7 padding -> ERR_PADDING
do
    local key = string.rep("11", 32)
    local iv  = string.rep("22", 16)
    -- fabricate 16 bytes of "ciphertext" that won't decrypt to valid padding
    expect_fail("corrupt PKCS#7 -> ERR_PADDING",
                { "aes-dec", key, iv, string.rep("00", 16) },
                "ERR_PADDING")
end
-- flip body byte -> verify-req must fail
do
    local IV    = "000102030405060708090a0b0c0d0e0f"
    local NONCE = "00112233445566778899aabbccddeeff"
    local TS    = "1732464000"
    local BODY  = "000102030405060708090a0b0c0d0e0fa88d903ece1f8a99b6a5ef59da7296bd"
    local SIG   = "c034f6790b0f9b5326ed9150151167571aec2dc4a63226b979eb193ab94285a7"
    -- flip last hex nibble of body
    local last = BODY:sub(-1)
    local flipped = BODY:sub(1, -2) .. (last == "d" and "e" or "d")
    expect_fail("flipping body byte breaks signature",
                { "verify-req", KMAC_HEX, "GET", "/api/ping", TS, NONCE,
                  SIG, flipped },
                "ERR_SIGN")
    -- flip last hex char of sig
    local last2 = SIG:sub(-1)
    local sigflip = SIG:sub(1, -2) .. (last2 == "7" and "8" or "7")
    expect_fail("flipping signature char rejects",
                { "verify-req", KMAC_HEX, "GET", "/api/ping", TS, NONCE,
                  sigflip, BODY },
                "ERR_SIGN")
end

----------------------------------------------------------------
-- I: random sanity
----------------------------------------------------------------
group("I. CSPRNG sanity")

do
    local seen = {}
    local dup = false
    for i = 1, 200 do
        local r = run_ok({ "random", "16" })
        if seen[r] then dup = true; break end
        seen[r] = true
        if #r ~= 32 then
            check("random 16 returns 32 hex chars", false, "got len=" .. #r)
            dup = true
            break
        end
    end
    check("200 random samples are unique and 32 hex chars long", not dup)
end

----------------------------------------------------------------
-- J: CLI meta
----------------------------------------------------------------
group("J. CLI meta")

do
    local out = run_ok({ "info" })
    check("info contains version 1.0.0", out:find("1.0.0", 1, true) ~= nil, out)
    check("info contains backend=soft|aesni",
          out:find("backend=aesni", 1, true) ~= nil
       or out:find("backend=soft", 1, true) ~= nil,
          out)
end

----------------------------------------------------------------
-- Summary
----------------------------------------------------------------
io.write(string.format("\n%s %d/%d passed\n",
                       (FAIL == 0 and "PASS" or "FAIL"),
                       PASS, PASS + FAIL))
if FAIL ~= 0 then os.exit(1) end
