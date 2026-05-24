local Yint = {}
Yint.__index = Yint

local YintError = {}
YintError.__index = YintError

local allowed_yint_headers = {
    ["x-yint-timestamp"] = true,
    ["x-yint-nonce"] = true,
    ["x-yint-sign"] = true,
}

local function dirname(path)
    return (path:gsub("[/\\][^/\\]*$", ""))
end

local function module_dir()
    local source = debug.getinfo(1, "S").source
    if source:sub(1, 1) == "@" then
        return dirname(source:sub(2))
    end
    return "."
end

local function is_windows()
    return package.config:sub(1, 1) == "\\"
end

local function shell_quote(value)
    value = tostring(value)
    if is_windows() then
        return '"' .. value:gsub('"', '\\"') .. '"'
    end
    return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function new_error(message, status)
    return setmetatable({ message = message, status = status }, YintError)
end

function YintError:__tostring()
    return self.message
end

local function raise(message, status)
    error(new_error(message, status), 2)
end

local function run(core_path, args, allow_empty)
    local parts = { shell_quote(core_path) }
    for i = 1, #args do
        parts[#parts + 1] = shell_quote(args[i])
    end

    local redirect = is_windows() and " 2>NUL" or " 2>/dev/null"
    local pipe = io.popen(table.concat(parts, " ") .. redirect, "r")
    if not pipe then
        raise("cannot run core", 500)
    end
    local out = pipe:read("*a") or ""
    local ok, _, code = pipe:close()
    out = out:gsub("[%r\n]+$", "")
    if ok == nil and code ~= 0 then
        if allow_empty then
            return nil
        end
        raise("core failed", 500)
    end
    if out == "" and not allow_empty then
        raise("core failed", 500)
    end
    return out
end

local function bin_to_hex(s)
    return (s:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hex_to_bin(hex)
    return (hex:gsub("..", function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

local function is_lower_hex(value, len)
    return type(value) == "string" and #value == len and value:match("^[0-9a-f]+$") ~= nil
end

local function normalize_headers(headers)
    local out = {}
    for name, value in pairs(headers or {}) do
        out[string.lower(tostring(name))] = tostring(value)
    end
    return out
end

local function reject_unknown_yint_headers(headers)
    for name, _ in pairs(headers) do
        if name:sub(1, 7) == "x-yint-" and not allowed_yint_headers[name] then
            raise("bad yint headers", 400)
        end
    end
end

local function required_header(headers, name)
    local value = headers[name]
    if value == nil then
        raise("missing yint header", 400)
    end
    return tostring(value)
end

local function abs(n)
    if n < 0 then
        return -n
    end
    return n
end

function Yint.new(master_key, opts)
    opts = opts or {}
    local self = setmetatable({}, Yint)
    self.core_path = opts.core_path or (module_dir() .. "/../../core/bin/yint")
    if is_windows() and opts.core_path == nil then
        self.core_path = self.core_path .. ".exe"
    end
    self.time_window = opts.time_window or 300
    if self.time_window < 1 then
        raise("bad time window", 400)
    end
    self.nonces = {}

    local derived = run(self.core_path, { "derive", bin_to_hex(master_key) }, false)
    local k_enc, k_mac = derived:match("^([0-9a-f]+)%s+([0-9a-f]+)$")
    if not (is_lower_hex(k_enc, 64) and is_lower_hex(k_mac, 64)) then
        raise("bad derive output", 500)
    end
    self.k_enc_hex = k_enc
    self.k_mac_hex = k_mac
    return self
end

function Yint:random_hex(nbytes)
    return run(self.core_path, { "random", tostring(nbytes) }, false)
end

function Yint:build_request(method, uri, plaintext)
    method = string.upper(method)
    local timestamp = tostring(os.time())
    local nonce = self:random_hex(16)
    local iv = self:random_hex(16)
    local body_hex = run(self.core_path, { "build-body", self.k_enc_hex, iv, bin_to_hex(plaintext) }, false)
    local sign = run(self.core_path, { "sign-req", self.k_mac_hex, method, uri, timestamp, nonce, body_hex }, false)
    return {
        headers = {
            ["X-Yint-Timestamp"] = timestamp,
            ["X-Yint-Nonce"] = nonce,
            ["X-Yint-Sign"] = sign,
        },
        body = hex_to_bin(body_hex),
        nonce = nonce,
    }
end

function Yint:cleanup_nonces(now)
    for nonce, expire_at in pairs(self.nonces) do
        if expire_at < now then
            self.nonces[nonce] = nil
        end
    end
end

function Yint:open_request(method, uri, headers, body)
    method = string.upper(method)
    local h = normalize_headers(headers)
    reject_unknown_yint_headers(h)

    local timestamp = required_header(h, "x-yint-timestamp")
    local nonce = required_header(h, "x-yint-nonce")
    local sign = required_header(h, "x-yint-sign")
    if timestamp:match("^[0-9]+$") == nil or not is_lower_hex(nonce, 32) or not is_lower_hex(sign, 64) then
        raise("bad yint headers", 400)
    end

    local now = os.time()
    local ts = tonumber(timestamp)
    if abs(now - ts) > self.time_window then
        raise("unauthorized", 401)
    end
    self:cleanup_nonces(now)
    if self.nonces[nonce] ~= nil then
        raise("unauthorized", 401)
    end

    local body_hex = bin_to_hex(body)
    local out = run(self.core_path, { "verify-req", self.k_mac_hex, method, uri, timestamp, nonce, sign, body_hex }, true)
    if out ~= "OK" then
        raise("unauthorized", 401)
    end

    self.nonces[nonce] = ts + self.time_window
    return self:decrypt_body(body)
end

function Yint:build_response(status, req_nonce, plaintext)
    local status_text = tostring(math.floor(status))
    local timestamp = tostring(os.time())
    local nonce = self:random_hex(16)
    local iv = self:random_hex(16)
    local body_hex = run(self.core_path, { "build-body", self.k_enc_hex, iv, bin_to_hex(plaintext) }, false)
    local sign = run(self.core_path, { "sign-resp", self.k_mac_hex, status_text, timestamp, nonce, req_nonce, body_hex }, false)
    return {
        headers = {
            ["X-Yint-Timestamp"] = timestamp,
            ["X-Yint-Nonce"] = nonce,
            ["X-Yint-Sign"] = sign,
        },
        body = hex_to_bin(body_hex),
    }
end

function Yint:open_response(status, req_nonce, headers, body)
    local status_text = tostring(math.floor(status))
    local h = normalize_headers(headers)
    reject_unknown_yint_headers(h)

    local timestamp = required_header(h, "x-yint-timestamp")
    local nonce = required_header(h, "x-yint-nonce")
    local sign = required_header(h, "x-yint-sign")
    if timestamp:match("^[0-9]+$") == nil or not is_lower_hex(nonce, 32) or not is_lower_hex(sign, 64) or not is_lower_hex(req_nonce, 32) then
        raise("bad yint headers", 400)
    end
    if abs(os.time() - tonumber(timestamp)) > self.time_window then
        raise("unauthorized", 401)
    end

    local body_hex = bin_to_hex(body)
    local out = run(self.core_path, { "verify-resp", self.k_mac_hex, status_text, timestamp, nonce, req_nonce, sign, body_hex }, true)
    if out ~= "OK" then
        raise("unauthorized", 401)
    end

    return self:decrypt_body(body)
end

function Yint:decrypt_body(body)
    local plain_hex = run(self.core_path, { "decrypt-body", self.k_enc_hex, bin_to_hex(body) }, true)
    if plain_hex == nil then
        raise("core failed", 500)
    end
    return hex_to_bin(plain_hex)
end

return {
    Yint = Yint,
    YintError = YintError,
    bin_to_hex = bin_to_hex,
    hex_to_bin = hex_to_bin,
}
