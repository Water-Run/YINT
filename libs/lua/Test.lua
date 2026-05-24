local yint = require("yint")

local pass, fail = 0, 0

local function check(name, ok, detail)
    if ok then
        pass = pass + 1
        print("[PASS] " .. name)
    else
        fail = fail + 1
        print("[FAIL] " .. name)
        if detail and detail ~= "" then
            print("       " .. detail)
        end
    end
end

local function expect_status(name, status, fn)
    local ok, err = pcall(fn)
    if ok then
        check(name, false, "no error")
    else
        check(name, type(err) == "table" and err.status == status, "status=" .. tostring(type(err) == "table" and err.status or nil))
    end
end

local master_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
local master = yint.hex_to_bin(master_hex)
local core = arg and arg[1] or "../../core/bin/yint"
local Y = yint.Yint.new(master, { core_path = core, time_window = 300 })

check("derive K_enc", Y.k_enc_hex == "82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5")
check("derive K_mac", Y.k_mac_hex == "ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50")

local req = Y:build_request("post", "/api/echo?x=1&x=2", "hello yint")
check("request body encrypted", req.body ~= "hello yint" and #req.body >= 32)
check("open request", Y:open_request("POST", "/api/echo?x=1&x=2", req.headers, req.body) == "hello yint")
expect_status("replay rejected", 401, function()
    Y:open_request("POST", "/api/echo?x=1&x=2", req.headers, req.body)
end)

local resp = Y:build_response(200, req.nonce, "world")
check("open response", Y:open_response(200, req.nonce, resp.headers, resp.body) == "world")
expect_status("response req nonce binding", 401, function()
    Y:open_response(200, string.rep("0", 32), resp.headers, resp.body)
end)

local bad = {}
for k, v in pairs(req.headers) do
    bad[k] = v
end
bad["X-Yint-Extra"] = "1"
expect_status("unknown request x-yint header", 400, function()
    Y:open_request("POST", "/api/echo?x=1&x=2", bad, req.body)
end)

print("")
print("pass=" .. pass .. " fail=" .. fail)
os.exit(fail == 0 and 0 or 1)
