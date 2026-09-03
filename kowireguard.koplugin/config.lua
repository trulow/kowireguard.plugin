--[[--
kowireguard config parser.

`wg setconf` rejects the wg-quick-only keys (Address, DNS, MTU, Table,
PostUp, ...), so the .conf is split in two here: the subset wg understands
is regenerated for setconf, and the rest is handed back for the plugin to
apply with ip/iptables itself.

IPv6 is stripped, not passed through.  This kernel has CONFIG_IPV6_TUNNEL
unset and wlan0 carries only a link-local v6 address, so v6 AllowedIPs would
produce route commands that fail.  Every strip is logged rather than
silently dropped.
]]

return function(env)

local _ = require("gettext")
local Util = env.util

local Config = {}

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function splitList(s)
    local out = {}
    for item in tostring(s):gmatch("[^,]+") do
        local v = trim(item)
        if v ~= "" then out[#out + 1] = v end
    end
    return out
end

-- Keys wg setconf accepts, per section.
local WG_INTERFACE_KEYS = { privatekey = "PrivateKey", listenport = "ListenPort", fwmark = "FwMark" }
local WG_PEER_KEYS = {
    publickey = "PublicKey",
    presharedkey = "PresharedKey",
    allowedips = "AllowedIPs",
    endpoint = "Endpoint",
    persistentkeepalive = "PersistentKeepalive",
}

-- Keys wg-quick handles that we apply ourselves.
local QUICK_KEYS = {
    address = true, dns = true, mtu = true, table = true,
    preup = true, postup = true, predown = true, postdown = true,
    saveconfig = true,
}

--- Parse a .conf file.
-- @string path absolute path to the config
-- @treturn table|nil parsed config, or nil plus an error string
function Config.parse(path)
    if not Util.validPath(path) then
        return nil, _("Config path contains unsupported characters.")
    end
    local data = Util.read(path)
    if not data then
        return nil, _("Config file could not be read.")
    end

    local cfg = {
        path = path,
        interface = {},
        peers = {},
        address = {},
        dns = {},
        mtu = nil,
        manage_table = true,
        warnings = {},
    }

    local section, peer
    local lineno = 0

    for raw in (data .. "\n"):gmatch("([^\n]*)\n") do
        lineno = lineno + 1
        local line = trim(raw:gsub("#.*$", ""))
        if line ~= "" then
            local sect = line:match("^%[(%a+)%]$")
            if sect then
                section = sect:lower()
                if section == "peer" then
                    peer = { allowed_ips = {}, fields = {} }
                    cfg.peers[#cfg.peers + 1] = peer
                end
            else
                local key, value = line:match("^([%w_]+)%s*=%s*(.*)$")
                if not key then
                    cfg.warnings[#cfg.warnings + 1] =
                        string.format("line %d: unparsable, ignored", lineno)
                else
                    local k = key:lower()
                    value = trim(value)
                    if section == "interface" then
                        Config._interfaceKey(cfg, k, key, value)
                    elseif section == "peer" and peer then
                        Config._peerKey(cfg, peer, k, key, value)
                    else
                        cfg.warnings[#cfg.warnings + 1] =
                            string.format("line %d: %s outside a section, ignored", lineno, key)
                    end
                end
            end
        end
    end

    if not cfg.interface.PrivateKey then
        return nil, _("Config has no PrivateKey in [Interface].")
    end
    if #cfg.peers == 0 then
        return nil, _("Config has no [Peer] section.")
    end
    for _idx, p in ipairs(cfg.peers) do
        if not p.fields.PublicKey then
            return nil, _("A [Peer] section has no PublicKey.")
        end
    end
    if #cfg.address == 0 then
        return nil, _("Config has no usable IPv4 Address in [Interface].")
    end

    return cfg
end

function Config._interfaceKey(cfg, k, key, value)
    if WG_INTERFACE_KEYS[k] then
        cfg.interface[WG_INTERFACE_KEYS[k]] = value
        return
    end
    if k == "address" then
        for _i, a in ipairs(splitList(value)) do
            if Util.validCIDR(a) then
                cfg.address[#cfg.address + 1] = a
            elseif Util.validIPv4(a) then
                cfg.address[#cfg.address + 1] = a .. "/32"
            else
                cfg.warnings[#cfg.warnings + 1] = "Address " .. a .. " is not IPv4, dropped"
            end
        end
    elseif k == "dns" then
        for _i, d in ipairs(splitList(value)) do
            if Util.validIPv4(d) then
                cfg.dns[#cfg.dns + 1] = d
            else
                cfg.warnings[#cfg.warnings + 1] = "DNS " .. d .. " is not IPv4, dropped"
            end
        end
    elseif k == "mtu" then
        local n = tonumber(value)
        if n and n >= 576 and n <= 1500 then
            cfg.mtu = n
        else
            cfg.warnings[#cfg.warnings + 1] = "MTU " .. value .. " out of range, ignored"
        end
    elseif k == "table" then
        if value:lower() == "off" then
            cfg.manage_table = false
            cfg.warnings[#cfg.warnings + 1] = "Table = off: kowireguard will not add tunnel routes"
        end
    elseif QUICK_KEYS[k] then
        -- PostUp/PreDown and friends are refused rather than executed.
        -- Running arbitrary provider-supplied shell as root on a device
        -- whose only recovery path is SSH is not a tradeoff worth making.
        cfg.warnings[#cfg.warnings + 1] = key .. " is not executed by kowireguard (ignored)"
    else
        cfg.warnings[#cfg.warnings + 1] = "unknown [Interface] key " .. key .. ", ignored"
    end
end

function Config._peerKey(cfg, peer, k, key, value)
    if k == "allowedips" then
        for _i, a in ipairs(splitList(value)) do
            if a:find(":") then
                cfg.warnings[#cfg.warnings + 1] = "AllowedIPs " .. a .. " is IPv6, dropped"
            elseif Util.validCIDR(a) then
                peer.allowed_ips[#peer.allowed_ips + 1] = a
            elseif Util.validIPv4(a) then
                peer.allowed_ips[#peer.allowed_ips + 1] = a .. "/32"
            else
                cfg.warnings[#cfg.warnings + 1] = "AllowedIPs " .. a .. " unparsable, dropped"
            end
        end
    elseif k == "endpoint" then
        local host, port = value:match("^%[?([^%]]+)%]?:(%d+)$")
        if not host then
            cfg.warnings[#cfg.warnings + 1] = "Endpoint " .. value .. " unparsable"
            return
        end
        if host:find(":") then
            cfg.warnings[#cfg.warnings + 1] = "Endpoint is IPv6, unsupported on this device"
            return
        end
        if not (Util.validIPv4(host) or Util.validHost(host)) then
            cfg.warnings[#cfg.warnings + 1] = "Endpoint host rejected by validator"
            return
        end
        if not Util.validPort(port) then
            cfg.warnings[#cfg.warnings + 1] = "Endpoint port out of range"
            return
        end
        peer.endpoint_host = host
        peer.endpoint_port = tonumber(port)
        peer.fields.Endpoint = value
    elseif WG_PEER_KEYS[k] then
        peer.fields[WG_PEER_KEYS[k]] = value
    else
        cfg.warnings[#cfg.warnings + 1] = "unknown [Peer] key " .. key .. ", ignored"
    end
end

--- Render the subset `wg setconf` understands.
-- Contains the private key, so the caller must write it only to tmpfs and
-- delete it immediately after use.
function Config.toSetconf(cfg)
    local out = { "[Interface]" }
    for _i, k in ipairs({ "PrivateKey", "ListenPort", "FwMark" }) do
        if cfg.interface[k] then
            out[#out + 1] = k .. " = " .. cfg.interface[k]
        end
    end
    for _i, p in ipairs(cfg.peers) do
        out[#out + 1] = ""
        out[#out + 1] = "[Peer]"
        for _j, k in ipairs({ "PublicKey", "PresharedKey", "Endpoint", "PersistentKeepalive" }) do
            if p.fields[k] then
                out[#out + 1] = k .. " = " .. p.fields[k]
            end
        end
        if #p.allowed_ips > 0 then
            out[#out + 1] = "AllowedIPs = " .. table.concat(p.allowed_ips, ", ")
        end
    end
    return table.concat(out, "\n") .. "\n"
end

--- True if any peer routes the whole v4 internet.
function Config.isDefaultRoute(cfg)
    for _i, p in ipairs(cfg.peers) do
        for _j, a in ipairs(p.allowed_ips) do
            if a == "0.0.0.0/0" then return true end
        end
    end
    return false
end

--- The peer whose endpoint needs a pinned host route (landmine 1).
function Config.primaryPeer(cfg)
    for _i, p in ipairs(cfg.peers) do
        if p.endpoint_host then return p end
    end
    return nil
end

--- Config text with the private key removed, for Diagnostics.
function Config.redactedText(path)
    local data = Util.read(path)
    if not data then return nil end
    return Util.redact(data)
end

return Config

end
