--[[--
kowireguard network layer: routes, DNS, firewall.

Two device-specific facts drive this file.

Landmine 1 (endpoint routing).  With AllowedIPs 0.0.0.0/0 the encrypted
packets to the endpoint get routed into the tunnel and the handshake loops
forever.  The fix is a host route to the endpoint via the original gateway,
plus a split default (0.0.0.0/1 + 128.0.0.0/1) instead of replacing the
default route.  The PW6 report in wtb04/wireguard.koplugin#2 failed because
a loose parse matched `via (%S+)` and `dev (%S+)` independently; the pattern
here is anchored to the whole line and returns nil on no-match.

Landmine 2 (firewall), as measured on this Colorsoft rather than assumed:
OUTPUT policy is ACCEPT with only loopback and SSH rules, so outbound UDP to
the endpoint already passes and no OUTPUT rule is added.  The real block is
INPUT policy DROP with every accept rule pinned to wlan0/ppp0/wwan0/lo/usb0.
Decrypted packets arriving on wg0 match nothing and are dropped: the tunnel
handshakes, counters rise, and nothing works.  Exactly one INPUT rule fixes
it, and it is removed verbatim on teardown.  Nothing is ever flushed.
]]

return function(env)

local socket = require("socket")
local _ = require("gettext")
local Util = env.util

local Net = {}

local RESOLV = "/etc/resolv.conf"

----------------------------------------------------------------------
-- Routing
----------------------------------------------------------------------

--- Parse the default route.
-- Anchored on the whole line.  Device output is exactly:
--   "default via 192.168.21.1 dev wlan0 "
-- @treturn table|nil {gw=, dev=} or nil plus reason
function Net.defaultRoute()
    local out, rc = Util.exec("ip route show default", true)
    if rc ~= 0 then
        return nil, _("Could not read the routing table.")
    end
    for line in out:gmatch("[^\n]+") do
        local gw, dev = line:match("^%s*default%s+via%s+(%S+)%s+dev%s+(%S+)")
        if gw and dev and Util.validIPv4(gw) and Util.validIface(dev) then
            return { gw = gw, dev = dev }
        end
    end
    -- No match is a hard stop, never a guess.
    return nil, _("No default route found. Is Wi-Fi connected?")
end

--- The on-link LAN prefix, so teardown and the kill switch never strand SSH.
function Net.lanRoute(dev)
    local out, rc = Util.exec("ip route show", true)
    if rc ~= 0 then return nil end
    for line in out:gmatch("[^\n]+") do
        local cidr, d = line:match("^%s*(%d+%.%d+%.%d+%.%d+/%d+)%s+dev%s+(%S+)%s+scope%s+link")
        if cidr and d == dev and Util.validCIDR(cidr) then
            return cidr
        end
    end
    return nil
end

--- Resolve an endpoint host to IPv4 using LuaSocket, not a shell.
function Net.resolveEndpoint(host)
    if Util.validIPv4(host) then return host end
    if not Util.validHost(host) then
        return nil, _("Endpoint hostname rejected by validator.")
    end
    local ip, err = socket.dns.toip(host)
    if not ip or not Util.validIPv4(ip) then
        Util.log("resolve failed for endpoint:", tostring(err))
        return nil, _("Could not resolve the endpoint hostname.")
    end
    Util.log("resolved endpoint", host, "->", ip)
    return ip
end

----------------------------------------------------------------------
-- Endpoint exclusion via policy routing
--
-- WireGuard's own encrypted packets must not enter the tunnel, or the
-- interface re-encrypts its own output in a loop (measured at roughly
-- 20 MB/s on this device).  Two ways to arrange that:
--
--   * A host route for the endpoint address via the physical gateway.
--     Simple, but it excludes that address for *all* traffic -- so any
--     other service reachable at the same IP becomes unreachable through
--     the tunnel.  Common when a WireGuard endpoint and a web service sit
--     behind one public address.
--
--   * An fwmark on WireGuard's socket plus an ip rule sending marked
--     packets out the physical interface.  The exclusion then applies only
--     to WireGuard's own traffic; everything else, including requests to
--     the endpoint's address, routes through the tunnel normally.
--
-- The second is what wg-quick does with `Table = auto`, and it is what this
-- plugin uses.  BusyBox ip supports `rule` and a custom table on this
-- firmware, verified on device.
--
-- Safety: without a working fwmark, adding the split-default routes starts
-- the loop immediately with nothing to stop it.  markApplied() is therefore
-- checked before any tunnel route is installed, and connect aborts if it
-- does not hold.
----------------------------------------------------------------------

-- Plugin constants, not user input, but asserted at load so a future edit
-- cannot introduce something the shell or BusyBox would reject.
Net.FWMARK = "0x4b57"      -- "KW"
assert(Net.FWMARK:match("^0x%x+$"), "FWMARK must be hex")
-- BusyBox ip rejects table IDs above 255 ("invalid argument to 'table'"), and
-- has no /etc/iproute2/rt_tables to name higher ones.  100 is inside the
-- range, outside the reserved IDs (253-255), and verified on device.
Net.RT_TABLE = "100"
assert(tonumber(Net.RT_TABLE) and tonumber(Net.RT_TABLE) >= 1 and tonumber(Net.RT_TABLE) <= 252,
    "RT_TABLE must be 1-252: BusyBox ip rejects higher IDs and 253-255 are reserved")

--- Route marked packets out the physical interface.
function Net.markRouteAdd(gw, dev)
    if not (Util.validIPv4(gw) and Util.validIface(dev)) then
        return false, _("Invalid gateway for the policy route.")
    end
    -- Replace only our own default route, never flush the table.  Nothing
    -- else on this device uses table 100, but flushing a shared table is the
    -- same class of mistake as flushing the firewall.
    Util.exec(string.format("ip route del default table %s", Net.RT_TABLE), true)
    local _o, rc = Util.exec(string.format("ip route add default via %s dev %s table %s",
        Util.q(gw), Util.q(dev), Net.RT_TABLE))
    if rc ~= 0 then
        return false, _("Could not add the policy route for the tunnel endpoint.")
    end
    if not Net.markRulePresent() then
        local _o2, rc2 = Util.exec(string.format("ip rule add fwmark %s lookup %s",
            Net.FWMARK, Net.RT_TABLE))
        if rc2 ~= 0 then
            return false, _("Could not add the policy rule for the tunnel endpoint.")
        end
    end
    return true
end

function Net.markRulePresent()
    local out, rc = Util.exec("ip rule show", true)
    if rc ~= 0 then return false end
    return out:find("fwmark " .. Net.FWMARK, 1, true) ~= nil
        or out:find("fwmark " .. Net.FWMARK:gsub("^0x", ""), 1, true) ~= nil
end

function Net.markRouteDel()
    local guard = 0
    while Net.markRulePresent() and guard < 8 do
        Util.exec(string.format("ip rule del fwmark %s lookup %s",
            Net.FWMARK, Net.RT_TABLE), true)
        guard = guard + 1
    end
    Util.exec(string.format("ip route del default table %s", Net.RT_TABLE), true)
end

--- Verify the policy route resolves through the physical interface.
-- Asks the kernel to route a marked packet; it must leave via the gateway.
function Net.markRouteVerify(gw, dev)
    if not Net.markRulePresent() then
        return false, _("The policy rule for the tunnel endpoint is missing.")
    end
    local out, rc = Util.exec(string.format("ip route show table %s", Net.RT_TABLE), true)
    if rc ~= 0 or out == "" then
        return false, _("The policy routing table is empty.")
    end
    local got_gw, got_dev = out:match("^%s*default%s+via%s+(%S+)%s+dev%s+(%S+)")
    if got_gw ~= gw or got_dev ~= dev then
        return false, _("The policy route does not use the physical interface.")
    end
    return true
end

--- Split default: two /1 routes rather than replacing the default route,
--- so the original default survives untouched for teardown.
function Net.addSplitDefault(iface)
    if not Util.validIface(iface) then
        return false, _("Invalid interface name.")
    end
    local ok = true
    for _i, prefix in ipairs({ "0.0.0.0/1", "128.0.0.0/1" }) do
        local _out, rc = Util.exec(string.format("ip route add %s dev %s", prefix, Util.q(iface)))
        if rc ~= 0 then ok = false end
    end
    if not ok then
        return false, _("Could not install tunnel routes.")
    end
    return true
end

function Net.delSplitDefault()
    for _i, prefix in ipairs({ "0.0.0.0/1", "128.0.0.0/1" }) do
        Util.exec("ip route del " .. prefix, true)
    end
end

--- Routes for a split-tunnel config (AllowedIPs narrower than 0.0.0.0/0).
function Net.addPeerRoutes(iface, cidrs)
    if not Util.validIface(iface) then return false end
    for _i, cidr in ipairs(cidrs) do
        if Util.validCIDR(cidr) and cidr ~= "0.0.0.0/0" then
            Util.exec(string.format("ip route add %s dev %s", Util.q(cidr), Util.q(iface)), true)
        end
    end
    return true
end

function Net.delPeerRoutes(cidrs)
    for _i, cidr in ipairs(cidrs) do
        if Util.validCIDR(cidr) and cidr ~= "0.0.0.0/0" then
            Util.exec("ip route del " .. Util.q(cidr), true)
        end
    end
end

function Net.routeTable()
    local out = Util.exec("ip route show", true)
    return out
end

----------------------------------------------------------------------
-- Firewall
----------------------------------------------------------------------

-- iptables v1.4.15 on this device supports -C, verified in Step 0, so add
-- and remove are both check-gated and therefore idempotent.
function Net.fwRule(iface, mode)
    if mode == "open" then
        return string.format("INPUT -i %s -j ACCEPT", iface)
    end
    return string.format("INPUT -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", iface)
end

function Net.fwPresent(iface, mode)
    if not Util.validIface(iface) then return false end
    local _out, rc = Util.exec("iptables -C " .. Net.fwRule(iface, mode), true)
    return rc == 0
end

function Net.fwAdd(iface, mode)
    if not Util.validIface(iface) then
        return false, _("Invalid interface name.")
    end
    if Net.fwPresent(iface, mode) then
        Util.log("firewall rule already present, not adding again")
        return true
    end
    local _out, rc = Util.exec("iptables -I " .. Net.fwRule(iface, mode))
    if rc ~= 0 then
        return false, _("Could not add the firewall rule for the tunnel.")
    end
    return true
end

function Net.fwDel(iface, mode)
    if not Util.validIface(iface) then return end
    -- Delete precisely what was added, and only while it is present.
    -- The firewall is never flushed: a Kindle left with no firewall after a
    -- failed teardown is a worse outcome than a stale rule.
    local guard = 0
    while Net.fwPresent(iface, mode) and guard < 8 do
        Util.exec("iptables -D " .. Net.fwRule(iface, mode))
        guard = guard + 1
    end
end

function Net.fwState(iface, mode)
    if Net.fwPresent(iface, mode) then
        return _("present")
    end
    return _("absent")
end

----------------------------------------------------------------------
-- Kill switch (optional, off by default)
--
-- Carves out loopback, the tunnel, the LAN prefix and the endpoint before
-- dropping everything else outbound.  The LAN carve-out is what keeps SSH
-- on port 2222 reachable, which is the only recovery path on this device.
----------------------------------------------------------------------

function Net.killSwitchRules(iface, lan_cidr, endpoint_ip, endpoint_port)
    local rules = {
        string.format("OUTPUT -o %s -j ACCEPT", iface),
    }
    if lan_cidr then
        rules[#rules + 1] = string.format("OUTPUT -d %s -j ACCEPT", lan_cidr)
    end
    if endpoint_ip and endpoint_port then
        rules[#rules + 1] = string.format("OUTPUT -d %s -p udp --dport %d -j ACCEPT",
            endpoint_ip, endpoint_port)
    end
    rules[#rules + 1] = "OUTPUT -o lo -j ACCEPT"
    return rules
end

function Net.killSwitchOn(iface, lan_cidr, endpoint_ip, endpoint_port)
    if not Util.validIface(iface) then return false end
    local rules = Net.killSwitchRules(iface, lan_cidr, endpoint_ip, endpoint_port)
    -- Insert accepts first, then append the terminal DROP, so there is never
    -- a moment where DROP is active without its carve-outs.
    for _i, r in ipairs(rules) do
        local _o, rc = Util.exec("iptables -C " .. r, true)
        if rc ~= 0 then Util.exec("iptables -I " .. r) end
    end
    local _o2, rc2 = Util.exec("iptables -C OUTPUT -j DROP", true)
    if rc2 ~= 0 then
        Util.exec("iptables -A OUTPUT -j DROP")
    end
    return true, rules
end

function Net.killSwitchOff(iface, lan_cidr, endpoint_ip, endpoint_port)
    -- DROP comes off first so connectivity is never lost mid-teardown.
    local guard = 0
    while guard < 8 do
        local _o, rc = Util.exec("iptables -C OUTPUT -j DROP", true)
        if rc ~= 0 then break end
        Util.exec("iptables -D OUTPUT -j DROP")
        guard = guard + 1
    end
    if not iface or not Util.validIface(iface) then return end
    local rules = Net.killSwitchRules(iface, lan_cidr, endpoint_ip, endpoint_port)
    for _i, r in ipairs(rules) do
        local g = 0
        while g < 8 do
            local _o, rc = Util.exec("iptables -C " .. r, true)
            if rc ~= 0 then break end
            Util.exec("iptables -D " .. r)
            g = g + 1
        end
    end
end

function Net.killSwitchActive()
    local _o, rc = Util.exec("iptables -C OUTPUT -j DROP", true)
    return rc == 0
end

----------------------------------------------------------------------
-- DNS
--
-- /etc/resolv.conf is a symlink to /var/run/resolv.conf on a tmpfs, and the
-- root filesystem is rw, so writing is safe.  We write *through* the symlink
-- so the link itself is never replaced.
--
-- Honest limitation: wifid rewrites this file on Wi-Fi state changes and we
-- cannot prevent that.  The failure mode is benign -- the LAN resolver stays
-- reachable over the surviving on-link route -- so the result is a DNS leak,
-- not a DNS outage.  dnsIsOurs() lets the status line report it instead of
-- pretending.
----------------------------------------------------------------------

function Net.dnsBackupPath()
    return env.run_dir .. "/resolv.conf.bak"
end

function Net.dnsBackup()
    local cur = Util.read(RESOLV)
    if not cur then
        return false, _("Could not read resolv.conf.")
    end
    if not Util.write(Net.dnsBackupPath(), cur) then
        return false, _("Could not write the DNS backup.")
    end
    Util.log("dns: backed up resolv.conf")
    return true
end

function Net.dnsSet(servers)
    if not servers or #servers == 0 then return true end
    local lines = {}
    for _i, s in ipairs(servers) do
        if Util.validIPv4(s) then
            lines[#lines + 1] = "nameserver " .. s
        end
    end
    if #lines == 0 then
        return false, _("No valid DNS servers in the config.")
    end
    if not Util.write(RESOLV, table.concat(lines, "\n") .. "\n") then
        return false, _("Could not write resolv.conf.")
    end
    Util.log("dns: set", table.concat(lines, " "))
    return true
end

function Net.dnsRestore()
    local bak = Util.read(Net.dnsBackupPath())
    if not bak then
        Util.log("dns: no backup to restore")
        return false
    end
    local ok = Util.write(RESOLV, bak)
    if ok then
        Util.log("dns: restored")
        os.remove(Net.dnsBackupPath())
    end
    return ok
end

--- Is resolv.conf still what we wrote?  False after wifid rewrites it.
function Net.dnsIsOurs(servers)
    if not servers or #servers == 0 then return true end
    local cur = Util.read(RESOLV) or ""
    for _i, s in ipairs(servers) do
        if not cur:find(s, 1, true) then return false end
    end
    return true
end

function Net.dnsCurrent()
    return Util.read(RESOLV) or ""
end


----------------------------------------------------------------------
-- Interface helpers
----------------------------------------------------------------------

function Net.ifaceExists(iface)
    if not Util.validIface(iface) then return false end
    local _out, rc = Util.exec("ip link show " .. Util.q(iface), true)
    return rc == 0
end

function Net.ifaceUp(iface, mtu)
    if not Util.validIface(iface) then return false end
    local m = tonumber(mtu) or 1420
    if m < 576 or m > 1500 then m = 1420 end
    local _o, rc = Util.exec(string.format("ip link set %s mtu %d up", Util.q(iface), m))
    return rc == 0
end

function Net.ifaceDown(iface)
    if not Util.validIface(iface) then return end
    Util.exec("ip link set " .. Util.q(iface) .. " down", true)
end

function Net.addrAdd(iface, cidrs)
    if not Util.validIface(iface) then return false end
    local any = false
    for _i, c in ipairs(cidrs) do
        if Util.validCIDR(c) then
            local _o, rc = Util.exec(string.format("ip addr add %s dev %s", Util.q(c), Util.q(iface)))
            if rc == 0 then any = true end
        end
    end
    return any
end

return Net

end
