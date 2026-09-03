--[[--
kowireguard tunnel lifecycle: connect, disconnect, startup reconciliation and
post-resume re-assertion.

Journal, process probing and status reading live in state.lua; this file
re-exports them so callers see one Tunnel interface.

Every mutation is journalled before it is made, so a teardown after a crash
reverses exactly what was done.  Teardown also scans for state independently
of the journal, so it still works if the journal is lost, and is safe to run
any number of times.
]]

return function(env)

local _ = require("gettext")
local Util = env.util
local Net = env.net
local Config = env.config
local State = env.state

-- One interface for callers: state reading and lifecycle on the same table.
local Tunnel = setmetatable({}, { __index = State })

-- Binary paths live in state.lua; bind them locally so the call sites below
-- resolve lexically rather than falling through to a nil global.
local wgBin = State.wgBin
local wgGoBin = State.wgGoBin

----------------------------------------------------------------------
-- Connect
----------------------------------------------------------------------

local function fail(journal, msg)
    State.last_error = msg
    Util.log("connect failed:", msg)
    Tunnel.writeJournal(journal)
    Tunnel.disconnect()
    State.busy = false
    return false, msg
end

--- Bring the tunnel up.  Synchronous; callers show a message first.
function Tunnel.connect(conf_name)
    if State.busy then return false, _("Already working.") end
    State.last_error = nil
    State.busy = true

    if not Tunnel.binariesPresent() then
        State.busy = false
        return false, _("wg and wireguard-go are not in the plugin's bin directory.")
    end

    -- Leave no previous state behind.
    Tunnel.disconnect()

    local iface = env.settings:readSetting("iface") or "wg0"
    if not Util.validIface(iface) then
        State.busy = false
        return false, _("Configured interface name is not valid.")
    end

    local conf_path = env.config_dir .. "/" .. conf_name
    if not Util.isFile(conf_path) then
        State.busy = false
        return false, _("Config file not found.")
    end

    local cfg, err = Config.parse(conf_path)
    if not cfg then
        State.busy = false
        return false, err
    end
    for _i, w in ipairs(cfg.warnings) do Util.log("config:", w) end

    local peer = Config.primaryPeer(cfg)
    if not peer then
        State.busy = false
        return false, _("Config has no usable endpoint.")
    end

    local journal = { iface = iface, conf = conf_name, steps = {} }
    local function mark(step, value)
        journal.steps[#journal.steps + 1] = step
        if value then journal[step] = value end
        Tunnel.writeJournal(journal)
    end

    -- 1. Default route, parsed strictly.
    local dr, drerr = Net.defaultRoute()
    if not dr then return fail(journal, drerr) end
    journal.gw, journal.dev = dr.gw, dr.dev
    journal.lan = Net.lanRoute(dr.dev)

    -- 2. Resolve the endpoint while normal DNS still applies.
    local ep_ip, eperr = Net.resolveEndpoint(peer.endpoint_host)
    if not ep_ip then return fail(journal, eperr) end
    journal.endpoint_ip = ep_ip
    journal.endpoint_port = peer.endpoint_port

    -- Substitute the resolved address into what wg will be given.  Two
    -- reasons, both load-bearing:
    --
    --  * A statically linked glibc `wg` cannot reliably call getaddrinfo()
    --    (NSS is dlopen'd at runtime), so a hostname endpoint would fail in
    --    setconf while a bare IP worked -- a confusing failure to chase.
    --  * With round-robin or split-horizon DNS, wg could otherwise resolve
    --    to a different address than the one we pin the host route to, and
    --    the tunnel would fail exactly as landmine 1 describes while every
    --    route looked correct.
    if peer.endpoint_host ~= ep_ip then
        Util.log("endpoint: passing resolved address to wg instead of hostname")
    end
    peer.fields.Endpoint = ep_ip .. ":" .. tostring(peer.endpoint_port)

    -- 3. Start wireguard-go, then prove it is still alive.  An ABI mismatch
    --    or a missing syscall kills it instantly and silently.
    Util.mkdirp(env.run_dir)
    local golog = env.run_dir .. "/wireguard-go.log"
    -- LOG_LEVEL=verbose: at the default "error" level wireguard-go prints
    -- nothing on a successful start, which makes an empty log ambiguous
    -- between "working" and "died silently".  Truncated per connect so the
    -- extra chatter cannot grow without bound on the /var tmpfs.
    Util.write(golog, "")
    local pid = Util.spawn(string.format(
        "WG_PROCESS_FOREGROUND=1 LOG_LEVEL=verbose %s %s >>%s 2>&1",
        Util.q(wgGoBin()), Util.q(iface), Util.q(golog)))
    mark("process", pid and tostring(pid) or "?")
    Util.exec("sleep 1", true)

    local running = Tunnel.findProcess(iface)
    local iface_up = Net.ifaceExists(iface)
    if not running and not iface_up then
        local tail = Util.tail(golog, 15) or ""
        Util.log("wireguard-go died immediately:", tail ~= "" and tail or "(no output)")
        return fail(journal, _("wireguard-go exited immediately. See Diagnostics for its output."))
    end
    if not iface_up then
        return fail(journal, _("wireguard-go started but no interface appeared."))
    end
    mark("iface")

    -- 4. Apply the wg-only subset.  Written to tmpfs at 0600 and deleted at
    --    once, so the private key never lands on USB-visible storage twice.
    local tmpconf = env.run_dir .. "/" .. iface .. ".conf"
    if not Util.write(tmpconf, Config.toSetconf(cfg)) then
        return fail(journal, _("Could not stage the tunnel configuration."))
    end
    Util.chmodBestEffort(tmpconf, "0600")
    local _o, rc = Util.exec(string.format("%s setconf %s %s",
        Util.q(wgBin()), Util.q(iface), Util.q(tmpconf)))
    os.remove(tmpconf)
    if rc ~= 0 then
        return fail(journal, _("wg setconf rejected the configuration."))
    end

    -- 5. Exclude WireGuard's own packets from the tunnel, by marking them
    --    and routing marked traffic out the physical interface.  Unlike a
    --    host route for the endpoint address, this leaves that address
    --    reachable through the tunnel for everything else -- which matters
    --    when a service shares a public IP with the endpoint.
    --
    --    This is a fail-closed gate.  If the mark is not actually set, the
    --    split-default routes added below would send WireGuard's own output
    --    back into itself, and the interface would re-encrypt its own
    --    traffic at roughly 20 MB/s with nothing to stop it.
    local _om, rcm = Util.exec(string.format("%s set %s fwmark %s",
        Util.q(wgBin()), Util.q(iface), Net.FWMARK))
    if rcm ~= 0 then
        return fail(journal, _("Could not set the WireGuard fwmark."))
    end

    local mout = Util.exec(string.format("%s show %s fwmark",
        Util.q(wgBin()), Util.q(iface)), true)
    if not mout:find(Net.FWMARK, 1, true) then
        return fail(journal, _("The WireGuard fwmark did not apply. Refusing to bring the tunnel up."))
    end
    mark("fwmark")

    local okr, rerr = Net.markRouteAdd(dr.gw, dr.dev)
    if not okr then return fail(journal, rerr) end
    mark("mark_route")

    local okv, verr = Net.markRouteVerify(dr.gw, dr.dev)
    if not okv then
        return fail(journal, verr .. " " .. _("Refusing to bring the tunnel up."))
    end
    Util.log("endpoint exclusion verified: fwmark", Net.FWMARK,
        "-> table", Net.RT_TABLE, "via", dr.gw, "dev", dr.dev)

    -- 6. Address and MTU.
    if not Net.addrAdd(iface, cfg.address) then
        return fail(journal, _("Could not assign the tunnel address."))
    end
    mark("addr")
    local mtu = cfg.mtu or env.settings:readSetting("mtu") or 1420
    journal.mtu = mtu
    if not Net.ifaceUp(iface, mtu) then
        return fail(journal, _("Could not bring the interface up."))
    end

    -- 7. Routes.
    if cfg.manage_table then
        if Config.isDefaultRoute(cfg) then
            local oks, serr = Net.addSplitDefault(iface)
            if not oks then return fail(journal, serr) end
            mark("split_default")
        else
            local cidrs = {}
            for _i, p in ipairs(cfg.peers) do
                for _j, a in ipairs(p.allowed_ips) do cidrs[#cidrs + 1] = a end
            end
            Net.addPeerRoutes(iface, cidrs)
            journal.peer_routes = table.concat(cidrs, ",")
            mark("peer_routes")
        end
    end

    -- 8. Firewall: the INPUT rule for decrypted traffic on wg0.
    local fw_mode = env.settings:readSetting("fw_mode") or "established"
    local okf, ferr = Net.fwAdd(iface, fw_mode)
    if not okf then return fail(journal, ferr) end
    journal.fw_mode = fw_mode
    mark("firewall")

    -- 9. DNS.
    local dns_mode = env.settings:readSetting("dns_mode") or "apply"
    if dns_mode == "apply" and #cfg.dns > 0 then
        if Net.dnsBackup() then
            local okd = Net.dnsSet(cfg.dns)
            if okd then
                env.dns_applied = cfg.dns
                mark("dns")
            else
                Util.log("dns: could not apply, leaving alone")
            end
        end
    end

    -- 10. Kill switch, only if explicitly enabled.
    if env.settings:isTrue("killswitch") then
        Net.killSwitchOn(iface, journal.lan, ep_ip, peer.endpoint_port)
        mark("killswitch")
    end

    journal.active = true
    -- Record which KOReader process owns this tunnel.  KOReader instantiates
    -- plugins per UI -- once for the file manager, again for the reader when
    -- a document is opened -- so init() runs more than once per process and
    -- startup reconciliation must not mistake a live tunnel for crash debris.
    journal.owner_pid = Util.selfPid()
    Tunnel.writeJournal(journal)
    env.settings:saveSetting("last_conf", conf_name)
    State.busy = false
    Util.log("connected on", iface, "via", conf_name)
    return true
end

----------------------------------------------------------------------
-- Disconnect.  Idempotent, journal-driven with a scan-based fallback.
----------------------------------------------------------------------

function Tunnel.disconnect()
    local j = Tunnel.readJournal() or {}
    local iface = j.iface or env.settings:readSetting("iface") or "wg0"
    if not Util.validIface(iface) then iface = "wg0" end

    -- Kill switch first, so connectivity is never lost mid-teardown.
    if j.killswitch or Net.killSwitchActive() then
        Net.killSwitchOff(iface, j.lan, j.endpoint_ip, j.endpoint_port)
    end

    if env.dns_applied or j.dns then
        Net.dnsRestore()
        env.dns_applied = nil
    end

    Net.fwDel(iface, j.fw_mode or env.settings:readSetting("fw_mode") or "established")
    -- Also clear the other mode, in case the setting changed while up.
    Net.fwDel(iface, "open")

    -- Order matters: the tunnel routes come out before the policy rule.
    -- Removing the rule first would leave WireGuard's own packets routed by
    -- the main table while the split default is still installed, sending
    -- them into the tunnel and starting the loop.
    Net.delSplitDefault()
    if j.peer_routes then
        local cidrs = {}
        for c in j.peer_routes:gmatch("[^,]+") do cidrs[#cidrs + 1] = c end
        Net.delPeerRoutes(cidrs)
    end
    Net.markRouteDel()

    Net.ifaceDown(iface)

    -- Stop the process.  The /proc scan is authoritative because it matches
    -- the binary and the interface as a whole argv entry; the journalled PID
    -- is only a fallback and is verified against its cmdline first, since it
    -- was the spawning subshell's number and may have been recycled.
    local scanned = Tunnel.findProcess(iface)
    if scanned then
        Util.killIfMatches(scanned, "wireguard%-go")
    elseif j.process then
        Util.killIfMatches(tonumber(j.process), "wireguard%-go")
    end

    -- Anything still standing after that gets one more pass, same check.
    local guard = 0
    local leftover = Tunnel.findProcess(iface)
    while leftover and guard < 3 do
        Util.killIfMatches(leftover, "wireguard%-go")
        guard = guard + 1
        leftover = Tunnel.findProcess(iface)
    end

    -- wireguard-go leaves its control socket behind if it was killed hard.
    -- iface is validated above, but quote it anyway: this runs as root.
    Util.exec("rm -f " .. Util.q("/var/run/wireguard/" .. iface .. ".sock"), true)

    Tunnel.clearJournal()
    Util.log("teardown complete for", iface)
    return true
end

--- Called at startup: reverse anything a crash or battery death left behind.
--- Called at startup: reverse anything a crash or battery death left behind.
--
-- The journal records the PID of the KOReader process that brought the
-- tunnel up.  If that PID matches this process, the tunnel is ours and still
-- running -- opening a book re-instantiates the plugin and calls init()
-- again, and tearing down there would kill a working tunnel mid-download.
-- A different (or missing) PID means a genuinely previous session.
function Tunnel.reconcileAtStartup()
    local j = Tunnel.readJournal()
    local iface = (j and j.iface) or env.settings:readSetting("iface") or "wg0"

    if j and j.active and j.owner_pid and j.owner_pid == Util.selfPid() then
        Util.log("startup: tunnel belongs to this process, leaving it up")
        return false
    end

    local stale = (j ~= nil) or Net.ifaceExists(iface) or (Tunnel.findProcess(iface) ~= nil)
        or Net.killSwitchActive() or Net.markRulePresent()
    if not stale then return false end
    Util.log("startup: previous session left state behind, tearing down")
    Tunnel.disconnect()
    return true
end

--- Re-verify after resume.  Interface, routes, firewall and DNS can all be
--- stale independently after a suspend or a Wi-Fi reconnect.
--- Re-verify after resume.  Interface, routes, firewall and DNS can all be
--- stale independently after a suspend or a Wi-Fi reconnect.
--
-- Returns true plus a list of what was repaired, or false plus a reason:
--   "gone"  -- the tunnel did not survive; the caller should tear down
--   "retry" -- something is wrong but cannot be fixed yet (typically Wi-Fi
--              has not reassociated, so there is no default route to pin the
--              endpoint route to).  The caller should call again shortly.
--
-- The retry path matters more than it looks.  While the endpoint route is
-- missing and AllowedIPs is 0.0.0.0/0, packets to the WireGuard endpoint are
-- routed into the tunnel itself: wireguard-go re-encrypts its own output in a
-- loop, burning battery and inflating the tx counter without moving any real
-- traffic.  Every second spent in that state is wasted, so an unrepairable
-- endpoint route is reported and retried rather than passed over in silence.
function Tunnel.reassert()
    local j = Tunnel.readJournal()
    if not j or not j.active then return false end
    local iface = j.iface
    local repaired = {}
    local retry = false

    if not Net.ifaceExists(iface) or not Tunnel.findProcess(iface) then
        Util.log("resume: tunnel is gone")
        return false, "gone"
    end

    if j.gw and j.dev then
        local ok = Net.markRouteVerify(j.gw, j.dev)
        if not ok then
            local dr, drerr = Net.defaultRoute()
            if dr then
                local added = Net.markRouteAdd(dr.gw, dr.dev)
                if added and Net.markRouteVerify(dr.gw, dr.dev) then
                    j.gw, j.dev = dr.gw, dr.dev
                    Tunnel.writeJournal(j)
                    repaired[#repaired + 1] = "endpoint exclusion"
                else
                    retry = true
                    Util.log("resume: endpoint exclusion re-added but did not verify")
                end
            else
                retry = true
                Util.log("resume: endpoint exclusion is missing and cannot be repaired yet",
                    "(" .. tostring(drerr) .. ")")
            end
        end
    end

    local fw_mode = j.fw_mode or "established"
    if not Net.fwPresent(iface, fw_mode) then
        Net.fwAdd(iface, fw_mode)
        repaired[#repaired + 1] = "firewall rule"
    end

    if env.dns_applied and not Net.dnsIsOurs(env.dns_applied) then
        Net.dnsSet(env.dns_applied)
        repaired[#repaired + 1] = "DNS"
    end

    if #repaired > 0 then
        Util.log("resume: repaired", table.concat(repaired, ", "))
    end
    -- Take the interface down while the endpoint route cannot be restored.
    -- Measured on a Colorsoft, a loop moves roughly 20 MB/s of
    -- self-encrypted traffic: the retry window would otherwise cost hundreds
    -- of megabytes of pointless encryption and a real battery hit.  Traffic
    -- is dead either way while the route is wrong; this simply stops the
    -- device burning power to achieve nothing, and still allows a slow Wi-Fi
    -- reassociation to succeed.
    if retry and not j.paused then
        Net.ifaceDown(iface)
        j.paused = true
        Tunnel.writeJournal(j)
        Util.log("resume: interface brought down to stop the tunnel looping")
    elseif not retry and j.paused then
        Net.ifaceUp(iface, j.mtu or env.settings:readSetting("mtu") or 1420)
        j.paused = nil
        Tunnel.writeJournal(j)
        repaired[#repaired + 1] = "interface resumed"
        Util.log("resume: route restored, interface back up")
    end

    if retry then
        return false, "retry"
    end
    return true, repaired
end

return Tunnel

end
