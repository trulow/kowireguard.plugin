--[[--
kowireguard tunnel state: the journal, process probing and status reading.

State is read, never remembered.  status() probes the interface, the process
and `wg show` on every call; a stored PID is treated as a hint for teardown,
never as evidence the tunnel is alive.

The journal is a plain serialised table on tmpfs.  That lifetime is exactly
right: it survives a KOReader crash, when routes are still in place and need
reversing, and does not survive a reboot, when they are already gone.
]]

return function(env)

local _ = require("gettext")
local Util = env.util
local Net = env.net

local State = {}

State.CONNECTING = "connecting"
State.CONNECTED = "connected"
State.DISCONNECTED = "disconnected"
State.ERROR = "error"

State.last_error = nil
State.busy = false

local function journalPath()
    return env.run_dir .. "/journal.lua"
end

----------------------------------------------------------------------
-- Journal.  Plain serialised table on tmpfs: survives a KOReader crash,
-- correctly does not survive a reboot (which clears the routes anyway).
----------------------------------------------------------------------

local function serialise(t, indent)
    indent = indent or ""
    local out = { "{" }
    for k, v in pairs(t) do
        local key = type(k) == "string" and string.format("[%q]=", k) or ""
        if type(v) == "table" then
            out[#out + 1] = indent .. "  " .. key .. serialise(v, indent .. "  ") .. ","
        elseif type(v) == "string" then
            out[#out + 1] = indent .. "  " .. key .. string.format("%q", v) .. ","
        elseif type(v) == "number" or type(v) == "boolean" then
            out[#out + 1] = indent .. "  " .. key .. tostring(v) .. ","
        end
    end
    out[#out + 1] = indent .. "}"
    return table.concat(out, "\n")
end

function State.readJournal()
    local data = Util.read(journalPath())
    if not data then return nil end
    local fn = loadstring("return " .. data)
    if not fn then return nil end
    local ok, res = pcall(fn)
    if ok and type(res) == "table" then return res end
    return nil
end

function State.writeJournal(j)
    Util.mkdirp(env.run_dir)
    Util.write(journalPath(), serialise(j))
end

function State.clearJournal()
    os.remove(journalPath())
end

----------------------------------------------------------------------
-- Process
----------------------------------------------------------------------

local function wgBin()
    return env.bin_dir .. "/wg"
end

local function wgGoBin()
    return env.bin_dir .. "/wireguard-go"
end

function State.binariesPresent()
    return Util.isFile(wgBin()) and Util.isFile(wgGoBin())
end

-- Exposed because tunnel.lua builds the launch and setconf commands.  These
-- were file-locals before state.lua was split out of tunnel.lua; keeping
-- them local left tunnel.lua calling undefined globals.
State.wgBin = wgBin
State.wgGoBin = wgGoBin

--- Find a running wireguard-go for this interface without trusting a PID.
--
-- Reads /proc/<pid>/cmdline rather than parsing `ps`.  BusyBox ps truncates
-- the command column to the terminal width, and with no tty (which is the
-- case under popen) that is 80 characters -- shorter than this plugin's
-- absolute path plus the interface name, so the trailing "wg0" was being
-- cut off and a live process read as dead.  /proc has no such limit.
function State.findProcess(iface)
    if not Util.validIface(iface) then return nil end

    for _i, entry in ipairs(Util.listDir("/proc", "^%d+$")) do
        local raw = Util.read("/proc/" .. entry .. "/cmdline")
        if raw and raw ~= "" then
            -- cmdline is NUL-separated; split into argv.
            local argv = {}
            for arg in raw:gmatch("([^%z]+)") do argv[#argv + 1] = arg end
            if argv[1] and argv[1]:find("wireguard%-go") then
                -- Match the interface as a whole argument, never a substring.
                for j = 2, #argv do
                    if argv[j] == iface then
                        return tonumber(entry)
                    end
                end
            end
        end
    end
    return nil
end

function State.binVersion(which)
    if not State.binariesPresent() then return _("not installed") end
    local bin = which == "wg" and wgBin() or wgGoBin()
    local out, rc = Util.exec(Util.q(bin) .. " --version", true)
    if rc ~= 0 then return _("failed to run") end
    -- First line only, and drop wg's trailing " - https://..." so the About
    -- screen does not wrap across three lines.
    local line = out:gsub("\n.*", ""):gsub("%s*%-%s*https?://%S*", ""):gsub("%s+$", "")
    return line
end

----------------------------------------------------------------------
-- Status.  Reads reality every time.
----------------------------------------------------------------------

function State.status()
    local iface = env.settings:readSetting("iface") or "wg0"
    local st = {
        iface = iface,
        state = State.DISCONNECTED,
        iface_exists = false,
        process = nil,
        peer = nil,
        handshake = nil,
        endpoint = nil,
        rx = 0,
        tx = 0,
        error = State.last_error,
    }

    if State.busy then
        st.state = State.CONNECTING
    end

    st.iface_exists = Net.ifaceExists(iface)
    st.process = State.findProcess(iface)

    if not State.binariesPresent() then
        st.state = State.DISCONNECTED
        st.detail = _("Binaries are not installed.")
        return st
    end

    if not st.iface_exists and not st.process then
        if not State.busy then st.state = State.DISCONNECTED end
        return st
    end

    -- Interface without a process, or vice versa, means a half-dead tunnel.
    if st.iface_exists and not st.process then
        st.state = State.ERROR
        st.detail = _("Interface exists but wireguard-go is not running.")
        Util.log("status: stale interface, process gone")
        return st
    end

    local out, rc = Util.exec(Util.q(wgBin()) .. " show " .. Util.q(iface) .. " dump", true)
    if rc ~= 0 then
        st.state = State.ERROR
        st.detail = _("wg show failed for this interface.")
        return st
    end

    -- dump format: line 1 is the interface (private key first -- never
    -- stored or displayed), subsequent lines are peers.
    local lineno = 0
    for line in out:gmatch("[^\n]+") do
        lineno = lineno + 1
        if lineno >= 2 then
            local f = {}
            for field in line:gmatch("[^\t]+") do f[#f + 1] = field end
            if #f >= 8 then
                st.peer = f[1]
                st.endpoint = (f[3] ~= "(none)") and f[3] or nil
                st.handshake = tonumber(f[5]) or 0
                st.rx = tonumber(f[6]) or 0
                st.tx = tonumber(f[7]) or 0
            end
        end
    end

    if st.peer then
        if not State.busy then st.state = State.CONNECTED end
        if st.handshake and st.handshake > 0 then
            st.handshake_age = os.time() - st.handshake
        end
    elseif not State.busy then
        st.state = State.ERROR
        st.detail = _("Interface is up but has no peer.")
    end

    -- DNS drift, reported rather than hidden.
    local dns = env.dns_applied
    if dns and #dns > 0 and not Net.dnsIsOurs(dns) then
        st.dns_clobbered = true
    end

    return st
end

return State

end
