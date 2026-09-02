--[[--
kowireguard utility layer.

Everything that touches the shell or the filesystem funnels through here so
that quoting, validation and exit-code handling exist in exactly one place.

Returned as a constructor so the module never enters KOReader's global
require() namespace.
]]

return function(_env) -- luacheck: no unused args

local logger = require("logger")
local lfs = require("libs/libkoreader-lfs")

local Util = {}

-- Log cap.  /mnt/us is a FUSE mount with 24G free, but an unbounded log on a
-- device the user only reaches over USB is still a trap.
local LOG_CAP = 96 * 1024

----------------------------------------------------------------------
-- Validation
--
-- Every value that reaches a shell string is checked here first.  These
-- commands run as root; a hostname or filename is never trusted.
----------------------------------------------------------------------

-- Linux interface names: <= 15 chars, no slash, no whitespace, no NUL.
function Util.validIface(name)
    if type(name) ~= "string" then return false end
    if #name < 1 or #name > 15 then return false end
    return name:match("^[%a][%w_%-]*$") ~= nil
end

-- Dotted-quad only.  IPv6 is deliberately unsupported on this device
-- (CONFIG_IPV6_TUNNEL is not set and wlan0 has no global v6 address).
function Util.validIPv4(s)
    if type(s) ~= "string" then return false end
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    for _, o in ipairs({ a, b, c, d }) do
        local n = tonumber(o)
        if not n or n > 255 then return false end
        if #o > 1 and o:sub(1, 1) == "0" then return false end
    end
    return true
end

function Util.validCIDR(s)
    if type(s) ~= "string" then return false end
    local addr, bits = s:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    if not addr then return false end
    local n = tonumber(bits)
    return Util.validIPv4(addr) and n and n >= 0 and n <= 32
end

function Util.validPort(p)
    local n = tonumber(p)
    return n ~= nil and n >= 1 and n <= 65535
end

-- Hostnames for endpoint resolution.  Letters, digits, dot, hyphen only.
function Util.validHost(s)
    if type(s) ~= "string" then return false end
    if #s < 1 or #s > 253 then return false end
    if s:match("^[%-%.]") or s:match("[%-%.]$") then return false end
    return s:match("^[%w%.%-]+$") ~= nil
end

-- Absolute paths without shell metacharacters or traversal.
function Util.validPath(p)
    if type(p) ~= "string" then return false end
    if p:sub(1, 1) ~= "/" then return false end
    if p:find("%.%.") then return false end
    return p:match("^[%w%._%-/ ]+$") ~= nil
end

-- Last-resort quoting for values that have already passed a validator.
-- Single quotes with the standard '\'' escape.
function Util.q(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

----------------------------------------------------------------------
-- Logging
----------------------------------------------------------------------

local log_path

function Util.setLogPath(p)
    log_path = p
end

local function rotate()
    if not log_path then return end
    local attr = lfs.attributes(log_path, "size")
    if not attr or attr < LOG_CAP then return end
    -- Keep the tail, drop the head.  One file, no .1/.2 clutter on a
    -- filesystem the user browses over USB.
    local f = io.open(log_path, "r")
    if not f then return end
    f:seek("end", -math.floor(LOG_CAP / 2))
    local tail = f:read("*a")
    f:close()
    local w = io.open(log_path, "w")
    if not w then return end
    w:write("[kowireguard] --- log truncated ---\n", tail or "")
    w:close()
end

function Util.log(...)
    local parts = {}
    for i = 1, select("#", ...) do
        parts[#parts + 1] = tostring((select(i, ...)))
    end
    local line = table.concat(parts, " ")
    logger.info("kowireguard:", line)
    if not log_path then return end
    rotate()
    local f = io.open(log_path, "a")
    if not f then return end
    f:write(os.date("%Y-%m-%d %H:%M:%S "), line, "\n")
    f:close()
end

----------------------------------------------------------------------
-- Execution
--
-- LuaJIT's popen():close() does not hand back an exit status, so the status
-- is smuggled out through stdout.  Landmine 7: a successful popen proves
-- nothing, so callers must check rc, not merely that output came back.
----------------------------------------------------------------------

local RC_MARK = "__kowireguard_rc="

function Util.exec(cmd, quiet)
    local p = io.popen(cmd .. " 2>&1; echo " .. RC_MARK .. "$?", "r")
    if not p then
        Util.log("exec: popen failed:", cmd)
        return "", -1
    end
    local out = p:read("*a") or ""
    p:close()
    local rc = tonumber(out:match(RC_MARK .. "(%d+)")) or -1
    out = out:gsub(RC_MARK .. "%d+%s*$", "")
    if not quiet then
        local trimmed = out:gsub("%s+$", "")
        Util.log("exec[" .. rc .. "]:", cmd, trimmed ~= "" and ("-> " .. trimmed) or "")
    end
    return out, rc
end

-- Fire-and-forget background launch returning the child PID.
function Util.spawn(cmd)
    local out, rc = Util.exec("( " .. cmd .. " ) >/dev/null 2>&1 & echo $!")
    if rc ~= 0 then return nil end
    return tonumber(out:match("(%d+)"))
end

--- The PID of the KOReader process this plugin is running inside.
-- Recorded in the journal so startup reconciliation can tell state left by a
-- crashed previous run from state this very process created.
function Util.selfPid()
    local raw = Util.read("/proc/self/stat")
    if not raw then return nil end
    return tonumber(raw:match("^(%d+)"))
end

function Util.pidAlive(pid)
    if not pid then return false end
    return lfs.attributes("/proc/" .. tostring(pid), "mode") == "directory"
end

--- Read a process's argv from /proc, NUL-separated, as a plain string.
-- Used to confirm a PID is what we think it is before signalling it.
function Util.cmdlineOf(pid)
    if not pid then return nil end
    local raw = Util.read("/proc/" .. tostring(pid) .. "/cmdline")
    if not raw or raw == "" then return nil end
    return (raw:gsub("%z", " "))
end

--- Kill a PID only if its command line still matches the expected pattern.
-- The PID recorded at launch belongs to the spawning subshell, which exits
-- straight away; that number can be recycled by an unrelated process, and
-- signalling it blind would kill something at random.  Verify, then signal.
function Util.killIfMatches(pid, pattern)
    if not pid or not Util.pidAlive(pid) then return false end
    local cmd = Util.cmdlineOf(pid)
    if not cmd or not cmd:find(pattern) then
        Util.log("refusing to kill pid", pid, "- cmdline does not match", pattern)
        return false
    end
    Util.exec("kill " .. tostring(pid), true)
    Util.exec("sleep 1", true)
    if Util.pidAlive(pid) and (Util.cmdlineOf(pid) or ""):find(pattern) then
        Util.exec("kill -9 " .. tostring(pid), true)
    end
    return true
end

----------------------------------------------------------------------
-- Files
----------------------------------------------------------------------

function Util.isFile(path)
    return lfs.attributes(path, "mode") == "file"
end

function Util.isDir(path)
    return lfs.attributes(path, "mode") == "directory"
end

function Util.read(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

function Util.write(path, data)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(data)
    f:close()
    return true
end

function Util.mkdirp(path)
    Util.exec("mkdir -p " .. Util.q(path), true)
    return Util.isDir(path)
end

-- Landmine 6: on /mnt/us (fuse.fsp, allow_other) modes are synthesized and
-- chmod is a no-op whose return value means nothing.  It does work on the
-- ext3 root and on the /var tmpfs, which is why the transient config lives
-- there.  Never treat the return of this as proof of anything.
function Util.chmodBestEffort(path, mode)
    Util.exec("chmod " .. mode .. " " .. Util.q(path), true)
end

function Util.listDir(path, pattern)
    local out = {}
    if not Util.isDir(path) then return out end
    for entry in lfs.dir(path) do
        if entry ~= "." and entry ~= ".." then
            if not pattern or entry:match(pattern) then
                out[#out + 1] = entry
            end
        end
    end
    table.sort(out)
    return out
end

function Util.tail(path, lines)
    local data = Util.read(path)
    if not data then return nil end
    local all = {}
    for line in data:gmatch("[^\n]*") do all[#all + 1] = line end
    local start = math.max(1, #all - lines)
    return table.concat(all, "\n", start, #all)
end

----------------------------------------------------------------------
-- Redaction.  Private keys never reach a log, a dialog or the status line.
----------------------------------------------------------------------

function Util.redact(text)
    if type(text) ~= "string" then return text end
    local out = text:gsub("([Pp]rivate[Kk]ey%s*=%s*)[^\n]*", "%1<redacted>")
    -- Bare base64 keys in `wg show dump` output.  Lua patterns have no {n}
    -- repetition, so match a long base64 run and length-check it in the
    -- replacement function instead.
    out = out:gsub("[%w%+/]+=", function(tok)
        if #tok == 44 then return "<redacted>" end
        return tok
    end)
    return out
end

function Util.humanAge(seconds)
    if not seconds or seconds < 0 then return "?" end
    local floor = math.floor
    if seconds < 60 then return string.format("%ds", floor(seconds)) end
    if seconds < 3600 then
        return string.format("%dm %ds", floor(seconds / 60), floor(seconds % 60))
    end
    return string.format("%dh %dm", floor(seconds / 3600), floor((seconds % 3600) / 60))
end

function Util.humanBytes(n)
    n = tonumber(n) or 0
    local units = { "B", "KiB", "MiB", "GiB" }
    local i = 1
    while n >= 1024 and i < #units do
        n = n / 1024
        i = i + 1
    end
    if i == 1 then return string.format("%d %s", math.floor(n), units[i]) end
    return string.format("%.1f %s", n, units[i])
end

return Util

end
