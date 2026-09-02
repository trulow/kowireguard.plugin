--[[--
kowireguard — WireGuard VPN for KOReader.

Sibling modules are loaded by absolute path with dofile() and each returns a
constructor taking a shared env table.  This deliberately avoids require(),
which would put files named config.lua / net.lua / menu.lua into KOReader's
global module namespace where they could collide with its own modules.
]]

local DataStorage = require("datastorage")
local Dispatcher = require("dispatcher")
local InfoMessage = require("ui/widget/infomessage")
local LuaSettings = require("luasettings")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local NetworkMgr = require("ui/network/manager")
local logger = require("logger")
local _ = require("gettext")
local T = require("ffi/util").template

local lfs = require("libs/libkoreader-lfs")

--- Resolve a possibly-relative path to an absolute one.
--
-- KOReader runs with its own directory as the working directory and hands
-- back relative paths from both debug.getinfo() and DataStorage, e.g.
-- "plugins/kowireguard.koplugin" and ".".  dofile() copes with that, but
-- every path here reaches a validator that requires a leading slash (an
-- anti-traversal check) and eventually a shell command run as root, so
-- anchor them all through this one function.
local function toAbsolute(p, fallback)
    if type(p) ~= "string" or p == "" then p = fallback end
    if type(p) ~= "string" or p == "" then return nil end
    p = p:gsub("^%./", "")
    if p == "." then p = "" end
    if p:sub(1, 1) ~= "/" then
        local cwd = lfs.currentdir() or "/mnt/us/koreader"
        p = (p == "") and cwd or (cwd .. "/" .. p)
    end
    p = p:gsub("/%./", "/"):gsub("/%.$", ""):gsub("//+", "/"):gsub("/+$", "")
    return p
end

local plugin_dir = toAbsolute(
    debug.getinfo(1, "S").source:match("^@?(.*)/[^/]*$"),
    "/mnt/us/koreader/plugins/kowireguard.koplugin")

local meta = dofile(plugin_dir .. "/_meta.lua")

local KOWG = WidgetContainer:extend{
    name = "kowireguard",
    is_doc_only = false,
}

----------------------------------------------------------------------
-- Wiring
--
-- Everything the plugin writes and keeps lives under one directory,
-- /mnt/us/koreader/kowireguard, derived from KOReader's data dir rather
-- than hardcoded.  Keeping configs there rather than inside the plugin
-- folder means upgrading or reinstalling the plugin no longer destroys
-- your tunnel configs.
--
-- The one exception is run_dir, which stays on the /var tmpfs.  Three
-- reasons, all load-bearing:
--   * USB storage mode unmounts /mnt/us underneath a running process;
--     wireguard-go writing its log there would die on EIO mid-write.
--   * The journal wants exactly tmpfs lifetime: it must survive a KOReader
--     crash, when routes are still applied and need reversing, and must not
--     survive a reboot, when they are already gone.
--   * The staged config passed to `wg setconf` contains your private key.
--     chmod works on tmpfs; on /mnt/us (fuse.fsp) modes are synthesized and
--     chmod is a no-op, so staging it there would write a second
--     unprotected plaintext copy of the key to USB-visible storage.
----------------------------------------------------------------------

local function resolveDataDir()
    -- DataStorage:getDataDir() is the documented accessor, but on this
    -- device it returns a path relative to KOReader's working directory,
    -- so the result goes through toAbsolute() like everything else.
    local ok, dir = pcall(function() return DataStorage:getDataDir() end)
    if ok and type(dir) == "string" and dir ~= "" then
        return toAbsolute(dir)
    end
    local ok2, sdir = pcall(function() return DataStorage:getSettingsDir() end)
    if ok2 and type(sdir) == "string" and sdir ~= "" then
        return toAbsolute((sdir:gsub("/settings/?$", "")))
    end
    return "/mnt/us/koreader"
end

local data_dir = (resolveDataDir() or "/mnt/us/koreader") .. "/kowireguard"

local env = {
    meta = meta,
    plugin_dir = plugin_dir,
    data_dir = data_dir,
    bin_dir = plugin_dir .. "/bin",
    config_dir = data_dir .. "/configs",
    log_path = data_dir .. "/kowireguard.log",
    settings_path = data_dir .. "/kowireguard_settings.lua",
    run_dir = "/var/run/kowireguard",
    home_dir = "/mnt/us",
    dns_applied = nil,
}

env.util = dofile(plugin_dir .. "/util.lua")(env)
env.util.setLogPath(env.log_path)
env.config = dofile(plugin_dir .. "/config.lua")(env)
env.net = dofile(plugin_dir .. "/net.lua")(env)
env.state = dofile(plugin_dir .. "/state.lua")(env)
env.tunnel = dofile(plugin_dir .. "/tunnel.lua")(env)

local Util = env.util

----------------------------------------------------------------------
-- Settings
----------------------------------------------------------------------

--- Move files left behind by an older layout into the data directory.
-- Copies rather than moves the configs, and never overwrites, so a failed
-- migration cannot lose a tunnel config.
local function migrateOldLayout()
    local Util = env.util
    local moved = {}

    -- Settings used to live in KOReader's shared settings directory.
    if not Util.isFile(env.settings_path) then
        local ok, sdir = pcall(function() return DataStorage:getSettingsDir() end)
        if ok and type(sdir) == "string" then
            local old = sdir .. "/kowireguard_settings.lua"
            local data = Util.isFile(old) and Util.read(old)
            if data and Util.write(env.settings_path, data) then
                moved[#moved + 1] = "settings"
            end
        end
    end

    -- Configs and the log used to live inside the plugin folder, where a
    -- reinstall would delete them.
    local old_cfg = env.plugin_dir .. "/configs"
    if Util.isDir(old_cfg) and old_cfg ~= env.config_dir then
        for _i, name in ipairs(Util.listDir(old_cfg, "%.conf$")) do
            local dest = env.config_dir .. "/" .. name
            if not Util.isFile(dest) then
                local data = Util.read(old_cfg .. "/" .. name)
                if data and Util.write(dest, data) then
                    moved[#moved + 1] = "config " .. name
                end
            end
        end
    end

    local old_log = env.plugin_dir .. "/kowireguard.log"
    if Util.isFile(old_log) and old_log ~= env.log_path then
        os.remove(old_log)
    end

    if #moved > 0 then
        Util.log("migrated to data dir:", table.concat(moved, ", "))
    end
end

local function initSettings()
    local settings = LuaSettings:open(env.settings_path)
    if settings:readSetting("iface") == nil then settings:saveSetting("iface", "wg0") end
    if settings:readSetting("mtu") == nil then settings:saveSetting("mtu", 1420) end
    if settings:readSetting("dns_mode") == nil then settings:saveSetting("dns_mode", "apply") end
    if settings:readSetting("fw_mode") == nil then settings:saveSetting("fw_mode", "established") end
    if settings:readSetting("killswitch") == nil then settings:saveSetting("killswitch", false) end
    settings:flush()
    return settings
end

----------------------------------------------------------------------
-- Dispatcher
----------------------------------------------------------------------

function KOWG:onDispatcherRegisterActions()
    Dispatcher:registerAction("kowireguard_connect",
        { category = "none", event = "KowireguardConnect", title = _("kowireguard connect"), general = true })
    Dispatcher:registerAction("kowireguard_disconnect",
        { category = "none", event = "KowireguardDisconnect", title = _("kowireguard disconnect"), general = true })
    Dispatcher:registerAction("kowireguard_toggle",
        { category = "none", event = "KowireguardToggle", title = _("kowireguard toggle"), general = true })
    Dispatcher:registerAction("kowireguard_status",
        { category = "none", event = "KowireguardStatus", title = _("kowireguard status"), general = true })
end

----------------------------------------------------------------------
-- Lifecycle
----------------------------------------------------------------------

-- KOReader instantiates a plugin once per UI: once for the file manager and
-- again for the reader when a document is opened.  init() therefore runs
-- several times in a single KOReader process, but the module chunk is
-- executed only once, so this flag is shared across those instances.
-- Directory setup, migration, settings, startup reconciliation and autostart
-- must happen exactly once; only menu and gesture registration are per-UI.
local process_setup_done = false

function KOWG:init()
    if not process_setup_done then
        process_setup_done = true

        -- Directories first: settings, log and configs all live under
        -- data_dir, so nothing may be opened before it exists.
        Util.mkdirp(env.data_dir)
        Util.mkdirp(env.config_dir)
        Util.mkdirp(env.run_dir)

        -- Fail loudly and early if a resolved directory would be rejected by
        -- the path validator.  Otherwise the first symptom is "Config path
        -- contains unsupported characters" at connect time, which points at
        -- the config rather than at the directory that is actually wrong.
        for _i, pair in ipairs({
            { "plugin", env.plugin_dir }, { "data", env.data_dir },
            { "configs", env.config_dir }, { "runtime", env.run_dir },
        }) do
            if not Util.validPath(pair[2]) then
                Util.log("STARTUP PROBLEM:", pair[1],
                    "directory is not a usable absolute path:", tostring(pair[2]))
            end
        end
        Util.log("paths: plugin=" .. tostring(env.plugin_dir),
                 "data=" .. tostring(env.data_dir))

        migrateOldLayout()

        env.settings = initSettings()
        env.menu = dofile(plugin_dir .. "/menu.lua")(env)

        -- Degrade gracefully: a missing binary or config must not stop the
        -- plugin from loading.  The status line and About explain what is
        -- missing and where it is expected.
        if not env.tunnel.binariesPresent() then
            Util.log("startup: wg/wireguard-go not found in", env.bin_dir)
        end

        -- Reverse anything a crash or a flat battery left behind.  A tunnel
        -- this same process brought up is left alone; see
        -- Tunnel.reconcileAtStartup.
        if env.tunnel.reconcileAtStartup() then
            Util.log("startup: cleaned up state from a previous session")
        end

        if env.settings:isTrue("autostart") and env.settings:readSetting("last_conf") then
            UIManager:scheduleIn(5, function() self:autoConnect() end)
        end

        Util.log("kowireguard", meta.version, "loaded; data dir", env.data_dir)
    end

    -- Per-instance: each UI needs its own menu entry and gesture bindings.
    self.env = env
    self:onDispatcherRegisterActions()
    self.ui.menu:registerToMainMenu(self)
end

function KOWG:autoConnect()
    if not NetworkMgr:isConnected() then
        Util.log("autostart: no network yet, skipping")
        return
    end
    local conf = env.settings:readSetting("last_conf")
    if not conf then return end
    local ok, err = env.tunnel.connect(conf)
    if not ok then
        Util.log("autostart failed:", tostring(err))
    end
end

function KOWG:addToMainMenu(menu_items)
    menu_items.kowireguard = env.menu.build()
end

----------------------------------------------------------------------
-- Events
----------------------------------------------------------------------

function KOWG:onResume()
    -- Interface, routes, firewall rule and DNS can each be stale
    -- independently after a suspend; re-verify all four.
    local st = env.tunnel.status()
    if st.state == env.tunnel.DISCONNECTED and not env.tunnel.readJournal() then
        return
    end
    UIManager:scheduleIn(2, function()
        local alive, why = env.tunnel.reassert()
        if alive then return end
        if why == "gone" then
            Util.log("resume: tunnel did not survive suspend")
            env.tunnel.disconnect()
            if env.settings:isTrue("reconnect_resume") then
                local conf = env.settings:readSetting("last_conf")
                if conf and NetworkMgr:isConnected() then
                    Util.log("resume: reconnecting")
                    env.tunnel.connect(conf)
                end
            end
        end
    end)
end

function KOWG:onSuspend()
    env.menu.cancelRefresh()
end

function KOWG:onNetworkConnected()
    -- wifid rewrites resolv.conf on every Wi-Fi state change.
    if env.dns_applied then
        UIManager:scheduleIn(2, function()
            env.tunnel.reassert()
        end)
    end
end

function KOWG:onNetworkDisconnected()
    env.util.log("network went away")
end

-- Landmine 5: USB mass storage pulls /mnt/us out from under the running
-- process, taking the binaries and the plugin log with it.  Stop cleanly
-- rather than letting wireguard-go die on EIO with the routes still in place.
function KOWG:onUsbPlugIn()
    local st = env.tunnel.status()
    if st.state == env.tunnel.CONNECTED or st.state == env.tunnel.ERROR then
        Util.log("USB connected: tearing the tunnel down before storage goes away")
        env.tunnel.disconnect()
        UIManager:show(InfoMessage:new{
            text = _("kowireguard disconnected the tunnel because USB storage mode unmounts the plugin folder."),
            timeout = 5,
        })
    end
end

function KOWG:onCloseWidget()
    env.menu.cancelRefresh()
end

function KOWG:onFlushSettings()
    if env.settings then env.settings:flush() end
end

-- Teardown on exit: a Kindle left with a dead tunnel's routes has no working
-- network and no way to fix it from the screen.
function KOWG:onExit()
    env.menu.cancelRefresh()
    local st = env.tunnel.status()
    if st.state ~= env.tunnel.DISCONNECTED or env.tunnel.readJournal() then
        Util.log("exit: tearing down")
        env.tunnel.disconnect()
    end
    if env.settings then env.settings:flush() end
end

-- Deliberately no KOWG.onClose alias: onClose is not a plugin lifecycle
-- event here and aliasing it to onExit risked tearing the tunnel down
-- whenever an unrelated widget closed.

----------------------------------------------------------------------
-- Dispatcher events
----------------------------------------------------------------------

function KOWG:onKowireguardConnect()
    local conf = env.settings:readSetting("last_conf")
    if not conf then
        UIManager:show(InfoMessage:new{ text = _("kowireguard: no tunnel selected.") })
        return true
    end
    if not NetworkMgr:isConnected() then
        UIManager:show(InfoMessage:new{ text = _("kowireguard: Wi-Fi is off.") })
        return true
    end
    UIManager:show(InfoMessage:new{ text = _("kowireguard: connecting…"), timeout = 1 })
    UIManager:nextTick(function()
        local ok, err = env.tunnel.connect(conf)
        UIManager:show(InfoMessage:new{
            text = ok and _("kowireguard: connected.") or T(_("kowireguard: %1"), err or _("failed")),
            timeout = ok and 2 or 5,
        })
    end)
    return true
end

function KOWG:onKowireguardDisconnect()
    UIManager:nextTick(function()
        env.tunnel.disconnect()
        UIManager:show(InfoMessage:new{ text = _("kowireguard: disconnected."), timeout = 2 })
    end)
    return true
end

function KOWG:onKowireguardToggle()
    local st = env.tunnel.status()
    if st.state == env.tunnel.CONNECTED or st.state == env.tunnel.ERROR then
        return self:onKowireguardDisconnect()
    end
    return self:onKowireguardConnect()
end

function KOWG:onKowireguardStatus()
    UIManager:show(InfoMessage:new{ text = env.menu.statusText(), timeout = 5 })
    return true
end

logger.dbg("kowireguard: main.lua loaded from", plugin_dir)

return KOWG
