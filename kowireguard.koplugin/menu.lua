--[[--
kowireguard menu: top-level entry, status line and the connect/disconnect actions.
The sub-menus live in menu_panels.lua.

Built with sub_item_table_func so labels re-evaluate every time the menu
opens, and with text_func/checked_func on items so nothing is a static
string.  The status line refreshes on a 5s timer while the menu is open and
the timer is cancelled on close -- this is an e-ink device and polling a
closed menu buys nothing but page flashes.
]]

return function(env)

local InfoMessage = require("ui/widget/infomessage")
local TextViewer = require("ui/widget/textviewer")
local UIManager = require("ui/uimanager")
local NetworkMgr = require("ui/network/manager")
local _ = require("gettext")
local T = require("ffi/util").template

local Util = env.util
local Tunnel = env.tunnel

local Menu = {}

local refresh_timer
local menu_instance

----------------------------------------------------------------------
-- Shared helpers, also handed to the panels module
----------------------------------------------------------------------

local function info(msg, timeout)
    UIManager:show(InfoMessage:new{ text = msg, timeout = timeout or 3 })
end

local function viewer(title, text)
    UIManager:show(TextViewer:new{
        title = title,
        text = (text and text ~= "") and text or _("(nothing to show)"),
        text_type = "code",
    })
end

function Menu.configs()
    return Util.listDir(env.config_dir, "%.conf$")
end

function Menu.activeConf()
    return env.settings:readSetting("last_conf")
end

local Panels = dofile(env.plugin_dir .. "/menu_panels.lua")(env, {
    info = info,
    viewer = viewer,
    configs = Menu.configs,
    activeConf = Menu.activeConf,
})

----------------------------------------------------------------------
-- Status line
----------------------------------------------------------------------

function Menu.statusText()
    local st = Tunnel.status()

    if not Tunnel.binariesPresent() then
        return _("Status: binaries missing") .. "\n" ..
            T(_("Expected in %1"), env.bin_dir)
    end

    if st.state == Tunnel.CONNECTING then
        return _("Status: Connecting…")
    end

    if st.state == Tunnel.ERROR then
        return T(_("Status: problem — %1"), st.detail or _("unknown"))
    end

    if st.state ~= Tunnel.CONNECTED then
        local line = _("Status: Disconnected")
        if st.error then
            line = line .. "\n" .. T(_("Last error: %1"), st.error)
        end
        return line
    end

    local parts = { T(_("Status: Connected — %1"), st.iface) }
    if st.handshake_age then
        parts[#parts + 1] = T(_("Handshake: %1 ago"), Util.humanAge(st.handshake_age))
    else
        parts[#parts + 1] = _("Handshake: none yet")
    end
    if st.endpoint then
        parts[#parts + 1] = T(_("Endpoint: %1"), st.endpoint)
    end
    parts[#parts + 1] = T(_("Transfer: %1 down / %2 up"),
        Util.humanBytes(st.rx), Util.humanBytes(st.tx))
    if st.dns_clobbered then
        parts[#parts + 1] = _("DNS: overwritten by the system (leaking)")
    end
    return table.concat(parts, "\n")
end

local function scheduleRefresh(touchmenu_instance)
    menu_instance = touchmenu_instance
    if refresh_timer then
        UIManager:unschedule(refresh_timer)
    end
    refresh_timer = function()
        if menu_instance then
            menu_instance:updateItems()
            UIManager:scheduleIn(5, refresh_timer)
        end
    end
    UIManager:scheduleIn(5, refresh_timer)
end

function Menu.cancelRefresh()
    if refresh_timer then
        UIManager:unschedule(refresh_timer)
        refresh_timer = nil
    end
    menu_instance = nil
end

----------------------------------------------------------------------
-- Connect / disconnect
----------------------------------------------------------------------

local function doConnect(touchmenu_instance)
    local conf = Menu.activeConf()
    if not conf then
        local list = Menu.configs()
        if #list == 0 then
            info(_("No tunnel configs. Use Import config… first."))
            return
        end
        conf = list[1]
    end
    if not NetworkMgr:isConnected() then
        NetworkMgr:promptWifiOn(function()
            info(_("Wi-Fi is on. Try connecting again."))
        end)
        return
    end
    info(_("Connecting…"), 1)
    -- Let the message paint before the blocking sequence runs.
    UIManager:nextTick(function()
        local ok, err = Tunnel.connect(conf)
        if not ok then
            info(T(_("Could not connect: %1"), err or _("unknown error")), 6)
        else
            info(_("Connected."), 2)
        end
        if touchmenu_instance then touchmenu_instance:updateItems() end
    end)
end

local function doDisconnect(touchmenu_instance)
    UIManager:nextTick(function()
        Tunnel.disconnect()
        info(_("Disconnected."), 2)
        if touchmenu_instance then touchmenu_instance:updateItems() end
    end)
end

----------------------------------------------------------------------
-- Top level
----------------------------------------------------------------------

function Menu.build()
    return {
        text_func = function()
            return T(_("kowireguard (v%1)"), env.meta.version)
        end,
        sorting_hint = "network",
        sub_item_table_func = function()
            return {
                {
                    text_func = Menu.statusText,
                    keep_menu_open = true,
                    callback = function(touchmenu_instance)
                        scheduleRefresh(touchmenu_instance)
                        if touchmenu_instance then touchmenu_instance:updateItems() end
                    end,
                    hold_callback = function()
                        viewer(_("Status detail"), Menu.statusText())
                    end,
                    separator = true,
                },
                {
                    text_func = function()
                        local st = Tunnel.status()
                        if st.state == Tunnel.CONNECTED then return _("Disconnect") end
                        return _("Connect")
                    end,
                    checked_func = function()
                        return Tunnel.status().state == Tunnel.CONNECTED
                    end,
                    keep_menu_open = true,
                    callback = function(touchmenu_instance)
                        local st = Tunnel.status()
                        if st.state == Tunnel.CONNECTED or st.state == Tunnel.ERROR then
                            doDisconnect(touchmenu_instance)
                        else
                            doConnect(touchmenu_instance)
                        end
                    end,
                },
                {
                    text_func = function()
                        local conf = Menu.activeConf()
                        if conf then
                            return T(_("Tunnels (%1)"), conf:gsub("%.conf$", ""))
                        end
                        return _("Tunnels")
                    end,
                    sub_item_table_func = Panels.tunnels,
                },
                {
                    text = _("Import config…"),
                    keep_menu_open = true,
                    callback = function(touchmenu_instance)
                        Panels.chooseConfig(touchmenu_instance)
                    end,
                    separator = true,
                },
                {
                    text = _("Settings"),
                    sub_item_table_func = Panels.settings,
                },
                {
                    text = _("Diagnostics"),
                    sub_item_table_func = Panels.diagnostics,
                },
                {
                    text_func = function()
                        return T(_("About kowireguard (v%1)"), env.meta.version)
                    end,
                    keep_menu_open = true,
                    callback = function()
                        viewer(_("About kowireguard"), Panels.aboutText())
                    end,
                },
            }
        end,
    }
end

return Menu

end
