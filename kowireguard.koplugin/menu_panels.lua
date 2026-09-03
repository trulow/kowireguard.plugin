--[[--
kowireguard menu panels: the Tunnels, Settings, Diagnostics and About sub-menus,
plus config import.

Split out of menu.lua purely to keep both files a readable size; menu.lua
owns the top-level entry and the status line.
]]

return function(env, helpers)

local ConfirmBox = require("ui/widget/confirmbox")
local PathChooser = require("ui/widget/pathchooser")
local SpinWidget = require("ui/widget/spinwidget")
local UIManager = require("ui/uimanager")
local Version = require("version")
local _ = require("gettext")
local T = require("ffi/util").template

local Util = env.util
local Net = env.net
local Tunnel = env.tunnel
local Config = env.config

local info = helpers.info
local viewer = helpers.viewer

local Panels = {}

function Panels.tunnels()
    local items = {}
    local list = helpers.configs()
    if #list == 0 then
        items[#items + 1] = {
            text = _("No configs found"),
            enabled = false,
        }
        return items
    end
    for _i, name in ipairs(list) do
        items[#items + 1] = {
            text = name:gsub("%.conf$", ""),
            checked_func = function() return helpers.activeConf() == name end,
            radio = true,
            callback = function(touchmenu_instance)
                env.settings:saveSetting("last_conf", name)
                env.settings:flush()
                local st = Tunnel.status()
                if st.state == Tunnel.CONNECTED then
                    info(_("Selected. Reconnect to apply."))
                end
                if touchmenu_instance then touchmenu_instance:updateItems() end
            end,
        }
    end
    return items
end

function Panels.settings()
    return {
        {
            text_func = function()
                return env.settings:isTrue("autostart")
                    and _("Connect automatically at startup: on")
                    or _("Connect automatically at startup: off")
            end,
            checked_func = function() return env.settings:isTrue("autostart") end,
            callback = function()
                env.settings:toggle("autostart")
                env.settings:flush()
            end,
            keep_menu_open = true,
        },
        {
            text_func = function()
                return env.settings:isTrue("reconnect_resume")
                    and _("Reconnect after resume: on")
                    or _("Reconnect after resume: off")
            end,
            checked_func = function() return env.settings:isTrue("reconnect_resume") end,
            callback = function()
                env.settings:toggle("reconnect_resume")
                env.settings:flush()
            end,
            keep_menu_open = true,
        },
        {
            text_func = function()
                local mode = env.settings:readSetting("dns_mode") or "apply"
                if mode == "apply" then
                    return _("DNS: use the tunnel's servers")
                end
                return _("DNS: leave the system's alone")
            end,
            callback = function(touchmenu_instance)
                local mode = env.settings:readSetting("dns_mode") or "apply"
                env.settings:saveSetting("dns_mode", mode == "apply" and "leave" or "apply")
                env.settings:flush()
                if touchmenu_instance then touchmenu_instance:updateItems() end
            end,
            help_text = _([[
The system's network daemon rewrites resolv.conf whenever Wi-Fi state changes, and kowireguard cannot prevent that. If it happens while connected, name lookups go to your local router instead of the tunnel — a DNS leak, not an outage. The status line reports it when it occurs.]]),
            keep_menu_open = true,
        },
        {
            text_func = function()
                local mode = env.settings:readSetting("fw_mode") or "established"
                if mode == "open" then
                    return _("Tunnel firewall: accept all inbound")
                end
                return _("Tunnel firewall: replies only")
            end,
            callback = function(touchmenu_instance)
                local mode = env.settings:readSetting("fw_mode") or "established"
                env.settings:saveSetting("fw_mode", mode == "open" and "established" or "open")
                env.settings:flush()
                if touchmenu_instance then touchmenu_instance:updateItems() end
            end,
            help_text = _([[
This device's INPUT policy is DROP, so decrypted packets arriving on the tunnel need an explicit rule. "Replies only" accepts traffic belonging to connections this device started. "Accept all inbound" also lets other peers on the VPN reach this device — useful for SSH from the far side of the tunnel.]]),
            keep_menu_open = true,
        },
        {
            text_func = function()
                return env.settings:isTrue("killswitch")
                    and _("Kill switch: on")
                    or _("Kill switch: off")
            end,
            checked_func = function() return env.settings:isTrue("killswitch") end,
            callback = function(touchmenu_instance)
                if env.settings:isTrue("killswitch") then
                    env.settings:saveSetting("killswitch", false)
                    env.settings:flush()
                    if touchmenu_instance then touchmenu_instance:updateItems() end
                    return
                end
                UIManager:show(ConfirmBox:new{
                    text = _([[
The kill switch drops all outbound traffic that is not going through the tunnel.

Your local network is carved out so SSH keeps working, but if a rule fails to apply this device can be left without network access and without an obvious way to recover it from the screen.

Enable it?]]),
                    ok_text = _("Enable"),
                    ok_callback = function()
                        env.settings:saveSetting("killswitch", true)
                        env.settings:flush()
                        if touchmenu_instance then touchmenu_instance:updateItems() end
                    end,
                })
            end,
            keep_menu_open = true,
        },
        {
            text_func = function()
                return T(_("MTU: %1"), env.settings:readSetting("mtu") or 1420)
            end,
            callback = function(touchmenu_instance)
                UIManager:show(SpinWidget:new{
                    value = env.settings:readSetting("mtu") or 1420,
                    value_min = 576,
                    value_max = 1500,
                    value_step = 10,
                    title_text = _("Tunnel MTU"),
                    info_text = _("A config's own MTU line takes precedence over this."),
                    callback = function(spin)
                        env.settings:saveSetting("mtu", spin.value)
                        env.settings:flush()
                        if touchmenu_instance then touchmenu_instance:updateItems() end
                    end,
                })
            end,
            keep_menu_open = true,
        },
    }
end

function Panels.diagnostics()
    return {
        {
            text = _("wg show"),
            keep_menu_open = true,
            callback = function()
                local iface = env.settings:readSetting("iface") or "wg0"
                if not Tunnel.binariesPresent() then
                    viewer(_("wg show"), _("Binaries are not installed."))
                    return
                end
                local out = Util.exec(Util.q(env.bin_dir .. "/wg") .. " show " .. Util.q(iface), true)
                viewer(_("wg show"), Util.redact(out))
            end,
        },
        {
            text = _("Routing table"),
            keep_menu_open = true,
            callback = function()
                local text = Net.routeTable() ..
                    "\n--- ip rule ---\n" .. (Util.exec("ip rule show", true) or "") ..
                    "\n--- table " .. Net.RT_TABLE .. " ---\n" ..
                    (Util.exec("ip route show table " .. Net.RT_TABLE, true) or "")
                viewer(_("Routing"), text)
            end,
        },
        {
            text_func = function()
                local iface = env.settings:readSetting("iface") or "wg0"
                local mode = env.settings:readSetting("fw_mode") or "established"
                return T(_("Firewall rule: %1"), Net.fwState(iface, mode))
            end,
            keep_menu_open = true,
            callback = function()
                local iface = env.settings:readSetting("iface") or "wg0"
                local mode = env.settings:readSetting("fw_mode") or "established"
                local text = T(_("Rule kowireguard manages:\n  iptables -I %1\n\nCurrently: %2\n\n"),
                    Net.fwRule(iface, mode), Net.fwState(iface, mode))
                local out = Util.exec("iptables -S INPUT", true)
                viewer(_("Firewall"), text .. out)
            end,
        },
        {
            text = _("Current DNS"),
            keep_menu_open = true,
            callback = function() viewer(_("resolv.conf"), Net.dnsCurrent()) end,
        },
        {
            text = _("Plugin log"),
            keep_menu_open = true,
            callback = function()
                viewer(_("kowireguard.log"), Util.redact(Util.tail(env.log_path, 120) or ""))
            end,
        },
        {
            text = _("wireguard-go output"),
            keep_menu_open = true,
            callback = function()
                local p = env.run_dir .. "/wireguard-go.log"
                viewer(_("wireguard-go"), Util.redact(Util.tail(p, 120) or _("(no output yet)")))
            end,
        },
        {
            text = _("Active config (key redacted)"),
            keep_menu_open = true,
            callback = function()
                local conf = helpers.activeConf()
                if not conf then
                    viewer(_("Config"), _("No config selected."))
                    return
                end
                local text = Config.redactedText(env.config_dir .. "/" .. conf)
                viewer(conf, text or _("Could not read the config."))
            end,
        },
        {
            text = _("Copy logs to plugin folder"),
            keep_menu_open = true,
            callback = function()
                local src = env.run_dir .. "/wireguard-go.log"
                local dst = env.data_dir .. "/wireguard-go.log"
                local data = Util.read(src)
                if data and Util.write(dst, Util.redact(data)) then
                    info(T(_("Written to %1"), dst))
                else
                    info(_("Nothing to copy."))
                end
            end,
        },
        {
            text = _("Force teardown"),
            keep_menu_open = true,
            separator = true,
            callback = function(touchmenu_instance)
                UIManager:show(ConfirmBox:new{
                    text = _("Reverse every change kowireguard may have made: routes, firewall rule, DNS, interface and process. Safe to run at any time."),
                    ok_text = _("Tear down"),
                    ok_callback = function()
                        Tunnel.disconnect()
                        info(_("Teardown complete."))
                        if touchmenu_instance then touchmenu_instance:updateItems() end
                    end,
                })
            end,
        },
        {
            text = _("Clear plugin log"),
            keep_menu_open = true,
            callback = function()
                Util.write(env.log_path, "")
                info(_("Log cleared."))
            end,
        },
    }
end

function Panels.aboutText()
    local iface = env.settings:readSetting("iface") or "wg0"
    local lines = {
        T(_("kowireguard %1"), env.meta.version),
        "",
        T(_("wg: %1"), Tunnel.binVersion("wg")),
        T(_("wireguard-go: %1"), Tunnel.binVersion("go")),
        T(_("KOReader: %1"), Version:getCurrentRevision() or _("unknown")),
        "",
        T(_("Interface: %1"), iface),
        T(_("Data: %1"), env.data_dir),
        T(_("Configs: %1"), env.config_dir),
        T(_("Binaries: %1"), env.bin_dir),
        T(_("Log: %1"), env.log_path),
        T(_("Runtime: %1 (tmpfs, cleared on reboot)"), env.run_dir),
        "",
        _("Config files hold your private key in plain text. This storage synthesizes file permissions, so a file mode cannot protect them: anyone with USB or filesystem access to this device can read your key."),
    }
    return table.concat(lines, "\n")
end

function Panels.importConfig(file_path, touchmenu_instance)
    if not Util.isFile(file_path) then
        info(_("That file could not be read."))
        return
    end
    local base = file_path:match("([^/]+)$")
    if not base or not base:match("^[%w%._%-]+$") then
        info(_("That filename contains characters kowireguard will not accept."))
        return
    end
    if not base:match("%.conf$") then base = base .. ".conf" end

    -- Parse before importing: a bad config should fail here, not at connect.
    local cfg, err = Config.parse(file_path)
    if not cfg then
        info(T(_("Not a usable WireGuard config: %1"), err), 6)
        return
    end

    Util.mkdirp(env.config_dir)
    local dest = env.config_dir .. "/" .. base
    local data = Util.read(file_path)
    if not data or not Util.write(dest, data) then
        info(_("Could not copy the config into the plugin folder."))
        return
    end
    Util.chmodBestEffort(dest, "0600")
    env.settings:saveSetting("last_conf", base)
    env.settings:flush()

    local msg = { T(_("Imported %1."), base) }
    if #cfg.warnings > 0 then
        msg[#msg + 1] = ""
        msg[#msg + 1] = _("Notes:")
        for _i, w in ipairs(cfg.warnings) do msg[#msg + 1] = "• " .. w end
    end
    msg[#msg + 1] = ""
    msg[#msg + 1] = _("The private key in this file is readable by anyone with access to this device's storage.")
    viewer(_("Import"), table.concat(msg, "\n"))
    if touchmenu_instance then touchmenu_instance:updateItems() end
end

function Panels.chooseConfig(touchmenu_instance)
    UIManager:show(PathChooser:new{
        title = _("Select a WireGuard .conf file"),
        select_directory = false,
        select_file = true,
        path = env.home_dir,
        file_filter = function(filename)
            return filename:match("%.conf$") ~= nil
        end,
        onConfirm = function(file_path)
            Panels.importConfig(file_path, touchmenu_instance)
        end,
    })
end

return Panels

end
