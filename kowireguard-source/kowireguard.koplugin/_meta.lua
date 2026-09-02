--[[--
kowireguard — WireGuard VPN client for KOReader.

This file is the single source of truth for the plugin version.  main.lua
loads it with dofile() and every other module receives the value through the
shared env table.  Do not hardcode the version anywhere else.

Note: the `name` field is deliberately absent.  KOReader v2026.07 derives the
plugin name from the directory and logs a deprecation warning for any _meta
that still sets it.
]]

local _ = require("gettext")

return {
    fullname = _("kowireguard — WireGuard VPN"),
    description = _([[WireGuard VPN client driving a real TUN interface with wireguard-go and wg.]]),
    version = "1.0.3",
}
