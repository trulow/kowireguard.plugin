# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.2] — 2026-09-03

Initial public release.

### Added

- WireGuard VPN client for jailbroken Kindles, managed entirely from
  KOReader's menu. Real `wg0` TUN interface via `wireguard-go` and `wg`, so
  HTTPS works natively — no CONNECT proxy, no patched `socket.http` or
  `ssl.https`, no hand-rolled certificate validation.
- Connect, disconnect and switch tunnels from **Network → kowireguard**.
- Live status: handshake age, endpoint, transfer counters, read from
  `wg show` on every call rather than from stored state.
- Import `.conf` files through the UI, validated on import. Configs and
  settings live outside the plugin folder, so reinstalling can't destroy
  them.
- Settings: autostart, reconnect on resume, DNS handling, MTU, optional kill
  switch with a LAN carve-out so SSH survives.
- Diagnostics: `wg show`, routing table with `ip rule` and the policy table,
  firewall state, logs, config with the private key redacted, force teardown.
- Dispatcher actions for gesture and profile bindings.
- Journalled teardown reversing routes, the policy rule, the firewall rule,
  DNS, the interface and the process — idempotent, and run on disconnect, on
  exit, on USB plug-in, and at startup if a previous session left state
  behind.

### Notable implementation details

- **Endpoint exclusion uses fwmark policy routing**, not a host route.
  WireGuard's own packets are marked and routed out the physical interface
  via a dedicated table, so the exclusion covers only WireGuard's traffic. A
  service sharing a public IP with your endpoint stays reachable through the
  tunnel — a host route would exclude that address for everything. This is
  what `wg-quick` does with `Table = auto`. The fwmark is verified before any
  tunnel route is installed, and connect aborts if it did not apply; without
  it, the interface re-encrypts its own output at roughly 20 MB/s.
- **Exactly one firewall rule** is added and removed, check-gated with
  `iptables -C`. The firewall is never flushed.
- **Process detection reads `/proc/<pid>/cmdline`.** This device's `ps`
  prints command names without arguments. PIDs are verified against their
  cmdline before any signal.
- **The endpoint is resolved in Lua** and `wg setconf` receives a bare IP,
  avoiding the static-glibc `getaddrinfo` limitation and guaranteeing `wg`
  cannot pick a different address than the one the policy route covers.
- **All paths are resolved to absolute at startup**; KOReader hands out
  relative ones on this device.
- **Startup reconciliation records the owning process ID**, because KOReader
  instantiates plugins per UI — `init()` runs again when a book is opened,
  and must not tear down a tunnel this same process started.
- IPv6 is stripped with a logged reason; Kindle kernels ship without
  `CONFIG_IPV6_TUNNEL`.
- `PostUp` / `PreDown` are ignored rather than executed.

### Known limitations

- The private key is not protected by file permissions. `/mnt/us`
  synthesizes modes, so `chmod` does nothing there.
- DNS can be overwritten by Amazon's `wifid` on Wi-Fi state changes. The
  result is a leak rather than an outage; the status line reports it.
- The status line refreshes on menu open, not continuously —
  `touchmenu_instance` doesn't exist in KOReader v2026.07.2.
- BusyBox `wget` on Kindle has no working TLS. Use `curl` for shell testing.

### Verified on

Kindle Colorsoft, kernel 5.15.41-lab126, armv7l, KOReader v2026.07.2, with
`wireguard-tools v1.0.20260223` and `wireguard-go v0.0.20250522`.
