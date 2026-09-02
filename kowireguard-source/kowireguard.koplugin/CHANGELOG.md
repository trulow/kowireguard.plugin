# Changelog

All notable changes to kowireguard are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.3] — 2026-09-02

### Fixed

- **The looping warning was never visible.** 1.0.2 appended it as the fifth
  line of the status text, after Connected / Handshake / Endpoint / Transfer,
  where a truncated menu item renders it off the end. A looping tunnel
  therefore still displayed as `Connected — wg0` with a recent handshake. The
  warning now replaces the status line entirely rather than trailing it,
  because a loop looks healthy on every other measure.

### Added

- **The interface is brought down while the endpoint route cannot be
  repaired.** Measured on a Colorsoft, a loop moves roughly **20 MB/s** of
  self-encrypted traffic — 420 MB within seconds of deleting the route, 702 MB
  after ten. The previous 23-second retry window would have cost several
  hundred megabytes of pointless encryption and a real battery hit on a
  1,700 mAh cell.

  Traffic is dead either way while the route is wrong, so taking the
  interface down costs nothing and stops the device burning power to achieve
  nothing. It is brought back up automatically once the route verifies,
  preserving the MTU recorded in the journal, so a slow Wi-Fi reassociation
  still recovers rather than being cut short.

- Status line reports `Status: paused — waiting for the network` while in
  that state.
- Journal records the interface MTU, so a paused interface is restored with
  the value it was configured with rather than a default.

### Notes

The 20 MB/s figure came from deliberately deleting the endpoint route on
hardware and watching the counters, rather than from estimation. The rate is
what justified changing the mitigation from "retry patiently" to "stop the
loop, then retry".

---

## [1.0.2] — 2026-09-02

### Fixed

- **A failed resume repair was silent, leaving the tunnel looping on itself.**
  When the endpoint host route is lost during suspend and `AllowedIPs` is
  `0.0.0.0/0`, packets to the WireGuard endpoint route into the tunnel they
  are supposed to carry: `wireguard-go` re-encrypts its own output in a loop,
  burning battery and inflating the tx counter without moving real traffic.

  `Tunnel.reassert()` detected the missing route but could only repair it by
  reading the current default route, and after a deep sleep Wi-Fi has often
  not reassociated yet, so `Net.defaultRoute()` returned nil. The function
  then fell through with no repair, **no log line**, and a success return.
  Recovery happened only when a later resume event fired — 55 seconds later
  in the observed case, during which roughly 1.4 GiB of self-encrypted
  traffic accumulated.

  `reassert()` now distinguishes "repaired", "gone" and "retry", logs plainly
  when repair is not yet possible, and verifies that a re-added route
  actually resolves before reporting success.

### Added

- Resume repair retries on a bounded schedule — first attempt at 2s, then up
  to seven more at 3s intervals, about 23 seconds total. If the network has
  not returned by then the tunnel is torn down with a message, rather than
  left looping indefinitely. A torn-down tunnel is honest; one silently
  re-encrypting its own output is not.
- Status line reports `Endpoint route lost — traffic is looping, repairing…`.
  Without it a looping tunnel looks healthy: interface up, process alive,
  peer present, handshake recent.

### Notes

This was found by inspecting the tx/rx ratio after a successful ten-minute
suspend test — 1.38 GiB sent against 116 KiB received. The tunnel reconnected
and worked correctly; the counters were the only visible symptom.

---

## [1.0.1] — 2026-09-02

### Fixed

- **Opening a book tore down a working tunnel.** KOReader instantiates
  plugins once per UI — once for the file manager, and again for the reader
  when a document is opened — so `init()` runs several times within a single
  KOReader process. Startup reconciliation saw a live `wg0` plus a journal
  file, concluded that a previous session had crashed and left state behind,
  and disconnected a tunnel this same process had brought up moments earlier.

  This affected **any** document open, not any particular plugin or file
  format. It surfaced while browsing and downloading through
  [suwayomi.plugin](https://github.com/trulow/suwayomi.plugin), but the
  download was incidental; opening the resulting `.cbz` was the trigger.

  Two independent guards now prevent it:

  1. The journal records the PID of the KOReader process that brought the
     tunnel up (`Util.selfPid()`, read from `/proc/self/stat`).
     `Tunnel.reconcileAtStartup()` leaves a tunnel alone when its recorded
     owner is the current process.
  2. `KOWG:init()` performs its one-time work — directory creation, layout
     migration, settings, path validation, startup reconciliation and
     autostart — once per process rather than once per UI. Only menu
     registration and Dispatcher bindings run per instance.

  Crash recovery is unchanged. A journal with a different PID, a journal
  written before this version (no PID recorded), an orphaned interface with
  no journal, or an active kill switch all still trigger a full teardown.

### Added

- `Util.selfPid()` — reads the current process ID from `/proc/self/stat`.
- Log line `startup: tunnel belongs to this process, leaving it up`,
  distinguishing the benign re-initialisation path from genuine crash
  recovery.
- TESTPLAN §21: "Opening a book does not disconnect", covering KOReader's
  per-UI plugin instantiation.
- README troubleshooting entry for the symptom.

### Verification

Release gate, all passing:

| check | result |
| --- | --- |
| syntax (LuaJIT, 9 files, 2620 lines) | clean |
| global writes | 0 |
| non-stdlib global reads | 0 |
| cross-file references | clean |
| dead functions | none |
| functional suite | 39/39 |
| path normalization (9 input shapes) | 9/9 |
| reconciliation ownership (5 scenarios) | 5/5 |
| layout migration + idempotency | pass |

The reconciliation scenarios were tested explicitly because the risk in a fix
of this shape is over-correcting and silently losing the crash recovery the
logic exists for.

---

## [1.0.0] — 2026-09-02

First release verified end to end on hardware: tunnel established, traffic
routing through `wg0` (`ip route get 1.1.1.1` → `dev wg0`, first traceroute
hop the tunnel gateway), and teardown reverting routes, firewall and DNS to a
captured baseline.

### Removed

- `Util.exists`, the only function with no call site.

### Verification

No unused locals, no unused `require`s, every `env` key read, every module
function called, no non-stdlib globals read or written, no TODO markers.

---

## [0.2.2] — 2026-09-02

### Fixed

- **`DataStorage:getDataDir()` returns a path relative to KOReader's working
  directory on this device**, so the data directory introduced in 0.2.1
  resolved without a leading slash and the path validator rejected every
  config with *"Config path contains unsupported characters."* Path
  normalization is now a single helper applied to every directory, covering
  relative paths, `.`, `./`, trailing slashes, doubled slashes and embedded
  dot segments.

  This was the same class of bug as the plugin-directory fix in 0.2.0. The
  earlier fix was applied to one path rather than treated as a property of
  how KOReader hands out paths.

### Added

- Startup validation of every resolved directory, logging a
  `STARTUP PROBLEM:` line naming the offending one rather than letting a bad
  directory surface later as a misleading config error.
- Resolved paths logged at startup and shown in About.

---

## [0.2.1] — 2026-09-02

### Changed

- **All persistent files moved to `/mnt/us/koreader/kowireguard/`**: settings
  (previously in KOReader's shared `settings/` directory), the plugin log,
  and tunnel configs (both previously inside the plugin folder, where a
  reinstall would delete them).
- The data directory is derived from KOReader's data directory rather than
  hardcoded, with a fallback if `DataStorage:getDataDir()` is unavailable.
- About now shows both the data directory and the runtime directory.

### Migration

Existing installs migrate on first run, **copying rather than moving** so a
failed migration cannot lose a config, and never overwriting an existing
destination file. Safe to run repeatedly.

### Unchanged by design

Runtime files stay on `/var/run/kowireguard` (tmpfs):

- USB storage mode unmounts `/mnt/us` underneath a running process;
  `wireguard-go` writing its log there would die on EIO mid-write.
- The journal wants exactly tmpfs lifetime: it must survive a KOReader crash,
  when routes are still applied and need reversing, and must not survive a
  reboot, when they are already gone.
- The staged config passed to `wg setconf` contains the private key. `chmod`
  works on tmpfs; on `/mnt/us` (`fuse.fsp`) modes are synthesized and `chmod`
  is a no-op, so staging there would write a second unprotected plaintext
  copy of the key to USB-visible storage.

---

## [0.2.0] — 2026-09-02

### Changed

- **Renamed from `krwg` to `kowireguard`** throughout: directory, menu key,
  settings file, log file, runtime directory, Dispatcher action names and
  event names.
- Dropped the deprecated `name` field from `_meta.lua`; KOReader v2026.07
  derives the plugin name from the directory and warns when it is set.
- `wireguard-go` now runs with `LOG_LEVEL=verbose`, its log truncated each
  connect. At the default level it prints nothing on success, which made an
  empty log ambiguous between "working" and "died silently" — and led to a
  live process being reported as dead.
- Removed the `onClose` alias for `onExit`, which risked tearing the tunnel
  down when an unrelated widget closed.
- Numeric formatting in the status line is explicitly floored.

### Fixed

- **Process detection parsed `ps`**, which on this device prints only the
  command name and never its arguments, so the interface name could never be
  matched and a running `wireguard-go` was reported as having exited
  immediately. Now reads `/proc/<pid>/cmdline`, matching the interface as a
  whole argv entry so `wg0` cannot match `wg01`.
- **`tunnel.lua` called `wgBin()` / `wgGoBin()` after they moved into
  `state.lua`**, where they resolved as nil globals and crashed KOReader on
  connect. A global-read audit now runs before packaging specifically to
  catch this class.
- **The plugin directory was used as KOReader supplies it, which is
  relative.** Path validators require a leading slash as an anti-traversal
  check, so config loading would have been rejected. Resolved to absolute at
  startup.
- **Teardown could signal a recycled PID.** The number recorded at launch
  belongs to the spawning subshell, which exits immediately; that number can
  be reused by an unrelated process. PIDs are now verified against their
  `/proc` cmdline before any signal.

---

## [0.1.0] — 2026-09-02

Initial implementation as `krwg`.

### Added

- Kernel TUN mode via `wireguard-go` and `wg`, so HTTPS works natively — no
  CONNECT proxy, no patched `socket.http` or `ssl.https`, no hand-rolled
  certificate validation.
- Endpoint host route pinned via the pre-tunnel gateway and **verified with
  `ip route get` before the interface is brought up**, aborting if
  verification fails. The default route is parsed with a whole-line anchored
  pattern; matching `via` and `dev` independently is a known way to break
  this on Kindle's route output.
- Split-default routing (`0.0.0.0/1` + `128.0.0.0/1`) rather than replacing
  the default route, leaving the original intact for teardown and preserving
  the on-link LAN route so SSH survives.
- A single firewall rule for decrypted traffic on the tunnel interface,
  check-gated with `iptables -C` on both add and remove. The firewall is
  never flushed.
- DNS backup, application and restore, written through the `resolv.conf`
  symlink, re-asserted on resume and on Wi-Fi reconnect, with leak detection
  reported in the status line.
- Journalled teardown reversing every mutation, safe to run repeatedly, with
  an independent scan-based fallback if the journal is lost. Runs on
  disconnect, on exit, on USB plug-in, and at startup.
- Live status line refreshing every 5s only while the menu is open, reading
  real state from `wg show <iface> dump` on every call.
- Config parser splitting wg-quick keys from what `wg setconf` accepts.
  IPv6 stripped with a logged reason; `PostUp`/`PreDown` ignored rather than
  executed.
- Endpoint resolved in Lua, with the resolved IP substituted into what `wg`
  receives — avoiding the static-glibc `getaddrinfo` limitation and ensuring
  `wg` cannot select a different address than the one the host route pinned.
- Optional kill switch, off by default, carving out loopback, the tunnel, the
  LAN prefix and the endpoint.
- Dispatcher actions for connect, disconnect, toggle and status.
- Private keys redacted from all logs, dialogs and diagnostics.

---

## Known limitations

Not bugs, and unchanged across versions:

- **The menu status line refreshes on open, not continuously.**
  `touchmenu_instance` does not exist in KOReader v2026.07.2's
  `touchmenu.lua`, so the plugin's in-place `updateItems()` calls are no-ops
  there. `text_func` is re-evaluated every time the menu is opened, so backing
  out and reopening always shows current state. Connect, disconnect and
  settings changes take effect immediately regardless.

- **The private key is not protected by file permissions.** `/mnt/us` is a
  `fuse.fsp` mount with `allow_other`; modes are synthesized and `chmod 0600`
  does nothing there. Anyone with USB or filesystem access can read it. Use a
  dedicated peer you can revoke.
- **DNS can be overwritten by the system.** Amazon's `wifid` rewrites
  `resolv.conf` on Wi-Fi state changes and the plugin cannot prevent it. The
  result is a leak rather than an outage, since the LAN resolver stays
  reachable. Drift is detected and reported in the status line.
- **IPv6 is not tunnelled.** Kindle kernels ship with `CONFIG_IPV6_TUNNEL`
  unset and Wi-Fi carries only a link-local v6 address. IPv6 values in
  configs are dropped with a logged reason. There is consequently no v6 path
  to leak through either.
- **BusyBox `wget` on Kindle has no working TLS** and fails with or without
  the tunnel. Use `curl` for shell testing. KOReader uses LuaSocket and
  LuaSec in-process and is unaffected.
- **Self-hosted endpoints make "what is my IP" useless as a test.** If the
  WireGuard server runs on your own home connection and you are on that LAN,
  traffic hairpins out through the same router and the address reads
  identically either way. Use `ip route get 1.1.1.1` (expect `dev wg0`) or
  `traceroute` (expect the tunnel gateway as first hop).

---

[1.0.3]: #103--2026-09-02
[1.0.2]: #102--2026-09-02
[1.0.1]: #101--2026-09-02
[1.0.0]: #100--2026-09-02
[0.2.2]: #022--2026-09-02
[0.2.1]: #021--2026-09-02
[0.2.0]: #020--2026-09-02
[0.1.0]: #010--2026-09-02
