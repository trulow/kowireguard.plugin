# kowireguard — WireGuard VPN for KOReader

> This is the reference document shipped inside the plugin. For installation
> and build instructions, see the repository README.

A WireGuard client for jailbroken Kindles, managed entirely from KOReader's
menu. It drives a real `wg0` TUN interface using `wireguard-go` and `wg`, so
traffic leaves through an ordinary network interface.

Developed and **verified working** on an **Amazon Kindle Colorsoft**, kernel
`5.15.41-lab126`, armv7l, KOReader `v2026.07.2`, with `wireguard-tools
v1.0.20260223` and `wireguard-go v0.0.20250522`.

## What is and is not tunnelled

**Tunnelled.** With `AllowedIPs = 0.0.0.0/0`, all IPv4 traffic from the
device — not just KOReader's. Routing is done with a split default
(`0.0.0.0/1` + `128.0.0.0/1`), so the original default route survives for
teardown.

**HTTPS works normally.** Packets go through a real interface, so TLS is
ordinary TLS. Nothing patches `socket.http` or `ssl.https`, no CONNECT proxy
is involved, and no certificate validation is hand-rolled. This is the main
reason for preferring a TUN interface over a userspace proxy.

**Not tunnelled:**

- **IPv6.** Stripped deliberately. This kernel has `CONFIG_IPV6_TUNNEL`
  unset and `wlan0` carries only a link-local v6 address. `::/0` in
  `AllowedIPs` is dropped and the drop is logged. There is no v6 path to
  leak through, but there is also no v6 through the tunnel.
- **Your local network.** The on-link LAN route is left in place on purpose,
  so SSH to the device keeps working while the tunnel is up. This is the
  only recovery path if something goes wrong.
- **Traffic before connect and after disconnect.** Unless the kill switch is
  on, there is no protection outside a connected session.
- **DNS, sometimes.** See below.

## Security limitations, stated plainly

**Your private key is not protected by file permissions.** `/mnt/us` is a
`fuse.fsp` mount with `allow_other`; modes are synthesized, and `chmod 0600`
on a config there does nothing. **Anyone with USB access or filesystem
access to this device can read your WireGuard private key.** Treat any key
you put on the Kindle as a key that may be compromised, and use a dedicated
peer you can revoke.

The plugin never logs or displays private keys — `wg show` output, config
views and log tails are redacted — but that protects against shoulder-surfing
a diagnostic screen, not against someone with the device.

**DNS can leak.** `/etc/resolv.conf` is a symlink to `/var/run/resolv.conf`
on tmpfs and is writable, so kowireguard backs it up and applies the tunnel's
servers. But Amazon's `wifid` rewrites that file whenever Wi-Fi state
changes and kowireguard cannot prevent it. When it happens, lookups go to your
local router instead of the tunnel — a leak, not an outage, because the LAN
resolver stays reachable. kowireguard re-asserts DNS on resume and on Wi-Fi
reconnect, and the status line says `DNS: overwritten by the system
(leaking)` when it detects drift. Set **Settings → DNS** to *leave the
system's alone* if you would rather it not touch resolv.conf at all.

## Requirements

- Jailbroken Kindle with root and KOReader installed
- Kernel TUN support. Verify with:
  ```sh
  zcat /proc/config.gz | grep '^CONFIG_TUN='   # expect CONFIG_TUN=y
  ls -l /dev/net/tun                           # expect c 10 200
  cat /dev/net/tun                             # expect "File descriptor in bad state"
  ```
  That last error is the success case: the driver is present and refused a
  read on an unconfigured interface.

## Build the binaries

There are no reputable prebuilt `wg` / `wireguard-go` binaries for this
target, so cross-compile them. Both recipes run on an amd64 host; no qemu or
binfmt needed.

```sh
mkdir -p ~/kowireguard-build && cd ~/kowireguard-build

# wg (wireguard-tools), statically linked
docker run --rm -v "$PWD:/out" debian:bookworm-slim sh -c '
  apt-get update && apt-get install -y --no-install-recommends \
      git make gcc-arm-linux-gnueabihf libc6-dev-armhf-cross ca-certificates
  git clone --depth 1 https://github.com/WireGuard/wireguard-tools /src
  cd /src/src && make CC=arm-linux-gnueabihf-gcc LDFLAGS=-static
  cp wg /out/wg'

# wireguard-go
# NOTE: wireguard-go's go.mod requires Go >= 1.23.1 and the official images
# set GOTOOLCHAIN=local, so an older image fails rather than self-upgrading.
# Use GOTOOLCHAIN=auto if upstream bumps the requirement again.
docker run --rm -v "$PWD:/out" -w /src -e GOTOOLCHAIN=auto golang:1.23 sh -c '
  git clone --depth 1 https://github.com/WireGuard/wireguard-go /src
  GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w" -o /out/wireguard-go'
```

The `wg` build emits this linker warning, which is expected and harmless:

```
config.c: in function `parse_endpoint':
warning: Using 'getaddrinfo' in statically linked applications requires
at runtime the shared libraries from the glibc version used for linking
```

It refers to `parse_endpoint`, which kowireguard never exercises: the endpoint is
resolved in Lua and `wg setconf` receives a bare IP. If you use `wg` by hand
with a hostname endpoint, see the musl note below.

Verify on the build host before copying anything:

```sh
file wg wireguard-go
```

Both must report `ELF 32-bit LSB executable, ARM, EABI5 ... statically
linked`. If `wg` says *dynamically linked*, the static flag did not take —
retry with `make CC=arm-linux-gnueabihf-gcc LDFLAGS='-static' CFLAGS='-static'`.
A dynamically linked binary dies instantly and silently on the Kindle.

**ABI targets**, read off two binaries already running on the device:

| binary | source | `e_flags` | matches |
|---|---|---|---|
| `wg` | C, hard-float | `0x05000400` | the device's `luajit` |
| `wireguard-go` | Go | `0x05000002` | the device's `tailscaled` |

Go does not emit a float-ABI attribute because its runtime does not link
libc, so the two values differ legitimately. Both are ELF32 LSB `EM_ARM`,
EABI v5.

### If `wg` misbehaves on a hostname endpoint

kowireguard hands `wg` an already-resolved IP, so this should not arise. But if you
use `wg` by hand, note that statically linked glibc cannot reliably call
`getaddrinfo()` — NSS is `dlopen`'d at runtime. Build against musl instead:

```sh
docker run --rm -v "$PWD:/out" alpine:3.19 sh -c '
  apk add --no-cache git make gcc musl-dev linux-headers
  git clone --depth 1 https://github.com/WireGuard/wireguard-tools /src
  cd /src/src && make LDFLAGS=-static && cp wg /out/wg'
```

Run that under `--platform linux/arm/v7` (needs qemu/binfmt), or use an
`arm-linux-musleabihf` cross toolchain.

## Install

```sh
scp -r kowireguard.koplugin root@KINDLE:/mnt/us/koreader/plugins/
scp wg wireguard-go root@KINDLE:/mnt/us/koreader/plugins/kowireguard.koplugin/bin/
```

No `chmod` is needed — this filesystem synthesizes permissions. Verify the
binaries by executing them, which is the only test that means anything here:

```sh
/mnt/us/koreader/plugins/kowireguard.koplugin/bin/wg --version
/mnt/us/koreader/plugins/kowireguard.koplugin/bin/wireguard-go --version
```

Restart KOReader. The plugin appears under **Network → kowireguard (v1.0.1)**.

Then **Import config…**, pick your `.conf`, and **Connect**. Imported configs
are copied to `/mnt/us/koreader/kowireguard/configs/`; you can also drop
files there directly.

Upgrading from an earlier version migrates settings and configs into that
directory automatically, copying rather than moving so a failed migration
cannot lose a config.

## Uninstall

Run **Diagnostics → Force teardown** first if a tunnel is up; otherwise
reboot, since routes live in kernel state, not on disk.

To remove the code but keep your configs and settings:

```sh
rm -rf /mnt/us/koreader/plugins/kowireguard.koplugin
```

To remove everything:

```sh
rm -rf /mnt/us/koreader/plugins/kowireguard.koplugin
rm -rf /mnt/us/koreader/kowireguard
```

Nothing is written anywhere else. `/var/run/kowireguard` is tmpfs and clears
itself on reboot.

## Sample config

```ini
[Interface]
PrivateKey = <your base64 private key>
Address = 10.7.0.2/32
DNS = 10.7.0.1
MTU = 1420

[Peer]
PublicKey = <server public key>
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

Notes on parsing:

- `Address`, `DNS`, `MTU` and `Table` are applied by kowireguard, not passed to
  `wg setconf`, which rejects them.
- `PostUp`, `PreDown` and friends are **ignored, not executed**. Running
  provider-supplied shell as root on a device whose only recovery path is
  SSH is not a tradeoff worth making. The Import screen lists what it
  ignored.
- `Table = off` means kowireguard adds no tunnel routes.
- Any IPv6 value is dropped with a note.
- `PersistentKeepalive` is worth setting behind consumer NAT.

## Menu

- **Status** — live, refreshing every 5s while open, cancelled on close.
  Shows state, handshake age, endpoint and transfer counters from
  `wg show <iface> dump`. Read from the interface each time; a stored PID is
  never treated as proof the tunnel is alive.
- **Connect / Disconnect**
- **Tunnels** — radio list of `configs/*.conf`
- **Import config…**
- **Settings** — autostart, reconnect on resume, DNS handling, tunnel
  firewall mode, kill switch, MTU
- **Diagnostics** — `wg show`, routing table, firewall rule state, DNS,
  plugin log, `wireguard-go` output, redacted config, force teardown, clear
  log
- **About kowireguard (v1.0.1)**

Gesture and profile bindings are registered with Dispatcher: `kowireguard connect`,
`kowireguard disconnect`, `kowireguard toggle`, `kowireguard status`.

## Device-specific behaviour

**Endpoint routing.** With `AllowedIPs = 0.0.0.0/0`, packets to the
WireGuard endpoint would themselves be routed into the tunnel and the
handshake would loop forever. kowireguard resolves the endpoint, pins a host route
to it via the pre-tunnel gateway, and then **verifies that route with `ip
route get` before bringing the interface up**. If verification fails it
aborts rather than starting a tunnel that cannot connect. The default route
is parsed with a whole-line anchored pattern
(`^%s*default%s+via%s+(%S+)%s+dev%s+(%S+)`) — matching `via` and `dev`
independently is what broke this on a PW6.

**Firewall.** Measured on this device rather than assumed: `OUTPUT` policy
is `ACCEPT`, so outbound UDP to the endpoint already passes and **kowireguard adds
no OUTPUT rule**. The real problem is `INPUT` policy `DROP` with every
accept rule pinned to `wlan0`/`ppp0`/`wwan0`/`lo`/`usb0` — decrypted packets
arriving on `wg0` match nothing. kowireguard inserts exactly one rule:

```
iptables -I INPUT -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

and removes precisely that rule on teardown, check-gated with `iptables -C`
so it is idempotent. **The firewall is never flushed.** A Kindle left with
no firewall after a failed teardown is worse than a stale rule.

**Teardown** reverses every mutation — kill switch, DNS, firewall, routes,
interface, process — is safe to run repeatedly, and runs on disconnect, on
exit, on USB plug-in, and at startup if a previous session left state
behind. State is journalled to `/var/run/kowireguard/journal.lua` on tmpfs, which
survives a KOReader crash and correctly does not survive a reboot. Teardown
also scans for state independently, so it works even if the journal is lost.

**USB.** Plugging into a computer unmounts `/mnt/us` and pulls the binaries
out from under the running process. kowireguard detects this and tears down first.

**Logs.** `wireguard-go` output goes to `/var/run/kowireguard/` on tmpfs, not
`/mnt/us` — a FUSE mount that disappears during USB storage mode would
otherwise kill the process mid-write. The plugin's own log is
`kowireguard.log` in the plugin directory, size-capped at 96 KiB, readable over
USB. Diagnostics can copy the tmpfs log into the plugin folder on demand.

## Kill switch

Off by default. When on, it drops all outbound traffic not going through the
tunnel, carving out loopback, the tunnel interface, your LAN prefix and the
endpoint. The LAN carve-out is what keeps SSH working. Accept rules are
inserted before the terminal `DROP` is appended, and the `DROP` is removed
first during teardown, so there is never a window where traffic is blocked
without the carve-outs in place.

If you enable this and something goes wrong, recover over SSH with:

```sh
iptables -D OUTPUT -j DROP
```

## Files

The plugin folder holds only code and the two binaries. Everything the
plugin creates lives outside it, so upgrading or reinstalling cannot destroy
your configs or settings.

```
/mnt/us/koreader/plugins/kowireguard.koplugin/   (code — safe to replace)
├── _meta.lua           version (single source of truth)
├── main.lua            entry point, events, Dispatcher
├── menu.lua            top-level menu, status line
├── menu_panels.lua     Tunnels / Settings / Diagnostics / About
├── tunnel.lua          connect, disconnect, resume
├── state.lua           journal, process probing, status
├── net.lua             routes, DNS, firewall
├── config.lua          wg-quick config parser
├── util.lua            exec, validation, logging, redaction
└── bin/                wg, wireguard-go

/mnt/us/koreader/kowireguard/                    (your data — persists)
├── configs/            your .conf files
├── kowireguard_settings.lua
├── kowireguard.log     size-capped at 96 KiB
└── wireguard-go.log    only if copied from Diagnostics

/var/run/kowireguard/                            (tmpfs — cleared on reboot)
├── journal.lua         what to reverse on teardown
├── wireguard-go.log    live process output
├── resolv.conf.bak     DNS backup
└── wg0.conf            staged config, deleted immediately after setconf
```

### Why runtime files stay on tmpfs

Three reasons, all specific to this device:

- USB storage mode unmounts `/mnt/us` underneath a running process.
  `wireguard-go` writing its log there would die on EIO mid-write.
- The journal wants exactly tmpfs lifetime: it must survive a KOReader crash,
  when routes are still applied and need reversing, and must not survive a
  reboot, when they are already gone.
- The staged config passed to `wg setconf` contains your private key. `chmod`
  works on tmpfs; on `/mnt/us` (`fuse.fsp`) modes are synthesized and `chmod`
  is a no-op, so staging it there would write a second unprotected plaintext
  copy of your key to USB-visible storage.

Sibling modules are loaded by absolute-path `dofile()` returning a
constructor, not `require()`, to keep files named `config.lua` and `net.lua`
out of KOReader's global module namespace.

Sibling modules are loaded by absolute-path `dofile()` returning a
constructor, not `require()`, to keep files named `config.lua` and `net.lua`
out of KOReader's global module namespace.

## Changelog

### 0.2.0

- Renamed from `krwg` to `kowireguard` throughout: directory, menu key,
  settings file, log file, runtime directory, Dispatcher action names and
  event names.
- Dropped the deprecated `name` field from `_meta.lua`. KOReader v2026.07
  derives the plugin name from the directory and warned about it.
- **Fixed:** process detection read `ps`, which on this device prints only
  the command name and never its arguments, so the interface name could
  never be matched and a live `wireguard-go` was reported as dead. Now reads
  `/proc/<pid>/cmdline`, matching the interface as a whole argv entry.
- **Fixed:** `tunnel.lua` called `wgBin()` / `wgGoBin()` after they moved
  into `state.lua`, so they resolved as nil globals and connect crashed
  KOReader.
- **Fixed:** the plugin directory was used as KOReader supplies it, which is
  relative. Every path validator requires a leading slash, so config loading
  would have been rejected. Resolved to absolute at startup.
- **Fixed:** teardown could signal a recycled PID. The number recorded at
  launch belongs to the spawning subshell, which exits immediately; a PID is
  now verified against its `/proc` cmdline before any signal.
- Removed the `onClose` alias for `onExit`, which risked tearing the tunnel
  down when an unrelated widget closed.
- `wireguard-go` now runs with `LOG_LEVEL=verbose` and its log is truncated
  each connect. At the default level it prints nothing on success, which made
  an empty log ambiguous between "working" and "died silently".
- Numeric formatting in the status line is explicitly floored.

### Known, unchanged

- BusyBox `wget` on this device has no working TLS and fails with or without
  the tunnel. Use `curl` for shell testing. KOReader itself uses LuaSocket
  and LuaSec in-process and is unaffected.
- If your WireGuard server is hosted on your own home connection, "what is
  my IP" reads the same tunnelled or not, because traffic hairpins out
  through the same router. Use `ip route get 1.1.1.1` (expect `dev wg0`) or
  `traceroute` (expect the tunnel gateway as first hop) instead.

### 0.2.1

- All persistent files moved to `/mnt/us/koreader/kowireguard/`: settings
  (previously in KOReader's shared `settings/` directory), the plugin log and
  your tunnel configs (both previously inside the plugin folder, where a
  reinstall would delete them). Existing installs migrate automatically on
  first run, copying rather than moving.
- The data directory is derived from KOReader's data dir rather than
  hardcoded, with a fallback if `DataStorage:getDataDir()` is unavailable.
- Runtime files stay on `/var/run/kowireguard` (tmpfs) by design — see
  "Why runtime files stay on tmpfs" above.
- About now shows both the data directory and the runtime directory.

### 0.2.2

- **Fixed:** `DataStorage:getDataDir()` returns a path relative to KOReader's
  working directory on this device, so the new data directory resolved to
  something without a leading slash and the path validator rejected every
  config with "Config path contains unsupported characters". Path
  normalization is now a single helper applied to every directory, covering
  relative paths, `.`, `./`, trailing slashes, doubled slashes and embedded
  dot segments.
- Startup now validates each resolved directory and logs a clear
  `STARTUP PROBLEM:` line naming the offending one, rather than letting a bad
  directory surface later as a misleading config error.
- Resolved paths are logged at startup and shown in About.

### 1.0.0

- Removed the one function with no call site (`Util.exists`).
- Verified: no unused locals, no unused requires, every `env` key read, every
  module function called, no non-stdlib globals read or written.
- First release verified end to end on hardware: tunnel up, traffic routing
  through `wg0`, teardown reverting routes, firewall and DNS to baseline.

### 1.0.1

- **Fixed: opening a book tore down a working tunnel.** KOReader instantiates
  plugins per UI — once for the file manager, again for the reader when a
  document is opened — so `init()` runs several times in one process. Startup
  reconciliation saw the live interface plus a journal, concluded a previous
  session had crashed, and disconnected. Two guards now: the journal records
  the PID of the KOReader process that brought the tunnel up and
  reconciliation leaves a tunnel owned by the current process alone, and the
  one-time setup in `init()` runs once per process rather than once per UI.
  Teardown after a genuine crash (different PID, or no journal) is unchanged.
