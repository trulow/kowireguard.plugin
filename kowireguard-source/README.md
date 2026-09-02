# kowireguard

A WireGuard VPN client for jailbroken Kindles, managed entirely from
KOReader's menu. No SSH, no KUAL, no terminal for day-to-day use.

It drives a real `wg0` TUN interface using `wireguard-go` and `wg`, so
traffic leaves through an ordinary network interface and **HTTPS works
natively** — no CONNECT proxy, no patched `socket.http` or `ssl.https`, no
hand-rolled certificate validation.

Verified working on an **Amazon Kindle Colorsoft**, kernel `5.15.41-lab126`,
armv7l, KOReader `v2026.07.2`, with `wireguard-tools v1.0.20260223` and
`wireguard-go v0.0.20250522`.

---

## Requirements

- A jailbroken Kindle with root access and KOReader installed
- Kernel TUN support
- Docker on a build machine (the binaries are not included; see below)

Verify TUN support before anything else:

```sh
zcat /proc/config.gz | grep '^CONFIG_TUN='   # expect CONFIG_TUN=y
ls -l /dev/net/tun                           # expect c 10 200
cat /dev/net/tun                             # expect "File descriptor in bad state"
```

That last error is the success case: the driver is present and refused a read
on an unconfigured interface. If `/dev/net/tun` is missing, create it — the
node can be absent while kernel support is present:

```sh
mkdir -p /dev/net && mknod /dev/net/tun c 10 200
```

---

## Building the binaries

This plugin ships no binaries. There are no reputable prebuilt `wg` or
`wireguard-go` builds for this target, so cross-compile them yourself. Both
recipes run on an amd64 host — no qemu or binfmt needed.

```sh
mkdir -p ~/kowireguard-build && cd ~/kowireguard-build

# wg (wireguard-tools), statically linked, hard-float
docker run --rm -v "$PWD:/out" debian:bookworm-slim sh -c '
  apt-get update && apt-get install -y --no-install-recommends \
      git make gcc-arm-linux-gnueabihf libc6-dev-armhf-cross ca-certificates
  git clone --depth 1 https://github.com/WireGuard/wireguard-tools /src
  cd /src/src && make CC=arm-linux-gnueabihf-gcc LDFLAGS=-static
  cp wg /out/wg'

# wireguard-go
docker run --rm -v "$PWD:/out" -w /src -e GOTOOLCHAIN=auto golang:latest sh -c '
  git clone --depth 1 https://github.com/WireGuard/wireguard-go /src
  GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w" -o /out/wireguard-go'
```

### Notes on these recipes

**`GOTOOLCHAIN=auto` is not optional.** `wireguard-go`'s `go.mod` requires a
Go version newer than some official images ship, and those images set
`GOTOOLCHAIN=local`, which makes the build fail rather than fetch the needed
toolchain. With `auto` the image downloads what the module asks for.

**The `getaddrinfo` linker warning on `wg` is expected and harmless:**

```
config.c: in function `parse_endpoint':
warning: Using 'getaddrinfo' in statically linked applications requires
at runtime the shared libraries from the glibc version used for linking
```

It refers to `parse_endpoint`, which this plugin never exercises. The
endpoint is resolved in Lua via LuaSocket and `wg setconf` receives a bare
IP. That is deliberate: it avoids the static-glibc NSS problem, and it
guarantees `wg` uses exactly the address the host route was pinned to. With
round-robin or split-horizon DNS, letting `wg` resolve independently can
select a different address than the one you routed, producing a tunnel that
handshakes forever while every route looks correct.

**Verify before copying anything to the device:**

```sh
file wg wireguard-go
```

Both must report `ELF 32-bit LSB executable, ARM, EABI5 ... statically
linked`. If `wg` says *dynamically linked*, the static flag did not take;
retry with `make CC=arm-linux-gnueabihf-gcc LDFLAGS='-static' CFLAGS='-static'`.
A dynamically linked binary dies instantly and silently on the Kindle.

Optionally confirm the ABI matches binaries already running on your device:

```sh
readelf -h wg | grep Flags            # expect 0x5000400 — matches KOReader's luajit
readelf -h wireguard-go | grep Flags  # expect 0x5000002 — matches tailscaled
```

The two differ legitimately: Go emits no float-ABI attribute because its
runtime does not link libc.

To shrink `wg` (it builds unstripped, ~650 KB):

```sh
docker run --rm -v "$PWD:/out" debian:bookworm-slim sh -c '
  apt-get update -qq && apt-get install -y -qq binutils-arm-linux-gnueabihf
  arm-linux-gnueabihf-strip /out/wg'
```

### Building for a different Kindle

The recipes target ARMv7 hard-float, which covers every current Kindle. Read
the ABI off a binary already running on your device rather than assuming:

```sh
od -An -tx1 -N 64 /mnt/us/koreader/luajit
```

Bytes 36–39 are `e_flags`, little-endian. `00 04 00 05` is `0x05000400` —
EABI v5, hard-float.

---

## Deploying

### 1. Copy the plugin

```sh
K=root@YOUR_KINDLE_IP

scp -P 2222 kowireguard.koplugin.zip $K:/mnt/us/
ssh -p 2222 $K
```

On the Kindle:

```sh
cd /mnt/us/koreader/plugins
unzip -o /mnt/us/kowireguard.koplugin.zip
rm /mnt/us/kowireguard.koplugin.zip
```

If BusyBox has no `unzip`, unpack on the build machine and copy the directory
instead:

```sh
unzip kowireguard.koplugin.zip
scp -P 2222 -r kowireguard.koplugin $K:/mnt/us/koreader/plugins/
```

### 2. Copy the binaries

```sh
scp -P 2222 wg wireguard-go \
  $K:/mnt/us/koreader/plugins/kowireguard.koplugin/bin/
```

### 3. Verify by executing them

`/mnt/us` synthesizes file permissions, so `ls -l` and `chmod` tell you
nothing there. Execution is the only meaningful test:

```sh
cd /mnt/us/koreader/plugins/kowireguard.koplugin/bin
./wg --version
./wireguard-go --version
```

Both must print a version string. No `chmod` is needed.

### 4. Capture a baseline

Useful for confirming teardown later:

```sh
ip route show > /tmp/routes.before
iptables -S > /tmp/fw.before
cat /etc/resolv.conf > /tmp/dns.before
```

### 5. Restart KOReader

Fully exit and relaunch — plugins are only scanned at startup. The entry
appears under **Network → kowireguard (v1.0.3)**.

### 6. Add a tunnel

Either use **Import config…** from the menu, which validates the file and
reports anything it ignored, or copy a `.conf` in directly:

```sh
scp -P 2222 myvpn.conf $K:/mnt/us/koreader/kowireguard/configs/
```

Then **Tunnels** → select it → **Connect**.

### 7. Confirm it works

```sh
cd /mnt/us/koreader/plugins/kowireguard.koplugin

bin/wg show wg0                  # recent handshake, rising counters
ip route get 1.1.1.1             # expect: dev wg0
ip route get YOUR_ENDPOINT_IP    # expect: via YOUR_GATEWAY dev wlan0
iptables -S INPUT | grep wg0     # exactly one rule
traceroute -n -m2 1.1.1.1        # first hop should be your tunnel gateway
curl -sS https://ifconfig.me     # your endpoint's address
```

Use `curl`, not `wget` — BusyBox `wget` on Kindle has no working TLS and
fails with or without the tunnel. KOReader itself uses LuaSocket and LuaSec
in-process and is unaffected.

If your WireGuard server is hosted on your own home connection and you are
currently on that LAN, "what is my IP" reads the same tunnelled or not,
because traffic hairpins out through the same router. Use `ip route get` or
`traceroute` instead.

---

## Sample config

```ini
[Interface]
PrivateKey = <your base64 private key>
Address = 10.8.0.2/32
DNS = 10.8.0.1
MTU = 1420

[Peer]
PublicKey = <server public key>
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

- `Address`, `DNS`, `MTU` and `Table` are applied by the plugin, not passed
  to `wg setconf`, which rejects them.
- `PostUp`, `PreDown` and friends are **ignored, not executed**. Running
  provider-supplied shell as root on a device whose only recovery path is SSH
  is not a tradeoff worth making. The import screen lists what it ignored.
- `Table = off` means no tunnel routes are added.
- Any IPv6 value is dropped with a note. This kernel has
  `CONFIG_IPV6_TUNNEL` unset and Kindle Wi-Fi carries only a link-local v6
  address.
- `PersistentKeepalive` is worth setting behind consumer NAT.
- If your `MTU` is unset the plugin default (1420) applies, adjustable in
  **Settings → MTU**. A config's own `MTU` line takes precedence over that
  setting. If large HTTPS responses stall while small ones succeed, lower it
  — 1400 or 1280.

---

## File layout

The plugin folder holds only code and binaries. Everything the plugin creates
lives outside it, so upgrading or reinstalling cannot destroy your configs.

```
/mnt/us/koreader/plugins/kowireguard.koplugin/   code — safe to replace
├── _meta.lua           version (single source of truth)
├── main.lua            entry point, events, Dispatcher
├── menu.lua            top-level menu, status line
├── menu_panels.lua     Tunnels / Settings / Diagnostics / About
├── tunnel.lua          connect, disconnect, resume
├── state.lua           journal, process probing, status
├── net.lua             routes, DNS, firewall
├── config.lua          wg-quick config parser
├── util.lua            exec, validation, logging, redaction
└── bin/                wg, wireguard-go (you supply these)

/mnt/us/koreader/kowireguard/                    your data — persists
├── configs/            your .conf files
├── kowireguard_settings.lua
└── kowireguard.log     size-capped at 96 KiB

/var/run/kowireguard/                            tmpfs — clears on reboot
├── journal.lua         what to reverse on teardown
├── wireguard-go.log    live process output
├── resolv.conf.bak     DNS backup
└── wg0.conf            staged config, deleted immediately after setconf
```

Runtime files stay on tmpfs deliberately:

- USB storage mode unmounts `/mnt/us` underneath a running process;
  `wireguard-go` writing its log there would die on EIO mid-write.
- The journal wants exactly tmpfs lifetime: it must survive a KOReader crash,
  when routes are still applied and need reversing, and must not survive a
  reboot, when they are already gone.
- The staged config contains your private key. `chmod` works on tmpfs; on
  `/mnt/us` modes are synthesized and `chmod` is a no-op, so staging it there
  would write a second unprotected plaintext copy of your key to USB-visible
  storage.

---

## Menu

- **Status** — live, refreshing every 5s while open, cancelled on close.
  State, handshake age, endpoint and transfer counters read from
  `wg show <iface> dump` on every call. A stored PID is never treated as
  evidence the tunnel is alive.
- **Connect / Disconnect**
- **Tunnels** — radio list of your configs
- **Import config…**
- **Settings** — autostart, reconnect on resume, DNS handling, tunnel
  firewall mode, kill switch, MTU
- **Diagnostics** — `wg show`, routing table, firewall rule state, DNS,
  plugin log, `wireguard-go` output, redacted config, force teardown, clear
  log
- **About kowireguard (v1.0.3)**

Gesture and profile bindings are registered with Dispatcher: `kowireguard
connect`, `disconnect`, `toggle`, `status`.

---

## Security limitations

**Your private key is not protected by file permissions.** `/mnt/us` is a
`fuse.fsp` mount with `allow_other`; modes are synthesized and `chmod 0600`
on a config there does nothing. **Anyone with USB or filesystem access to the
device can read your WireGuard private key.** Use a dedicated peer you can
revoke.

The plugin never logs or displays private keys — `wg show` output, config
views and log tails are all redacted — but that protects against
shoulder-surfing a diagnostic screen, not against someone holding the device.

**DNS can leak.** `/etc/resolv.conf` symlinks to `/var/run/resolv.conf` on
tmpfs and is writable, so the plugin backs it up and applies the tunnel's
servers. But Amazon's `wifid` rewrites that file on Wi-Fi state changes and
the plugin cannot prevent it. When it happens, lookups go to your local
router instead of the tunnel — a leak, not an outage, since the LAN resolver
stays reachable. DNS is re-asserted on resume and on Wi-Fi reconnect, and the
status line reports `DNS: overwritten by the system (leaking)` when drift is
detected. Set **Settings → DNS** to *leave the system's alone* to opt out
entirely.

**What is not tunnelled:** IPv6 (stripped deliberately — there is no v6 path
to leak through, but also none through the tunnel); your local network (the
on-link route is preserved on purpose so SSH keeps working, which is the only
recovery path); and anything before connect or after disconnect unless the
kill switch is on.

---

## Device-specific behaviour

**Endpoint routing.** With `AllowedIPs = 0.0.0.0/0`, packets to the WireGuard
endpoint would themselves be routed into the tunnel and the handshake would
loop forever. The plugin resolves the endpoint, pins a host route to it via
the pre-tunnel gateway, and **verifies that route with `ip route get` before
bringing the interface up**, aborting if verification fails. The default
route is parsed with a whole-line anchored pattern; matching `via` and `dev`
independently is a known way to break this on Kindle's output format.

**Firewall.** Measured rather than assumed: on this device `OUTPUT` policy is
`ACCEPT`, so outbound UDP to the endpoint already passes and **no OUTPUT rule
is added**. The real block is `INPUT` policy `DROP` with every accept rule
pinned to `wlan0`/`ppp0`/`wwan0`/`lo`/`usb0` — decrypted packets arriving on
`wg0` match nothing. Exactly one rule is inserted:

```
iptables -I INPUT -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

and removed precisely on teardown, check-gated with `iptables -C` so it is
idempotent. **The firewall is never flushed.** A Kindle left with no firewall
after a failed teardown is worse than a stale rule.

**Teardown** reverses every mutation — kill switch, DNS, firewall, routes,
interface, process — is safe to run repeatedly, and runs on disconnect, on
exit, on USB plug-in, and at startup if a previous session left state behind.
State is journalled, and teardown also scans for state independently so it
works even if the journal is lost. PIDs are verified against their
`/proc` cmdline before any signal, since the number recorded at launch
belongs to a subshell that exits immediately and could be recycled.

**Kill switch.** Off by default. When on, it drops all outbound traffic not
going through the tunnel, carving out loopback, the tunnel, your LAN prefix
and the endpoint. The LAN carve-out is what keeps SSH working. Recover with:

```sh
iptables -D OUTPUT -j DROP
```

---

## Uninstalling

Run **Diagnostics → Force teardown** first if a tunnel is up; otherwise
reboot, since routes live in kernel state, not on disk.

Remove the code but keep configs and settings:

```sh
rm -rf /mnt/us/koreader/plugins/kowireguard.koplugin
```

Remove everything:

```sh
rm -rf /mnt/us/koreader/plugins/kowireguard.koplugin
rm -rf /mnt/us/koreader/kowireguard
```

Nothing is written anywhere else. `/var/run/kowireguard` is tmpfs and clears
on reboot.

---

## Troubleshooting

**Plugin does not appear in the menu.** `tail -40 /mnt/us/koreader/crash.log`
— a Lua load error names the file and line.

**"wireguard-go exited immediately."** `cat
/var/run/kowireguard/wireguard-go.log`. The process runs with
`LOG_LEVEL=verbose`, so a successful start is visible too; an empty log means
it never launched.

**Connect fails.** `tail -30 /mnt/us/koreader/kowireguard/kowireguard.log`.
Every shell command is logged with its exit code, private keys redacted.

**"Config path contains unsupported characters."** Check the startup line in
the log: `grep 'paths:\|STARTUP PROBLEM' kowireguard.log`. Config filenames
must match `[A-Za-z0-9._-]+`.

**Tunnel disconnects when you open a book.** Fixed in 1.0.1. If you see
`previous session left state behind` in the log right after opening a
document, you are on an older build.

**Tunnel connects but no traffic.** Confirm the firewall rule exists:
`iptables -S INPUT | grep wg0`. A fresh handshake with rising counters and no
traffic is the `INPUT DROP` policy eating decrypted packets.

**Large HTTPS responses stall, small ones work.** MTU. Probe for the working
size, then set it in **Settings → MTU** or the config:

```sh
for s in 1412 1372 1332 1292 1252; do
  printf "mtu %s: " "$((s+28))"
  ping -M do -s $s -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL
done
```

---

## Development

Lua 5.1 / LuaJIT, no dependencies beyond KOReader's own. Sibling modules are
loaded by absolute-path `dofile()` returning a constructor rather than
`require()`, to keep files named `config.lua` and `net.lua` out of KOReader's
global module namespace.

Checks worth running before any commit:

```sh
# syntax
for f in *.lua; do luajit -bl "$f" /dev/null >/dev/null || echo "FAIL $f"; done

# no global writes
for f in *.lua; do echo "$f $(luajit -bl $f | grep -c GSET)"; done

# no non-stdlib global reads — catches a local moved between files
for f in *.lua; do
  luajit -bl "$f" | grep GGET | sed 's/.*; *"//; s/".*//' | sort -u
done
```

That last check exists because splitting a module once left `tunnel.lua`
calling helpers that had moved into `state.lua`, where they resolved as nil
globals and crashed on connect.

`TESTPLAN.md` in the plugin directory has a 20-step manual test plan covering
fresh install, first connect, HTTPS and OPDS, endpoint-route verification,
firewall add/remove, DNS restore, bad key, unreachable endpoint, Wi-Fi off,
sleep/wake, external process kill, teardown after simulated crash, USB
connect while running, and uninstall.

---

## Known limitation: menu refresh

`touchmenu_instance` does not exist in KOReader v2026.07.2's `touchmenu.lua`,
so the in-place `updateItems()` calls in the menu code are no-ops on that
version. The status line updates **when you open the menu, not while it is
open** — `text_func` is re-evaluated on every open, so backing out and
reopening always shows current state. Connect, disconnect and settings changes
all take effect immediately; only the live redraw is inert.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Credits

Builds on prior art from
[wtb04/wireguard.koplugin](https://github.com/wtb04/wireguard.koplugin) and
[victoria-riley-barnett/koreader-tailscale](https://github.com/victoria-riley-barnett/koreader-tailscale),
which established that userspace WireGuard and Go networking binaries work on
this class of hardware.

## License

MIT
