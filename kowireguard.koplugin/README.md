# kowireguard

A WireGuard VPN client for jailbroken Kindles, managed entirely from
KOReader's menu. No SSH, no KUAL, no terminal for day-to-day use.

It drives a real `wg0` TUN interface with `wireguard-go` and `wg`, so traffic
leaves through an ordinary network interface and **HTTPS works natively** — no
CONNECT proxy, no patched `socket.http` or `ssl.https`, no hand-rolled
certificate validation.

Verified on a Kindle Colorsoft, kernel 5.15.41-lab126, armv7l, KOReader
v2026.07.2.

## Features

- Connect, disconnect and switch tunnels from **Network → kowireguard**
- Live status: handshake age, endpoint, transfer counters
- Import `.conf` files through the UI, with validation on import
- Autostart, reconnect-on-resume, DNS handling, MTU, optional kill switch
- Diagnostics: `wg show`, routes, firewall state, logs, redacted config,
  force teardown
- Gesture and profile bindings via Dispatcher
- Complete, idempotent teardown — routes, firewall rule, DNS, interface and
  process are all reversed, including after a crash

## Requirements

- Jailbroken Kindle with root and KOReader installed
- Kernel TUN support:

  ```sh
  zcat /proc/config.gz | grep '^CONFIG_TUN='   # expect CONFIG_TUN=y
  cat /dev/net/tun                             # expect "File descriptor in bad state"
  ```

  That error is the success case — the driver refused a read on an
  unconfigured interface. If `/dev/net/tun` is missing:

  ```sh
  mkdir -p /dev/net && mknod /dev/net/tun c 10 200
  ```

- Docker on a build machine (binaries are not distributed)

## Build the binaries

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

Verify before copying:

```sh
file wg wireguard-go
```

Both must report `ELF 32-bit LSB executable, ARM, EABI5 ... statically
linked`. A dynamically linked `wg` dies instantly and silently on the Kindle.

Two notes on these recipes:

- **`GOTOOLCHAIN=auto` is required.** `wireguard-go`'s `go.mod` outruns the Go
  version in some official images, and those images set `GOTOOLCHAIN=local`,
  which makes the build fail rather than fetch what it needs.
- **The `getaddrinfo` linker warning on `wg` is expected.** It refers to
  `parse_endpoint`, which this plugin never exercises — the endpoint is
  resolved in Lua and `wg setconf` receives a bare IP.

## Install

```sh
scp -P 2222 kowireguard-1.0.3.zip root@KINDLE:/mnt/us/
```

On the Kindle:

```sh
cd /mnt/us/koreader/plugins
unzip -o /mnt/us/kowireguard-1.0.3.zip
rm /mnt/us/kowireguard-1.0.3.zip

scp -P 2222 wg wireguard-go \
  root@KINDLE:/mnt/us/koreader/plugins/kowireguard.koplugin/bin/
```

Verify by executing them — `/mnt/us` synthesizes permissions, so `ls -l` and
`chmod` mean nothing there:

```sh
cd /mnt/us/koreader/plugins/kowireguard.koplugin
bin/wg --version
bin/wireguard-go --version
```

Restart KOReader. The entry appears under **Network → kowireguard (v2.0.1)**.

Then **Import config…**, or drop a `.conf` into
`/mnt/us/koreader/kowireguard/configs/`, and **Connect**.

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

- `Address`, `DNS`, `MTU` and `Table` are applied by the plugin, not passed to
  `wg setconf`, which rejects them.
- `PostUp` / `PreDown` are **ignored, not executed**. Running provider-supplied
  shell as root on a device whose only recovery path is SSH isn't a trade worth
  making. The import screen lists what it ignored.
- IPv6 values are dropped with a note — Kindle kernels ship without
  `CONFIG_IPV6_TUNNEL`.
- `PersistentKeepalive = 25` matters behind consumer or carrier NAT.

## File layout

```
/mnt/us/koreader/plugins/kowireguard.koplugin/   code — safe to replace
/mnt/us/koreader/kowireguard/                    configs, settings, log
/var/run/kowireguard/                            runtime — clears on reboot
```

Your configs and settings live outside the plugin folder, so upgrading or
reinstalling can't destroy them.

## Verifying it works

```sh
ip route get 1.1.1.1              # expect: dev wg0
traceroute -n -m2 1.1.1.1         # first hop should be your tunnel gateway
curl -sS https://ifconfig.me      # your VPN's exit address
```

Use `curl`, not `wget` — BusyBox `wget` on Kindle has no working TLS and fails
with or without the tunnel. KOReader uses LuaSocket and LuaSec in-process and
is unaffected.

If your WireGuard server runs on your own home connection and you're on that
LAN, "what is my IP" reads the same either way, because traffic hairpins out
through the same router. Use `ip route get` or `traceroute` instead.

## Security notes

**Your private key is not protected by file permissions.** `/mnt/us` is a
`fuse.fsp` mount with `allow_other`; modes are synthesized and `chmod 0600`
does nothing. Anyone with USB or filesystem access can read it. Use a
dedicated peer you can revoke.

The plugin never logs or displays private keys, but that protects against
shoulder-surfing a diagnostic screen, not against someone holding the device.

**DNS can be overwritten.** Amazon's `wifid` rewrites `resolv.conf` on Wi-Fi
state changes and the plugin can't prevent it. The result is a leak rather
than an outage, and the status line reports it when detected.

## How it handles the awkward parts

**Endpoint routing.** With `AllowedIPs = 0.0.0.0/0`, packets to the endpoint
would themselves route into the tunnel and the handshake would loop forever —
measured at roughly 20 MB/s of self-encrypted traffic. The plugin pins a host
route to the endpoint via the pre-tunnel gateway and **verifies it with
`ip route get` before bringing the interface up**, aborting if verification
fails. It re-verifies after resume, and if the route can't be restored yet it
takes the interface down to stop the loop rather than retrying while traffic
burns.

**Firewall.** Measured rather than assumed: `OUTPUT` policy is `ACCEPT`, so no
OUTPUT rule is needed. `INPUT` policy is `DROP` with every accept rule pinned
to `wlan0`/`ppp0`/`wwan0`/`lo`/`usb0`, so decrypted packets on `wg0` match
nothing. One rule is inserted and removed precisely, check-gated with
`iptables -C`. **The firewall is never flushed.**

**Process detection.** Reads `/proc/<pid>/cmdline`, not `ps` — the `ps` on this
device prints command names without arguments, so the interface name can never
be matched. PIDs are verified against their cmdline before any signal.

**Plugin lifecycle.** KOReader instantiates plugins per UI, so `init()` runs
again when you open a book. The journal records the owning process ID so
startup reconciliation doesn't tear down a tunnel this same process started.

## Uninstall

**Disconnect first** — from the menu, or **Diagnostics → Force teardown**.
Routes, the firewall rule, DNS and the `wireguard-go` process live in kernel
and process state, not on disk, so deleting the plugin while connected leaves
them in place with nothing left to reverse them.

```sh
rm -rf /mnt/us/koreader/plugins/kowireguard.koplugin   # code and binaries
rm -rf /mnt/us/koreader/kowireguard                    # configs, settings, log
rm -rf /var/run/kowireguard                            # runtime (tmpfs)
```

Nothing is written anywhere else.

To keep your configs and settings for a later reinstall, remove only the first
directory.

If you deleted the plugin while connected, or you are not sure:

```sh
iptables -D INPUT -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
ip route del 0.0.0.0/1 2>/dev/null; ip route del 128.0.0.0/1 2>/dev/null
ip route del <YOUR_ENDPOINT_IP> 2>/dev/null
pkill -f wireguard-go
ip link set wg0 down 2>/dev/null
cp /var/run/kowireguard/resolv.conf.bak /var/run/resolv.conf 2>/dev/null
```

Then confirm the device is back to its original state:

```sh
ip route show                       # default route and LAN only
iptables -S INPUT | wc -l           # same count as before installing
cat /etc/resolv.conf                # your normal resolver
ip link show wg0 2>&1 | head -1     # expect "can't find device"
```

Worth capturing that state before you install, so you have something to
compare against:

```sh
mkdir -p /mnt/us/kowg-baseline
ip route show > /mnt/us/kowg-baseline/routes.before
iptables -S > /mnt/us/kowg-baseline/fw.before
cat /etc/resolv.conf > /mnt/us/kowg-baseline/dns.before
```

## Troubleshooting

| symptom | check |
| --- | --- |
| Plugin missing from menu | `tail -40 /mnt/us/koreader/crash.log` |
| "wireguard-go exited immediately" | `cat /var/run/kowireguard/wireguard-go.log` |
| Connect fails | `tail -30 /mnt/us/koreader/kowireguard/kowireguard.log` |
| Connected but no traffic | `iptables -S INPUT \| grep wg0` |
| Large downloads stall | lower MTU — try 1400, then 1280 |

## Credits

Builds on prior art from
[wtb04/wireguard.koplugin](https://github.com/wtb04/wireguard.koplugin) and
[victoria-riley-barnett/koreader-tailscale](https://github.com/victoria-riley-barnett/koreader-tailscale),
which established that userspace WireGuard and Go networking binaries work on
this class of hardware.

## License

MIT. The `wg` (GPL-2.0) and `wireguard-go` (MIT) binaries are not distributed
here — build them yourself with the recipes above.
