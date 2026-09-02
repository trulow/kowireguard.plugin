# kowireguard manual test plan

Run over SSH with the KOReader UI visible. Your LAN route survives a
connected tunnel and the SSH accept rule on port 2222 is not
interface-pinned, so **SSH keeps working throughout** — including during a
half-completed teardown. Do not run these over a tunnelled or remote
connection.

Recovery, if a test leaves the device stranded:

```sh
iptables -D OUTPUT -j DROP 2>/dev/null            # only if kill switch was on
ip route del 0.0.0.0/1 2>/dev/null; ip route del 128.0.0.0/1 2>/dev/null
iptables -D INPUT -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
pkill -f wireguard-go; ip link set wg0 down 2>/dev/null
cp /var/run/kowireguard/resolv.conf.bak /var/run/resolv.conf 2>/dev/null
```

Baseline to capture before you start, for comparison afterwards:

```sh
ip route show > /tmp/routes.before
iptables -S > /tmp/fw.before
cat /etc/resolv.conf > /tmp/dns.before
```

---

### 1. Fresh install

Copy the plugin, restart KOReader.

- Plugin loads with no error toast
- **Network → kowireguard (v1.0.3)** — version is in the label, no dialog needed
- Status reads `Status: binaries missing` with the expected path, if `bin/`
  is empty
- Plugin still loads with `bin/` and `configs/` both empty

### 2. Binaries present, no config

Copy `wg` and `wireguard-go` into `bin/`, restart.

- Both `--version` calls succeed from a shell
- **About** shows both version strings, the KOReader revision, and the
  interface, config, binary and log paths
- Status reads `Disconnected`
- **Connect** with no config gives *No tunnel configs*, does not crash

### 3. Import config

- **Import config…** opens PathChooser, filtered to `.conf`
- Importing a valid config copies it into `configs/` and reports any parse
  notes (ignored keys, dropped IPv6)
- The import summary states the private key is readable by anyone with
  device access
- Importing a file that is not a WireGuard config is rejected **at import**,
  not at connect
- **Tunnels** lists it with a radio mark

### 4. First connect

Tap **Connect**.

- Status goes `Connecting…` then `Connected — wg0`
- Handshake age, endpoint and transfer counters appear and update
- Status refreshes about every 5s while the menu is open

Verify from a shell:

```sh
ip link show wg0                    # up, MTU 1420
ip route show                       # 0.0.0.0/1 and 128.0.0.0/1 via wg0
                                    # 192.168.21.0/24 link route still present
ip route get <ENDPOINT_IP>          # via 192.168.21.1 dev wlan0
iptables -S INPUT | grep wg0        # exactly one rule
cat /var/run/kowireguard/journal.lua
```

### 5. HTTPS over the tunnel

```sh
wget -qO- https://ifconfig.me       # endpoint's address, not your ISP's
curl -sI https://www.google.com | head -1
```

In KOReader: open an **OPDS catalogue** over HTTPS and browse it, then
download a book. This is the acceptance criterion — it must work with no
proxy configured and no patched socket layer. Check
**Settings → Network → Proxy** is empty.

### 6. Endpoint route verification

Force the failure the verification exists to catch:

```sh
ip route del <ENDPOINT_IP>          # while disconnected
```

Then edit a config to point at an unroutable endpoint, or block the route,
and connect.

- Connect aborts with *Refusing to bring the tunnel up*
- No `wg0` remains, no split-default routes remain, no firewall rule remains
- `ip route show` matches `/tmp/routes.before`

### 7. Firewall rule added and removed

```sh
iptables -S INPUT | grep wg0        # present while connected
```

Disconnect, then:

```sh
diff <(iptables -S) /tmp/fw.before   # no difference
```

**The instructive test:** connect, then delete the rule by hand while the
tunnel is up:

```sh
iptables -D INPUT -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
ping -c3 1.1.1.1                     # fails: INPUT DROP eats decrypted packets
```

`wg show` still reports a fresh handshake and rising counters. This is the
failure mode the rule exists for. Re-add it and traffic resumes.

### 8. DNS applied and restored

```sh
cat /etc/resolv.conf                # tunnel's server while connected
ls -l /etc/resolv.conf              # still a symlink -> /var/run/resolv.conf
```

Disconnect, then `diff /etc/resolv.conf /tmp/dns.before` — identical.

Leak detection: while connected, overwrite it as `wifid` would:

```sh
echo "nameserver 192.168.21.1" > /var/run/resolv.conf
```

Open the menu — status should add `DNS: overwritten by the system
(leaking)`. Toggle Wi-Fi off and on; kowireguard should re-assert within a few
seconds.

Also test **Settings → DNS → leave the system's alone**: connect and confirm
resolv.conf is untouched.

### 9. Bad key

Edit a config's `PrivateKey` to `AAAA` and connect.

- Fails at `wg setconf` with *wg setconf rejected the configuration*
- Full teardown: no interface, no routes, no firewall rule
- The staged config at `/var/run/kowireguard/wg0.conf` is gone
- Neither the log nor any dialog contains the key

### 10. Unreachable endpoint

Point a config at an endpoint that does not answer.

- Connect succeeds structurally; status shows `Connected — wg0` with
  `Handshake: none yet`
- Counters show tx rising, rx flat
- Disconnect tears down cleanly

Then test an unresolvable hostname: expect *Could not resolve the endpoint
hostname* and no partial state.

### 10b. Hostname endpoint reaches wg as an IP

With a hostname `Endpoint`, connect and check the log:

```sh
grep 'resolved endpoint\|passing resolved address' \
  /mnt/us/koreader/kowireguard/kowireguard.log
wg show wg0 endpoints
```

The endpoint shown must be the same address as the pinned host route:

```sh
ip route show | grep "$(wg show wg0 endpoints | awk '{print $2}' | cut -d: -f1)"
```

If those differ, `wg` resolved independently and the tunnel will not pass
traffic even though every route looks correct. kowireguard substitutes the resolved
IP before `setconf` specifically to prevent this.

### 11. Wi-Fi off

Turn Wi-Fi off, tap **Connect**.

- Prompts to enable Wi-Fi rather than shelling out or failing obscurely
- With Wi-Fi off and no default route, connect aborts with *No default
  route found*

### 12. Sleep / wake

Connect, sleep the device 5+ minutes, wake it.

- Status recovers within a few seconds
- If the interface survived: endpoint route, firewall rule and DNS are each
  re-verified; the log lists anything repaired
- If it did not: full teardown, then reconnect if **reconnect on resume** is
  on
- Repeat with the setting off — expect teardown and no reconnect

### 13. wireguard-go killed externally

```sh
pkill -9 -f wireguard-go
```

Open the menu.

- Status reads `Status: problem — Interface exists but wireguard-go is not
  running` — not a stale `Connected`
- The event is logged
- **Disconnect** cleans up the orphaned interface, routes and rule

### 14. Teardown after a simulated crash

Connect, then kill KOReader without letting it exit cleanly:

```sh
pkill -9 -f koreader
```

Confirm routes and rule are still in place (nothing ran to remove them).
Restart KOReader.

- Startup detects the leftover state and tears it down
- `ip route show` matches `/tmp/routes.before`; `iptables -S` matches
  `/tmp/fw.before`
- The journal file is gone

Also test **teardown idempotency**: run **Diagnostics → Force teardown**
three times in a row from a disconnected state. No errors, no change.

### 15. USB connect while running

Connect the tunnel, then plug the Kindle into a computer and enter USB
storage mode.

- kowireguard tears the tunnel down and says why
- No orphaned `wireguard-go` after unplugging
- Routes and firewall are clean

### 16. Kill switch

Enable it (confirm the warning appears), connect.

```sh
iptables -S OUTPUT                  # carve-outs, then a terminal DROP
ssh root@KINDLE                     # still works from the LAN
```

Disconnect and confirm `iptables -S OUTPUT` matches `/tmp/fw.before` — the
`DROP` must be gone. Then repeat the crash test from §14 with the kill
switch on: after restart, outbound traffic must work again.

### 17. Gestures and profiles

Bind `kowireguard toggle` to a gesture in **Gesture Manager**.

- Appears in the action list
- Toggles the tunnel with a status toast
- `kowireguard status` shows the same text as the menu status line

### 18. Diagnostics

Each entry opens and shows plausible content: `wg show` (private key
redacted), routing table, firewall rule state, resolv.conf, plugin log,
`wireguard-go` output, active config (`PrivateKey = <redacted>`).

Grep the logs for leaks:

```sh
grep -i 'privatekey' /mnt/us/koreader/kowireguard/kowireguard.log
```

Should return nothing but redacted lines. Confirm the log stops growing past
~96 KiB and keeps its tail.

### 19. Data directory and migration

```sh
ls -R /mnt/us/koreader/kowireguard/
ls /mnt/us/koreader/plugins/kowireguard.koplugin/
```

The data directory holds `configs/`, the settings file and the plugin log.
The plugin directory holds only `.lua` files and `bin/` — nothing the plugin
wrote. Upgrading from an older layout should have copied settings and configs
across; check `kowireguard.log` for a `migrated to data dir:` line.

Then confirm a reinstall preserves data: delete the plugin directory, unzip a
fresh copy, restart, and verify your tunnel is still listed under **Tunnels**
with its settings intact.

### 20. Uninstall

Force teardown, exit KOReader, then remove the plugin directory and the data
directory. Restart: no menu entry, no errors, network unchanged from
baseline.

### 21. Opening a book does not disconnect

Connect, then from the file manager open any document — a CBZ or EPUB, ideally
one downloaded over the tunnel.

- The tunnel stays up; the status line still reads `Connected`
- `bin/wg show wg0` shows an unbroken handshake and rising counters
- The log shows `startup: tunnel belongs to this process, leaving it up`,
  **not** `previous session left state behind`

Then close the document and return to the file manager, and confirm the same.
This exercises the per-UI plugin instantiation that KOReader performs on every
document open.

### 22. Endpoint route survives suspend, or is repaired promptly

Connect, note the transfer counters, sleep the device 10+ minutes, wake it.

```sh
bin/wg show wg0 | grep transfer
ip route get YOUR_ENDPOINT_IP        # must be via your LAN gateway, NOT dev wg0
tail -20 /mnt/us/koreader/kowireguard/kowireguard.log
```

- If the route survived, nothing is logged and the counters look sane.
- If it was lost, expect `resume: repaired endpoint route` within a few
  seconds of wake.
- If Wi-Fi has not returned, expect `endpoint route is missing and cannot be
  repaired yet` followed by retries, then either a repair or a teardown.

**The tell for a loop is the counter ratio.** Sent vastly exceeding received —
gigabytes against kilobytes — means the endpoint fell into the tunnel and
wireguard-go was re-encrypting its own output. `ip route get` on the endpoint
returning `dev wg0` is the direct confirmation.


### 23. Endpoint route loop is detected, displayed and stopped

Have this ready before you start — you lose internet during the test, though
SSH over your LAN keeps working:

```sh
ip route add YOUR_ENDPOINT_IP via YOUR_GATEWAY dev wlan0
```

Connect, then break the endpoint route by hand:

```sh
bin/wg show wg0 | grep transfer      # note the values
ip route del YOUR_ENDPOINT_IP
ip route get YOUR_ENDPOINT_IP        # now shows "dev wg0" — the loop is live
```

- Counters: **sent** climbs at roughly 20 MB/s while **received** stays flat.
  That ratio is the signature of a loop.
- Open the kowireguard menu: the status line must read
  `Status: PROBLEM — endpoint route lost`, not `Connected`.

Restore it and confirm recovery:

```sh
ip route add YOUR_ENDPOINT_IP via YOUR_GATEWAY dev wlan0
bin/wg show wg0 | grep transfer      # sent stops climbing
```

Do not leave the loop running longer than needed to read the screen.

To exercise the automatic path instead, delete the route and immediately sleep
the device. On wake the log should show either `resume: repaired endpoint
route`, or `interface brought down to stop the tunnel looping` followed by
`route restored, interface back up` once Wi-Fi returns.
