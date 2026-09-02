# bin/

Place the two cross-compiled binaries here:

- `wg` — from wireguard-tools, statically linked
- `wireguard-go`

Build recipes are in the plugin README. Both must be
`ELF 32-bit LSB executable, ARM, EABI5, statically linked`.

No chmod is needed: this filesystem synthesizes permissions. Verify by
executing them, which is the only test that means anything here:

    ./wg --version
    ./wireguard-go --version

Nothing else is written to the plugin directory. Configs, settings and the
plugin log live in /mnt/us/koreader/kowireguard/ so that reinstalling or
upgrading the plugin cannot destroy them. wireguard-go's runtime output goes
to /var/run/kowireguard/ on tmpfs, because /mnt/us disappears during USB
storage mode and would kill the process mid-write.
