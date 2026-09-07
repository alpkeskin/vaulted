# vaulted-cli

The `vaulted` command line tool, part of
[Vaulted](https://github.com/alpkeskin/vaulted), field-level encryption for
databases.

```sh
cargo install vaulted-cli
```

Installs a binary named `vaulted`.

```sh
vaulted init                                 # keyring at ./vaulted.keys.json, mode 0600
vaulted status
vaulted key list
vaulted key rotate                           # new key version, promoted to primary

echo -n 'alp@example.com' | vaulted encrypt -f users.email
vaulted inspect 'vlt:v1:key-0001:aes256gcm:…'
vaulted rotate -f users.email < old.txt > new.txt
```

Two rules hold throughout: **no command touches a database**, and **no command
prints key material**. `decrypt` prints plaintext, because that is what it was
asked to do; everything else stays quiet about values. Schema migration and bulk
re-encryption need to know about your tables, so they belong in an application
rather than in a tool that would have to guess.

The keyring comes from `--keyring PATH`, then `VAULTED_KEYRING_FILE`, then an
inline `VAULTED_KEYRING` document, then `./vaulted.keys.json`. A keyring file
readable by anyone but its owner is refused.

The library behind this is
[`vaulted-core`](https://crates.io/crates/vaulted-core).

Licensed under the MIT license.
