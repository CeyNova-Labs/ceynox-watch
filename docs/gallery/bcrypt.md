## ceynox-watch: `npm:bcrypt@6.0.0 in node:lts-slim`

**exit 0** · 896ms · 8 programs run · 1 destination · 703 files read, 622 written

Nothing touched the credential, browser, history or startup locations in the catalog.

### Network (1 destination)

| Destination | Sent | Received | By |
|---|---:|---:|---|
| `registry.npmjs.org:443 (104.16.1.34)  tcp, https` ×3 | 7.8 kB | 670.0 kB | `node` |

### Programs (8 run)

```
node /usr/local/bin/npm install --no-audit --no-fund --no-update-notifier --loglevel=error bcrypt@6.0.0
  sh -c node-gyp-build  [npm:bcrypt]
    node /work/node_modules/.bin/node-gyp-build  [npm:bcrypt]
      sh -c node-gyp-build-test  [npm:bcrypt]
        node /work/node_modules/.bin/node-gyp-build-test  [npm:bcrypt]
```

### Files

703 read, 622 written.

- Written: `/tmp/node-compile-cache (541)`, `./node_modules (66)`, `~/.npm (13)`, `./package-lock.json (1)`, `./package.json (1)`
- Read: `/usr/local (664)`, `./node_modules (8)`, `/proc (8)`, `/usr/lib (8)`, `/sys (5)`, `/usr/bin (3)`, `/etc/gai.conf (1)`, `/etc/host.conf (1)`, `/etc/hosts (1)`, `/etc/ld.so.cache (1)`, `/etc/nsswitch.conf (1)`, `/etc/resolv.conf (1)`, `+1 more`

<sub>Recorded by [ceynox-watch](https://github.com/CeyNova-Labs/ceynox-watch) 0.2.0. It shows what happened; it does not decide what is malicious.</sub>
