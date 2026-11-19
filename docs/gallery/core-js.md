## ceynox-watch: `npm:core-js@3.51.0 in node:lts-slim`

**exit 0** · 1.2s · 4 programs run · 1 destination · 694 files read, 4,289 written

Nothing touched the credential, browser, history or startup locations in the catalog.

### Network (1 destination)

| Destination | Sent | Received | By |
|---|---:|---:|---|
| `registry.npmjs.org:443 (104.16.5.34)  tcp, https` | 2.6 kB | 493.3 kB | `node` |

### Programs (4 run)

```
node /usr/local/bin/npm install --no-audit --no-fund --no-update-notifier --loglevel=error core-js@3.51.0
  sh -c 'node -e "try{require('./postinstall')}catch(e){}"'  [npm:core-js]
    node -e 'try{require('./postinstall')}catch(e){}'  [npm:core-js]
```

### Files

694 read, 4,289 written.

- Written: `./node_modules (3,741)`, `/tmp/node-compile-cache (541)`, `~/.npm (5)`, `./package-lock.json (1)`, `./package.json (1)`
- Read: `/usr/local (664)`, `/usr/lib (8)`, `/proc (6)`, `/sys (5)`, `./node_modules (2)`, `/usr/bin (2)`, `/etc/gai.conf (1)`, `/etc/host.conf (1)`, `/etc/hosts (1)`, `/etc/ld.so.cache (1)`, `/etc/nsswitch.conf (1)`, `/etc/resolv.conf (1)`, `+1 more`

<sub>Recorded by [ceynox-watch](https://github.com/CeyNova-Labs/ceynox-watch) 0.2.0. It shows what happened; it does not decide what is malicious.</sub>
