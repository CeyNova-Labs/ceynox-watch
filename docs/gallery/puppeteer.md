## ceynox-watch: `npm:puppeteer@25.18.1 in node:lts-slim`

**exit 0** · 14.8s · 4 programs run · 2 destinations · 726 files read, 3,157 written

Nothing touched the credential, browser, history or startup locations in the catalog.

### Network (2 destinations)

| Destination | Sent | Received | By |
|---|---:|---:|---|
| `registry.npmjs.org:443 (104.16.1.34)  tcp, https` ×15 | 49.6 kB | 7.4 MB | `node` |
| `storage.googleapis.com:443 (142.251.10.207)  tcp, https` ×2 | 3.7 kB | 331.7 MB | `node [npm:puppeteer]` |

### Programs (4 run)

```
node /usr/local/bin/npm install --no-audit --no-fund --no-update-notifier --loglevel=error puppeteer@25.18.1
  sh -c 'node install.mjs'  [npm:puppeteer]
    node install.mjs  [npm:puppeteer]
```

### Files

726 read, 3,157 written.

- Written: `./node_modules (2,505)`, `/tmp/node-compile-cache (541)`, `~/.npm (107)`, `~/.cache (2)`, `./package-lock.json (1)`, `./package.json (1)`
- Read: `/usr/local (664)`, `./node_modules (30)`, `/usr/lib (8)`, `/proc (6)`, `/sys (5)`, `~/.npm (4)`, `/usr/bin (2)`, `/etc/gai.conf (1)`, `/etc/host.conf (1)`, `/etc/hosts (1)`, `/etc/ld.so.cache (1)`, `/etc/nsswitch.conf (1)`, `+2 more`

<sub>Recorded by [ceynox-watch](https://github.com/CeyNova-Labs/ceynox-watch) 0.2.0. It shows what happened; it does not decide what is malicious.</sub>
