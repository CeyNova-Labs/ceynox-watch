# Demo

Two harmless stand-ins for packages that go after credentials when they are installed. Each opens a few well-known secret locations in your home directory and opens one connection to `example.com`. They keep nothing and send nothing: file contents are read and dropped, and the connection is closed without a byte of yours in it. Read them first; each is about twenty lines.

## pip: [`sneaky-pip`](sneaky-pip/setup.py)

pip runs a package's `setup.py` when it installs it.

```sh
python3 -m venv /tmp/scratch-venv
ceynox-watch -- /tmp/scratch-venv/bin/pip install /path/to/ceynox-watch/demo/sneaky-pip
```

## npm: [`sneaky-package`](sneaky-package/collect.js)

npm runs a dependency's `postinstall` script.

```sh
mkdir /tmp/scratch && cd /tmp/scratch
npm init -y >/dev/null
ceynox-watch -- npm install --install-links /path/to/ceynox-watch/demo/sneaky-package
```

Recent versions of npm do not run a dependency's install scripts until you approve them, and say so in a warning. To see the demo there, approve it and install again:

```sh
npm install-scripts approve sneaky-package
rm -rf node_modules && ceynox-watch -- npm install
```
