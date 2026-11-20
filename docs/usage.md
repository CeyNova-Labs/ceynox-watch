# Usage reference

## Options

| Watching | |
|---|---|
| `-- <command>` | run a command and watch it |
| `--pid <pid>[,<pid>...]` | Linux: watch processes that are already running |
| `--all` | Linux: watch the whole machine |
| `--inspect <package>` | install an npm or PyPI package in a throwaway container and watch that |
| `--image <image>` | with `--inspect`: the container image to install in |
| `--hosts` | macOS: show addresses and host names of connections (asks `sudo`) |
| `--buffer-mb <n>` | Linux: kernel event buffer size, default 16 |

| On the terminal | |
|---|---|
| `-q`, `--quiet` | no live output, only the summary |
| `-v`, `--verbose` | also show every file opened |
| `--no-summary` | no summary at the end |
| `--color auto\|always\|never` | `NO_COLOR` is honored |

| To a file, and back | |
|---|---|
| `--json <file>` | also write every event as JSON, one per line (`-` for standard output with `--pid` or `--all`) |
| `--view <file>` | show a file written with `--json`; add `--follow` to keep up with one being written |
| `--report <file>` | also write the run as a page to share: `.html` or `.md` |

| Comparing | |
|---|---|
| `--write-baseline <file>` | save what this run did |
| `--baseline <file>` | say what this run did that an earlier one did not. Takes a baseline, or a `--json` recording |
| `--fail-on flagged\|new` | exit 3 when the command succeeded but touched the catalog (`flagged`) or did something the baseline lacks (`new`) |

## Exit status

ceynox-watch exits with your command's status. Two values are its own: `125` when ceynox-watch itself failed, and `3` from `--fail-on`. Its output goes to standard error, so pipes and redirections of the command keep working.

## Privileges

Run it as yourself. On Linux it asks `sudo` for the part that needs root; on macOS it needs none. Your command always runs as you, with your environment.

## Labels

Each line names the process and, where it can be told, the package it runs for:

| Label | Meaning |
|---|---|
| `[npm:name]` | an install script or build of that npm package |
| `[pypi:name]` | pip building or installing that package |
| `[crate:name]` | that crate's Cargo build script |
| `[gem:name]` | RubyGems building that gem's native extension |
| `[npx:name]`, `[uvx:name]`, `[bunx:name]`, `[pnpm:name]`, `[yarn:name]`, `[pipx:name]` | a package fetched and run in one go, as named on the command line |

## Baselines

A baseline is a small JSON file of four lists: programs run, hosts contacted, catalog locations touched, areas written to. Process ids, timings, counts and temporary names are left out, so two runs of the same install compare equal and the file can be committed. Hosts are compared by name.

## The GitHub Action

```yaml
- uses: CeyNova-Labs/ceynox-watch@v0.2.3
  id: watch
  with:
    run: npm ci
    baseline: .github/ceynox-watch.json   # optional
    fail-on: new                          # optional: flagged, new, or both
```

| Input | |
|---|---|
| `run` | the command to watch, run with bash |
| `baseline` | path of a baseline in the repository. Until the file exists nothing is compared, and the step says so |
| `fail-on` | `flagged`, `new`, or both separated by a comma |
| `working-directory` | where to run the command |
| `version` | the release to use; defaults to the action's own |

The report goes to the job summary. Three paths are set as outputs and as environment variables for later steps: `report` (`CEYNOX_WATCH_REPORT`), `recording` (`CEYNOX_WATCH_RECORDING`) and `baseline` (`CEYNOX_WATCH_BASELINE`).

To start comparing: take the baseline from the first run (upload it as an artifact), and commit it at the path you gave. Make it on the runner, not on your laptop. Tested on GitHub's Linux runners.

## JSON

`--json` writes one object per event:

```json
{"ts":1795011840123,"pid":4211,"type":"exec","ppid":4207,"uid":1000,"exe":"/usr/bin/node","argv":["node","collect.js"],"cwd":"/home/dev/app/node_modules/sneaky-package"}
{"ts":1795011840182,"pid":4211,"type":"open","path":"/home/dev/.aws/credentials"}
{"ts":1795011840210,"pid":4211,"type":"connect","peer":{"net":"ip","ip":"172.66.147.243","port":443,"proto":"tcp"},"name":"example.com"}
{"ts":1795011840260,"pid":4211,"type":"exit","code":0}
```

| Type | Fields |
|---|---|
| `fork` | `ppid` |
| `exec` | `ppid`, `uid`, `exe`, `argv`, `cwd` |
| `open` | `path`; `"write":true` when opened for writing; `"dir":true` for a directory |
| `connect` | `peer` (`ip`, `unix` or `port`), `name` when known |
| `close` | `peer`, `sent`, `received` in bytes. Linux only |
| `exit` | `code` or `signal` |
| `lost` | `count` of dropped events |

`ts` is milliseconds since the Unix epoch. The format may change before 1.0.
