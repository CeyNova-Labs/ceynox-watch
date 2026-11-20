# Limits

What ceynox-watch does not do or cannot see.

## What it is not

- **Not a sandbox.** By the time you read that a key was opened, it was opened. Run untrusted code somewhere disposable if the outcome matters.
- **Not a verdict.** It lists what happened and flags catalog locations. It does not decide what is malicious.
- **Not proof against root.** A process running as root can interfere with any tracing tool, this one included.

## What it does not see

- **Contents.** A file that was opened counts as read even if nothing was read. You see where a connection went and, on Linux, how much it carried, never what was in it.
- **Work done by another service.** If a watched process asks a running daemon to act for it (Docker, `systemd-run`, an SSH agent), you see the request, not what the daemon then does.
- **Files already open.** A descriptor inherited from outside the watched tree is used without an open being seen.
- **Amounts over UDP.** Transfer sizes are TCP only, counted when a connection closes. QUIC, and so HTTP/3, is not measured, and a connection still open when watching stops is not in the totals.
- **Some host names.** On Linux names come from plain DNS over UDP. DNS over HTTPS, or an address hard-coded in a program, shows as an address. On macOS with `--hosts` names also come from the TLS handshake. When two names share an address, the latest wins. A host that redirects DNS to another port with a firewall rule shows addresses only.
- **Everything, under extreme load.** Events can be dropped. The output says so and says how many. `--buffer-mb` raises the limit.

## --inspect

- **The container is empty.** No credentials are in it and none are planted, so a package that only acts when it finds something to take shows less than it would on a developer's machine.
- **A container is not a virtual machine.** It shares your kernel and your network. Do not use it for something built to break out of containers.
- **Installing is not using.** A Python wheel runs none of its own code until imported. Add a command after `--` to watch that too.

## Baselines

- **A baseline is as steady as the install.** An install that picks mirrors at random, or names programs after temporary files, shows differences that mean nothing.
- **Baselines do not travel.** One made on your laptop does not fit a CI runner.

## macOS

macOS sees less than Linux; the [platform table](../README.md#linux-and-macos) lists what. The one that surprises people: a program that sandboxes itself (browsers, some AI coding agents) cannot do so under ceynox-watch, because macOS does not allow a sandbox inside a sandbox.
