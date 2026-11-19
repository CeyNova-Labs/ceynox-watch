# Security policy

ceynox-watch runs with elevated privileges in front of code you do not trust. Bugs in it matter, and reports are welcome.

## Reporting a vulnerability

Please report privately, in either of two ways:

- through GitHub: [**Security → Report a vulnerability**](https://github.com/CeyNova-Labs/ceynox-watch/security/advisories/new) on this repository;
- by email to [security@ceynovahq.com](mailto:security@ceynovahq.com).

Do not open a public issue for something exploitable.

Include what you did, what happened, and the kernel and distribution you were on. A proof of concept helps but is not required. You will get an acknowledgement within three working days, and credit in the release notes unless you prefer otherwise. A fix for a confirmed vulnerability is released as soon as it is ready, and the details are published with it or shortly after, at a time agreed with you. If 90 days pass without a fix, you are free to publish.

## What counts

- Anything that lets a watched process gain privileges through ceynox-watch, or reach its privileged helper.
- Anything that lets a watched process hide activity the documentation says is reported, other than the cases listed under [Limits](README.md#limits).
- Anything that lets a watched process forge or corrupt the output, for example through file names or arguments.
- Crashes, hangs or unbounded memory use caused by input a watched process or the network controls (file names, arguments, DNS replies).
- A way to make the kernel programs do anything other than observe.

## What does not

- Evasion by a process that already runs as root. ceynox-watch does not claim to withstand that.
- The limits the README lists, such as work handed to an already-running daemon.

## Supported versions

Until 1.0, only the latest release receives fixes.
