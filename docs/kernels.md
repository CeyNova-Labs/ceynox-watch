# Kernels it has been run on

Each row is `dev/smoke.sh` run against a real kernel: a small command watched, and eight things checked in the result. To add a row, run it and [post the output](https://github.com/CeyNova-Labs/ceynox-watch/issues/2):

```sh
dev/smoke.sh "$(command -v ceynox-watch)"
```

## Linux, x86-64

| Distribution | Kernel | Result |
|---|---|---|
| Ubuntu 26.04 | GitHub's runner | works (full test suite, every change) |
| Ubuntu 22.04 | 5.15 | works |
| Debian 12 | 6.1 | works |
| AlmaLinux 9 | 5.14 (RHEL) | works |

Run under emulation except the first. On Debian 12 and AlmaLinux 9 connections showed addresses without names, because the test machine redirects DNS (see below).

## Linux, arm64

| Distribution | Kernel | Result |
|---|---|---|
| Fedora 45 | 7.2 | works |
| Docker Desktop | 7.0 | works (full test suite) |
| Debian 13 | 6.12 | works |
| AlmaLinux 10 | 6.12 (RHEL) | works |
| openSUSE Leap 16 | 6.12 | works |
| Ubuntu 24.04 | 6.8 | works |
| AlmaLinux 9 | 5.14 (RHEL) | works |
| Alpine 3.24 | 6.18 `virt` | **does not start** |
| Debian 12 | 6.1 | **does not start** |
| Ubuntu 22.04 | 5.15 | **does not start** |

The three that do not start cannot attach a program to a kernel function (fentry), which is how file opens and connections are observed. On arm64 that needs a newer kernel than on x86-64, built with function tracing: 6.1 lacks it, 6.8 has it, and Alpine's `virt` kernel is built without it. RHEL's 5.14 has it backported.

## macOS

| Version | Hardware | Result |
|---|---|---|
| macOS 27 | Apple silicon | works |
| macOS 15 | Apple silicon, GitHub's runner | works (test suite, every change) |

Not run by us: Intel Macs.

## Known to matter

- **Releases up to 0.2.3 do not start on kernel 6.8 or older.** The kernel refused one program, whose length check sat where older verifiers could not follow it. 0.2.3 was seen to fail on 6.8, 6.1 and 5.15 and to work on 6.12. Fixed on `main`, which the tables above are for; it will be in the release after 0.2.3.
- **A host that redirects DNS to another port hides names.** Names come from DNS replies on port 53. Where a firewall rule rewrites that port (some virtual machine setups do), connections show addresses only.
- **Not tried:** Arch, Debian 11, kernels before 5.14, and anything not listed.
