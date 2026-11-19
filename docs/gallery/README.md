# What installing a package does

Each page here is the record of one package being installed, made with:

```sh
ceynox-watch --inspect <package> --report <file>.md
```

The install ran in a throwaway container, as an unprivileged user with an empty home directory, and ceynox-watch recorded which programs it started, which hosts it talked to and how much went each way. The pages are the tool's own output, unedited.

| Package | What its install does |
|---|---|
| [esbuild](esbuild.md) | runs an install script that checks the binary it shipped |
| [core-js](core-js.md) | runs a postinstall script |
| [bcrypt](bcrypt.md) | looks for a prebuilt native module, through two helper scripts |
| [puppeteer](puppeteer.md) | its install script downloads a browser, a few hundred megabytes from a second host |
| [requests](requests.md) | nothing of its own: it is a wheel, so pip only unpacks it |

**Nothing on these pages is an accusation.** These are well-known packages doing what they are documented to do, and they are here to show what ordinary looks like. That is the point of having a record: the day one of them, or something you depend on, does something it did not do before, there is something to compare with.

A few things to keep in mind when reading them:

- The container starts empty, so there were no credentials for anything to find. See [Limits](../../README.md#limits).
- Installing is not the same as using. A Python wheel runs none of its own code until it is imported; `ceynox-watch --inspect pypi:<name> -- python -c 'import <name>'` watches that too.
- Addresses behind a host name change from day to day. The names are what to compare.

To regenerate the pages against the current releases: `dev/gallery.sh`.
