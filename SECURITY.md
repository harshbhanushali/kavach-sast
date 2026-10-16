# Security

## Supported versions

Security fixes go to the latest release.

| Version | Supported |
| :-- | :-- |
| 0.1.x | yes |
| older | no |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private reporting: open the repository's **Security** tab and choose
**Report a vulnerability** (https://github.com/harshbhanushali/kavach-sast/security/advisories/new). Only the maintainer can read
it. Include what you found, how to reproduce it, the version, and what an attacker
gains. Do not include real customer apps or credentials.

What to expect: an acknowledgement within 7 days, a fix or a clear answer as soon as it
can be reproduced, and credit in the release notes if you want it. This is a one-person
project, so please be patient and give a reasonable time to fix before disclosing.

## What to expect from a deployment

See [DEPLOYMENT.md](DEPLOYMENT.md#security-model) for what the server does to protect
itself and what it leaves to you (TLS, disk encryption, backups, network exposure).

## Design notes that matter to a reviewer

- **Uploaded artifacts are untrusted input.** They are decoded and decompiled in a
  worker thread with time limits, and deleted when the scan ends. A scan is bounded
  in concurrency, time and upload size.
- **Nothing leaves the machine.** The console loads no third-party resources and the
  server makes no outbound requests.
- **The default password is public, and says so.** The first account starts on the
  published `admin` / `kavach` unless the operator sets `KAVACH_SAST_ADMIN_PASSWORD`.
  The console warns until it is changed, the server logs a warning at every start, and the
  port is published on `127.0.0.1` only by default. The static development token, a
  credential that would outlive a password change, exists only outside production.
- **Reports can contain secrets found in an app.** Findings quote the values they
  matched (that is how they are verified), so the database, backups and exported
  reports carry the same sensitivity as the app itself.
