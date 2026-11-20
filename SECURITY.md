# Security policy

## Reporting a vulnerability

Please email **security@vouchcompute.com**. Include what you found, how to reproduce it, the app version
and your operating system. Please do not open a public issue for a security problem.

We will acknowledge your report within 3 working days and keep you updated until it is resolved. We ask that you give
us reasonable time to fix the problem before you disclose it, and that you do not access other people's data or
disrupt the service while testing.

## Scope

In scope: this desktop app, its installer and auto-updater, the job sandbox, and how the app stores its device key.

The app is designed so that its safety does not depend on its source code being secret. All work is checked and
metered by the server, so a modified client cannot earn more than the work it actually does.

## Supported versions

Only the latest released version receives security fixes. The app updates itself; updates are signed, and the app
refuses an update that is unsigned, signed with an unknown key, or older than the installed version.
