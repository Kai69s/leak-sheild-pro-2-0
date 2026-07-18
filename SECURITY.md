# Security Policy

## Authorized Use

LeakShield Pro is intended for defensive assessment of systems you own or are
explicitly authorized to test. Do not use it to probe third-party systems
without permission.

Website assessment uses passive inspection and low-impact public checks. It
does not perform authentication bypass, credential guessing, destructive
requests, or exploit execution. Private, loopback, link-local, and reserved
network destinations are blocked, including after redirects.

## Reporting a Vulnerability

Please report security defects privately to the repository maintainers rather
than opening a public issue that contains sensitive details. Include the
affected version, reproduction conditions, impact, and a suggested mitigation
when possible. Do not include real credentials or data belonging to another
person or organization.

Maintainers should acknowledge a report promptly, validate it, prepare a fix,
and coordinate disclosure after supported deployments have had time to update.

## Supported Version

Security fixes target the latest release on the default branch. Deployments
should keep Python and JavaScript dependencies updated and configure admin
credentials through environment variables rather than source files.
