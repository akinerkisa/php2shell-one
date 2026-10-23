# Source provenance and maintenance

Pinned on 21 October 2026. This repo does not auto-download mutable advisories, IOCs or WAF rules and therefore does not claim to have all later updates.

## Primary advisories

- https://www.php.net/archive/2026.php#2026-10-21-5
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065
- https://ubuntu.com/security/notices/USN-8948-1
- https://ubuntu.com/security/notices/USN-8948-2
- https://cert.europa.eu/publications/security-advisories/2026-018
- https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014/

## Defensive context

- https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
- https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection

Only the PHP releases and Ubuntu package thresholds are machine-comparable **first-party policies** in v0.4.0. CERT and threat-research links are context and are **not** automatically ingested, translated into verified signatures or claimed as a successful exploit demonstration.

## Change policy

A PR changing `src/patchproof/data/advisories.json` must link the official vendor advisory, state its release time, cover all affected branches and supply positive/negative tests. Record support/EOL/ESM restrictions. Do not mark an unknown vendor patched from upstream version string alone.
