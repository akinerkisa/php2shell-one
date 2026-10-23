# Evidence levels and platform coverage

| Environment | CLI capability | What this does NOT prove |
|---|---|---|
| PHP upstream version (8.2–8.5) | Fixed-threshold comparison | Installed build, vendor backport, worker restart |
| Ubuntu 14.04–26.10 | USN pinned minimum package versions | Cryptographic package contents unless separately attested |
| Linux PHP-FPM / Apache mod_php | /proc loaded-file identity, package ownership checks | Unobservable workers, custom binaries, other SAPIs |
| Stopped Docker image | Filesystem package inventory, no start | Running container, provenance, compiled PHP binaries |
| Dockerfiles / Compose | Official PHP tag review | Deployed digests, templating, custom images |
| Access/error/EDR logs | Heuristic investigation | Successful exploit, complete traffic coverage |
| PHP ini / pool config | Read-only heuristic checks | Effective runtime config, mitigating either CVE completely |
| Remote HEAD | Header metadata only | PHP existence, RCE susceptibility, fixed status |

Important: strict runtime check returns `UNKNOWN` if package provenance is not corroborated, worker not observed, or vendor policy missing. Upstream version number checks are only informational. A verdict `FIXED_RUNTIME` is limited to web worker processes observed with matching packaged binaries and evidence; it is not an entire fleet guarantee.

## Roadmap, not implemented in v0.4.0

- Debian, RHEL/Rocky/Alma, Alpine, CloudLinux, Plesk, cPanel native package attestation
- Kubernetes deployed digest + runtime correlation; full SBOM/vulnerability-feed ingestion
- Third-party vendor WAF telemetry connectors and automatic IOC feed signature verification
- Full log format autodetection and process-tree correlations for every EDR schema
- Integration tests on real ModSecurity/Nginx/Cloud Armor deployments

Do not treat planned items as present functionality.
