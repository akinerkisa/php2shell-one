# PHP2Shell incident-response runbook

1. **Inventory assets:** List exposed PHP SAPIs, supported/legacy versions, package owners, running PHP-FPM pools and mod_php hosts. Inventory non-HTTP runtimes separately.
2. **Contain:** If immediate patching is impossible, reduce public exposure and restrict management surfaces. Do not assume multipart blocking or any php.ini setting fully resolves the vulnerabilities.
3. **Patch and restart:** Use official PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or *vendor-confirmed* backport. Restart or replace all running PHP workers. Confirm binary identity and origin.
4. **Preserve records:** Collect HTTP access, WAF events, PHP/server error logs, EDR process trees, file modification telemetry and egress flow metadata securely. Protect session tokens and sensitive content.
5. **Hunt:** `php2shell hunt --access-log ... --error-log ... --events-json ... --since 2026-10-17T00:00:00Z --format json`. Starting 17 October is a conservative reference point reflecting early public threat intelligence; choose your retention/window based on environment.
6. **Correlate:** Spikes of multipart POSTs, 5xx responses and PHP OOMs should be cross-referenced with web worker forks, outbound network connections, modified webroot artifacts and user sessions. An IP hit alone is not attribution.
7. **Validate recovery:** Confirm packages, binary mappings and worker restart; then benign requests and application smoke tests. Continue WAF/EDR monitoring. A non-exploit smoke test is not proof that RCE is impossible.
8. **Communicate and retain evidence:** Record timestamps, asset IDs, evidence sources, versions and residual unknowns. Escalate confirmed compromise with standard IR procedures.

## Optional IOC file

Only ingest IPs and SHA-256 hashes from a verified source you assessed. JSON:

```json
{"ips": ["192.0.2.20"], "sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}
```

`192.0.2.0/24` is reserved for documentation and is not a live threat IOC. Do not publish incident-derived user/session data. All sample records in this repo are synthetic.
