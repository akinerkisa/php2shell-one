# Benign patched lab

Optional, locally bound PHP development server. **No vulnerable image or exploit is included.**

```bash
docker compose -f lab/docker-compose.yml up -d
curl -i http://127.0.0.1:8080/
docker compose -f lab/docker-compose.yml down
```

Images must be pulled separately if not present. Docker Hub tags can change; pin and attest the digest in a real deployment. The container has an internal-only network and a loopback host bind. A response `ok` is a smoke test, not a proof of mitigation.
