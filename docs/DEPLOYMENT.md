# VulnInt deployment guide

## Hardware sizing

| Profile               | CPU | RAM   | Disk   | Hosts monitored |
|-----------------------|-----|-------|--------|-----------------|
| Lab / single tenant   | 2   | 4 GB  | 40 GB  | up to ~50       |
| Small operations team | 4   | 8 GB  | 100 GB | up to ~500      |
| Production hosting    | 8   | 16 GB | 250 GB | 1k–5k           |

OpenSearch and PostgreSQL are the dominant memory consumers. Bump JVM
heap (`OPENSEARCH_JAVA_OPTS`) and Postgres `shared_buffers` /
`work_mem` if you exceed these thresholds.

---

## First-time install on a fresh VPS (Ubuntu 22.04+ / Debian 12)

```bash
# 1. Base packages
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg ufw fail2ban

# 2. Docker Engine
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# 3. Firewall — allow only what you need
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp           # SSH (restrict to mgmt IPs in production)
sudo ufw allow 80/tcp           # HTTP (for ACME challenge / redirect)
sudo ufw allow 443/tcp          # HTTPS
sudo ufw enable

# 4. Clone and configure
git clone <this repo> /opt/vulnint
cd /opt/vulnint
cp .env.example .env
$EDITOR .env

# 5. Build, start, migrate, seed
make build
make up
make migrate
make seed

# 6. Run an initial feed pull (otherwise the catalog is empty)
make run-feeds
```

Verify everything is healthy:

```bash
make ps              # all services in 'healthy' state
make logs SERVICE=api
curl -fsS http://localhost/healthz   # 200 ok
```

---

## TLS termination

Two supported patterns:

### A) NGINX terminates TLS (default for single-host)

1. Obtain a cert (Let's Encrypt example):

   ```bash
   sudo apt-get install -y certbot
   sudo certbot certonly --standalone -d vulnint.example.com
   sudo mkdir -p ./docker/nginx/certs
   sudo cp /etc/letsencrypt/live/vulnint.example.com/fullchain.pem ./docker/nginx/certs/
   sudo cp /etc/letsencrypt/live/vulnint.example.com/privkey.pem   ./docker/nginx/certs/
   ```

2. Mount the certs and uncomment the HTTPS block in
   `docker/nginx/conf.d/default.conf`. Add this to `docker-compose.yml`
   under the `nginx` service:

   ```yaml
   volumes:
     - ./docker/nginx/certs:/etc/nginx/certs:ro
   ports:
     - "443:443"
   ```

3. Renewal — add a cron job:

   ```cron
   0 3 * * * certbot renew --post-hook "cp /etc/letsencrypt/live/vulnint.example.com/*.pem /opt/vulnint/docker/nginx/certs/ && docker compose -f /opt/vulnint/docker-compose.yml exec nginx nginx -s reload"
   ```

### B) Front with a managed TLS LB (Caddy, Traefik, AWS ALB, …)

Leave NGINX listening on `:80` only. Point your LB at the host's port 80
and let the LB handle certificates and HTTP/2. No further config needed
in this repo.

---

## Backups

### Postgres

Daily logical dump (cron):

```bash
0 2 * * * docker compose -f /opt/vulnint/docker-compose.yml \
    exec -T postgres pg_dump -U vulnint vulnint \
    | gzip > /var/backups/vulnint/$(date +\%F).sql.gz
```

Retain 30 days:

```bash
find /var/backups/vulnint -name '*.sql.gz' -mtime +30 -delete
```

### OpenSearch

The CVE index is **rebuildable** — `make reindex` walks the catalog from
Postgres and repopulates OpenSearch. You don't need a separate backup
strategy for it. Just snapshot Postgres.

### Configuration

`.env` and any TLS certs you've installed are the only persistent
configuration outside Postgres. Keep them in your secrets store.

---

## Scaling

The compose stack is single-host but each service scales horizontally.

- **API** is stateless; replicate behind NGINX with
  `docker compose up -d --scale api=3` (or move to k8s).
- **Workers** scale per-queue. Run dedicated worker replicas for the
  `feeds`, `correlation`, and `alerts` queues so heavy NVD pulls don't
  block correlation:

  ```bash
  docker compose up -d --scale worker=3
  ```

  In each worker, set `CELERY_QUEUES=feeds` (or `correlation`,
  `alerts`) to specialize.

- **Postgres**: standard read-replica patterns apply. The hot tables
  are `correlations` and `affected_products`.

- **OpenSearch**: increase the heap and run as a multi-node cluster
  for catalogs over ~5M CVE/affected-product rows.

---

## Hardening checklist

- [ ] Rotate `JWT_SECRET` to a 64+ byte random value.
- [ ] Set `ENV=production` in `.env`. The API enables HSTS only in
      production.
- [ ] Restrict SSH to a management VPN / bastion.
- [ ] Disable Postgres / Redis / OpenSearch port exposure on the host
      (compose only binds them to the internal Docker network — verify
      with `docker compose port postgres 5432`; should fail).
- [ ] Set up log shipping for `nginx` access logs and the API's
      structured JSON logs.
- [ ] Enable 2FA on all upstream feed accounts (NVD API key, GitHub for
      pull, etc.).
- [ ] Configure at least one alert channel (`SMTP_*`, `TELEGRAM_*`,
      Slack/Discord webhook, or a SIEM webhook) so production alerts
      actually leave the box.
- [ ] Periodically run `make test` and check for new CVEs against the
      VulnInt host itself (yes, eat your own dog food).

---

## Common operations

```bash
make logs SERVICE=worker         # tail worker logs
make shell-api                   # exec into the API container
make psql                        # interactive Postgres prompt
make run-feeds                   # trigger all feeds now
make reindex                     # rebuild the OpenSearch index
make worker-status               # celery inspect active
```

---

## Upgrading

Stop, pull, rebuild, migrate:

```bash
cd /opt/vulnint
git pull
make build
make down
make up
make migrate
```

Migrations are forward-only. Always snapshot Postgres before a major
upgrade.

---

## Troubleshooting

| Symptom                                      | Likely cause                                            |
|----------------------------------------------|---------------------------------------------------------|
| `/api/v1/cves` returns empty                 | No feeds have run yet — `make run-feeds`                |
| Agent gets `401 unauthorized`                 | Token mismatch — regenerate in dashboard, redeploy      |
| Correlations not appearing for a Linux box   | OS family detection failed — check the agent's report   |
| OpenSearch unhealthy                          | Heap too small — bump `OPENSEARCH_JAVA_OPTS` to `-Xmx2g` |
| Email alerts not sending                      | `SMTP_TLS=true` mismatched with port 465 (use 587)      |
| `make migrate` stuck                          | Connection blocked by old Alembic lock — bounce postgres|
