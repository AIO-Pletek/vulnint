# VulnInt — Vulnerability Intelligence & Management Platform

Internal vulnerability management for hosting / provider infrastructure.
Tracks Ubuntu, Debian, AlmaLinux, Rocky, CloudLinux, Windows Server, and
cPanel/WHM. Ingests CVE data from upstream feeds, correlates against the
package inventory of every managed host, and dispatches alerts when a
matching vulnerability is found.

> **Status**: production-ready foundation — all backend services, agents,
> and dashboard pages are in place. Build, migrate, seed, and the platform
> is functional.

---

## Architecture

```
   ┌──────────────┐    ┌──────────────┐
   │  CVE feeds   │    │   Linux /    │
   │  NVD · USN · │    │   Windows    │
   │  Debian ·    │    │   agents     │
   │  Alma/Rocky· │    └──────┬───────┘
   │  CISA KEV ·  │           │ POST /api/v1/inventory
   │  cPanel ·    │           │ (X-Agent-Token)
   │  ExploitDB   │           ▼
   └──────┬───────┘    ┌──────────────┐
          │            │              │
          │ Celery     │   FastAPI    │◀──┐
          ▼ tasks      │     api      │   │ JWT
   ┌──────────────┐    └──────┬───────┘   │
   │   Workers    │           │           │
   │  (feeds /    │◀──┐       ▼           │
   │ correlation/ │   │  ┌──────────┐    ┌─────────┐
   │  alerts)     │   └──│ Postgres │    │ Next.js │
   └──────┬───────┘      └──────────┘    │ frontend│
          │              ┌──────────┐    └─────────┘
          ├─────────────▶│OpenSearch│         ▲
          │              └──────────┘         │
          ▼                                   │
   ┌──────────────┐                           │
   │ Notification │                           │
   │  channels    │       ┌───────┐           │
   │ Email · TG · │       │ NGINX │───────────┘
   │ Discord ·    │◀──────┤reverse│
   │ Slack · SIEM │       │ proxy │
   └──────────────┘       └───────┘
```

### Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic
- **Workers**: Celery + Redis broker, beat scheduler
- **Storage**: PostgreSQL 16 + OpenSearch 2 (CVE search index)
- **Frontend**: Next.js 14 App Router, TypeScript, Tailwind, Radix UI
- **Edge**: NGINX reverse proxy with rate limits and TLS-ready config
- **Agents**: Linux (stdlib Python 3, systemd timer) and Windows
  (PowerShell, scheduled task)
- **Auth**: JWT for users, hashed bearer tokens for agents, RBAC

---

## Quick start (single host with Docker)

```bash
git clone <this repo> vulnint
cd vulnint
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET, INITIAL_ADMIN_PASSWORD,
# and any feed-specific keys you have (NVD_API_KEY is recommended).

make build
make up
make migrate
make seed       # creates default roles + the admin user

# Trigger an initial feed run:
make run-feeds

# Open https://localhost  (or http://<host>) and sign in with
# the INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD from .env
```

The `make` targets wrap `docker compose` — see `Makefile` for the full list
(`make logs`, `make shell-api`, `make reindex`, `make test`, etc.).

---

## Adding a server

1. In the dashboard, **Servers → Add server** — copy the agent token
   shown on creation (it isn't retrievable again).
2. On the target host:

   **Linux** (any of: Ubuntu, Debian, AlmaLinux, Rocky, CloudLinux):
   ```bash
   sudo bash agents/linux/install.sh https://vulnint.example.com <TOKEN>
   ```

   **Windows Server**:
   ```powershell
   .\Install-Agent.ps1 -ApiUrl https://vulnint.example.com -AgentToken <TOKEN>
   ```

3. The first inventory typically arrives within ~2 minutes. Correlations
   (which CVEs affect this host's installed packages) appear under
   **Vulnerabilities** as soon as the feed catalog is populated.

---

## Repository layout

```
vulnint/
├── backend/                FastAPI service + Celery workers
│   ├── app/
│   │   ├── api/v1/         REST routes (auth, servers, cves, …)
│   │   ├── core/           Config, DB, OpenSearch, security
│   │   ├── models/         SQLAlchemy ORM models
│   │   ├── repositories/   Data access patterns
│   │   ├── schemas/        Pydantic request/response models
│   │   ├── services/       Notify, audit, search, scoring
│   │   ├── utils/          Versioning (dpkg/rpm), risk scoring
│   │   └── workers/        Celery app + feed connectors + tasks
│   ├── alembic/            Database migrations
│   ├── tests/              Pytest unit tests
│   └── Dockerfile
├── frontend/               Next.js dashboard
│   ├── app/                App router pages (login, dashboard/*)
│   ├── components/         UI primitives + layout
│   └── lib/                API client, auth, helpers
├── agents/
│   ├── linux/              Python 3 agent + systemd installer
│   └── windows/            PowerShell agent + scheduled-task installer
├── docker/
│   ├── nginx/              Reverse-proxy config (rate limits, TLS-ready)
│   └── postgres/           Init SQL (extensions)
├── docs/                   Deployment, agents, API
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Documentation

- [Deployment & operations](docs/DEPLOYMENT.md) — VPS setup, TLS, backups, scaling
- [Agents](docs/AGENTS.md) — installation per OS, troubleshooting
- API — interactive docs at `/docs` once the API is running

---

## Security model

- All routes (other than `/auth/login`, `/auth/refresh`, and `/health`)
  require a valid JWT.
- RBAC via permission codes (see `app/auth/permissions.py`); routes use
  `Depends(require_permissions(...))`.
- Agent tokens are bearer-style but never returned after creation —
  only their SHA-256 hash is stored. Regenerate in the UI if compromised.
- Audit log records every authentication, role change, and correlation
  status update.
- NGINX enforces strict security headers (HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and
  per-route rate limits.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for hardening recommendations.

---

## License

Internal. Do not redistribute.
