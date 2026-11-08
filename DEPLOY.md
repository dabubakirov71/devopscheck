# Deployment Guide

## Prerequisites

- Docker + Docker Compose v2 installed
- A `.env` file at the project root (copy `.env.example` and fill in secrets)

---

## Local development

```bash
# First time or after credential changes — start everything
docker compose -f docker/docker-compose.yml up --build

# Subsequent starts (no rebuild needed)
docker compose -f docker/docker-compose.yml up
```

On every container start the entrypoint automatically runs:
1. `python manage.py migrate --noinput` — applies pending migrations
2. `python manage.py compilemessages` — compiles PO translation files to .mo
3. Django dev server on `http://localhost:8000`

No manual steps required.

---

## Production deployment

### First deploy

1. Copy and fill in secrets:
   ```bash
   cp .env.example .env
   # edit .env — set SECRET_KEY, DB_PASSWORD, domain, OAuth keys, payment keys, etc.
   ```

2. Build and start:
   ```bash
   docker compose -f docker/docker-compose.prod.yml up -d --build
   ```

On startup the entrypoint automatically runs:
1. `python manage.py migrate --noinput`
2. `python manage.py compilemessages`
3. `python manage.py collectstatic --noinput`
4. Gunicorn on port 8000 (Nginx proxies to it)

Both `web` and `admin` bind to `127.0.0.1` only. Nginx is the only thing the
internet can reach.

---

## Reaching the admin

The admin is a separate process. `ADMIN_SITE=1` swaps its URL configuration for
one that serves `/admin/` and nothing else, and the public process does not
route `/admin/` at all — on the customer-facing domain it returns 404, and Nginx
returns 404 for it too before Gunicorn is ever woken.

It shares the code and the database, because it is the same models; what is
separated is the *exposure*. It listens on `127.0.0.1:8001` and is **not
proxied**. Open an SSH tunnel from your own machine:

```bash
ssh -N -L 8001:127.0.0.1:8001 user@your-server
# then browse to http://localhost:8001/admin/
```

Nothing else is needed — the admin process serves its own static files through
WhiteNoise, so it does not depend on the public site's Nginx `/static/` block.

Create the first superuser once:

```bash
docker compose -f docker/docker-compose.prod.yml exec admin \
    python manage.py createsuperuser
```

**Do not** publish port 8001, add an Nginx `proxy_pass` for `/admin/`, or set
`ADMIN_SITE=1` in `.env` — the last one would turn the whole public site into an
admin login page.

If you would rather have it on a URL than a tunnel, put it on its own hostname
with its own certificate and an IP allowlist, never on the customer-facing
domain. `AdminIsNotOnThePublicSiteTest` fails the build if `/admin/` ever comes
back to the public URL configuration.

### Redeploy after a code push

```bash
git pull
docker compose -f docker/docker-compose.prod.yml up -d --build
```

### View logs

```bash
# All services
docker compose -f docker/docker-compose.prod.yml logs -f

# Single service
docker compose -f docker/docker-compose.prod.yml logs -f web
```

---

## Resetting the local database

If the Postgres volume gets into a bad state (e.g. credential mismatch from an old volume):

```bash
docker compose -f docker/docker-compose.yml down
docker volume rm docker_pgdata
docker compose -f docker/docker-compose.yml up --build
```

The entrypoint will run all migrations from scratch on the fresh volume.

---

## Credential mismatch fix

Previously `docker-compose.yml` hardcoded `POSTGRES_PASSWORD: devopsaudit` while
Django read `DB_PASSWORD` from `.env` (`change_in_production`). Recreating the
Postgres volume with any other `DB_PASSWORD` value caused *password authentication
failed* on startup.

**Fix applied:** both Postgres and Django now read the same `${DB_PASSWORD}` from
`.env` via Compose variable substitution. A single source of truth means volume
recreation will never cause a credential mismatch again.