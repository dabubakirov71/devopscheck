#!/bin/sh
set -e

# Only the web service runs migrations, translations and static collection.
# Celery starts with RUN_MIGRATIONS unset (or "0") to avoid parallel schema
# writes that cause duplicate key errors on a fresh database.
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "==> Running migrations..."
    # Fatal: broken schema means the app cannot start safely.
    python manage.py migrate --noinput

    echo "==> Compiling translations..."
    # Deduplicate .po files first (msguniq is bundled with the gettext package
    # already installed in the image). Non-fatal: a bad .po file falls back to
    # the existing .mo or the raw msgid — it should never take down the app.
    if command -v msguniq >/dev/null 2>&1; then
        for po_file in locale/*/LC_MESSAGES/django.po; do
            msguniq --use-first "$po_file" -o "$po_file" 2>/dev/null || true
        done
    fi
    python manage.py compilemessages --ignore=.eval-cache --ignore=tests || echo "WARNING: compilemessages failed — continuing with existing .mo files"

    # collectstatic is baked into the image at build time; skip in dev (runserver
    # serves files directly) but run in prod to populate the static_files volume.
    if [ "${DEBUG:-False}" = "False" ] || [ "${DEBUG:-False}" = "false" ] || [ "${DEBUG:-False}" = "0" ]; then
        echo "==> Collecting static files..."
        python manage.py collectstatic --noinput
    fi
fi

exec "$@"