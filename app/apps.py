from django.apps import AppConfig


class AppConfig_(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        # Connecting a social account has to create the provider profile the
        # rest of the product reads; the receivers live in app.signals.
        from app import signals  # noqa: F401
