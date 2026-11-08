"""
Re-write every stored provider token through the encrypted field.

Reads go through EncryptedTextField.from_db_value, so a legacy plaintext row and
an already-encrypted row both come back as plaintext; writing that value back
encrypts it. Running this twice is safe — the second pass is a no-op in effect.
"""
from django.core.management.base import BaseCommand

from app.models import GithubProfile, GitlabProfile


class Command(BaseCommand):
    help = 'Encrypt provider access tokens that are still stored as plaintext.'

    def handle(self, *args, **options):
        total = 0
        for model in (GithubProfile, GitlabProfile):
            for pk, token in model.objects.values_list('pk', 'access_token'):
                if token:
                    model.objects.filter(pk=pk).update(access_token=token)
                    total += 1
        self.stdout.write(self.style.SUCCESS(f'Re-encrypted {total} token(s).'))
