"""
Encryption at rest for provider access tokens (GitHub / GitLab PATs).

Tokens are the most sensitive data this app stores: a leaked GitHub PAT gives
read access to a customer's private source. They are encrypted with Fernet
(AES-128-CBC + HMAC-SHA256) before hitting the database.

Key resolution order:
  1. TOKEN_ENCRYPTION_KEY env var — a urlsafe-base64 32-byte Fernet key.
  2. Derived from SECRET_KEY via HKDF-SHA256 (so existing deployments keep
     working without a new env var, at the cost of tying token secrecy to
     SECRET_KEY). A warning is logged once when this path is used.

Generate a dedicated key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Ciphertext is stored with an "enc:v1:" prefix. Values without that prefix are
treated as legacy plaintext and returned as-is, so the switch is transparent
for rows written before this module existed. `manage.py encrypt_tokens`
rewrites those rows.
"""
import base64
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)

PREFIX = 'enc:v1:'

_fernet = None
_warned = False


def _derive_key_from_secret(secret: str) -> bytes:
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'devops-audit.token-encryption.v1',
        info=b'provider-access-token',
    ).derive(secret.encode())
    return base64.urlsafe_b64encode(raw)


def get_fernet() -> Fernet:
    global _fernet, _warned
    if _fernet is None:
        key = getattr(settings, 'TOKEN_ENCRYPTION_KEY', '') or ''
        if key:
            _fernet = Fernet(key.encode() if isinstance(key, str) else key)
        else:
            if not _warned:
                logger.warning(
                    'TOKEN_ENCRYPTION_KEY is not set — deriving the token encryption '
                    'key from SECRET_KEY. Set a dedicated key in production so that '
                    'rotating SECRET_KEY does not invalidate stored tokens.'
                )
                _warned = True
            _fernet = Fernet(_derive_key_from_secret(settings.SECRET_KEY))
    return _fernet


def encrypt(value: str) -> str:
    """Encrypt a plaintext token. Empty values and already-encrypted values pass through."""
    if not value:
        return value
    if value.startswith(PREFIX):
        return value
    return PREFIX + get_fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Decrypt a stored token. Legacy plaintext values are returned unchanged."""
    if not value or not value.startswith(PREFIX):
        return value
    try:
        return get_fernet().decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, ValueError):
        logger.error('Failed to decrypt a stored token — wrong TOKEN_ENCRYPTION_KEY?')
        return ''


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(PREFIX)


class EncryptedTextField(models.TextField):
    """
    TextField that transparently encrypts on write and decrypts on read.

    Stored as text rather than a fixed-width char column because Fernet
    ciphertext is ~1.5x the plaintext length plus the prefix.
    """

    def from_db_value(self, value, expression, connection):
        return decrypt(value) if value is not None else value

    def to_python(self, value):
        if value is None:
            return value
        return decrypt(value)

    def get_prep_value(self, value):
        if value is None or value == '':
            return value
        return encrypt(str(value))
