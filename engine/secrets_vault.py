from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False

ROOT = Path(__file__).parent.parent.absolute()
CONFIGS = ROOT / "configs"
CRED_FILE = CONFIGS / "credentials.yaml"
ENV_KEY = "SEC_CHECKER_VAULT_KEY"


class VaultError(RuntimeError):
    pass


def _derive_key(passphrase):
    if not passphrase:
        raise VaultError("empty passphrase")
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _get_passphrase():
    p = os.environ.get(ENV_KEY)
    if not p:
        raise VaultError(ENV_KEY + " not set in environment")
    return p


def is_encrypted(path=None):
    p = Path(path) if path else CRED_FILE
    if not p.exists():
        return False
    try:
        head = p.read_bytes()[:64]
    except Exception:
        return False
    return head.startswith(b"SECVAULT1:")


def encrypt_file(path=None, passphrase=None):
    if not HAS_FERNET:
        raise VaultError("cryptography library not installed")
    p = Path(path) if path else CRED_FILE
    if not p.exists():
        raise VaultError(str(p) + " does not exist")
    if is_encrypted(p):
        return False
    passphrase = passphrase or _get_passphrase()
    key = _derive_key(passphrase)
    f = Fernet(key)
    plaintext = p.read_bytes()
    token = f.encrypt(plaintext)
    backup = p.with_suffix(p.suffix + ".plain.bak")
    if not backup.exists():
        backup.write_bytes(plaintext)
    p.write_bytes(b"SECVAULT1:" + token)
    return True


def decrypt_bytes(data, passphrase=None):
    if not HAS_FERNET:
        raise VaultError("cryptography library not installed")
    if not data.startswith(b"SECVAULT1:"):
        return data
    passphrase = passphrase or _get_passphrase()
    key = _derive_key(passphrase)
    f = Fernet(key)
    try:
        return f.decrypt(data[10:])
    except InvalidToken as e:
        raise VaultError("invalid passphrase or corrupted vault: " + str(e))


def read_file(path=None, passphrase=None):
    p = Path(path) if path else CRED_FILE
    if not p.exists():
        return None
    data = p.read_bytes()
    if not is_encrypted(p):
        return data.decode("utf-8")
    plaintext = decrypt_bytes(data, passphrase)
    return plaintext.decode("utf-8")


def rotate(passphrase_new, passphrase_old=None, path=None):
    plaintext = read_file(path, passphrase_old)
    if plaintext is None:
        raise VaultError("no file to rotate")
    p = Path(path) if path else CRED_FILE
    key = _derive_key(passphrase_new)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    p.write_bytes(b"SECVAULT1:" + token)


__all__ = ["VaultError", "is_encrypted", "encrypt_file", "decrypt_bytes",
           "read_file", "rotate", "HAS_FERNET"]
