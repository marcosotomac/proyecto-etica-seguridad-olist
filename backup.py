"""Respaldo y restauración de la base con cifrado autenticado AES-256-GCM.

Comandos:
  py backup.py backup instance/backups/copia.enc
  py backup.py restore instance/backups/copia.enc --destination instance/restaurada.db
"""
import argparse
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from db_crypto import DB, KEY_DIR, SQLITE_HEADER, connect, load_key, private_dir

KEY = KEY_DIR / "backup.key"
MAGIC = b"OLIST-BACKUP-v1\n"
NONCE = 12
TAG = 16


def get_key():
    return load_key(KEY, create=True)


def seal(data, key, magic):
    """Formato: magic || nonce(12) || ciphertext+tag. El magic va como dato asociado."""
    nonce = os.urandom(NONCE)
    return magic + nonce + AESGCM(key).encrypt(nonce, data, magic)


def unseal(content, key, magic):
    if not content.startswith(magic) or len(content) < len(magic) + NONCE + TAG:
        raise ValueError("Formato de archivo cifrado inválido")
    offset = len(magic)
    try:
        return AESGCM(key).decrypt(content[offset:offset + NONCE], content[offset + NONCE:], magic)
    except InvalidTag as exc:
        raise ValueError("El archivo fue alterado o la clave no corresponde (etiqueta GCM inválida)") from exc


def write_private(path, data):
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def backup(destination):
    if not DB.exists():
        raise FileNotFoundError(DB)
    destination = Path(destination)
    with tempfile.TemporaryDirectory() as temp:
        snapshot = Path(temp) / "snapshot.db"
        with DB.open("rb") as stream:
            legacy = stream.read(16) == SQLITE_HEADER
        opener = sqlite3.connect if legacy else connect
        with closing(opener(DB)) as source, closing(opener(snapshot)) as target:
            source.backup(target)
        write_private(destination, seal(snapshot.read_bytes(), get_key(), MAGIC))
    print(f"Respaldo cifrado: {destination}")


def restore(source, destination):
    data = unseal(Path(source).read_bytes(), get_key(), MAGIC)
    destination = Path(destination)
    write_private(destination, data)
    legacy = data.startswith(SQLITE_HEADER)
    opener = sqlite3.connect if legacy else connect
    with closing(opener(destination)) as db:
        result = db.execute("PRAGMA integrity_check").fetchone()[0]
        count = db.execute("SELECT count(*) FROM deliveries").fetchone()[0] if result == "ok" else 0
    if result != "ok":
        destination.unlink(missing_ok=True)
        raise ValueError("La base restaurada no pasó integrity_check")
    print(f"Restauración comprobada: {destination} · integrity_check=ok · {count} entregas")
    if legacy:
        print("Respaldo anterior a SQLCipher: la base restaurada está en texto claro; migra antes de usarla.")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["backup", "restore"])
    parser.add_argument("path", nargs="?", help="Archivo .enc (backup/restore)")
    parser.add_argument("--destination", help="Ruta de restauración; obligatoria para restore")
    args = parser.parse_args()
    if not args.path:
        parser.error(f"{args.command} requiere la ruta del archivo .enc")
    elif args.command == "backup":
        backup(args.path)
    elif not args.destination:
        parser.error("restore requiere --destination")
    else:
        restore(args.path, args.destination)
