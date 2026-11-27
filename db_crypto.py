"""Conexiones SQLCipher, rutas de instancia y custodia local de claves.

Variables de entorno opcionales:
- ``OLIST_INSTANCE``: carpeta de la base operativa, respaldos y PKI (por defecto ``instance/``).
- ``OLIST_KEY_DIR``: carpeta de las claves simétricas (por defecto, la misma instancia).
  Permite guardar ``db.key``, ``backup.key`` y ``source.key`` en otro volumen, separado de la base.
"""
import os
from pathlib import Path

import sqlcipher3

ROOT = Path(__file__).resolve().parent
INSTANCE = Path(os.environ.get("OLIST_INSTANCE", ROOT / "instance")).resolve()
KEY_DIR = Path(os.environ.get("OLIST_KEY_DIR", INSTANCE)).resolve()
DB = INSTANCE / "olist.db"
KEY = KEY_DIR / "db.key"
SQLITE_HEADER = b"SQLite format 3\x00"


def private_dir(path):
    """Crea una carpeta accesible solo para el usuario actual."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # Windows ignora parte de los bits POSIX.
        pass
    return path


def load_key(path, create=False):
    """Lee una clave de 32 bytes; la crea con permisos 0600 si se solicita."""
    path = Path(path)
    private_dir(path.parent)
    if not path.exists() and create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
        except FileExistsError:
            pass
    if not path.exists():
        raise RuntimeError(f"Falta {path.name}; sin ella no se puede descifrar la información")
    key = path.read_bytes()
    if len(key) != 32:
        raise RuntimeError(f"{path.name} debe tener 32 bytes")
    return key


def database_key(create=False):
    return load_key(KEY, create=create)


def connect(path=DB, create=False):
    path = Path(path)
    if path == DB and path.exists():
        with path.open("rb") as stream:
            if stream.read(16) == SQLITE_HEADER:
                raise RuntimeError("La base todavía está en texto claro: ejecuta py migrate_db.py")
    key = database_key(create=create)
    private_dir(path.parent)
    db = sqlcipher3.connect(path)
    db.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
    db.execute("PRAGMA temp_store = MEMORY")
    try:
        db.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlcipher3.DatabaseError as exc:
        db.close()
        raise RuntimeError("No se pudo abrir la base cifrada: clave incorrecta o archivo dañado") from exc
    db.row_factory = sqlcipher3.Row
    return db
