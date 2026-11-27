"""Verificación de extremo a extremo sobre la instancia REAL (base cifrada, CA propia, HTTPS).

Crea dos cuentas desechables con contraseñas aleatorias que nunca se imprimen, ejecuta
las comprobaciones mediante solicitudes HTTPS reales validadas contra la CA del proyecto y
elimina las cuentas al terminar. Escribe el resultado en informe/evidencias/verificacion-final.txt.

    py scripts/verify_live.py
"""
import http.cookiejar
import re
import secrets
import ssl
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as olist_app  # noqa: E402
import backup  # noqa: E402
import pki  # noqa: E402
from db_crypto import DB, SQLITE_HEADER, connect  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

OUT = ROOT / "informe" / "evidencias" / "verificacion-final.txt"
lines, failures = [], []


def check(code, ok, detail):
    lines.append(f"[{'OK ' if ok else 'FALLA'}] {code} {detail}")
    if not ok:
        failures.append(code)


class Browser:
    """Cliente HTTPS que valida el certificado contra la CA propia y conserva cookies."""

    def __init__(self, base, ctx):
        self.base = base
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            NoRedirect())

    def request(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            with self.opener.open(self.base + path, body) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def login(self, user, password):
        _, _, html = self.request("/login")
        token = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        return self.request("/login", {"csrf": token, "username": user, "password": password})[0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"Olist Lab · verificación en vivo · {stamp}")
    lines.append("Instancia real: base SQLCipher, CA propia, HTTPS en 127.0.0.1. Cuentas desechables.\n")

    # S01 cifrado en reposo y minimización
    header = DB.read_bytes()[:16]
    with connect() as db:
        n = db.execute("SELECT count(*) FROM deliveries").fetchone()[0]
        cols = [r[1] for r in db.execute("PRAGMA table_info(deliveries)")]
    check("S01", header != SQLITE_HEADER, f"Cabecera de la base: {header[:8].hex()}… (no es 'SQLite format 3'); {n} entregas con la clave.")
    check("S01", not {"seller_id", "customer_id"} & set(cols), f"Columnas importadas: {', '.join(cols)}.")
    check("S01", backup.SEALED_ZIP.exists() and not backup.SOURCE_ZIP.exists(),
          "ZIP fuente sellado con AES-256-GCM (data/olist.zip.enc); no queda copia en claro.")

    # S02 certificados y TLS
    pki.verify()
    users = {"verif_admin": ("admin", f"Va-{secrets.token_urlsafe(16)}1"),
             "verif_lector": ("reader", f"Vl-{secrets.token_urlsafe(16)}1")}
    for name, (role, pw) in users.items():
        olist_app.create_user(name, pw, role)
    server = make_server("127.0.0.1", 0, olist_app.app, ssl_context=pki.server_context())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"https://localhost:{server.port}"
    try:
        ctx = ssl.create_default_context(cafile=str(pki.CA_CRT))
        import socket
        with socket.create_connection(("127.0.0.1", server.port)) as raw, \
                ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            subject = dict(x[0] for x in tls.getpeercert()["issuer"])["commonName"]
            check("S02", True, f"TLS verificado contra la CA propia: {tls.version()}, {tls.cipher()[0]}, emisor '{subject}'.")
        try:
            with socket.create_connection(("127.0.0.1", server.port)) as raw:
                ssl.create_default_context().wrap_socket(raw, server_hostname="localhost")
            check("S02", False, "Un cliente sin la CA aceptó el certificado.")
        except ssl.SSLCertVerificationError:
            check("S02", True, "Un cliente sin la CA instalada rechaza el certificado (no hay confianza implícita).")

        anon = Browser(base, ctx)
        status, headers, _ = anon.request("/login")
        check("S02", "max-age" in headers.get("Strict-Transport-Security", ""), "HSTS presente en respuestas HTTPS.")
        check("S04", anon.request("/")[0] == 302 and anon.request("/api/dashboard")[0] == 401,
              "Sin sesión: panel 302 → /login; API 401.")
        check("S04", anon.request("/login", {"username": "x"})[0] == 400, "POST de ingreso sin CSRF: 400.")

        # S03 hashes
        with connect() as db:
            hashes = {r[0]: r[1] for r in db.execute(
                "SELECT username, password_hash FROM users WHERE username LIKE 'verif_%'")}
        check("S03", all(h.startswith("scrypt:") for h in hashes.values()) and len(set(hashes.values())) == 2,
              "Contraseñas guardadas como scrypt con sal única por cuenta.")

        admin, lector = Browser(base, ctx), Browser(base, ctx)
        check("S04", admin.login("verif_admin", users["verif_admin"][1]) == 302, "Ingreso del administrador con CSRF: 302.")
        check("S04", lector.login("verif_lector", users["verif_lector"][1]) == 302, "Ingreso del lector con CSRF: 302.")
        check("S04", (admin.request("/audit")[0], lector.request("/audit")[0]) == (200, 403), "Auditoría: admin 200, lector 403.")

        import json
        general = json.loads(admin.request("/api/dashboard")[2])
        ma = json.loads(admin.request("/api/dashboard?state=MA")[2])
        zz = json.loads(admin.request("/api/dashboard?state=ZZ")[2])
        s = general["summary"]
        check("F02", s["n"] == 96470, f"General: {s['n']} pedidos, {s['late_pct']} % tardíos, {s['avg_delay']} días, "
                                      f"reseñas {s['ontime_review']}/{s['late_review']}.")
        check("F02", ma["summary"]["n"] == 717, f"Filtro MA: {ma['summary']['n']} pedidos, {ma['summary']['late_pct']} % tardíos.")
        check("F02", zz["summary"]["n"] == 0 and admin.request("/api/dashboard?state=1')")[0] == 400,
              "Estado inexistente ZZ: 0 pedidos; formato inválido: 400.")
        rr = json.loads(admin.request("/api/dashboard?state=RR")[2])
        hidden = [f"{h['day_type']} n={h['n']}" for h in rr["holiday"] if h.get("suppressed")]
        check("P01", bool(hidden) and all(h["late_pct"] is None for h in rr["holiday"] if h.get("suppressed")),
              f"Supresión en servidor (filtro RR, k=30): tasa oculta para {'; '.join(hidden)}.")

        fails = [lector.login("verif_lector", "Incorrecta-000A") for _ in range(5)]
        check("S04", fails == [401] * 5 and lector.login("verif_lector", users["verif_lector"][1]) == 429,
              "5 fallos por usuario en 15 min → 429 incluso con la clave correcta.")

        with connect() as db:
            acts = [r[0] for r in db.execute(
                "SELECT action FROM audit_log WHERE username LIKE 'verif_%' ORDER BY id")]
            dump = " ".join(acts)
        check("S05", {"login", "login_failed", "login_blocked", "access_denied:/audit", "audit_view"} <= set(acts)
              and "Incorrecta" not in dump, f"Eventos auditados: {', '.join(sorted(set(acts)))}; sin contraseñas.")
    finally:
        server.shutdown()
        for name in users:
            olist_app.delete_user(name)
        with connect() as db:
            db.execute("DELETE FROM login_attempts WHERE username LIKE 'verif_%'")

    # S06 respaldo
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        backup.backup(tmp / "copia.enc")
        restored = backup.restore(tmp / "copia.enc", tmp / "restaurada.db")
        check("S06", restored == 96470, f"Respaldo AES-256-GCM restaurado: integrity_check=ok, {restored} entregas.")
        data = bytearray((tmp / "copia.enc").read_bytes())
        data[len(data) // 2] ^= 1
        (tmp / "alterada.enc").write_bytes(bytes(data))
        try:
            backup.restore(tmp / "alterada.enc", tmp / "no.db")
            check("S06", False, "Se aceptó una copia alterada.")
        except ValueError:
            check("S06", not (tmp / "no.db").exists(), "Copia con 1 bit alterado: rechazada por la etiqueta GCM; no se escribe salida.")

    lines.append(f"\nResultado: {sum(l.startswith('[OK') for l in lines)} comprobaciones correctas, {len(failures)} fallidas.")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
