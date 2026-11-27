"""Requerimientos de seguridad S01-S09 y funcionales F1-F4 verificados automáticamente."""
import sqlite3
from pathlib import Path

import pytest

import app as olist_app
import backup
import pki
from conftest import login
from db_crypto import DB, KEY, SQLITE_HEADER, connect


# S01 · Cifrado en reposo ---------------------------------------------------------------------------
def test_database_file_is_not_plaintext_sqlite():
    assert DB.read_bytes()[:16] != SQLITE_HEADER
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(DB).execute("SELECT * FROM deliveries").fetchone()


def test_wrong_key_cannot_open_database(tmp_path, monkeypatch):
    import db_crypto
    bad = tmp_path / "bad.key"
    bad.write_bytes(b"\x00" * 32)
    monkeypatch.setattr(db_crypto, "KEY", bad)
    with pytest.raises(RuntimeError, match="clave incorrecta"):
        db_crypto.connect(DB)


def test_keys_are_separated_from_database_and_private():
    assert KEY.parent != DB.parent
    assert KEY.stat().st_mode & 0o077 == 0


# S03 · Contraseñas con hash -------------------------------------------------------------------------
def test_passwords_stored_as_salted_hashes():
    with connect() as db:
        hashes = [r[0] for r in db.execute("SELECT password_hash FROM users")]
    assert all(h.startswith(("scrypt:", "pbkdf2:")) for h in hashes)
    assert len(set(hashes)) == len(hashes)
    assert not any("Prueba-2026" in h for h in hashes)


@pytest.mark.parametrize("weak", ["corta1A", "todominusculas123", "SinDigitosNiNada"])
def test_weak_passwords_rejected(weak):
    with pytest.raises(ValueError):
        olist_app.create_user("debil", weak, "reader")


# S04 · Autenticación, autorización, CSRF, sesión -----------------------------------------------------
def test_dashboard_requires_session(client):
    assert client.get("/").status_code == 302
    assert client.get("/api/dashboard").status_code == 401


def test_login_without_csrf_rejected(client):
    assert client.post("/login", data={"username": "admin1", "password": "x"}).status_code == 400


def test_wrong_password_generic_message(client):
    r = login(client, "admin1", "Incorrecta-2026x")
    assert r.status_code == 401 and "Credenciales incorrectas".encode() in r.data
    r = login(client, "no_existe", "Incorrecta-2026x")
    assert r.status_code == 401 and "Credenciales incorrectas".encode() in r.data


def test_rbac_audit_admin_only(client):
    login(client, "lector1")
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/audit").status_code == 403
    client.get("/login")
    login(client, "admin1")
    assert client.get("/audit").status_code == 200


def test_session_is_permanent_with_timeout(client):
    login(client, "admin1")
    with client.session_transaction() as s:
        assert s.permanent
    assert olist_app.app.permanent_session_lifetime.total_seconds() == 1800


def test_logout_requires_csrf(client):
    login(client, "admin1")
    assert client.post("/logout").status_code == 400


def test_bruteforce_lockout_by_user(client):
    for _ in range(olist_app.USER_LIMIT):
        login(client, "lector1", "Incorrecta-2026x")
    assert login(client, "lector1").status_code == 429  # bloqueado aun con la clave correcta


def test_bruteforce_lockout_by_ip(client):
    for i in range(olist_app.IP_LIMIT):
        login(client, f"spray{i}", "Incorrecta-2026x", ip="10.9.9.9")
    assert login(client, "admin1", ip="10.9.9.9").status_code == 429
    assert login(client, "admin1", ip="10.0.0.2").status_code == 302


def test_security_headers(client):
    h = client.get("/login").headers
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" in client.get("/login", base_url="https://localhost").headers


def test_session_cookie_flags(client):
    login(client, "admin1")
    cookie = client.get_cookie("session")
    assert cookie.secure and cookie.http_only and cookie.same_site == "Lax"


def test_session_revoked_after_password_change_or_deletion(client):
    login(client, "lector1")
    assert client.get("/api/dashboard").status_code == 200
    olist_app.set_password("lector1", "Lector-Nueva-2026")
    assert client.get("/api/dashboard").status_code == 401
    olist_app.set_password("lector1", "Lector-Prueba-2026")
    olist_app.create_user("temporal", "Temporal-Prueba-2026", "admin")
    login(client, "temporal", "Temporal-Prueba-2026")
    assert client.get("/audit").status_code == 200
    olist_app.delete_user("temporal")
    assert client.get("/audit").status_code == 302


def test_complementary_suppression():
    rows = [{"state": "A", "n": 500}, {"state": "B", "n": 40}, {"state": "C", "n": 5}]
    assert [r["state"] for r in olist_app.with_complement(rows)] == ["A"]  # B también se oculta
    rows.append({"state": "D", "n": 3})
    assert [r["state"] for r in olist_app.with_complement(rows)] == ["A", "B"]


# S05 · Auditoría -----------------------------------------------------------------------------------
def test_audit_records_events_without_passwords(client):
    login(client, "lector1", "Incorrecta-2026x")
    login(client, "lector1")
    client.get("/audit")
    with connect() as db:
        actions = [r[0] for r in db.execute("SELECT action FROM audit_log")]
        dump = " ".join(str(tuple(r)) for r in db.execute("SELECT * FROM audit_log"))
    assert {"login_failed", "login", "access_denied:/audit"} <= set(actions)
    assert "Prueba-2026" not in dump and "Incorrecta" not in dump


def test_audit_retention_purge():
    with connect() as db:
        db.execute("INSERT INTO audit_log(at, username, action) VALUES ('2000-01-01 00:00:00','x','viejo')")
    assert olist_app.purge_audit(180) >= 1
    with connect() as db:
        assert not db.execute("SELECT 1 FROM audit_log WHERE action='viejo'").fetchone()


# F1-F3 y privacidad · agregados, validación, supresión de grupos pequeños --------------------------
def test_dashboard_aggregates_and_filter(client):
    login(client, "admin1")
    data = client.get("/api/dashboard").get_json()
    assert data["summary"]["n"] == 210
    # RR (<30) se oculta y, por supresión complementaria, también SP: si no, RR = total - SP.
    assert data["states"] == []
    sp = client.get("/api/dashboard?state=SP").get_json()["summary"]
    assert sp["n"] == 200 and sp["late_pct"] == 20.0


def test_small_groups_suppressed_server_side(client):
    login(client, "admin1")
    rr = client.get("/api/dashboard?state=RR").get_json()
    assert rr["summary"]["n"] == 10 and rr["summary"]["late_pct"] is None and rr["summary"]["suppressed"]
    holiday = client.get("/api/dashboard").get_json()["holiday"]
    assert all(h["late_pct"] is None for h in holiday)  # partición: se ocultan ambas celdas


@pytest.mark.parametrize("bad", ["S", "SPX", "1A", "'OR", "S%"])
def test_invalid_filter_rejected(client, bad):
    login(client, "admin1")
    assert client.get(f"/api/dashboard?state={bad}").status_code == 400


def test_no_individual_identifiers_in_schema():
    with connect() as db:
        cols = {r[1] for r in db.execute("PRAGMA table_info(deliveries)")}
    assert not cols & {"customer_id", "seller_id", "order_id", "customer_city", "customer_zip_code_prefix"}


# S06 · Respaldo, restauración y detección de alteraciones ------------------------------------------
def test_backup_restore_roundtrip(tmp_path):
    copy = tmp_path / "copia.enc"
    backup.backup(copy)
    assert copy.read_bytes().startswith(backup.MAGIC) and b"deliveries" not in copy.read_bytes()
    assert backup.restore(copy, tmp_path / "restaurada.db") == 210


def test_tampered_backup_rejected(tmp_path):
    copy = tmp_path / "copia.enc"
    backup.backup(copy)
    data = bytearray(copy.read_bytes())
    data[-40] ^= 0x01
    copy.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="alterado"):
        backup.restore(copy, tmp_path / "no.db")
    assert not (tmp_path / "no.db").exists()


def test_backup_rotation(tmp_path):
    import os, time
    for i in range(4):
        backup.backup(tmp_path / f"c{i}.enc")
        os.utime(tmp_path / f"c{i}.enc", (time.time() + i, time.time() + i))
    backup.prune(tmp_path, 2)
    assert sorted(p.name for p in tmp_path.glob("*.enc")) == ["c2.enc", "c3.enc"]


def test_source_zip_sealing(tmp_path, monkeypatch):
    plain = tmp_path / "olist.zip"
    plain.write_bytes(b"PK\x03\x04 contenido de prueba")
    monkeypatch.setattr(backup, "SOURCE_ZIP", plain)
    monkeypatch.setattr(backup, "SEALED_ZIP", tmp_path / "olist.zip.enc")
    backup.seal_source(delete_plain=True)
    assert not plain.exists()
    assert b"contenido" not in (tmp_path / "olist.zip.enc").read_bytes()
    assert backup.open_source() == b"PK\x03\x04 contenido de prueba"


# S02 · Certificados con CA propia -------------------------------------------------------------------
def test_own_ca_issues_valid_server_certificate():
    pki.create_ca()
    pki.issue_server()
    pki.verify()
    ctx = pki.server_context()
    import ssl
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert pki.CA_KEY.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_tls_handshake_verified_against_own_ca():
    """Levanta el servidor real con TLS y comprueba la cadena como lo haría un navegador."""
    import ssl, socket, threading
    from werkzeug.serving import make_server
    if not pki.SRV_CRT.exists():
        pki.create_ca(); pki.issue_server()
    server = make_server("127.0.0.1", 0, olist_app.app, ssl_context=pki.server_context())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ctx = ssl.create_default_context(cafile=str(pki.CA_CRT))  # verificación estricta + hostname
        with socket.create_connection(("127.0.0.1", server.port)) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                assert tls.version() in ("TLSv1.2", "TLSv1.3")
                tls.sendall(b"GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                assert b"200 OK" in tls.recv(4096)
        untrusted = ssl.create_default_context()  # sin la CA propia, la conexión debe fallar
        with socket.create_connection(("127.0.0.1", server.port)) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                untrusted.wrap_socket(raw, server_hostname="localhost")
    finally:
        server.shutdown()
