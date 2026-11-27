"""Olist Lab: backend Flask del panel académico. Ejecutar con HTTPS y la CA propia (pki.py)."""
import argparse
import getpass
import hashlib
import secrets
import sys
from datetime import timedelta
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from db_crypto import INSTANCE, ROOT, connect as encrypted_connect, private_dir

ROLES = ("admin", "analyst", "reader")
MIN_GROUP = 30            # supresión de celdas pequeñas (riesgo de inferencia)
USER_LIMIT, IP_LIMIT = 5, 20  # intentos fallidos admitidos en 15 minutos
AUDIT_RETENTION_DAYS = 180

private_dir(INSTANCE)
KEY_FILE = INSTANCE / "secret.key"
if not KEY_FILE.exists():
    KEY_FILE.write_text(secrets.token_hex(32), encoding="ascii")
    KEY_FILE.chmod(0o600)

app = Flask(__name__)
app.secret_key = KEY_FILE.read_text(encoding="ascii").strip()
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), SESSION_REFRESH_EACH_REQUEST=True,
                  MAX_CONTENT_LENGTH=1024 * 1024)


def connect():
    db = encrypted_connect()
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL
        CHECK(role IN ('admin','analyst','reader')))""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        username TEXT, action TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        username TEXT NOT NULL)""")
    if "ip" not in {row[1] for row in db.execute("PRAGMA table_info(login_attempts)")}:
        db.execute("ALTER TABLE login_attempts ADD COLUMN ip TEXT")
    return db


def audit(action, username=None):
    with connect() as db:
        db.execute("INSERT INTO audit_log(username, action) VALUES (?,?)", (username, action[:120]))


def check_csrf():
    expected = session.get("csrf")
    if not expected or not secrets.compare_digest(request.form.get("csrf", ""), expected):
        audit("csrf_rejected:" + request.path, session.get("username"))
        abort(400)


def credential_version(password_hash):
    """Huella del hash vigente: cambia al rotar la contraseña y revoca las sesiones previas."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def session_is_valid():
    """Revalida la sesión contra la base en cada solicitud (usuario borrado, rol o clave cambiados)."""
    if not session.get("username"):
        return False
    with connect() as db:
        user = db.execute("SELECT password_hash, role FROM users WHERE username=?", (session["username"],)).fetchone()
    if not user or user["role"] != session.get("role") or credential_version(user["password_hash"]) != session.get("cv"):
        audit("session_revoked", session.get("username"))
        session.clear()
        return False
    return True


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session_is_valid():
            if request.path.startswith("/api/"):
                return jsonify({"error": "sesión requerida"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                audit("access_denied:" + request.path, session.get("username"))
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
                                                   "object-src 'none'")
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def client_ip():
    return (request.remote_addr or "?")[:45]


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        with connect() as db:
            db.execute("DELETE FROM login_attempts WHERE at < datetime('now', '-1 day')")
            by_user = db.execute("""SELECT count(*) FROM login_attempts WHERE username=?
                AND at >= datetime('now', '-15 minutes')""", (username,)).fetchone()[0]
            by_ip = db.execute("""SELECT count(*) FROM login_attempts WHERE ip=?
                AND at >= datetime('now', '-15 minutes')""", (client_ip(),)).fetchone()[0]
        if by_user >= USER_LIMIT or by_ip >= IP_LIMIT:
            audit("login_blocked", username)
            abort(429, "Demasiados intentos. Espera 15 minutos.")
        with connect() as db:
            user = db.execute("SELECT password_hash, role FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            with connect() as db:
                db.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            session.clear()  # nuevo identificador de sesión y nuevo token CSRF
            session.permanent = True
            session["username"], session["role"] = username, user["role"]
            session["cv"] = credential_version(user["password_hash"])
            audit("login", username)
            return redirect(url_for("dashboard"))
        with connect() as db:
            db.execute("INSERT INTO login_attempts(username, ip) VALUES (?,?)", (username, client_ip()))
        audit("login_failed", username)
        error = "Credenciales incorrectas"  # mismo mensaje para usuario inexistente o clave errónea
    session["csrf"] = secrets.token_urlsafe(32)
    return render_template("login.html", error=error, csrf=session["csrf"]), (401 if error else 200)


@app.post("/logout")
@login_required
def logout():
    check_csrf()
    audit("logout", session["username"])
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def dashboard():
    built = ROOT / "frontend" / "dist"
    if built.is_dir():
        return send_from_directory(built, "index.html")
    abort(503, "Compila el frontend: cd frontend; npm ci; npm run build")


@app.get("/assets/<path:filename>")
@login_required
def frontend_assets(filename):
    return send_from_directory(ROOT / "frontend" / "dist" / "assets", filename)


def with_complement(rows):
    """Filtra grupos < MIN_GROUP con supresión complementaria.

    Si se ocultara exactamente un grupo, su valor podría deducirse restando los visibles del total;
    en ese caso también se oculta el grupo visible más pequeño (Hundepool et al., control de
    divulgación estadística)."""
    rows = [dict(r) for r in rows]
    hidden = [r for r in rows if r["n"] < MIN_GROUP]
    visible = [r for r in rows if r["n"] >= MIN_GROUP]
    if len(hidden) == 1 and visible:
        visible.remove(min(visible, key=lambda r: r["n"]))
    return visible


def suppress(row):
    """Oculta porcentajes y medias de grupos menores a MIN_GROUP; conserva solo el tamaño."""
    data = dict(row)
    if data.get("n", 0) < MIN_GROUP:
        data.update({k: None for k in data if k not in ("n", "state", "month", "day_type")})
        data["suppressed"] = True
    return data


def suppress_partition(rows):
    """Feriado/día común forman una partición de 2018: si una celda se oculta, se ocultan ambas."""
    rows = [suppress(r) for r in rows]
    if any(r.get("suppressed") for r in rows):
        for r in rows:
            r.update(late_pct=None, suppressed=True)
    return rows


@app.get("/api/dashboard")
@login_required
def dashboard_api():
    state = request.args.get("state", "").upper().strip()
    if state and (len(state) != 2 or not state.isalpha()):
        audit("invalid_filter", session["username"])
        abort(400)
    params = {"state": state or None}
    with connect() as db:
        summary = db.execute("""SELECT count(*) n, sum(is_late) late,
            round(100.0 * avg(is_late), 1) late_pct,
            round(avg(CASE WHEN is_late=1 THEN delay_days END), 1) avg_delay,
            round(avg(CASE WHEN is_late=0 THEN review_score END), 2) ontime_review,
            round(avg(CASE WHEN is_late=1 THEN review_score END), 2) late_review
            FROM deliveries WHERE (:state IS NULL OR customer_state = :state)""", params).fetchone()
        states = db.execute("""SELECT customer_state state, count(*) n,
            round(100.0 * avg(is_late),1) late_pct FROM deliveries
            GROUP BY customer_state ORDER BY late_pct DESC""").fetchall()
        months = db.execute("""SELECT substr(purchase_date,1,7) month, count(*) n,
            round(100.0 * avg(is_late),1) late_pct FROM deliveries WHERE (:state IS NULL OR customer_state = :state)
            GROUP BY substr(purchase_date,1,7) ORDER BY month""", params).fetchall()
        holiday = db.execute("""SELECT CASE WHEN h.date IS NULL THEN 'Día común' ELSE 'Feriado nacional' END day_type,
            count(*) n, round(100.0 * avg(d.is_late),1) late_pct
            FROM deliveries d LEFT JOIN holidays h ON d.purchase_date=h.date
            WHERE d.purchase_date BETWEEN '2018-01-01' AND '2018-12-31'
            AND (:state IS NULL OR d.customer_state = :state)
            GROUP BY day_type ORDER BY day_type""", params).fetchall()
    audit("dashboard_api" + (":" + state if state else ""), session["username"])
    return jsonify({"state": state, "summary": suppress(summary), "min_group": MIN_GROUP,
                    "states": with_complement(states),
                    "months": with_complement(months),
                    "holiday": suppress_partition(holiday),
                    "user": {"username": session["username"], "role": session["role"]},
                    "csrf": session.setdefault("csrf", secrets.token_urlsafe(32))})


@app.get("/audit")
@role_required("admin")
def audit_view():
    with connect() as db:
        entries = db.execute("SELECT at, username, action FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
        total = db.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    audit("audit_view", session["username"])
    return render_template("audit.html", entries=entries, total=total, retention=AUDIT_RETENTION_DAYS)


@app.errorhandler(429)
def too_many(error):
    return render_template("login.html", error="Demasiados intentos. Espera 15 minutos.",
                           csrf=session.setdefault("csrf", secrets.token_urlsafe(32))), 429


# --- Administración por consola (no expuesta en la web) -------------------------------------------

def validate_password(password):
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")
    if password.lower() == password or not any(c.isdigit() for c in password):
        raise ValueError("Usa mayúsculas, minúsculas y al menos un dígito")


def create_user(username, password, role):
    if role not in ROLES or not username:
        raise ValueError("Usuario requerido y rol válido: " + ", ".join(ROLES))
    validate_password(password)
    with connect() as db:
        db.execute("INSERT INTO users VALUES (?,?,?)", (username, generate_password_hash(password), role))
    audit(f"user_created:{username}:{role}", "console")


def set_password(username, password):
    validate_password(password)
    with connect() as db:
        if not db.execute("UPDATE users SET password_hash=? WHERE username=?",
                          (generate_password_hash(password), username)).rowcount:
            raise ValueError("El usuario no existe")
    audit(f"password_reset:{username}", "console")


def delete_user(username):
    with connect() as db:
        if not db.execute("DELETE FROM users WHERE username=?", (username,)).rowcount:
            raise ValueError("El usuario no existe")
    audit(f"user_deleted:{username}", "console")


def purge_audit(days):
    with connect() as db:
        removed = db.execute("DELETE FROM audit_log WHERE at < datetime('now', ?)", (f"-{int(days)} days",)).rowcount
    audit(f"audit_purged:{removed}:>{int(days)}d", "console")
    return removed


def read_password(from_stdin):
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Contraseña: ")
    if first != getpass.getpass("Repite la contraseña: "):
        raise SystemExit("Las contraseñas no coinciden")
    return first


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Olist Lab")
    parser.add_argument("command", choices=["run", "run-local-http", "create-user", "set-password",
                                            "delete-user", "list-users", "purge-audit"])
    parser.add_argument("--username")
    parser.add_argument("--role", default="reader", choices=ROLES)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--days", type=int, default=AUDIT_RETENTION_DAYS)
    parser.add_argument("--password-stdin", action="store_true", help="Lee la contraseña de stdin (automatización)")
    args = parser.parse_args()
    if args.command in {"create-user", "set-password", "delete-user"} and not args.username:
        parser.error("--username es obligatorio")
    if args.command == "create-user":
        create_user(args.username, read_password(args.password_stdin), args.role)
        print("Usuario creado")
    elif args.command == "set-password":
        set_password(args.username, read_password(args.password_stdin))
        print("Contraseña actualizada")
    elif args.command == "delete-user":
        delete_user(args.username)
        print("Usuario eliminado")
    elif args.command == "list-users":
        with connect() as db:
            for row in db.execute("SELECT username, role FROM users ORDER BY username"):
                print(f"{row['username']}\t{row['role']}")
    elif args.command == "purge-audit":
        print(f"Eventos eliminados (más de {args.days} días): {purge_audit(args.days)}")
    elif args.command == "run-local-http":
        # Solo para ver el prototipo si el navegador no confía en la CA. NO protege el tráfico.
        app.config["SESSION_COOKIE_SECURE"] = False
        app.run(host="127.0.0.1", port=args.port or 5001, debug=False)
    else:
        from pki import server_context
        app.run(host="127.0.0.1", port=args.port or 5000, debug=False, ssl_context=server_context())
