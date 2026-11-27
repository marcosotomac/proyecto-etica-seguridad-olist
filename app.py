"""Olist Lab: backend Flask del panel académico. Ejecutar con HTTPS de desarrollo."""
import argparse
import getpass
import secrets
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from db_crypto import INSTANCE, ROOT, connect as encrypted_connect

ROLES = ("admin", "analyst", "reader")

INSTANCE.mkdir(parents=True, exist_ok=True)
KEY_FILE = INSTANCE / "secret.key"
if not KEY_FILE.exists():
    KEY_FILE.write_text(secrets.token_hex(32), encoding="ascii")

app = Flask(__name__)
app.secret_key = KEY_FILE.read_text(encoding="ascii").strip()
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
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
    return db


def audit(action, username=None):
    with connect() as db:
        db.execute("INSERT INTO audit_log(username, action) VALUES (?,?)", (username, action))


def check_csrf():
    expected = session.get("csrf")
    if not expected or not secrets.compare_digest(request.form.get("csrf", ""), expected):
        abort(400)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
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
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        with connect() as db:
            by_user = db.execute("""SELECT count(*) FROM login_attempts WHERE username=?
                AND at >= datetime('now', '-15 minutes')""", (username,)).fetchone()[0]
        if by_user >= 5:
            audit("login_blocked", username)
            abort(429, "Demasiados intentos. Espera 15 minutos.")
        with connect() as db:
            user = db.execute("SELECT password_hash, role FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            with connect() as db:
                db.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            session.clear()  # nuevo identificador de sesión y nuevo token CSRF
            session["username"], session["role"] = username, user["role"]
            audit("login", username)
            return redirect(url_for("dashboard"))
        with connect() as db:
            db.execute("INSERT INTO login_attempts(username) VALUES (?)", (username,))
        audit("login_failed", username)
        error = "Credenciales incorrectas"
    session["csrf"] = secrets.token_urlsafe(32)
    return render_template("login.html", error=error, csrf=session["csrf"])


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


@app.get("/api/dashboard")
@login_required
def dashboard_api():
    state = request.args.get("state", "").upper().strip()
    if state and (len(state) != 2 or not state.isalpha()):
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
            GROUP BY customer_state HAVING count(*) >= 30 ORDER BY late_pct DESC""").fetchall()
        months = db.execute("""SELECT substr(purchase_date,1,7) month, count(*) n,
            round(100.0 * avg(is_late),1) late_pct FROM deliveries WHERE (:state IS NULL OR customer_state = :state)
            GROUP BY substr(purchase_date,1,7) HAVING count(*) >= 30 ORDER BY month""", params).fetchall()
        holiday = db.execute("""SELECT CASE WHEN h.date IS NULL THEN 'Día común' ELSE 'Feriado nacional' END day_type,
            count(*) n, round(100.0 * avg(d.is_late),1) late_pct
            FROM deliveries d LEFT JOIN holidays h ON d.purchase_date=h.date
            WHERE d.purchase_date BETWEEN '2018-01-01' AND '2018-12-31'
            AND (:state IS NULL OR d.customer_state = :state)
            GROUP BY day_type ORDER BY day_type""", params).fetchall()
    audit("dashboard_api" + (":" + state if state else ""), session["username"])
    return jsonify({"state": state, "summary": dict(summary),
                    "states": [dict(row) for row in states],
                    "months": [dict(row) for row in months],
                    "holiday": [dict(row) for row in holiday],
                    "user": {"username": session["username"], "role": session["role"]},
                    "csrf": session.setdefault("csrf", secrets.token_urlsafe(32))})


@app.get("/audit")
@role_required("admin")
def audit_view():
    with connect() as db:
        entries = db.execute("SELECT at, username, action FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    audit("audit_view", session["username"])
    return render_template("audit.html", entries=entries)


# --- Administración por consola (no expuesta en la web) -------------------------------------------

def create_user(username, password, role):
    if role not in ROLES or not username or len(password) < 12:
        raise ValueError("Usuario requerido, rol válido y contraseña de al menos 12 caracteres")
    with connect() as db:
        db.execute("INSERT INTO users VALUES (?,?,?)", (username, generate_password_hash(password), role))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Olist Lab")
    parser.add_argument("command", choices=["run", "run-local-http", "create-user"])
    parser.add_argument("--username")
    parser.add_argument("--role", default="reader")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    if args.command == "create-user":
        create_user(args.username, getpass.getpass("Contraseña: "), args.role)
        print("Usuario creado")
    elif args.command == "run-local-http":
        # Solo para ver el prototipo en navegadores que bloquean certificados autofirmados.
        app.config["SESSION_COOKIE_SECURE"] = False
        app.run(host="127.0.0.1", port=args.port or 5001, debug=False)
    else:
        app.run(host="127.0.0.1", port=args.port or 5000, debug=False, ssl_context="adhoc")
