"""Instancia aislada con datos sintéticos: las pruebas nunca tocan instance/ ni el dataset real."""
import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="olist-test-"))
os.environ["OLIST_INSTANCE"] = str(_TMP / "instance")
os.environ["OLIST_KEY_DIR"] = str(_TMP / "keys")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

import app as olist_app  # noqa: E402
from db_crypto import connect  # noqa: E402

PASSWORDS = {"admin1": "Admin-Prueba-2026", "lector1": "Lector-Prueba-2026"}


def _seed():
    with connect(create=True) as db:
        db.executescript("""
            DROP TABLE IF EXISTS deliveries; DROP TABLE IF EXISTS holidays;
            CREATE TABLE holidays (date TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE deliveries (id INTEGER PRIMARY KEY, purchase_date TEXT NOT NULL,
              estimated_date TEXT NOT NULL, delivered_date TEXT NOT NULL, customer_state TEXT NOT NULL,
              review_score INTEGER, delay_days REAL NOT NULL, is_late INTEGER NOT NULL);
            INSERT INTO holidays VALUES ('2018-04-21', 'Tiradentes');
        """)
        rows = []
        for i in range(200):  # SP: 200 pedidos, 20 % tardíos
            late = int(i % 5 == 0)
            rows.append((f"2018-03-{i % 28 + 1:02d}", "2018-03-30", "2018-04-02" if late else "2018-03-25",
                         "SP", 2 if late else 5, 3.0 if late else -5.0, late))
        for i in range(10):  # RR: grupo pequeño que debe suprimirse
            rows.append(("2018-04-21", "2018-05-01", "2018-05-03", "RR", 1, 2.0, 1))
        db.executemany("""INSERT INTO deliveries (purchase_date, estimated_date, delivered_date, customer_state,
            review_score, delay_days, is_late) VALUES (?,?,?,?,?,?,?)""", rows)
    olist_app.create_user("admin1", PASSWORDS["admin1"], "admin")
    olist_app.create_user("lector1", PASSWORDS["lector1"], "reader")


_seed()


@pytest.fixture()
def client():
    olist_app.app.config.update(TESTING=True)
    with olist_app.app.test_client() as c:
        yield c
    with connect() as db:
        db.execute("DELETE FROM login_attempts")


def login(client, username, password=None, ip="10.0.0.1"):
    client.get("/login")
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post("/login", data={"csrf": token, "username": username,
                                       "password": password or PASSWORDS[username]},
                       environ_base={"REMOTE_ADDR": ip})
