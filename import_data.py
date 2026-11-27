"""Importa únicamente las columnas necesarias desde el ZIP original de Olist.

Minimización: no se importan identificadores de clientes ni de vendedores, nombres,
ciudades, códigos postales, coordenadas, pagos ni el texto libre de las reseñas.
"""
import csv
import io
import zipfile

from db_crypto import DB, ROOT, connect

ZIP = ROOT / "data" / "olist.zip"


def rows(archive, name):
    with archive.open(name) as raw:
        yield from csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))


def day(value):
    return value[:10] if value else None


INSERT = """INSERT INTO deliveries (purchase_date, estimated_date, delivered_date, customer_state,
    review_score, delay_days, is_late) VALUES (?,?,?,?,?,?,?)"""


def main():
    if not ZIP.exists():
        raise SystemExit(f"Falta {ZIP}. Descarga el ZIP original de Olist.")
    with zipfile.ZipFile(ZIP) as archive:
        customers = {r["customer_id"]: r["customer_state"] for r in rows(archive, "olist_customers_dataset.csv")}
        reviews = {}
        for r in rows(archive, "olist_order_reviews_dataset.csv"):
            reviews.setdefault(r["order_id"], int(r["review_score"]))
        with connect(create=True) as db:
            db.executescript("""
                DROP TABLE IF EXISTS deliveries;
                DROP TABLE IF EXISTS holidays;
                CREATE TABLE holidays (date TEXT PRIMARY KEY, name TEXT NOT NULL);
                CREATE TABLE deliveries (
                    id INTEGER PRIMARY KEY,
                    purchase_date TEXT NOT NULL,
                    estimated_date TEXT NOT NULL,
                    delivered_date TEXT NOT NULL,
                    customer_state TEXT NOT NULL,
                    review_score INTEGER CHECK (review_score BETWEEN 1 AND 5),
                    delay_days REAL NOT NULL,
                    is_late INTEGER NOT NULL CHECK (is_late IN (0,1))
                );
                CREATE INDEX ix_deliveries_state ON deliveries(customer_state);
                CREATE INDEX ix_deliveries_purchase ON deliveries(purchase_date);
            """)
            with (ROOT / "holidays_2018.csv").open(encoding="utf-8", newline="") as file:
                db.executemany("INSERT INTO holidays(date,name) VALUES (:date,:name)", csv.DictReader(file))
            batch = []
            skipped = 0
            for r in rows(archive, "olist_orders_dataset.csv"):
                estimated, delivered = day(r["order_estimated_delivery_date"]), day(r["order_delivered_customer_date"])
                purchase = day(r["order_purchase_timestamp"])
                state = customers.get(r["customer_id"])
                if r["order_status"] != "delivered" or not all((estimated, delivered, purchase, state)):
                    skipped += 1
                    continue
                # julianday conserva fracciones y evita errores en cambios de mes/año.
                delay = db.execute("SELECT julianday(?) - julianday(?)", (delivered, estimated)).fetchone()[0]
                batch.append((purchase, estimated, delivered, state, reviews.get(r["order_id"]), delay, int(delay > 0)))
                if len(batch) >= 5000:
                    db.executemany(INSERT, batch)
                    batch.clear()
            if batch:
                db.executemany(INSERT, batch)
            count = db.execute("SELECT count(*) FROM deliveries").fetchone()[0]
    print(f"Importados {count:,} pedidos entregados; excluidos {skipped:,} sin entrega o datos completos. Base: {DB}")


if __name__ == "__main__":
    main()
