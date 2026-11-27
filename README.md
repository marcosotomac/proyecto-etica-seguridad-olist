# Olist Lab — Ética y Seguridad de Datos (DS3031)

Proyecto de **Ronal Jesus Condor Blas y Marco Soto Maceda**. Es una demostración local para analizar entregas tardías del conjunto histórico de Olist (2016–2018), comparar la satisfacción de pedidos puntuales y tardíos y explorar diferencias por estado, mes y feriados nacionales de Brasil. Las comparaciones son descriptivas: no prueban causalidad ni representan el desempeño actual de una empresa.

**Entrega final DS3031 — Tipo 2:** [informe en GitHub Pages](https://ronaljcb.github.io/proyecto-etica-seguridad-olist/) · [informe PDF](informe/Informe_Olist.pdf) · [presentación](informe/Presentacion_Tipo2.pdf) · [guion de la demo](informe/Demo_Tipo2.md) · [evidencias de seguridad](informe/evidencias/)

## Qué hace la aplicación

- Importa solo las columnas necesarias de Olist (fechas, estado federado, reseña) y los nueve feriados nacionales de Brasil de 2018. **No importa identificadores de clientes, pedidos ni vendedores**, nombres, ciudades, coordenadas, pagos ni texto libre.
- Muestra indicadores agregados: 96 470 pedidos, 6 534 tardíos (6,8 %), retraso medio de 10,6 días y calificaciones de 4,29/5 (puntuales) frente a 2,27/5 (tardíos). Permite filtrar por estado. Los grupos con menos de 30 pedidos se suprimen **en el servidor**, con supresión complementaria.
- Seguridad:

| Requerimiento | Implementación |
|---|---|
| Datos en reposo | SQLCipher (AES-256 + HMAC); ZIP fuente sellado con AES-256-GCM; claves de 256 bits con permisos 0600, separables mediante `OLIST_KEY_DIR` |
| Datos en tránsito y certificados | **CA propia** (`pki.py`: raíz ECDSA P-384 → servidor P-256 con SAN y serverAuth); TLS ≥ 1.2; HSTS |
| Hash | scrypt con sal; mínimo 12 caracteres con mayúsculas, minúsculas y dígito |
| Accesos | Roles `admin`/`analyst`/`reader`, CSRF, sesión de 30 min revocada al cambiar la clave o el rol, bloqueo por usuario (5) y por IP (20) |
| Auditoría | Ingresos, fallos, bloqueos, consultas, denegaciones, CSRF y cambios de cuentas; retención de 180 días (`purge-audit`) |
| Backups | AES-256-GCM autenticado, rotación `--keep`, restauración con `integrity_check` |
| Análisis | Bandit, pip-audit, npm audit, gitleaks, 35 pruebas pytest y 20 comprobaciones en vivo; CI semanal y Dependabot |

## Instalación (Windows con PowerShell, o macOS/Linux reemplazando `py` por `python3`)

Necesitas **Python 3.11+**, **Node.js 22** y Git.

```powershell
git clone https://github.com/ronaljcb/proyecto-etica-seguridad-olist.git
cd proyecto-etica-seguridad-olist
py -m pip install -r requirements.txt -r requirements-dev.txt
New-Item -ItemType Directory -Force data | Out-Null
Invoke-WebRequest 'https://www.kaggle.com/api/v1/datasets/download/olistbr/brazilian-ecommerce' -OutFile 'data\olist.zip'
py backup.py seal-source --delete-plain   # cifra el ZIP y borra la copia en claro
py import_data.py
py pki.py init                            # CA propia + certificado del servidor
py app.py create-user --username marco --role admin
npm --prefix frontend ci
npm --prefix frontend run build
py app.py run
```

Abre **https://127.0.0.1:5000/login**. Para que el navegador confíe en el servidor, instala `instance/pki/ca.crt` como raíz **solo en tu equipo** y antes compara su huella con `py pki.py show`:

- **Windows:** `certutil -addstore -user Root instance\pki\ca.crt`
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain instance/pki/ca.crt`

Si no puedes instalar la CA, `py app.py run-local-http` sirve el panel en http://127.0.0.1:5001. Ese modo **no protege el tráfico**.

El ZIP de Kaggle usado para las cifras tiene SHA-256 `967E41E04FC306FE604E2A693F488995A8B41E5047418F8A5C8E4ABD6DECA784`.

## Operación

```powershell
py app.py list-users | set-password --username X | delete-user --username X | purge-audit --days 180
py backup.py backup instance\backups\copia.enc --keep 7
py backup.py restore instance\backups\copia.enc --destination instance\restaurada.db
py pki.py verify | show | server
scripts/security_scan.sh          # Bandit + pip-audit + npm audit + pytest → informe/evidencias/
py scripts/verify_live.py         # 20 comprobaciones HTTPS sobre la instancia real
```

Para regenerar las capturas, ejecuta `node frontend/capture_evidence.mjs`. Las credenciales se leen de `OLIST_ADMIN_USER`, `OLIST_ADMIN_PASS`, `OLIST_READER_USER` y `OLIST_READER_PASS`; **nunca se escriben en el código**.

## Archivos

| Ruta | Función |
|---|---|
| `import_data.py`, `holidays_2018.csv` | Importación mínima de las dos fuentes |
| `db_crypto.py`, `migrate_db.py` | SQLCipher, custodia de claves y migración desde SQLite |
| `app.py`, `templates/` | Backend, autenticación, API con supresión y auditoría |
| `pki.py` | CA propia y certificado TLS |
| `backup.py` | Respaldo, restauración, rotación y sellado del ZIP |
| `frontend/src/` | Panel React con shadcn/ui |
| `tests/`, `scripts/`, `.github/workflows/` | Pruebas, verificación, escaneo y CI |
| `informe/` | Informe LaTeX, presentación, guion de la demo y evidencias |
| `docs/` | Sitio de GitHub Pages |

`data/` e `instance/` (ZIP sellado, base, claves, CA y respaldos) **están excluidas de Git**. Guarda una copia protegida de tus claves fuera del proyecto: si se pierde `db.key`, la base no puede abrirse. Cada integrante genera las suyas. El servidor Flask es de desarrollo y escucha solo en `127.0.0.1`.

El informe se compila con `tectonic informe/Informe_Olist.tex` (o `pdflatex`), y la presentación con `informe/Presentacion_Tipo2.tex`.
