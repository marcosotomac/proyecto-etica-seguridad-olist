# Demostración en vivo — DS3031, Tipo 2 (entrega final)

Duración objetivo: **6–8 minutos**. Ronal conduce los pasos 1–2 y Marco los pasos 3–5.

## Preparación (antes de la clase)

```bash
py -m pip install -r requirements.txt -r requirements-dev.txt
npm --prefix frontend ci && npm --prefix frontend run build
py backup.py seal-source --delete-plain     # si aún existe data/olist.zip en claro
py import_data.py
py pki.py init                              # CA propia + certificado del servidor
py app.py create-user --username demo_admin --role admin
py app.py create-user --username demo_lector --role reader
```

Instala `instance/pki/ca.crt` como raíz de confianza **solo en el equipo de la demo**:

- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain instance/pki/ca.crt`
- **Windows:** `certutil -addstore -user Root instance\pki\ca.crt`

Antes de instalarla, comprueba la huella SHA-256 con `py pki.py show`. Al terminar el curso, elimínala del almacén de confianza.

Ten preparada la contraseña de cada cuenta. No la muestres en pantalla y no la escribas en archivos del repositorio.

## Recorrido

| # | Acción | Qué decir | Resultado esperado |
|---|---|---|---|
| 1 | `py pki.py show` → `py app.py run` → abrir **https://127.0.0.1:5000** | El certificado lo emitió nuestra CA (ECDSA, SAN, serverAuth); el navegador confía porque instalamos la raíz explícitamente. | Candado sin advertencias; TLS 1.3. |
| 2 | Ingresar como `demo_admin`; filtrar **MA**; abrir **Auditoría**. | Solo agregados; grupos <30 se suprimen en el servidor. | 96 470 → 717 pedidos; eventos `login`, `dashboard_api:MA`. |
| 3 | En otra ventana privada, ingresar como `demo_lector` y abrir `/audit`. | Autorización en el backend; el intento queda registrado. | **403**; evento `access_denied:/audit` visible para el admin. |
| 4 | `py backup.py backup instance/backups/demo.enc --keep 7` → `py backup.py restore instance/backups/demo.enc --destination instance/demo-restaurada.db` | Respaldo autenticado; restauración verificada. | `integrity_check=ok · 96470 entregas`. |
| 5 | `scripts/security_scan.sh` y `py scripts/verify_live.py` | Bandit, pip-audit y npm audit encontraron 4 alertas y 15 CVE, todas corregidas. | 0 hallazgos · 35/35 pruebas · 20/20 comprobaciones. |

Cierre (30 s): DPIA. Explica quiénes son los afectados, por qué solo se publican agregados y qué riesgo residual queda: las claves están en el equipo y la CA es privada.

## Plan B

- **El navegador no confía en la CA:** muestra la conexión con `curl --cacert instance/pki/ca.crt -I https://127.0.0.1:5000/login` y usa `py app.py run-local-http` (http://127.0.0.1:5001) **solo** para la parte visual. Aclara que ese modo no protege el tráfico.
- **No hay red:** todo funciona sin conexión. Solo `pip-audit` y `npm audit` necesitan Internet; en ese caso, muestra los reportes de `informe/evidencias/`.

## Evidencias por objetivo

| Objetivo | Evidencia |
|---|---|
| Consultar sin divulgar filas | Filtro MA (717) vs. total (96 470); supresión `k=30` (`verify_live` P01). |
| Proteger accesos y registrar actividad | Admin 200, lector 403, bloqueo 429, revocación de sesión (pytest). |
| Proteger el transporte | TLS 1.3 validado contra la CA propia; un cliente sin la CA lo rechaza. |
| Recuperar información | Restauración `ok`; una copia con 1 bit alterado se rechaza. |
| Analizar la implementación | `informe/evidencias/` (Bandit, pip-audit, npm audit, pytest, hallazgos). |
| Responder a incidentes | Caso real de credenciales publicadas (informe, sección 10.2). |

## Ejercicio de formación del equipo

Simulen la pérdida de la base: borren una copia de prueba, restauren desde el respaldo y verifiquen el número de filas. Luego repasen el caso de las credenciales publicadas siguiendo las seis fases del plan. Registren la fecha, los asistentes, el resultado y los acuerdos en el registro del equipo.
