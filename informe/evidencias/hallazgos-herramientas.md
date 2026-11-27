# Hallazgos de las herramientas de análisis y correcciones (entrega final)

| Herramienta | Tipo | Hallazgo inicial | Corrección | Resultado final |
|---|---|---|---|---|
| Bandit 1.9 | SAST Python | 3 × B608 (SQL construido dinámicamente) en el panel (pasada de septiembre). | Consultas fijas con parámetros con nombre. | 0 |
| Bandit 1.9 | SAST Python | 4 × B101 en `pki.py`: la validación del certificado usaba `assert`, que `python -O` elimina. 1 × B105 (falso positivo) en `verify_live.py`. | Validaciones explícitas que lanzan `ValueError`; se quitó el literal. | 0 en 859 líneas |
| npm audit | SCA JS | 15 vulnerabilidades (7 altas, 8 moderadas) en dependencias de producción: `undici`, `hono`, `zod`, `systeminformation`… arrastradas por el CLI `shadcn` y el paquete `cn` (ver `npm-audit-antes.json`). | `shadcn` pasa a `devDependencies` (solo se usa al compilar); se retira `cn` y se reemplaza por 3 líneas propias; `npm audit fix`. | 0 (producción y desarrollo) |
| pip-audit 2.x | SCA Python | 0 vulnerabilidades conocidas en Flask, cryptography y sqlcipher3-wheels. | — | 0 |
| gitleaks 8 | Secretos | 0 en el historial; sin embargo, una revisión manual encontró dos contraseñas de demo en `frontend/generate_screenshots.js` (commit `861221a`) que la regla genérica no detecta. | Scripts reescritos para leer credenciales del entorno; contraseñas de ambas cuentas rotadas; incidente documentado. | Contraseñas expuestas invalidadas |
| pytest | Pruebas | — | 35 pruebas automatizadas de S01–S06, P01 y F1–F3 (incluye revocación de sesiones y supresión complementaria). | 35/35 |
| `scripts/verify_live.py` | E2E sobre HTTPS real | — | 20 comprobaciones contra la instancia real con TLS validado por la CA propia. | 20/20 |

La CI (`.github/workflows/security.yml`) ejecuta Bandit, pip-audit, npm audit, pytest y gitleaks en cada push y cada lunes. Dependabot propone actualizaciones semanales.
