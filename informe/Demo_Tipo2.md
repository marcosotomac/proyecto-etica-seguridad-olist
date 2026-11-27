# Demostración en vivo — DS3031, Tipo 2

## Preparación

Sigan la instalación del README. Compilen React con `npm --prefix frontend run build`.
Creen dos cuentas de prueba nuevas con `py app.py create-user --username demo_final_admin --role admin`
y `py app.py create-user --username demo_final_lector --role reader`. Usen contraseñas
locales distintas, de al menos 12 caracteres.

## Recorrido (6–8 minutos)

1. Ronal presenta el problema y arranca `py app.py run`. Abre
   https://127.0.0.1:5000/login y explica el certificado autofirmado. Si el
   navegador bloquea la demo, muestra el certificado y la conexión con
   `curl.exe -k -I https://127.0.0.1:5000/login` y usa HTTP local solo para
   la parte visual. La opción `-k` se reserva para comprobar este servidor local.
2. Con la cuenta administradora muestra los 96 470 pedidos, aplica MA y
   comprueba los 717. Abre Auditoría y muestra la consulta recién registrada.
3. Marco cierra sesión e ingresa como lector. Abre `/audit` y muestra el 403.
   Explica que la restricción se aplica en Flask.
4. Muestra el respaldo y la restauración en una ruta separada:
   ```powershell
   py backup.py backup instance/demo-final.enc
   py backup.py restore instance/demo-final.enc --destination instance/demo-final-restaurada.db
   ```
5. Ejecuta Bandit y explica qué cambió entre ambas pasadas:
   ```powershell
   py -m pip install bandit==1.9.4
   py -m bandit app.py backup.py db_crypto.py import_data.py migrate_db.py
   ```
6. Cierren con la DPIA. Nombren a los afectados y expliquen por qué se publica
   solo material agregado y qué riesgos quedan por el ZIP y las claves locales.

Ensayen juntos el recorrido, incluida una simulación de pérdida de la base.
Registren fecha, asistentes, resultado de la restauración y acciones pendientes
cuando lo realicen. No muestren contraseñas, claves ni el ZIP durante la exposición.

## Evidencias por objetivo

| Objetivo | Qué mostrar | Resultado esperado |
| --- | --- | --- |
| Consultar sin divulgar filas | Filtrar MA y comparar con el total | 717 vs. 96 470 pedidos |
| Proteger acceso y registrar actividad | Ingresar con ambos roles y visitar Auditoría | Administrador 200, lector 403. Ingreso y consultas registrados |
| Proteger el transporte | Mostrar conexión local por HTTPS | TLS 1.3 y certificado autofirmado |
| Recuperar información | Restaurar a una ruta de prueba nueva | Integridad correcta. El respaldo alterado se rechazó en la verificación registrada |
| Explicar privacidad | Mostrar clasificación y DPIA | Distinguir datos enlazables, sensibles potenciales y agregados |
| Justificar los cambios de código | Comparar las dos pasadas de Bandit | Tres alertas iniciales, cero en los cinco módulos revisados |

Para la formación, alternen los roles de operador y observador y simulen
una pérdida de la base. Comprueben qué claves se necesitan y cómo reportarían
el incidente. Al terminar, dejen constancia de la fecha, asistentes, resultados
y acuerdos en el registro del equipo.
