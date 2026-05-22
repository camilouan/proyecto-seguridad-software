# Proyecto 5 - OWASP como guía de aseguramiento

## Requerimientos de seguridad

- Autenticación con contraseñas hasheadas y consultas parametrizadas.
- No ejecutar comandos del sistema con entrada del usuario.
- Escapar siempre la salida en vistas HTML y no marcar contenido no confiable como seguro.
- Validar entradas con allowlist cuando la opción sea limitada.
- Mantener cookies de sesión con `HttpOnly` y `SameSite=Lax`.
- Probar de forma repetible los payloads de inyección antes de entregar cambios.

## Checklist basada en OWASP

- [ ] Cada consulta SQL usa parámetros y no concatenación.
- [ ] Ninguna ruta expone `shell=True`, `os.system` o ejecución equivalente con datos externos.
- [ ] El contenido del usuario se renderiza escapado por defecto.
- [ ] Los controles administrativos usan allowlist explícita.
- [ ] Las contraseñas se almacenan con hash, no en texto plano.
- [ ] Las pruebas cubren payloads de SQLi, command injection y XSS.

## Debilidades identificadas y corregidas

| Debilidad | STRIDE | Impacto CIA | Evidencia en cambio | Corrección aplicada |
| --- | --- | --- | --- | --- |
| Posible SQL injection en login y filtrado de tareas | Tampering / Elevation of Privilege | Confidencialidad e Integridad | En [app.py](../app.py), la autenticación y el listado usan `?` con SQLite; la prueba de regresión está en [tests/test_security.py](../tests/test_security.py) | Se reemplazó cualquier patrón de concatenación por consultas parametrizadas y hash de contraseñas |
| Posible command injection en diagnóstico administrativo | Tampering / Elevation of Privilege | Confidencialidad e Integridad | En [app.py](../app.py), `/diagnostics` solo acepta valores de `DIAGNOSTIC_CHECKS`; no hay invocación a shell | Se eliminó la ejecución de comandos y se sustituyó por un allowlist de comprobaciones internas |
| Posible script injection / stored XSS en notas de tareas | Information Disclosure / Tampering | Integridad y Confidencialidad | En [templates/tasks.html](../templates/tasks.html), las notas se muestran con escape automático de Jinja; la regresión está en [tests/test_security.py](../tests/test_security.py) | Se quitó cualquier renderizado inseguro y no se usa `|safe` para contenido del usuario |

## Rutina de aseguramiento

1. Instalar dependencias con `pip install -r requirements.txt`.
2. Ejecutar `pytest`.
3. Iniciar la app y validar manualmente estos casos:
   - Login con `admin / Admin123!`.
   - Intento de SQLi: `admin' OR '1'='1` debe fallar.
   - Nota con `<script>alert(1)</script>` debe mostrarse como texto.
   - `GET /diagnostics?check=whoami` debe devolver `400`.

## Criterio de entrega

El hardening queda documentado y repetible porque cada debilidad tiene una corrección explícita en código y una prueba de regresión asociada.