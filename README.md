# Proyecto 5 - OWASP como guía de aseguramiento

Mini aplicación Flask creada para revisar y endurecer un flujo básico de login, formulario, listado y diagnóstico siguiendo criterios de OWASP, con foco en inyecciones y prácticas seguras.

## Objetivo

Demostrar cómo una revisión guiada por OWASP permite identificar debilidades, corregirlas en el código y validar el resultado con una rutina repetible de pruebas.

## Alcance

- Autenticación con contraseñas hasheadas.
- Formulario de alta de tareas.
- Listado filtrable por texto.
- Ruta administrativa de diagnóstico con allowlist.
- Revisión de riesgos por SQL injection, command injection y script injection / stored XSS.

## Entregables

- Requerimientos de seguridad y checklist en [docs/owasp_hardening.md](docs/owasp_hardening.md).
- Código corregido y endurecido en [app.py](app.py).
- Pruebas de regresión en [tests/test_security.py](tests/test_security.py).

## Evidencia de corrección

- SQL injection mitigada con consultas parametrizadas en [app.py](app.py).
- Command injection mitigada con allowlist interna en [app.py](app.py).
- Script injection / stored XSS mitigada por escape automático en las vistas de Jinja en [templates/tasks.html](templates/tasks.html).
- Validación repetible implementada en [tests/test_security.py](tests/test_security.py).

## Cómo ejecutar

1. Instalar dependencias:

```bash
pip install -r requirements.txt
```

2. Iniciar la aplicación:

```bash
flask --app app run
```

3. Acceder con cualquiera de estas cuentas de prueba:
- `admin / Admin123!`
- `demo / Demo123!`

## Cómo validar

Ejecutar la rutina repetible de aseguramiento:

```bash
pytest
```

Pruebas manuales recomendadas:

- Intentar iniciar sesión con `admin' OR '1'='1`.
- Guardar una nota con `<script>alert(1)</script>`.
- Probar `GET /diagnostics?check=whoami`.

## Estado del proyecto

- Repositorio publicado en GitHub: https://github.com/camilouan/proyecto-seguridad-software
- Pruebas automáticas ejecutadas correctamente: `3 passed`

La explicación técnica y la justificación STRIDE/CIA están documentadas en [docs/owasp_hardening.md](docs/owasp_hardening.md).