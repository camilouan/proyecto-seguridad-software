# Mini app OWASP - aseguramiento aplicado

Aplicación Flask pequeña para demostrar revisión y hardening guiados por OWASP en un flujo con login, formulario, listado y diagnóstico.

## Ejecución

1. Crear e instalar dependencias.
2. Ejecutar la app con `flask --app app run`.
3. Iniciar sesión con `admin / Admin123!` o `demo / Demo123!`.

## Validación

Ejecutar la rutina repetible de aseguramiento:

```bash
pytest
```

La guía de seguridad, el checklist y la justificación de correcciones están en `docs/owasp_hardening.md`.