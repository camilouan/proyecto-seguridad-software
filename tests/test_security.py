from __future__ import annotations

import pytest

from app import create_app, init_db


@pytest.fixture()
def app(tmp_path):
    # Se crea una app aparte para que las pruebas no toquen la base real.
    database_path = tmp_path / "test.db"
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database_path),
            "SECRET_KEY": "test-secret",
        }
    )
    with app.app_context():
        init_db()
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username: str = "admin", password: str = "Admin123!"):
    # Ayuda para iniciar sesión igual que lo haría una persona desde el navegador.
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_login_rejects_sql_injection_payload(client):
    # Este intento raro de login debe fallar.
    response = login(client, username="admin' OR '1'='1", password="anything")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Credenciales inválidas." in body
    assert "Listado de tareas" not in body


def test_diagnostics_rejects_non_allowlisted_input(client):
    login(client)

    response = client.get("/diagnostics?check=whoami")

    assert response.status_code == 400
    assert "Chequeo no permitido" in response.get_data(as_text=True)


def test_task_notes_are_escaped_on_listing(client):
    login(client)

    response = client.post(
        "/tasks/new",
        data={"title": "Demo", "note": "<script>alert(1)</script>"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body