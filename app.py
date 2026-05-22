from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for, current_app
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config: dict | None = None) -> Flask:
    # Aquí se arma la app y se deja lista para usarla también en pruebas.
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
        DATABASE=os.path.join(app.root_path, "app.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if test_config:
        app.config.update(test_config)

    register_db_hooks(app)
    register_routes(app)

    with app.app_context():
        init_db()

    return app


def register_db_hooks(app: Flask) -> None:
    # Al final de cada petición, se cierra la conexión para no dejarla abierta.
    @app.teardown_appcontext
    def close_db(exception: Exception | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()


def get_db() -> sqlite3.Connection:
    # Se abre la base solo cuando hace falta y se usa la configuración actual.
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


def init_db() -> None:
    # Si la base está vacía, se crean las tablas y se cargan datos de ejemplo.
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );
        """
    )

    user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if user_count == 0:
        # Las contraseñas se guardan con hash, nunca en texto plano.
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("Admin123!"), "admin"),
        )
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("demo", generate_password_hash("Demo123!"), "user"),
        )

        admin_id = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()["id"]
        demo_id = db.execute("SELECT id FROM users WHERE username = ?", ("demo",)).fetchone()["id"]
        db.executemany(
            "INSERT INTO tasks (owner_id, title, note) VALUES (?, ?, ?)",
            [
                (admin_id, "Revisar checklist OWASP", "Verificar consultas parametrizadas y salida escapada."),
                (demo_id, "Preparar demo", "Mostrar que <script>alert(1)</script> se imprime como texto."),
            ],
        )

    db.commit()


def register_routes(app: Flask) -> None:
    # Dejamos el usuario actual disponible en todas las vistas.
    @app.context_processor
    def inject_user() -> dict[str, object | None]:
        return {"current_user": get_current_user()}

    # La página principal manda al lugar que más sentido tiene.
    @app.get("/")
    def index() -> object:
        if session.get("user_id"):
            return redirect(url_for("tasks"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> object:
        # El inicio de sesión valida datos sin mezclar texto del usuario en la consulta.
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = authenticate_user(username, password)

            if user is None:
                flash("Credenciales inválidas.", "error")
            else:
                # Limpiamos la sesión anterior antes de entrar con otra cuenta.
                session.clear()
                session["user_id"] = user["id"]
                flash(f"Bienvenido, {user['username']}.", "success")
                return redirect(url_for("tasks"))

        return render_template("login.html", title="Inicio de sesión")

    @app.post("/logout")
    def logout() -> object:
        # Cerrar sesión solo borra los datos de la sesión actual.
        session.clear()
        flash("Sesión cerrada.", "success")
        return redirect(url_for("login"))

    @app.get("/tasks")
    @login_required
    def tasks() -> object:
        # Aquí se muestran solo las tareas del usuario que entró.
        search_term = request.args.get("q", "").strip()
        task_list = list_tasks(search_term)
        return render_template(
            "tasks.html",
            title="Listado de tareas",
            tasks=task_list,
            search_term=search_term,
        )

    @app.route("/tasks/new", methods=["GET", "POST"])
    @login_required
    def new_task() -> object:
        # Este formulario guarda una nueva tarea sin confiar en lo que escriba el usuario.
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            note = request.form.get("note", "").strip()

            if not title:
                flash("El título es obligatorio.", "error")
            else:
                # No armamos consultas pegando texto del usuario.
                db = get_db()
                db.execute(
                    "INSERT INTO tasks (owner_id, title, note) VALUES (?, ?, ?)",
                    (session["user_id"], title, note),
                )
                db.commit()
                flash("Tarea guardada.", "success")
                return redirect(url_for("tasks"))

        return render_template("task_form.html", title="Nueva tarea")

    @app.get("/diagnostics")
    @login_required
    def diagnostics() -> object:
        # Esta parte queda solo para admin y solo acepta opciones permitidas.
        require_admin()
        check_name = request.args.get("check", "server_time")
        if check_name not in DIAGNOSTIC_CHECKS:
            abort(400, description="Chequeo no permitido.")
        result = DIAGNOSTIC_CHECKS[check_name]()
        return render_template("diagnostics.html", title="Diagnóstico", check_name=check_name, result=result)


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    # Buscamos el usuario de forma segura y comparamos la contraseña con hash.
    if not username or not password:
        return None

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return None
    return user


def list_tasks(search_term: str) -> list[sqlite3.Row]:
    # El filtro se aplica solo a las tareas del usuario y sin sorpresas raras.
    db = get_db()
    current_user = get_current_user()
    if current_user is None:
        return []

    pattern = f"%{escape_like(search_term)}%"
    return db.execute(
        """
        SELECT id, title, note, created_at
        FROM tasks
        WHERE owner_id = ?
          AND (title LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')
        ORDER BY datetime(created_at) DESC, id DESC
        """,
        (current_user["id"], pattern, pattern),
    ).fetchall()


def escape_like(value: str) -> str:
    # Escapamos los símbolos especiales para que el filtro no cambie de más.
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def get_current_user() -> sqlite3.Row | None:
    # Sacamos el usuario actual desde la sesión, si existe.
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def require_admin() -> None:
    # Solo los administradores pueden entrar a esta pantalla.
    current_user = get_current_user()
    if current_user is None or current_user["role"] != "admin":
        abort(403)


def login_required(view):
    # Pequeño control para que no entren usuarios sin iniciar sesión.
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def internal_server_time() -> str:
    # Devuelve la hora del servidor sin ejecutar nada externo.
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


DIAGNOSTIC_CHECKS = {
    # Opciones permitidas para el diagnóstico. Nada más.
    "server_time": internal_server_time,
    "app_status": lambda: "ok",
}


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)