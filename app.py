import sqlite3
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request


DB_PATH = Path(__file__).with_name("data.db")

app = Flask(__name__)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client TEXT NOT NULL,
                cred_type TEXT NOT NULL,
                secret TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(client, cred_type)
            )
            """
        )


def save_credential(client: str, secret: str, cred_type: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO credentials (client, cred_type, secret)
            VALUES (?, ?, ?)
            ON CONFLICT(client, cred_type)
            DO UPDATE SET
                secret = excluded.secret,
                updated_at = CURRENT_TIMESTAMP
            """,
            (client, cred_type, secret),
        )


def parse_request_values() -> tuple[Any, Any, Any]:
    client = request.args.get("client")
    secret = request.args.get("pass")
    cred_type = request.args.get("type")

    if request.method == "POST":
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            if isinstance(payload, dict):
                client = payload.get("client", client)
                secret = payload.get("pass", secret)
                cred_type = payload.get("type", cred_type)

        client = request.form.get("client", client)
        secret = request.form.get("pass", secret)
        cred_type = request.form.get("type", cred_type)

    return client, secret, cred_type


@app.route("/", methods=["GET", "POST"])
def store_password() -> tuple[Any, int] | Any:
    client, secret, cred_type = parse_request_values()

    missing = [
        name
        for name, value in (("client", client), ("pass", secret), ("type", cred_type))
        if not value
    ]
    if missing:
        source = "query parameters" if request.method == "GET" else "request fields"
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"missing required {source}",
                    "missing": missing,
                }
            ),
            400,
        )

    save_credential(client, secret, cred_type)

    return jsonify(
        {
            "ok": True,
            "message": "saved",
            "client": client,
            "type": cred_type,
            "method": request.method,
        }
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000, debug=True)