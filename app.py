import json
import os
import sqlite3
import urllib3
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote_plus

from flask import Flask, jsonify, request
import requests


DB_PATH = Path(__file__).with_name("data.db")

app = Flask(__name__)


class SQLiteStore:
    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self.get_connection() as conn:
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vaultwarden_item_map (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client TEXT NOT NULL,
                    cred_type TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(client, cred_type)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def upsert_credential(self, client: str, secret: str, cred_type: str) -> None:
        with self.get_connection() as conn:
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

    def get_vaultwarden_item_id(self, client: str, cred_type: str) -> Optional[str]:
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT item_id FROM vaultwarden_item_map
                WHERE client = ? AND cred_type = ?
                """,
                (client, cred_type),
            ).fetchone()
            return row["item_id"] if row else None

    def upsert_vaultwarden_item_id(self, client: str, cred_type: str, item_id: str) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vaultwarden_item_map (client, cred_type, item_id)
                VALUES (?, ?, ?)
                ON CONFLICT(client, cred_type)
                DO UPDATE SET
                    item_id = excluded.item_id,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (client, cred_type, item_id),
            )

    def list_credentials(self) -> list[dict[str, str]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT client, cred_type, secret
                FROM credentials
                ORDER BY client, cred_type
                """
            ).fetchall()
            return [
                {
                    "client": row["client"],
                    "type": row["cred_type"],
                    "secret": row["secret"],
                }
                for row in rows
            ]

    def get_config(self, key: str) -> Optional[str]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT value FROM app_config WHERE key = ?", (key,)).fetchone()
            if row:
                return row["value"]
            return None

    def set_config(self, key: str, value: str) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO app_config (key, value)
                VALUES (?, ?)
                ON CONFLICT(key)
                DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, value),
            )


def cfg(key: str, default: Optional[str] = None) -> Optional[str]:
    # Prefer SQLite-backed config; allow env fallback for compatibility.
    value = STORE.get_config(key)
    if value is not None:
        return value
    return os.getenv(key, default)


STORE = SQLiteStore()
STORE.init_db()


class CredentialBackend:
    def save(self, client: str, secret: str, cred_type: str) -> None:
        raise NotImplementedError()


class SQLiteBackend(CredentialBackend):
    def save(self, client: str, secret: str, cred_type: str) -> None:
        STORE.upsert_credential(client, secret, cred_type)


class VaultwardenMapping:
    def __init__(self) -> None:
        self.type_map = self._load_json_map("VW_TYPE_MAP_JSON")
        self.client_map = self._load_json_map("VW_CLIENT_MAP_JSON")
        self.name_template = cfg("VW_NAME_TEMPLATE", "pass-collector:{client}:{type}") or "pass-collector:{client}:{type}"
        self.username_template = cfg("VW_USERNAME_TEMPLATE", "{client}") or "{client}"
        self.notes_template = cfg("VW_NOTES_TEMPLATE", "client={client}; type={type}") or "client={client}; type={type}"

    def _load_json_map(self, env_name: str) -> dict[str, str]:
        raw = cfg(env_name)
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{env_name} must be valid JSON object") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError(f"{env_name} must be a JSON object")
        return {str(k): str(v) for k, v in parsed.items()}

    def map_values(self, client: str, cred_type: str) -> tuple[str, str]:
        mapped_client = self.client_map.get(client, client)
        mapped_type = self.type_map.get(cred_type, cred_type)
        return mapped_client, mapped_type

    def make_cipher_payload(self, client: str, secret: str, cred_type: str, organization_id: Optional[str]) -> dict[str, Any]:
        mapped_client, mapped_type = self.map_values(client, cred_type)
        values = {
            "client": mapped_client,
            "type": mapped_type,
            "raw_client": client,
            "raw_type": cred_type,
        }
        payload: dict[str, Any] = {
            "type": 1,
            "name": self.name_template.format(**values),
            "notes": self.notes_template.format(**values),
            "favorite": False,
            "login": {
                "username": self.username_template.format(**values),
                "password": secret,
                "totp": None,
                "uris": [],
            },
            "collectionIds": [],
            "folderId": None,
            "secureNote": None,
            "card": None,
            "identity": None,
            "reprompt": 0,
        }
        if organization_id:
            payload["organizationId"] = organization_id
        return payload


class VaultwardenBackend(CredentialBackend):
    def __init__(self, organization_id: Optional[str] = None) -> None:
        self.organization_id = organization_id
        self.base_url = (cfg("VW_API_URL", "") or "").rstrip("/")
        self.token = cfg("VW_ACCESS_TOKEN")
        self.mapping = VaultwardenMapping()

        if not self.base_url:
            raise RuntimeError("VW_API_URL is required when BACKEND=vaultwarden")
        if not self.token:
            raise RuntimeError("VW_ACCESS_TOKEN is required when BACKEND=vaultwarden")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )
        verify_ssl_raw = (cfg("VW_VERIFY_SSL", "true") or "true").lower()
        self.session.verify = verify_ssl_raw not in ("false", "0", "no")
        if not self.session.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _request(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(method=method, url=url, json=payload, timeout=15)
        except requests.RequestException as exc:
            raise RuntimeError(f"vaultwarden API request failed: {exc}") from exc

        if response.status_code >= 400:
            body = response.text.strip()
            raise RuntimeError(
                f"vaultwarden API error {response.status_code} {method} {path}: {body}"
            )

        if response.text:
            try:
                return response.json()
            except json.JSONDecodeError:
                return response.text
        return None

    def _delete_cipher_if_known(self, client: str, cred_type: str) -> None:
        existing_id = STORE.get_vaultwarden_item_id(client, cred_type)
        if not existing_id:
            return

        url = f"{self.base_url}/api/ciphers/{quote_plus(existing_id)}"
        try:
            response = self.session.delete(url=url, timeout=15)
        except requests.RequestException as exc:
            raise RuntimeError(f"vaultwarden API request failed during delete: {exc}") from exc

        # Ignore missing records to allow id-map drift recovery.
        if response.status_code in (404, 410):
            return
        if response.status_code >= 400:
            body = response.text.strip()
            raise RuntimeError(
                f"vaultwarden API error {response.status_code} DELETE /api/ciphers/<id>: {body}"
            )

    def _extract_cipher_id(self, response_payload: Any) -> str:
        if isinstance(response_payload, dict):
            cipher_id = response_payload.get("id") or response_payload.get("Id")
            if cipher_id:
                return str(cipher_id)

            data = response_payload.get("data") or response_payload.get("Data")
            if isinstance(data, dict):
                nested_id = data.get("id") or data.get("Id")
                if nested_id:
                    return str(nested_id)

        raise RuntimeError("Vaultwarden create response did not include cipher id")

    def save(self, client: str, secret: str, cred_type: str) -> None:
        payload = self.mapping.make_cipher_payload(client, secret, cred_type, self.organization_id)

        self._delete_cipher_if_known(client, cred_type)
        created = self._request("POST", "/api/ciphers", payload)
        new_id = self._extract_cipher_id(created)
        STORE.upsert_vaultwarden_item_id(client, cred_type, new_id)



def get_backend_name() -> str:
    return (cfg("BACKEND", "sqlite") or "sqlite").strip().lower()


def build_backend() -> CredentialBackend:
    backend_name = get_backend_name()
    if backend_name == "sqlite":
        return SQLiteBackend()
    if backend_name == "vaultwarden":
        org_id = cfg("VW_ORGANIZATION_ID")
        return VaultwardenBackend(organization_id=org_id)
    raise RuntimeError("Unsupported BACKEND value. Use 'sqlite' or 'vaultwarden'.")


BACKEND = build_backend()


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
def store_password() -> Union[tuple[Any, int], Any]:
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

    try:
        BACKEND.save(client, secret, cred_type)
    except Exception as exc:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"failed to save credential: {exc}",
                }
            ),
            500,
        )

    return jsonify(
        {
            "ok": True,
            "message": "saved",
            "client": client,
            "type": cred_type,
            "method": request.method,
            "backend": get_backend_name(),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)