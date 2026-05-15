import base64
import json
import os
import sqlite3
import urllib3
import uuid
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote_plus

from flask import Flask, jsonify, request
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _crypto_hmac
from cryptography.hazmat.primitives import padding as _sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_der_private_key


DB_PATH = Path(__file__).with_name("data.db")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Bitwarden client-side encryption helpers
# ---------------------------------------------------------------------------

def _bw_encrypt(plaintext: str, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypt a UTF-8 string to Bitwarden EncString format '2.iv|ct|mac'."""
    iv = os.urandom(16)
    padder = _sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    h = _crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ct)
    mac = h.finalize()
    return (
        f"2.{base64.b64encode(iv).decode()}"
        f"|{base64.b64encode(ct).decode()}"
        f"|{base64.b64encode(mac).decode()}"
    )


def _bw_decrypt_enc_string(enc_string: str, enc_key: bytes, mac_key: bytes) -> bytes:
    if not enc_string.startswith("2."):
        raise ValueError(f"Unsupported EncString type: {enc_string[:3]!r}")
    _, rest = enc_string.split(".", 1)
    parts = rest.split("|")
    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    mac_bytes = base64.b64decode(parts[2])
    h = _crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ct)
    try:
        h.verify(mac_bytes)
    except InvalidSignature as exc:
        raise ValueError("MAC verification failed") from exc
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = _sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _bw_derive_keys(email: str, password: str, kdf_type: int, kdf_iterations: int,
                    kdf_memory: Optional[int] = None, kdf_parallelism: Optional[int] = None) -> tuple[bytes, bytes]:
    """Derive (enc_key, mac_key) stretched from master password."""
    salt = email.strip().lower().encode("utf-8")
    secret = password.encode("utf-8")
    if kdf_type == 0:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=kdf_iterations)
        master_key = kdf.derive(secret)
    elif kdf_type == 1:
        from argon2.low_level import Type, hash_secret_raw  # type: ignore[import]
        mem_kb = (kdf_memory or 64) * 1024
        master_key = hash_secret_raw(
            secret=secret, salt=salt,
            time_cost=kdf_iterations or 3, memory_cost=mem_kb,
            parallelism=kdf_parallelism or 4, hash_len=32, type=Type.ID,
        )
    else:
        raise ValueError(f"Unsupported KDF type {kdf_type}")
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
    return enc_key, mac_key


def _bw_load_sym_keys(
    session: requests.Session,
    base_url: str,
    master_password: str,
    org_id: Optional[str] = None,
) -> tuple[bytes, bytes]:
    """Fetch /api/sync and derive (enc_key, mac_key) for org or personal vault."""
    resp = session.get(f"{base_url}/api/sync?excludeDomains=true", timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Sync failed ({resp.status_code})")
    data = resp.json()
    profile = data.get("profile") or data.get("Profile") or data
    email = profile.get("email") or profile.get("Email") or ""
    kdf_type = int(profile.get("kdf") if profile.get("kdf") is not None else (profile.get("Kdf") or 0))
    kdf_iter = int(profile.get("kdfIterations") or profile.get("KdfIterations") or 600_000)
    kdf_mem = profile.get("kdfMemory") or profile.get("KdfMemory")
    kdf_par = profile.get("kdfParallelism") or profile.get("KdfParallelism")
    stretched_enc, stretched_mac = _bw_derive_keys(email, master_password, kdf_type, kdf_iter, kdf_mem, kdf_par)
    profile_key_str = profile.get("key") or profile.get("Key") or ""
    user_sym_bytes = _bw_decrypt_enc_string(profile_key_str, stretched_enc, stretched_mac)
    user_enc_key, user_mac_key = user_sym_bytes[:32], user_sym_bytes[32:64]
    if not org_id:
        return user_enc_key, user_mac_key
    priv_key_str = profile.get("privateKey") or profile.get("PrivateKey") or ""
    priv_key_der = _bw_decrypt_enc_string(priv_key_str, user_enc_key, user_mac_key)
    rsa_key = load_der_private_key(priv_key_der, password=None)
    orgs_list = profile.get("organizations") or profile.get("Organizations") or []
    org_entry = next(
        (o for o in orgs_list if (o.get("id") or o.get("Id") or "").lower() == org_id.lower()),
        None,
    )
    if org_entry is None:
        raise RuntimeError(f"Organization {org_id} not found in sync profile")
    org_key_str = org_entry.get("key") or org_entry.get("Key") or ""
    if org_key_str.startswith("4."):
        rsa_ct = base64.b64decode(org_key_str[2:])
        org_sym = rsa_key.decrypt(
            rsa_ct,
            _asym_padding.OAEP(
                mgf=_asym_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return org_sym[:32], org_sym[32:64]
    if org_key_str.startswith("2."):
        org_sym = _bw_decrypt_enc_string(org_key_str, user_enc_key, user_mac_key)
        return org_sym[:32], org_sym[32:64]
    raise ValueError(f"Unsupported org key EncString type: {org_key_str[:3]!r}")


def _fetch_bearer_token(base_url: str, client_id: str, client_secret: str, verify_ssl: bool = True) -> str:
    url = f"{base_url}/identity/connect/token"
    try:
        resp = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "api",
                "DeviceIdentifier": str(uuid.uuid4()),
                "DeviceType": "21",
                "DeviceName": "pass-collector",
            },
            verify=verify_ssl,
            timeout=15,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Token request to {url} failed: {exc}") from exc
    if resp.status_code >= 400:
        raise RuntimeError(f"Token request failed ({resp.status_code}): {resp.text.strip()}")
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("Token response did not include access_token")
    return str(token)


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

    def make_cipher_payload(
        self,
        client: str,
        secret: str,
        cred_type: str,
        organization_id: Optional[str],
        collection_id: Optional[str] = None,
        sym_keys: Optional[tuple[bytes, bytes]] = None,
    ) -> dict[str, Any]:
        mapped_client, mapped_type = self.map_values(client, cred_type)
        values = {
            "client": mapped_client,
            "type": mapped_type,
            "raw_client": client,
            "raw_type": cred_type,
        }

        def _enc(s: str) -> str:
            if sym_keys:
                return _bw_encrypt(s, sym_keys[0], sym_keys[1])
            return s

        payload: dict[str, Any] = {
            "type": 1,
            "name": _enc(self.name_template.format(**values)),
            "notes": _enc(self.notes_template.format(**values)),
            "favorite": False,
            "login": {
                "username": _enc(self.username_template.format(**values)),
                "password": _enc(secret),
                "totp": None,
                "uris": [],
            },
            "collectionIds": [collection_id] if collection_id else [],
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
    def __init__(self, organization_id: Optional[str] = None, collection_id: Optional[str] = None) -> None:
        self.organization_id = organization_id
        self.collection_id = collection_id
        self.base_url = (cfg("VW_API_URL", "") or "").rstrip("/")
        self.mapping = VaultwardenMapping()

        if not self.base_url:
            raise RuntimeError("VW_API_URL is required when BACKEND=vaultwarden")

        verify_ssl_raw = (cfg("VW_VERIFY_SSL", "true") or "true").lower()
        verify_ssl = verify_ssl_raw not in ("false", "0", "no")

        token = cfg("VW_ACCESS_TOKEN")
        if not token:
            client_id = cfg("VW_CLIENT_ID")
            client_secret = cfg("VW_CLIENT_SECRET")
            if client_id and client_secret:
                token = _fetch_bearer_token(self.base_url, client_id, client_secret, verify_ssl)
        if not token:
            raise RuntimeError(
                "VW_ACCESS_TOKEN or both VW_CLIENT_ID and VW_CLIENT_SECRET are required when BACKEND=vaultwarden"
            )

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )
        self.session.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Load pre-derived encryption key so new incoming credentials are stored
        # with proper Bitwarden encryption. The master password is never stored;
        # VW_SYM_KEY is the base64-encoded 64-byte derived key saved by `migrate`.
        self.sym_keys: Optional[tuple[bytes, bytes]] = None
        sym_key_b64 = cfg("VW_SYM_KEY")
        if sym_key_b64:
            try:
                raw = base64.b64decode(sym_key_b64)
                self.sym_keys = (raw[:32], raw[32:64])
            except Exception as exc:
                raise RuntimeError(f"VW_SYM_KEY is invalid: {exc}") from exc

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
        payload = self.mapping.make_cipher_payload(
            client, secret, cred_type, self.organization_id, self.collection_id, self.sym_keys
        )

        self._delete_cipher_if_known(client, cred_type)
        if self.collection_id:
            created = self._request("POST", "/api/ciphers/create", {"cipher": payload, "collectionIds": [self.collection_id]})
        else:
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
        collection_id = cfg("VW_COLLECTION_ID")
        return VaultwardenBackend(organization_id=org_id, collection_id=collection_id)
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