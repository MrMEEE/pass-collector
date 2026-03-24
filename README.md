# pass-collector

Super simple Python webserver that accepts GET and POST requests with:

- `client`
- `pass`
- `type`

It stores values in SQLite (`data.db`) and enforces uniqueness on (`client`, `type`).
If the same combination arrives again, the existing value is overwritten.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Server starts at `http://localhost:8000`.

## Example requests

Create or update using GET:

```bash
curl "http://localhost:8000/?client=acme&pass=abc123&type=ssh"
```

Update same (`client`, `type`) with new value:

```bash
curl "http://localhost:8000/?client=acme&pass=new-secret&type=ssh"
```

Create or update using POST form data:

```bash
curl -X POST "http://localhost:8000/" \
	-d "client=acme" \
	-d "pass=newest-secret" \
	-d "type=ssh"
```

Create or update using POST JSON:

```bash
curl -X POST "http://localhost:8000/" \
	-H "Content-Type: application/json" \
	-d '{"client":"acme","pass":"json-secret","type":"ssh"}'
```

## Notes

- Query strings are usually logged by proxies and browsers, so GET with secrets is not secure for production.
- Prefer POST for sending secrets.
- This is intentionally minimal for local/simple usage.