<p align="center">
  <img src="assets/Sealium-logo-transparent.png" width="400" alt="Sealium Logo">
</p>

<p align="center">
  <a href="https://pypi.org/project/sealium/"><img src="https://img.shields.io/pypi/v/sealium?style=flat-square&logo=pypi&color=2c8cff" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2c8cff?style=flat-square" alt="License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.13+-2c8cff?style=flat-square&logo=python" alt="Python"></a>
</p>

---

# 🔒 Sealium

**Secure license key generation, software activation, and hardware binding.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Hybrid Encryption** | RSA-4096-OAEP key wrapping + AES-256-GCM payload |
| 🎫 **License Keys** | Cryptographically secure random keys (128-bit) |
| 💻 **Hardware Binding** | Bind licenses to specific machines (SHA-256 fingerprint) |
| ⏰ **Expiration Control** | Set expiry dates and feature flags |
| 🛡️ **Anti-Replay** | Timestamp window + nonce deduplication |
| 🌐 **Client-Server** | Ready-to-use FastAPI backend |
| 🔁 **Idempotent** | Same machine may reactivate safely |

---

## 📦 Installation

```bash
pip install sealium
```

---

## 🚀 Quick Example

```python
from sealium.client.activator import Activator

# Client only needs the server's PUBLIC key.
activator = Activator(
    server_url="http://localhost:8000/v1/activation",
    server_public_key_pem=open("data/server_public.pem").read(),
)

response = activator.activate("your-license-key")

if response.result == "success":
    print(f"✅ Activated until {response.authorized_until}")
    print(f"   Features: {response.features}")
else:
    print(f"❌ {response.error_msg}")
```

---

## 🧱 Architecture

```
src/sealium/
├── common/        # Shared primitives (crypto, models, machine_code, time_source)
├── client/        # Activator + hybrid-encryption key manager
├── server/        # FastAPI app factory, routes, services, database, config
│   ├── routes/    # Thin HTTP layer
│   ├── services/  # activation_service, replay_guard (pure, injectable)
│   └── ...
└── scripts/       # generate_keys, generate_activation_codes
```

Key principle: **no import side effects**. Importing the package performs no I/O,
no network calls, no hardware reads. Server resources (private key, DB) are
initialized in the FastAPI lifespan and are injectable for testing.

See `src/docs/mechanism.md` for the full protocol specification.

---

## 🔧 Requirements

- Python 3.13+
- cryptography, requests, fastapi, uvicorn (wmi on Windows only)

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest
```

The test suite runs fully offline: the FastAPI server is driven in-process via
`TestClient`, the database is a throwaway SQLite file, and the timestamp source
is injected — no live server or network required.

---

## 🛡️ Deployment Hardening

Sealium is designed to run **behind a reverse proxy / firewall**, not exposed bare to
the public network:

- **Bind address** — defaults to `0.0.0.0`; restrict via `HOST=127.0.0.1` when running
  co-located with the proxy.
- **TLS** — the app-layer hybrid encryption protects every payload end-to-end, but you
  should still terminate TLS at the reverse proxy (with HSTS) to hide metadata.
- **Rate limiting** — enabled by default (`RATE_LIMIT_ENABLED`, 60 req / 60 s per IP);
  tune via `RATE_LIMIT_MAX_REQUESTS` / `RATE_LIMIT_WINDOW_SECONDS`. In multi-worker
  deployments the limiter is per-process — inject a shared backend for global limits.
- **Docs** — `/docs`, `/redoc`, `/openapi.json` are auto-disabled when `DEBUG=false`.
- **Key material** — `data/server_private.pem` and the SQLite DB are created with
  `0600` permissions; never commit them (already gitignored).
- **Multi-worker caveat** — the in-memory replay guard and rate limiter are
  per-process; for cross-worker consistency, inject a shared store (Redis).

---

## 📄 License

MIT © 2026 Kevin Orson Hsu

---

<p align="center">
  <sub>Built with ❤️ for Python developers</sub>
</p>
