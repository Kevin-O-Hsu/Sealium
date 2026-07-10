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

Sealium is a production-oriented licensing toolkit: a FastAPI activation server plus a
zero-long-term-key client. Every payload is end-to-end protected by RSA-4096 + AES-256-GCM
hybrid encryption. Licenses bind to a machine through a **multi-surface hardware fingerprint**
(SMBIOS firmware table + disk IOCTL + WMI, cross-validated) with **weighted similarity
matching** — tolerant to minor hardware changes, hard to spoof.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Hybrid Encryption** | RSA-4096-OAEP key wrapping + AES-256-GCM payload, end-to-end |
| 🎫 **License Keys** | Cryptographically secure random keys (128-bit) |
| 💻 **Hardware Binding** | Multi-surface fingerprint (SMBIOS + disk IOCTL + WMI cross-validation) with weighted similarity matching — survives minor hardware swaps, resists spoofing |
| ⏰ **Expiration Control** | Set expiry dates and feature flags per code |
| 🛡️ **Anti-Replay** | Timestamp window (authoritative remote clock) + nonce deduplication |
| 🌐 **Client-Server** | Ready-to-use FastAPI backend; client needs only the server's public key |
| 🔁 **Idempotent** | Same machine may reactivate safely |

---

## 📚 Documentation

The [`docs/`](docs/) directory contains the full, production-grade documentation (in Chinese).
Quick pointers:

- [系统架构](docs/architecture.md) — layered design, module responsibilities, activation data flow
- [加密与传输协议](docs/protocol.md) — hybrid encryption, binary packet format, anti-replay
- [硬件绑定原理](docs/hardware-binding.md) — fingerprint generation, cross-validation, matching algorithm (**1.3.0 redesign**)
- [服务端部署指南](docs/server-guide.md) — install, keys, code generation, reverse proxy/TLS, multi-worker
- [客户端集成指南](docs/client-guide.md) — embedding activation in your application
- [配置参考](docs/configuration.md) — TOML schema & environment variable overrides
- [安全模型](docs/security.md) — threat model, mitigations, known limitations
- [故障排查](docs/troubleshooting.md) — error codes and diagnostics

---

## 📦 Installation

```bash
pip install sealium
```

---

## 🚀 Quick Example

```python
from sealium.client.activator import Activator, ActivationError

# The client only needs the server's PUBLIC key.
activator = Activator(
    server_url="https://activation.example.com/v1/activation",
    server_public_key_pem=open("data/server_public.pem").read(),
)

try:
    response = activator.activate("your-license-key")
    if response.result == "success":
        print(f"✅ Activated until {response.authorized_until}")
        print(f"   Features: {response.features}")
    else:
        print(f"❌ {response.error_msg}")
except ActivationError as e:
    print(f"⚠️ Activation error: {e}")
```

---

## 🧱 Architecture

```
src/sealium/
├── common/        # Shared primitives
│   ├── crypto.py          # RSA-4096 / AES-256-GCM
│   ├── models.py          # ActivationRequest/Response/Code
│   ├── fingerprint.py     # MachineFingerprint + matches() (new in 1.3.0)
│   ├── machine_code.py    # collection → component fingerprint
│   ├── hardware/          # native SMBIOS/IOCTL + WMI surfaces (new in 1.3.0)
│   └── time_source.py     # authoritative timestamp
├── client/        # Activator + hybrid-encryption key manager
├── server/        # FastAPI app factory, routes, services, database, config
└── scripts/       # generate_keys, generate_activation_codes
```

Key principle: **no import side effects**. Importing the package performs no I/O,
no network calls, no hardware reads. Server resources (private key, DB) are
initialized in the FastAPI lifespan and are injectable for testing.

See [docs/architecture.md](docs/architecture.md) for the full design.

---

## 🚀 Server in 60 seconds

Zero config — install and run:

```bash
pip install sealium

# 1. Generate the server RSA keypair (keep private key on the server only)
python -m sealium.scripts.generate_keys

# 2. Generate activation codes into the database
python -m sealium.scripts.generate_activation_codes --count 10 --features pro

# 3. Run the activation service (behind a reverse proxy in production)
python -m sealium.server.run
```

Sensible defaults work out of the box (binds `0.0.0.0:8000`, data in `./data/`). To
customize, generate a config template and edit:

```bash
python -m sealium.server.config_cli init     # writes sealium.toml in the current dir
python -m sealium.server.config_cli check    # validate
```

Secrets (e.g. private-key passphrase) come from env vars, never the config file:
`SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=...`. Distribute `data/server_public.pem` with
your client. Full guide: [docs/server-guide.md](docs/server-guide.md).

---

## 🔧 Requirements

- Python 3.13+
- `cryptography`, `requests`, `fastapi`, `uvicorn` (`wmi` on Windows only — needed for
  client-side hardware collection)

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest
```

The test suite runs fully offline: the FastAPI server is driven in-process via
`TestClient`, the database is a throwaway SQLite file, hardware collection and the
timestamp source are injected — no live server, network, or real hardware required.

---

## 🛡️ Deployment Hardening

Sealium is designed to run **behind a reverse proxy / firewall**, not exposed bare to
the public network:

- **Bind address** — defaults to `0.0.0.0`; restrict via `[server] host = "127.0.0.1"` in
  `sealium.toml` (or `SEALIUM_SERVER__HOST`) when running co-located with the proxy.
- **TLS** — terminate TLS at the reverse proxy (with HSTS) to hide metadata.
- **Rate limiting** — enabled by default (`[rate_limit]`, 60 req / 60 s per IP).
- **Docs** — `/docs`, `/redoc`, `/openapi.json` are auto-disabled when `[server] debug = false`.
- **Config** — `sealium.toml` + `SEALIUM_*` env / `.env`; private-key passphrase stored as
  `SecretStr` (never echoed). Validate with `python -m sealium.server.config_cli check`.
- **Key material** — `data/server_private.pem` and the SQLite DB are created with
  `0600` permissions; the private key can be passphrase-encrypted.
- **Multi-worker caveat** — the in-memory replay guard and rate limiter are
  per-process; for cross-worker consistency, inject a shared store (Redis).

See [docs/security.md](docs/security.md) for the full threat model and hardening checklist.

---

## 📄 License

MIT © 2026 Kevin Orson Hsu
