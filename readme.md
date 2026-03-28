```markdown
<p align="center">
  <img src="assets/Sealium-logo-transparent.png" width="400" alt="Sealium Logo">
</p>

<p align="center">
  <a href="https://pypi.org/project/sealium/"><img src="https://img.shields.io/pypi/v/sealium?style=flat-square&logo=pypi&color=2c8cff" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-2c8cff?style=flat-square" alt="License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.13+-2c8cff?style=flat-square&logo=python" alt="Python"></a>
</p>

---

# 🔒 Sealium

**Secure license key generation, software activation, and hardware binding.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **RSA-4096 Encryption** | Secure client-server communication |
| 🎫 **License Keys** | Cryptographically secure random keys |
| 💻 **Hardware Binding** | Bind licenses to specific machines |
| ⏰ **Expiration Control** | Set expiry dates and feature flags |
| 🛡️ **Anti-Replay** | Nonce-based replay attack prevention |
| 🌐 **Client-Server** | Ready-to-use FastAPI backend |

---

## 📦 Installation

```bash
pip install sealium
```

---

## 🚀 Quick Example

```python
from sealium.client.activator import Activator

# Activate a license
activator = Activator(
    server_url="http://localhost:8000/v1/activation",
    server_public_key_pem=open("data/server_public.pem").read(),
    client_private_key_pem=open("data/client_private.pem").read()
)

response = activator.activate("your-license-key")

if response.result == "success":
    print(f"✅ Activated until {response.authorized_until}")
else:
    print(f"❌ {response.error_msg}")
```

---

## 🔧 Requirements

- Python 3.13+
- cryptography, requests, fastapi, uvicorn, sqlalchemy

---

## 📄 License

GPLv3 © Sealium Contributors

---

<p align="center">
  <sub>Built with ❤️ for Python developers</sub>
</p>
```