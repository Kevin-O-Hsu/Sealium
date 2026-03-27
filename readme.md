# Sealium

<p align="center">
  <img src="assets/Sealium-logo-transparent.png" width="400" alt="Sealium Logo">
</p>

<p align="center">
  <a href="https://pypi.org/project/sealium/">
    <img src="https://img.shields.io/pypi/v/sealium?style=flat-square&logo=pypi&logoColor=white&color=2c8cff" alt="PyPI">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-GPLv3-2c8cff?style=flat-square" alt="License">
  </a>
  <a href="https://www.python.org">
    <img src="https://img.shields.io/badge/python-3.13+-2c8cff?style=flat-square&logo=python&logoColor=white" alt="Python">
  </a>
</p>

---

### Secure License & Activation Management

Sealium is a lightweight Python library that handles **license key generation, software activation, and hardware binding** with a focus on security and simplicity.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **License Keys** | Generate cryptographically secure license keys |
| **Activation** | Manage activations with hardware binding support |
| **Validation** | Verify license status with expiration checks |
| **Simple API** | Clean, intuitive interface |
| **Minimal Dependencies** | Lightweight with no unnecessary bloat |

---

## 📦 Installation

```bash
pip install sealium
```

---

## 🚀 Quick Example

```python
from sealium import LicenseManager

# Create a license
license = LicenseManager.generate_license(
    product="Sealium Pro",
    expires="2025-12-31"
)

# Validate activation
if LicenseManager.verify_license(license.key, hardware_id):
    print("✅ License activated successfully")
else:
    print("❌ Invalid license or hardware mismatch")
```

---

## 🔧 Requirements

- Python 3.13 or higher
- No external dependencies required

---

## 📄 License

This project is licensed under the **GPLv3 License**. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with ❤️ for Python developers</sub>
</p>