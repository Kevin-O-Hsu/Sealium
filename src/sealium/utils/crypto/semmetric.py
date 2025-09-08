from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
import base64


class SymmetricEncryption:
    """
    对称加密工具类，基于 Fernet (AES-128-CBC + HMAC-SHA256)，安全且易于使用。
    Symmetric encryption utility class based on Fernet (AES-128-CBC + HMAC-SHA256), secure and easy to use.

    支持从密钥文件加载密钥，用于加密和解密字符串数据。
    Supports loading keys from file for encrypting and decrypting string data.
    密钥必须是 32 字节的 URL-safe base64 编码字符串（Fernet 格式）。
    Key must be a 32-byte URL-safe base64-encoded string (Fernet format).
    """

    def __init__(
        self,
        key_path: str | Path | None = None,
    ) -> None:
        self.key_path: Path | None = None
        self.cipher: Fernet | None = None
        self.key_data: str | None = None

        # -------------------------------
        # 处理 key_path：转换为 Path / Process key_path: convert to Path
        # -------------------------------
        if key_path is None:
            pass  # 保持为 None / Keep as None
        elif isinstance(key_path, str) or isinstance(key_path, Path):
            self.key_path = Path(key_path)
        else:
            raise TypeError(
                f"key_path must be str, Path, or None, got {type(key_path)}"
            )

        # -------------------------------
        # 校验密钥文件路径（如果提供了） / Validate key file path (if provided)
        # -------------------------------
        if self.key_path is not None:
            self._validate_path(self.key_path, "Symmetric key file")
            self._load_key()

    def _validate_path(self, path: Path, name: str) -> None:
        """
        私有方法：验证路径存在且为文件。
        Private method: Validate that path exists and is a file.
        """
        if not path.exists():
            raise FileNotFoundError(f"{name} not found: {path}")
        if not path.is_file():
            raise ValueError(f"{name} is not a file: {path}")

    def _load_key(self) -> None:
        """
        私有方法：从文件加载对称密钥并初始化 Fernet。
        Private method: Load symmetric key from file and initialize Fernet.
        """
        assert self.key_path is not None
        try:
            self.key_data = self.key_path.read_text().strip()
            self.cipher = Fernet(self.key_data)
        except Exception as e:
            raise ValueError(
                f"Failed to load or parse symmetric key from {self.key_path}: {e}"
            ) from e

    def encrypt(self, message: str) -> str:
        """
        使用对称密钥加密字符串，返回 Base64 编码的密文。
        Encrypt string using symmetric key, return Base64-encoded ciphertext.
        """
        if self.cipher is None:
            raise ValueError("Symmetric key not loaded. Cannot encrypt.")

        try:
            encrypted_data = self.cipher.encrypt(message.encode("utf-8"))
            return base64.b64encode(encrypted_data).decode("ascii")
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext_base64: str) -> str:
        """
        解密 Base64 编码的密文，返回原始字符串。
        Decrypt Base64-encoded ciphertext and return original string.
        """
        if self.cipher is None:
            raise ValueError("Symmetric key not loaded. Cannot decrypt.")

        try:
            ciphertext = base64.b64decode(ciphertext_base64)
            decrypted_data = self.cipher.decrypt(ciphertext)
            return decrypted_data.decode("utf-8")
        except InvalidToken:
            raise ValueError(
                "Decryption failed: invalid token (possibly corrupted or wrong key)"
            )
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}") from e

    def generate_key(self, set_this: bool = False) -> str:
        """
        生成一个新的安全随机密钥（Base64 编码字符串）。
        Generate a new secure random key (Base64-encoded string).
        """
        key = Fernet.generate_key().decode("ascii")  # this is b64 bytes
        if set_this:
            self.key_data = key
            self.cipher = Fernet(key)
        return key

    def save_key(self, path: str | Path) -> None:
        """
        将密钥保存到文件。
        Save the key to file.
        """
        key_path = Path(path)
        key_path.write_text(self.key_data)
