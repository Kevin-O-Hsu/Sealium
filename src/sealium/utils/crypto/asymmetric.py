from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from pathlib import Path
import base64


class AsymmetricEncryption:
    def __init__(
        self,
        public_key_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
    ) -> None:

        # 转换为 Path 并验证（如果提供了路径） / Convert to Path and validate (if path is provided)
        if public_key_path is None:
            pass  # 保持为 None / Keep as None
        elif isinstance(public_key_path, str) or isinstance(public_key_path, Path):
            public_key_path = Path(public_key_path)
        else:
            raise TypeError(
                f"public_key_path must be str, Path, or None, got {type(public_key_path)}"
            )

        if private_key_path is None:
            pass  # 保持为 None / Keep as None
        elif isinstance(private_key_path, str) or isinstance(private_key_path, Path):
            private_key_path = Path(private_key_path)
        else:
            raise TypeError(
                f"private_key_path must be str, Path, or None, got {type(private_key_path)}"
            )

        # 校验公钥路径 / Validate public key path
        if public_key_path is not None:
            self._validate_path(public_key_path, "Public key file")
        # 校验私钥路径 / Validate private key path
        if private_key_path is not None:
            self._validate_path(private_key_path, "Private key file")

        # 所有校验通过，安全赋值 / All validations passed, assign safely
        self.public_key_path: Path | None = public_key_path
        self.private_key_path: Path | None = private_key_path

        self.public_key: rsa.RSAPublicKey | None = None
        self.private_key: rsa.RSAPrivateKey | None = None

        # 安全加载（此时路径已验证存在） / Load safely (paths already validated to exist)
        if self.public_key_path:
            self._load_public_key()
        if self.private_key_path:
            self._load_private_key()

    def _load_public_key(self) -> None:
        """
        私有方法：加载公钥。
        Private method: Load public key.
        """
        assert self.public_key_path is not None
        try:
            key_data = self.public_key_path.read_text().strip()
            # 检查是否是有效的PEM格式 / Check if it's valid PEM format
            if not key_data.startswith("-----BEGIN"):
                raise ValueError("Invalid PEM format: missing BEGIN header")
            self.public_key = serialization.load_pem_public_key(
                key_data.encode("utf-8")
            )
        except ValueError as e:
            if "Unable to load PEM file" in str(e) or "MalformedFraming" in str(e):
                raise ValueError(
                    f"Failed to load public key from {self.public_key_path}: "
                    f"Invalid or corrupted PEM file format"
                ) from e
            else:
                raise ValueError(
                    f"Failed to load public key from {self.public_key_path}: {e}"
                ) from e
        except Exception as e:
            raise ValueError(
                f"Failed to load public key from {self.public_key_path}: {e}"
            ) from e

    def _load_private_key(self) -> None:
        """
        私有方法：加载私钥。
        Private method: Load private key.
        """
        assert self.private_key_path is not None
        try:
            key_data = self.private_key_path.read_text().strip()
            # 检查是否是有效的PEM格式 / Check if it's valid PEM format
            if not key_data.startswith("-----BEGIN"):
                raise ValueError("Invalid PEM format: missing BEGIN header")
            self.private_key = serialization.load_pem_private_key(
                key_data.encode("utf-8"), None
            )
        except ValueError as e:
            if "Unable to load PEM file" in str(e) or "MalformedFraming" in str(e):
                raise ValueError(
                    f"Failed to load private key from {self.private_key_path}: "
                    f"Invalid or corrupted PEM file format"
                ) from e
            else:
                raise ValueError(
                    f"Failed to load private key from {self.private_key_path}: {e}"
                ) from e
        except Exception as e:
            raise ValueError(
                f"Failed to load private key from {self.private_key_path}: {e}"
            ) from e

    def encrypt(self, message):
        if self.public_key is None:
            raise ValueError("Public key not loaded. Use load_public_key() to load it.")

        # 使用公钥加密 / Encrypt using public key
        ciphertext = self.public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ciphertext).decode("ascii")

    def decrypt(self, ciphertext_base64):
        if self.private_key is None:
            raise ValueError(
                "Private key not loaded. Use load_private_key() to load it."
            )

        # Base64 解码并解密 / Decode Base64 and decrypt
        ciphertext = base64.b64decode(ciphertext_base64)
        decrypted_message = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message.decode("utf-8")

    def generate_keys(
        self, key_size: int = 2048, set_this: bool = False
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        生成一个新的 RSA 密钥对。
        Generate a new RSA key pair.

        :param key_size: 密钥长度，默认为 2048 位 / Key size in bits, default is 2048
        """
        if key_size < 512:
            raise ValueError("Key size must be at least 512 bits.")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

        if set_this:
            self.private_key = private_key
            self.public_key = public_key

        return private_key, public_key

    def save_keys(
        self, public_key_path: str | Path, private_key_path: str | Path
    ) -> None:
        """
        将当前已生成的公钥和私钥保存为 PEM 文件。
        Save the currently generated public and private keys as PEM files.

        :param public_key_path: 公钥保存路径 / Path to save public key
        :param private_key_path: 私钥保存路径 / Path to save private key
        """
        if self.public_key is None or self.private_key is None:
            raise ValueError(
                "Keys have not been generated yet. Call generate_keys() first."
            )

        if isinstance(public_key_path, str):
            public_path = Path(public_key_path)
        else:
            public_path = public_key_path

        if isinstance(private_key_path, str):
            private_path = Path(private_key_path)
        else:
            private_path = private_key_path

        # 序列化并写入公钥 / Serialize and write public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path.write_bytes(public_pem)

        # 序列化并写入私钥 / Serialize and write private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_path.write_bytes(private_pem)

        # 更新实例变量 / Update instance variables
        self.public_key_path = public_path
        self.private_key_path = private_path

    def _validate_path(self, path: Path, name: str) -> None:
        # 检查文件是否存在 / Check if file exists
        if not path.exists():
            raise FileNotFoundError(f"{name} not found: {path}")
        # 检查是否为文件（而非目录） / Check if it's a file (not a directory)
        if not path.is_file():
            raise ValueError(f"{name} is not a file: {path}")
