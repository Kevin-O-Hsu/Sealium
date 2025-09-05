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

        # 转换为 Path 并验证（如果提供了路径）
        if public_key_path is None:
            pass  # 保持为 None
        elif isinstance(public_key_path, str):
            public_key_path = Path(public_key_path)
        elif isinstance(public_key_path, Path):
            public_key_path = public_key_path
        else:
            raise TypeError(
                f"public_key_path must be str, Path, or None, got {type(public_key_path)}"
            )

        if private_key_path is None:
            pass  # 保持为 None
        elif isinstance(private_key_path, str):
            private_key_path = Path(private_key_path)
        elif isinstance(private_key_path, Path):
            private_key_path = private_key_path
        else:
            raise TypeError(
                f"private_key_path must be str, Path, or None, got {type(private_key_path)}"
            )

        # 校验公钥路径
        if public_key_path is not None:
            self._validate_path(public_key_path, "Public key file")
        # 校验私钥路径
        if self.private_key_path is not None:
            self._validate_path(private_key_path, "Private key file")

        # 所有校验通过，安全赋值
        self.public_key_path: Path | None = public_key_path
        self.private_key_path: Path | None = private_key_path

        self.public_key: rsa.RSAPublicKey | None = None
        self.private_key: rsa.RSAPrivateKey | None = None

        # 安全加载（此时路径已验证存在）
        if self.public_key_path:
            self._load_public_key()
        if self.private_key_path:
            self._load_private_key()

    def _load_public_key(self) -> None:
        """私有方法：加载公钥"""
        assert self.public_key_path is not None
        try:
            key_data = self.public_key_path.read_text().strip()
            self.public_key = serialization.load_pem_public_key(key_data)
        except Exception as e:
            raise ValueError(
                f"Failed to load public key from {self.public_key_path}: {e}"
            ) from e

    def _load_private_key(self) -> None:
        """私有方法：加载私钥"""
        assert self.private_key_path is not None
        try:
            key_data = self.private_key_path.read_text().strip()
            self.private_key = serialization.load_pem_private_key(key_data)
        except Exception as e:
            raise ValueError(
                f"Failed to load private key from {self.private_key_path}: {e}"
            ) from e

    def encrypt(self, message):
        if self.public_key is None:
            raise ValueError("Public key not loaded. Use load_public_key() to load it.")

        # 使用公钥加密
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

        # Base64 解码并解密
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

        :param key_size: 密钥长度，默认为 2048 位
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

        :param public_key_path: 公钥保存路径
        :param private_key_path: 私钥保存路径
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

        # 序列化并写入公钥
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path.write_bytes(public_pem)

        # 序列化并写入私钥
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_path.write_bytes(private_pem)

        # 更新实例变量
        self.public_key_path = public_path
        self.private_key_path = private_path

    def _validate_path(self, path: Path, name: str) -> None:
        if not path.exists():
            raise FileNotFoundError(f"{name} not found: {path}")
        if not path.is_file():
            raise ValueError(f"{name} is not a file: {path}")
