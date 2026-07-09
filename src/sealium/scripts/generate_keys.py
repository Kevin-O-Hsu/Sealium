# src/sealium/scripts/generate_keys.py
"""
生成服务端 RSA 密钥对。

默认输出到服务端配置指定的路径（``data/server_private.pem`` 与
``data/server_public.pem``）。客户端只需分发公钥。
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Tuple, Union

from sealium.common.constants import RSA_KEY_SIZE
from sealium.common.crypto import RSAEncryptor
from sealium.server.config import config


def _resolve_paths(
    private_key_path: Optional[Union[str, Path]],
    public_key_path: Optional[Union[str, Path]],
) -> Tuple[Path, Path]:
    priv = Path(private_key_path) if private_key_path else config.server_private_key_path
    if public_key_path:
        pub = Path(public_key_path)
    elif config.server_public_key_path is not None:
        pub = config.server_public_key_path
    else:
        pub = priv.parent / "server_public.pem"
    return priv, pub


def generate_key_pair(
    private_key_path: Optional[Union[str, Path]] = None,
    public_key_path: Optional[Union[str, Path]] = None,
    key_size: int = RSA_KEY_SIZE,
) -> Tuple[Path, Path]:
    """
    生成 RSA 密钥对并写入文件。

    :return: (私钥路径, 公钥路径)。
    """
    priv_path, pub_path = _resolve_paths(private_key_path, public_key_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    encryptor = RSAEncryptor.generate(key_size=key_size)
    priv_path.write_bytes(encryptor.export_private_key())
    pub_path.write_bytes(encryptor.export_public_key())

    return priv_path, pub_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="生成服务端 RSA 密钥对")
    parser.add_argument("--private-key", type=str, help="私钥输出路径")
    parser.add_argument("--public-key", type=str, help="公钥输出路径")
    parser.add_argument("--key-size", type=int, default=RSA_KEY_SIZE, help="密钥位数")
    args = parser.parse_args()

    priv, pub = generate_key_pair(args.private_key, args.public_key, args.key_size)
    print(f"✅ 私钥已生成: {priv}")
    print(f"✅ 公钥已生成: {pub}")
    print("\n请妥善保管私钥，仅将公钥分发给客户端。")
