# src/sealium/server/config.py
"""
服务端配置管理。

统一管理所有配置项，支持环境变量覆盖。配置以 ``ServerConfig`` 实例承载，
``ServerConfig.from_env`` 构造过程不做任何 I/O（不检查文件存在性），因此
``import sealium.server.config`` 零副作用；文件校验在 ``validate()`` 中显式进行，
由应用启动生命周期调用。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional


@dataclass
class ServerConfig:
    """服务端配置。"""

    project_root: Path
    database_path: Path
    server_private_key_path: Path
    server_public_key_path: Optional[Path]
    timestamp_tolerance_seconds: int
    replay_cache_size: int
    host: str
    port: int
    debug: bool
    cors_origins: list[str]
    api_prefix: str
    activation_path: str
    log_level: str
    log_format: str

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> ServerConfig:
        """
        从环境变量构造配置。

        :param env: 环境变量映射；为 ``None`` 时使用 ``os.environ``。可注入便于测试。
        """
        e = os.environ if env is None else env

        def get(key: str, default: str) -> str:
            return e.get(key, default)

        project_root = Path(__file__).resolve().parents[3]
        public_env = get("SERVER_PUBLIC_KEY_PATH", "")
        return cls(
            project_root=project_root,
            database_path=Path(get("DATABASE_PATH", str(project_root / "data" / "database.db"))),
            server_private_key_path=Path(
                get("SERVER_PRIVATE_KEY_PATH", str(project_root / "data" / "server_private.pem"))
            ),
            server_public_key_path=Path(public_env) if public_env else None,
            timestamp_tolerance_seconds=int(get("TIME_STAMP_TOLERANCE_SECONDS", "300")),
            replay_cache_size=int(get("REPLAY_CACHE_SIZE", "10000")),
            host=get("HOST", "0.0.0.0"),
            port=int(get("PORT", "8000")),
            debug=get("DEBUG", "False").lower() == "true",
            cors_origins=[o.strip() for o in get("CORS_ORIGINS", "*").split(",")],
            api_prefix=get("API_PREFIX", "/v1"),
            activation_path=get("ACTIVATION_PATH", "/activation"),
            log_level=get("LOG_LEVEL", "INFO"),
            log_format=get(
                "LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            ),
        )

    def ensure_directories(self) -> None:
        """确保必要的目录存在。"""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.server_private_key_path.parent.mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        """验证配置有效性（检查必需文件存在）。"""
        errors = []
        if not self.server_private_key_path.exists():
            errors.append(f"服务端私钥文件不存在: {self.server_private_key_path}")
        if errors:
            raise RuntimeError("配置验证失败:\n" + "\n".join(errors))

    def activation_route(self) -> str:
        """完整激活路由（prefix + path），如 ``/v1/activation``。"""
        return f"{self.api_prefix}{self.activation_path}"

    def display(self) -> None:
        """打印当前配置（调试用）。"""
        print("=" * 50)
        print("服务端配置:")
        print(f"  数据库路径: {self.database_path}")
        print(f"  服务端私钥: {self.server_private_key_path}")
        print(f"  时间戳偏差: {self.timestamp_tolerance_seconds}秒")
        print(f"  服务器地址: {self.host}:{self.port}")
        print(f"  调试模式: {self.debug}")
        print("=" * 50)


# 默认配置实例（导入无副作用：from_env 不做 I/O）
config = ServerConfig.from_env()
