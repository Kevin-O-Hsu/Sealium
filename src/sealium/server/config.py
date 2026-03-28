# src/sealium/server/config.py
"""
服务端配置管理
统一管理所有配置项，支持环境变量覆盖
"""

import os
from pathlib import Path
from typing import Optional


class ServerConfig:
        """
        服务端配置类
        支持从环境变量读取配置，提供默认值
        """

        # 项目根目录（自动检测）
        PROJECT_ROOT = Path(__file__).resolve().parents[3]  # 从 server/config.py 向上3级

        # ==================== 数据库配置 ====================
        DATABASE_PATH: Path = Path(os.environ.get(
                "DATABASE_PATH",
                PROJECT_ROOT / "data" / "database.db"
        ))

        # ==================== 密钥配置 ====================
        # 服务端私钥路径
        SERVER_PRIVATE_KEY_PATH: Path = Path(os.environ.get(
                "SERVER_PRIVATE_KEY_PATH",
                PROJECT_ROOT / "data" / "server_private.pem"
        ))

        # 客户端公钥路径
        CLIENT_PUBLIC_KEY_PATH: Path = Path(os.environ.get(
                "CLIENT_PUBLIC_KEY_PATH",
                PROJECT_ROOT / "data" / "client_public.pem"
        ))

        # 服务端公钥路径（可选，用于测试）
        SERVER_PUBLIC_KEY_PATH: Optional[Path] = Path(os.environ.get(
                "SERVER_PUBLIC_KEY_PATH",
                PROJECT_ROOT / "data" / "server_public.pem"
        )) if os.environ.get("SERVER_PUBLIC_KEY_PATH") else None

        # ==================== 安全配置 ====================
        # 时间戳允许偏差（秒）
        TIME_STAMP_TOLERANCE_SECONDS: int = int(os.environ.get(
                "TIME_STAMP_TOLERANCE_SECONDS",
                300
        ))

        # 防重放缓存大小
        REPLAY_CACHE_SIZE: int = int(os.environ.get(
                "REPLAY_CACHE_SIZE",
                10000
        ))

        # ==================== 服务器配置 ====================
        # 服务器主机
        HOST: str = os.environ.get("HOST", "0.0.0.0")

        # 服务器端口
        PORT: int = int(os.environ.get("PORT", 8000))

        # 调试模式
        DEBUG: bool = os.environ.get("DEBUG", "False").lower() == "true"

        # CORS 允许的来源
        CORS_ORIGINS: list = os.environ.get(
                "CORS_ORIGINS",
                "*"
        ).split(",")

        # ==================== API 配置 ====================
        # API 前缀
        API_PREFIX: str = os.environ.get("API_PREFIX", "/v1")

        # 激活接口路径
        ACTIVATION_PATH: str = os.environ.get("ACTIVATION_PATH", "/activation")

        # ==================== 日志配置 ====================
        # 日志级别
        LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

        # 日志格式
        LOG_FORMAT: str = os.environ.get(
                "LOG_FORMAT",
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        @classmethod
        def ensure_directories(cls):
                """确保必要的目录存在"""
                # 确保数据目录存在
                cls.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

                # 确保证书目录存在
                cls.SERVER_PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
                cls.CLIENT_PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

        @classmethod
        def validate(cls):
                """验证配置的有效性"""
                errors = []

                # 检查必要的密钥文件是否存在
                if not cls.SERVER_PRIVATE_KEY_PATH.exists():
                        errors.append(f"服务端私钥文件不存在: {cls.SERVER_PRIVATE_KEY_PATH}")

                if not cls.CLIENT_PUBLIC_KEY_PATH.exists():
                        errors.append(f"客户端公钥文件不存在: {cls.CLIENT_PUBLIC_KEY_PATH}")

                if errors:
                        raise RuntimeError(f"配置验证失败:\n" + "\n".join(errors))

        @classmethod
        def display(cls):
                """打印当前配置（用于调试）"""
                print("=" * 50)
                print("服务端配置:")
                print(f"  数据库路径: {cls.DATABASE_PATH}")
                print(f"  服务端私钥: {cls.SERVER_PRIVATE_KEY_PATH}")
                print(f"  客户端公钥: {cls.CLIENT_PUBLIC_KEY_PATH}")
                print(f"  时间戳偏差: {cls.TIME_STAMP_TOLERANCE_SECONDS}秒")
                print(f"  服务器地址: {cls.HOST}:{cls.PORT}")
                print(f"  调试模式: {cls.DEBUG}")
                print("=" * 50)


# 创建全局配置实例（便于导入）
config = ServerConfig()