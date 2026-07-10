# src/sealium/server/config.py
"""
服务端配置管理（工业级：pydantic-settings + TOML）。

配置来源分层（优先级从高到低）：

1. 构造参数（``ServerConfig(server=...)``，测试 / 程序化注入）
2. 环境变量（``SEALIUM_`` 前缀，``__`` 嵌套分隔符，如 ``SEALIUM_SERVER__PORT``）
3. ``.env`` 文件（与 2 同语义，用于本地开发 / 敏感项）
4. TOML 配置文件（``sealium.toml``，结构化主载体；路径由 ``SEALIUM_CONFIG`` 指定）
5. 内置默认值

设计要点
--------
* **零配置开箱即用**：``paths`` 与各组都有合理默认，无 ``sealium.toml`` 也能启动；
  TOML 仅作覆盖。
* **结构化 + 可审计**：TOML 可注释、可版本化 review；环境变量只覆盖敏感项
  与部署差异。
* **类型与范围校验**：pydantic 在构造时即校验（``port`` 范围、``threshold``
  越界等直接 ``ValidationError``），错误信息聚合。
* **敏感字段隔离**：私钥口令用 :class:`pydantic.SecretStr`，``repr``/``model_dump``
  不暴露明文。
* **路径相对解析**：TOML 内相对路径解析为相对配置文件所在目录（部署可移植）。
* **惰性加载**：本模块 **导入零副作用**——不读文件、不读环境；只有显式调用
  :func:`get_config`（或 ``create_app`` 默认路径）才首次构造。私钥等重 I/O 仍
  由应用 ``lifespan`` 在启动时处理（见 :func:`validate`）。
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.9 / 3.10：tomllib 尚未进入标准库，用等价 API 的第三方 tomli
    import tomli as tomllib

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from sealium.common.fingerprint import MachineIdPolicy

# TOML 配置文件默认查找路径；可被 ``SEALIUM_CONFIG`` 环境变量覆盖。
_DEFAULT_CONFIG_FILENAME = "sealium.toml"


def _config_file_path() -> Path:
    """当前生效的 TOML 配置文件路径（``SEALIUM_CONFIG`` 或默认 ``sealium.toml``）。"""
    return Path(os.environ.get("SEALIUM_CONFIG", _DEFAULT_CONFIG_FILENAME))


def _config_base_dir() -> Path:
    """相对路径的解析基目录：配置文件所在目录；配置文件不存在则为当前工作目录。"""
    p = _config_file_path()
    return p.resolve().parent if p.exists() else Path.cwd().resolve()


# ---------------------------------------------------------------------------
# 嵌套子模型
# ---------------------------------------------------------------------------
class ServerModel(BaseModel):
    """网络与路由。"""

    host: str = "0.0.0.0"  # 生产建议 127.0.0.1（置于反代后）
    port: int = Field(8000, ge=1, le=65535)
    debug: bool = False  # 生产必须 False
    api_prefix: str = "/v1"
    activation_path: str = "/activation"


class PathsModel(BaseModel):
    """存储与密钥路径（TOML 内相对路径相对配置文件目录解析）。"""

    database: Path = Path("data/database.db")
    private_key: Path = Path("data/server_private.pem")
    public_key: Optional[Path] = None  # 可选，仅调试用


class SecurityModel(BaseModel):
    """时间窗口、防重放缓存、私钥口令。"""

    timestamp_tolerance_seconds: int = Field(300, gt=0)
    replay_cache_size: int = Field(10000, gt=0)
    # 私钥落盘口令（LOW-001）：经 .env / 环境变量注入，绝不写入 sealium.toml。
    # SecretStr 的 repr / model_dump 不暴露明文，防止落日志或进调试端点。
    private_key_passphrase: Optional[SecretStr] = None


class RateLimitModel(BaseModel):
    """进程内固定窗口限流。"""

    enabled: bool = True
    max_requests: int = Field(60, ge=1)
    window_seconds: int = Field(60, ge=1)


class MachineIdModel(BaseModel):
    """同机判定策略（见 common.fingerprint.MachineIdPolicy）。"""

    threshold: float = Field(0.70, ge=0.0, le=1.0)
    core_min: int = Field(3, ge=0)
    spoof_max: float = Field(0.5, ge=0.0, le=1.0)


class LoggingModel(BaseModel):
    """日志。"""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class CorsModel(BaseModel):
    """CORS。原生客户端（octet-stream）无需浏览器凭据。"""

    origins: list[str] = ["*"]


# ---------------------------------------------------------------------------
# TOML 配置源（pydantic-settings 自定义源）
# ---------------------------------------------------------------------------
class TomlConfigSettingsSource(PydanticBaseSettingsSource):
    """从 TOML 配置文件读取设置（``SEALIUM_CONFIG`` 或默认 ``sealium.toml``）。

    文件不存在时返回空 dict，回退到字段默认值（零配置开箱即用）。
    """

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        self._toml_path = _config_file_path()
        self._data: dict[str, Any] = {}
        if self._toml_path.exists():
            with self._toml_path.open("rb") as f:
                loaded = tomllib.load(f)
            if isinstance(loaded, dict):
                self._data = loaded

    def get_field_value(
        self, field, field_name: str
    ) -> Tuple[Any, str, bool]:
        """供默认 ``__call__`` 流程使用（本源重写了 ``__call__``，此为桩）。"""
        value = self._data.get(field_name)
        return value, field_name, False

    def __call__(self) -> dict[str, Any]:
        return self._data


# ---------------------------------------------------------------------------
# 顶层配置
# ---------------------------------------------------------------------------
class ServerConfig(BaseSettings):
    """服务端配置（pydantic-settings 驱动）。"""

    model_config = SettingsConfigDict(
        env_prefix="SEALIUM_",
        env_file=".env",
        env_nested_delimiter="__",  # SEALIUM_RATE_LIMIT__MAX_REQUESTS=120
        extra="ignore",
        case_sensitive=False,
    )

    server: ServerModel = ServerModel()
    paths: PathsModel = PathsModel()
    security: SecurityModel = SecurityModel()
    rate_limit: RateLimitModel = RateLimitModel()
    machine_id: MachineIdModel = MachineIdModel()
    logging: LoggingModel = LoggingModel()
    cors: CorsModel = CorsModel()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # 优先级（前者覆盖后者）：构造参数 > 环境变量 > .env > TOML 文件 > secret 文件
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    @model_validator(mode="after")
    def _resolve_relative_paths(self) -> "ServerConfig":
        """TOML 内相对路径 → 相对配置文件目录；绝对路径原样（部署可移植）。"""
        base = _config_base_dir()

        def _abs(p: Path) -> Path:
            return p if p.is_absolute() else (base / p).resolve()

        self.paths.database = _abs(self.paths.database)
        self.paths.private_key = _abs(self.paths.private_key)
        if self.paths.public_key is not None:
            self.paths.public_key = _abs(self.paths.public_key)
        return self

    # ---------- 便捷方法 ----------
    def ensure_directories(self) -> None:
        """确保数据库与私钥的父目录存在。"""
        self.paths.database.parent.mkdir(parents=True, exist_ok=True)
        self.paths.private_key.parent.mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        """业务校验（必需文件存在等）。由应用 lifespan 在启动时显式调用。"""
        errors: list[str] = []
        if not self.paths.private_key.exists():
            errors.append(f"服务端私钥文件不存在: {self.paths.private_key}")
        if errors:
            raise RuntimeError("配置验证失败:\n" + "\n".join(errors))

    def activation_route(self) -> str:
        """完整激活路由（prefix + path），如 ``/v1/activation``。"""
        return f"{self.server.api_prefix}{self.server.activation_path}"

    def machine_id_policy(self) -> MachineIdPolicy:
        """转换为 common 层 :class:`MachineIdPolicy`（weights 沿用默认权重表）。"""
        return MachineIdPolicy(
            threshold=self.machine_id.threshold,
            core_min=self.machine_id.core_min,
            spoof_max=self.machine_id.spoof_max,
        )

    @property
    def passphrase_secret(self) -> Optional[str]:
        """私钥口令明文（仅供私钥加载用）；未设返回 ``None``。"""
        ps = self.security.private_key_passphrase
        return ps.get_secret_value() if ps is not None else None

    def safe_dump(self) -> dict[str, Any]:
        """脱敏快照（用于 ``/debug/config`` 与 ``config_cli show``）。

        敏感字段（私钥口令）以 ``<set>`` / ``<unset>`` 表示，绝不回显明文。
        路径输出为字符串，便于阅读。
        """

        def _p(p: Optional[Path]) -> Optional[str]:
            return str(p) if p is not None else None

        ps = self.security.private_key_passphrase
        return {
            "config_file": str(_config_file_path()),
            "server": {
                "host": self.server.host,
                "port": self.server.port,
                "debug": self.server.debug,
                "api_prefix": self.server.api_prefix,
                "activation_path": self.server.activation_path,
                "activation_route": self.activation_route(),
            },
            "paths": {
                "database": _p(self.paths.database),
                "private_key": _p(self.paths.private_key),
                "public_key": _p(self.paths.public_key),
            },
            "security": {
                "timestamp_tolerance_seconds": self.security.timestamp_tolerance_seconds,
                "replay_cache_size": self.security.replay_cache_size,
                "private_key_passphrase": "<set>" if ps is not None else "<unset>",
            },
            "rate_limit": self.rate_limit.model_dump(),
            "machine_id": self.machine_id.model_dump(),
            "logging": self.logging.model_dump(),
            "cors": self.cors.model_dump(),
        }


# ---------------------------------------------------------------------------
# 惰性加载入口（保持 import 零副作用）
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_config() -> ServerConfig:
    """加载并缓存服务端配置（首次调用才读取 TOML / 环境变量）。

    用 ``lru_cache`` 保证进程内单例；测试可用 ``get_config.cache_clear()`` 重置。
    """
    return ServerConfig()


# 注意：本模块不再提供模块级 ``config`` 单例，避免导入即读配置。
# 调用方显式使用 ``get_config()``，或由 ``create_app(config=...)`` 注入。
