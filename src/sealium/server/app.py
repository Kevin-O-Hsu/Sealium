# src/sealium/server/app.py
"""
FastAPI 应用工厂。

``create_app`` 只组装路由、中间件并定义生命周期，**不在导入时执行任何 I/O**
（不读私钥、不连数据库）——资源在 lifespan 启动时才初始化并挂到 ``app.state``。
因此 ``import sealium.server.app`` 零副作用；所有运行时依赖均可注入，便于测试。
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Callable, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sealium import __version__
from sealium.common.crypto import RSAEncryptor
from sealium.common.exceptions import ConfigError
from sealium.server.activation_service import ActivationService
from sealium.server.config import ServerConfig, config as default_config
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase
from sealium.server.replay_guard import ReplayGuard
from sealium.server.routes.activation import create_router

logger = logging.getLogger("sealium.server")


def _load_server_encryptor(cfg: ServerConfig) -> RSAEncryptor:
    """从文件加载服务端私钥。"""
    if not cfg.server_private_key_path.exists():
        raise ConfigError(f"服务端私钥文件不存在: {cfg.server_private_key_path}")
    with open(cfg.server_private_key_path, "rb") as f:
        return RSAEncryptor.from_private_key_pem(f.read())


def _open_storage(cfg: ServerConfig) -> tuple[SQLiteDatabase, ActivationCodeStorage]:
    """打开数据库并初始化表结构，返回 (db, storage)。"""
    db = SQLiteDatabase(cfg.database_path)
    db.connect()
    db.init_tables()
    return db, ActivationCodeStorage(db)


def create_app(
    config: Optional[ServerConfig] = None,
    *,
    encryptor: Optional[RSAEncryptor] = None,
    storage: Optional[ActivationCodeStorage] = None,
    replay_guard: Optional[ReplayGuard] = None,
    now_provider: Optional[Callable[[], datetime]] = None,
) -> FastAPI:
    """
    创建 FastAPI 应用。

    所有运行时依赖（加密器、存储、防重放、时间）均可注入；为 ``None`` 时从
    配置加载真实资源（私钥文件、SQLite）。测试时注入临时依赖即可完全离线运行。
    """
    cfg = config or default_config

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(
            level=getattr(logging, cfg.log_level.upper(), logging.INFO),
            format=cfg.log_format,
        )
        logger.info("启动 Sealium 激活服务...")
        cfg.ensure_directories()
        # 真实资源模式才校验私钥文件；注入加密器时跳过文件校验
        if encryptor is None:
            cfg.validate()
        server_encryptor = encryptor or _load_server_encryptor(cfg)

        own_db = storage is None
        db_handle: Optional[SQLiteDatabase] = None
        if storage is not None:
            activation_storage = storage
        else:
            db_handle, activation_storage = _open_storage(cfg)

        app.state.config = cfg
        app.state.server_encryptor = server_encryptor
        app.state.activation_service = ActivationService(
            activation_storage,
            replay_guard if replay_guard is not None else ReplayGuard(max_size=cfg.replay_cache_size),
            cfg.timestamp_tolerance_seconds,
            now_provider=now_provider,
        )

        if cfg.debug:
            cfg.display()

        try:
            yield
        finally:
            if own_db and db_handle is not None:
                db_handle.close()
            logger.info("关闭 Sealium 激活服务...")

    app = FastAPI(
        title="Sealium Activation Server",
        version=__version__,
        description="在线激活验证模块服务端",
        lifespan=lifespan,
        debug=cfg.debug,
    )
    app.state.config = cfg

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(create_router(cfg.activation_path), prefix=cfg.api_prefix)

    @app.get("/health", tags=["health"])
    async def health_check() -> dict:
        """健康检查端点。"""
        return {"status": "ok", "service": "activation"}

    if cfg.debug:

        @app.get("/debug/config", tags=["debug"])
        async def debug_config() -> dict:
            """查看当前配置（仅调试模式）。"""
            return {
                "database_path": str(cfg.database_path),
                "server_private_key": str(cfg.server_private_key_path),
                "server_public_key": (
                    str(cfg.server_public_key_path) if cfg.server_public_key_path else None
                ),
                "time_stamp_tolerance": cfg.timestamp_tolerance_seconds,
                "replay_cache_size": cfg.replay_cache_size,
                "host": cfg.host,
                "port": cfg.port,
                "debug": cfg.debug,
                "api_prefix": cfg.api_prefix,
                "activation_path": cfg.activation_path,
            }

    return app


# 默认应用实例，供 ``uvicorn sealium.server.app:app`` 使用。
# create_app 仅组装路由 / 中间件、定义 lifespan，不执行任何 I/O，导入零副作用。
app = create_app()
