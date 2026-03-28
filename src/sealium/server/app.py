# src/sealium/server/app.py
"""
FastAPI 应用入口
创建应用实例，配置中间件，挂载路由
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from .activation import router as activation_router
from .config import config

# ==================== 日志配置 ====================
logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)


# ==================== 生命周期管理 ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
        """
        应用生命周期管理
        启动时执行初始化，关闭时执行清理
        """
        # 启动时执行
        logger.info("启动 Sealium 激活服务...")

        # 确保目录存在
        config.ensure_directories()

        # 验证配置
        try:
                config.validate()
                logger.info("配置验证通过")
        except Exception as e:
                logger.error(f"配置验证失败: {e}")
                raise

        # 打印配置（调试模式）
        if config.DEBUG:
                config.display()

        yield  # 应用运行期间

        # 关闭时执行
        logger.info("关闭 Sealium 激活服务...")


# ==================== 创建 FastAPI 应用 ====================
app = FastAPI(
        title="Sealium Activation Server",
        version="1.0.0",
        description="在线激活验证模块服务端",
        lifespan=lifespan,
        debug=config.DEBUG,
)

# ==================== CORS 中间件 ====================
app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
)

# ==================== 路由挂载 ====================
app.include_router(activation_router)


# ==================== 健康检查接口 ====================
@app.get("/health", tags=["health"])
async def health_check():
        """健康检查端点"""
        return {"status": "ok", "service": "activation"}


# ==================== 配置信息接口（仅调试模式） ====================
if config.DEBUG:
        @app.get("/debug/config", tags=["debug"])
        async def debug_config():
                """查看当前配置（仅调试模式）"""
                return {
                        "database_path": str(config.DATABASE_PATH),
                        "server_private_key": str(config.SERVER_PRIVATE_KEY_PATH),
                        "client_public_key": str(config.CLIENT_PUBLIC_KEY_PATH),
                        "time_stamp_tolerance": config.TIME_STAMP_TOLERANCE_SECONDS,
                        "replay_cache_size": config.REPLAY_CACHE_SIZE,
                        "host": config.HOST,
                        "port": config.PORT,
                        "debug": config.DEBUG,
                        "api_prefix": config.API_PREFIX,
                        "activation_path": config.ACTIVATION_PATH,
                }