# src/sealium/server/app.py
"""
FastAPI 应用入口
创建应用实例，配置中间件，挂载路由
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from sealium.server.activation import router as activation_router

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
        """
        应用生命周期管理
        启动时执行初始化，关闭时执行清理
        """
        # 启动时执行
        logger.info("启动 Sealium 激活服务...")
        # 可在此添加数据库连接检查、私钥检查等
        # 例如：验证数据库连接是否正常、服务端私钥是否可加载等

        yield  # 应用运行期间

        # 关闭时执行
        logger.info("关闭 Sealium 激活服务...")
        # 可在此添加资源清理逻辑，如关闭数据库连接池等


# 创建 FastAPI 应用，传入 lifespan
app = FastAPI(
        title="Sealium Activation Server",
        version="1.0.0",
        description="在线激活验证模块服务端",
        lifespan=lifespan,  # 使用新的生命周期管理方式
)

# CORS 中间件（允许所有来源，生产环境建议限制）
app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
)

# 挂载激活路由
app.include_router(activation_router)


# 健康检查接口
@app.get("/health", tags=["health"])
async def health_check():
        """健康检查端点"""
        return {"status": "ok", "service": "activation"}