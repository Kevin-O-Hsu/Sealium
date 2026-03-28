# run_server.py - 服务端启动脚本

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "sealium.server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # 开发模式
        log_level="info"
    )