#!/usr/bin/env python
# tests/test_integration.py
"""
真实集成测试：需要服务端已启动，数据库已配置，密钥文件存在。
运行前请确保：
  - 服务端已在 http://localhost:8000 运行（uvicorn sealium.server.app:app）
  - 数据库已初始化（运行 generate_activation_codes.py 生成至少一个激活码）
  - 客户端代码中的服务端公钥与服务端私钥匹配
"""

import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sealium.client.activator import Activator, ActivationError
from pathlib import Path
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage

# ==================== 配置（与服务端一致） ====================
DATABASE_PATH = Path("I:/Programming/Sealium/data/database.db")
SERVER_URL = "http://localhost:8000/v1/activation"

# 服务端公钥路径
SERVER_PUBLIC_KEY_PATH = Path("I:/Programming/Sealium/data/server_public.pem")
# 客户端私钥路径
CLIENT_PRIVATE_KEY_PATH = Path("I:/Programming/Sealium/data/client_private.pem")


# ==================== 辅助函数 ====================
def load_server_public_key() -> str:
    """加载服务端公钥"""
    if not SERVER_PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(f"服务端公钥文件不存在: {SERVER_PUBLIC_KEY_PATH}")
    with open(SERVER_PUBLIC_KEY_PATH, "r") as f:
        return f.read()


def load_client_private_key() -> str:
    """加载客户端私钥"""
    if not CLIENT_PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(f"客户端私钥文件不存在: {CLIENT_PRIVATE_KEY_PATH}")
    with open(CLIENT_PRIVATE_KEY_PATH, "r") as f:
        return f.read()


def main():
    print("=== 开始集成测试 ===")

    # 1. 检查服务端是否可访问
    import requests

    try:
        resp = requests.get("http://localhost:8000/health", timeout=2)
        if resp.status_code != 200:
            print("⚠️  服务端健康检查失败，请确认服务已启动。")
            return
        print("✅ 服务端健康检查通过")
    except Exception as e:
        print(f"❌ 无法连接服务端: {e}")
        print("请确保服务端已启动：uvicorn sealium.server.app:app --reload")
        return

    # 2. 从数据库获取一个未使用的激活码
    db = SQLiteDatabase(DATABASE_PATH)
    db.connect()
    storage = ActivationCodeStorage(db)

    all_codes = storage.list_all()
    unused = [c for c in all_codes if c.status == 0]  # 0 表示未激活

    if not unused:
        print(
            "❌ 数据库中没有未使用的激活码，请先运行 generate_activation_codes.py 生成。"
        )
        db.close()
        return

    test_code = unused[0].activation_code
    print(f"📋 使用激活码: {test_code}")

    # 3. 创建客户端激活器（需要传入服务端公钥和客户端私钥）
    try:
        server_pub_key = load_server_public_key()
        client_priv_key = load_client_private_key()
    except Exception as e:
        print(f"❌ 加载密钥失败: {e}")
        db.close()
        return

    activator = Activator(SERVER_URL, server_pub_key, client_priv_key)

    # 4. 执行激活
    print("🔄 正在激活...")
    try:
        response = activator.activate(test_code)
    except ActivationError as e:
        print(f"❌ 激活失败: {e}")
        db.close()
        return

    # 5. 输出结果
    if response.result == "success":
        print("✅ 激活成功！")
        print(f"   授权截止: {response.authorized_until}")
        print(f"   功能: {response.features}")

        # 再次查询数据库，确认激活码已绑定
        updated = storage.get_by_code(test_code)
        if updated and updated.status == 1:
            print(f"✅ 数据库验证: 激活码已绑定机器码 {updated.bound_machine_code}")
        else:
            print("⚠️  数据库记录未更新，请检查服务端逻辑")
    else:
        print(f"❌ 激活失败: {response.error_msg}")

    db.close()


if __name__ == "__main__":
    main()
