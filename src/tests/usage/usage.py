#!/usr/bin/env python
# src/tests/usage/usage.py
"""
使用示例：激活码激活流程
演示如何初始化 Activator 并执行激活。
"""

import sys
from pathlib import Path

# 添加项目根目录到 Python 路径（此脚本位于 src/tests/usage/）
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from sealium.client.activator import Activator, ActivationError

# ==================== 配置 ====================
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # 项目根目录
DATA_DIR = PROJECT_ROOT / "data"  # 存放密钥和数据库的目录
SERVER_PUBLIC_KEY_FILE = DATA_DIR / "server_public.pem"  # 服务端公钥
CLIENT_PRIVATE_KEY_FILE = DATA_DIR / "client_private.pem"  # 客户端私钥
SERVER_URL = "http://localhost:8000/v1/activation"  # 激活接口地址


def main():
    print("=== Sealium 激活客户端示例 ===\n")

    # 1. 检查密钥文件是否存在
    if not SERVER_PUBLIC_KEY_FILE.exists():
        print(f"错误：服务端公钥文件不存在: {SERVER_PUBLIC_KEY_FILE}")
        return
    if not CLIENT_PRIVATE_KEY_FILE.exists():
        print(f"错误：客户端私钥文件不存在: {CLIENT_PRIVATE_KEY_FILE}")
        return

    # 2. 读取密钥内容
    with open(SERVER_PUBLIC_KEY_FILE, "r") as f:
        server_pub_key = f.read()
    with open(CLIENT_PRIVATE_KEY_FILE, "r") as f:
        client_priv_key = f.read()

    # 3. 创建激活器
    activator = Activator(SERVER_URL, server_pub_key, client_priv_key)

    # 4. 获取用户输入的激活码
    activation_code = input("请输入激活码: ").strip()
    if not activation_code:
        print("激活码不能为空")
        return

    # 5. 执行激活
    print("\n正在激活...")
    try:
        response = activator.activate(activation_code)
    except ActivationError as e:
        print(f"激活失败: {e}")
        return

    # 6. 输出结果
    if response.result == "success":
        print("\n✅ 激活成功！")
        print(f"授权截止: {response.authorized_until}")
        if response.features:
            print(f"功能: {', '.join(response.features)}")
        else:
            print("功能: 无")
        print(f"服务器返回的随机数: {response.nonce}")
    else:
        print(f"\n❌ 激活失败: {response.error_msg}")


if __name__ == "__main__":
    main()
