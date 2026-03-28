# src/sealium/common/constants.py
"""
常量定义模块
"""

# ==================== RSA 相关 ====================
RSA_KEY_SIZE: int = 2048                  # 密钥长度（位）

# ==================== 时间相关 ====================
TIME_STAMP_TOLERANCE_SECONDS = 300   # 时间戳允许偏差（秒），5分钟

# ==================== 激活码状态 ====================
ACTIVATION_STATUS_UNUSED = 0         # 未激活
ACTIVATION_STATUS_USED = 1           # 已激活

# ==================== 网络请求相关 ====================
REQUEST_TIMEOUT_SECONDS = 10         # HTTP 请求超时时间（秒）
TIMESTAMP_API_URL = "https://aisenseapi.com/services/v1/timestamp"  # 权威时间戳 API

# ==================== 激活码相关 ====================
ACTIVATION_CODE_LENGTH = 32          # 激活码长度（字符），可根据实际调整

# ==================== 本地存储相关 ====================
LOCAL_LICENSE_FILENAME = "license.dat"    # 本地授权文件名
LOCAL_KEY_FILENAME = "client_key.pem"     # 客户端私钥文件名（可选）

# ==================== 调试/开发相关 ====================
DEBUG_MODE = False                   # 调试模式（生产环境设为 False）