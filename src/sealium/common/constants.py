# src/sealium/common/constants.py
"""
常量定义模块
"""

# ==================== RSA 相关 ====================
RSA_KEY_SIZE: int = 2048  # 密钥长度（位）

# ==================== 时间相关 ====================
TIME_STAMP_TOLERANCE_SECONDS = 300  # 时间戳允许偏差（秒），5分钟

# ==================== 激活码状态 ====================
ACTIVATION_STATUS_UNUSED = 0  # 未激活
ACTIVATION_STATUS_USED = 1  # 已激活

# ==================== 网络请求相关 ====================
REQUEST_TIMEOUT_SECONDS = 10  # HTTP 请求超时时间（秒）
TIMESTAMP_API_URL = "https://aisenseapi.com/services/v1/timestamp"  # 权威时间戳 API
