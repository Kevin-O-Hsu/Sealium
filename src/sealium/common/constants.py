# src/sealium/common/constants.py
"""
协议与算法常量。

只存放与部署无关的纯常量（密钥长度、nonce 长度、网络端点等）。
部署相关的可调参数（如时间戳容忍度）属于服务端配置，集中定义在
``sealium.server.config``，避免同一事实出现两份真相。
"""

from __future__ import annotations

# ==================== RSA ====================
RSA_KEY_SIZE: int = 4096  # RSA 密钥长度（位）

# ==================== AES-256-GCM ====================
AES_KEY_SIZE: int = 256  # AES 密钥长度（位）= 32 字节
AES_GCM_NONCE_SIZE: int = 12  # GCM nonce 长度（字节）
AES_GCM_TAG_SIZE: int = 16  # GCM 认证标签长度（字节）

# ==================== 激活码 ====================
ACTIVATION_CODE_BYTES: int = 16  # 随机字节数；十六进制编码后为 32 字符（128 位）
ACTIVATION_STATUS_UNUSED: int = 0
ACTIVATION_STATUS_USED: int = 1
# 激活码哈希存储的默认 pepper（MEDIUM-002）。源码内固定值仅作域分隔兜底；
# 生产部署应经 SEALIUM_SECURITY__CODE_HASH_PEPPER 注入随机值以获得部署唯一性。
# 与 fingerprint pepper 同理：激活码已 128 位高熵，pepper 公开亦不影响预像安全。
CODE_HASH_PEPPER_DEFAULT: str = "sealium-v1-code-hash-pepper"

# ==================== 网络 / 权威时间源 ====================
REQUEST_TIMEOUT_SECONDS: int = 10  # HTTP 请求超时（秒）
TIMESTAMP_API_URL: str = "https://aisenseapi.com/services/v1/timestamp"  # 权威时间戳 API
# 激活请求体大小硬上限（MEDIUM-001）：合法包 < 8KB（RSA-4096 密文 + AES 包 + 小 JSON 明文），
# 设 64KB 给足余量，超限直接 413 拒绝，防单个大包触发 json.loads 内存耗尽 DoS。
MAX_ACTIVATION_BODY_BYTES: int = 65_536
# 解密后 JSON 明文大小上限（MEDIUM-001 纵深）：堵住"小密钥包解出超大 JSON"的二次放大。
MAX_ACTIVATION_PLAINTEXT_BYTES: int = 65_536
