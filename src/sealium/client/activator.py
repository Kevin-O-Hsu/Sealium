# src/sealium/client/activator.py
"""
客户端激活核心逻辑
每次启动时调用，与服务器验证激活码
"""

import json
import requests
from typing import Optional, Tuple

from sealium.common import constants
from sealium.common.utils import Utils
from sealium.common.models import ActivationRequest, ActivationResponse
from sealium.client.key_manager import ClientKeyManager


class ActivationError(Exception):
    """激活相关异常"""
    pass


class Activator:
    """
    激活器
    负责执行完整的激活流程
    """

    def __init__(self, server_url: str, server_public_key_pem: str):
        """
        初始化激活器

        :param server_url: 服务器激活接口 URL
        :param server_public_key_pem: 服务端公钥 PEM 字符串
        """
        self.server_url = server_url
        self.server_public_key_pem = server_public_key_pem

    def activate(self, activation_code: str) -> ActivationResponse:
        """
        执行激活流程

        :param activation_code: 用户输入的激活码
        :return: ActivationResponse 对象
        :raises ActivationError: 激活过程中发生错误
        """
        # 1. 获取机器码
        machine_code = Utils.generate_machine_code()

        # 2. 生成随机数 nonce
        nonce_c = Utils.generate_nonce(16)  # 16 字节 -> 32 个十六进制字符

        # 3. 获取权威时间戳
        try:
            timestamp = Utils.get_timestamp_from_api(timeout=constants.REQUEST_TIMEOUT_SECONDS)
        except Exception as e:
            raise ActivationError(f"获取时间戳失败: {e}")

        # 4. 创建密钥管理器并生成临时密钥对
        key_mgr = ClientKeyManager(self.server_public_key_pem)
        client_pubkey = key_mgr.generate_temp_keypair()

        # 5. 构造请求明文
        request_obj = ActivationRequest(
            activation_code=activation_code,
            machine_code=machine_code,
            timestamp=timestamp,
            nonce=nonce_c,
            client_pubkey=client_pubkey,
        )
        request_plain = json.dumps(request_obj.to_dict()).encode('utf-8')

        # 6. 加密请求
        try:
            encrypted_request = key_mgr.encrypt_request(request_plain)
        except Exception as e:
            raise ActivationError(f"加密请求失败: {e}")

        # 7. 发送 HTTPS 请求
        try:
            resp = requests.post(
                self.server_url,
                data=encrypted_request,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=constants.REQUEST_TIMEOUT_SECONDS
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise ActivationError(f"网络请求失败: {e}")

        # 8. 解密响应
        try:
            decrypted_data = key_mgr.decrypt_response(resp.content)
        except Exception as e:
            raise ActivationError(f"解密响应失败: {e}")

        # 9. 解析 JSON
        try:
            response_dict = json.loads(decrypted_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ActivationError(f"解析响应失败: {e}")

        # 10. 创建响应对象
        activation_response = ActivationResponse.from_dict(response_dict)

        # 11. 验证 nonce（确保响应中的 nonce 存在且非空）
        if activation_response.nonce is None or len(activation_response.nonce) == 0:
            raise ActivationError("响应中缺少 nonce")

        return activation_response