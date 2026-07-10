# src/sealium/client/activator.py
"""
客户端激活核心逻辑。

每次启动时调用，与服务器验证激活码。对外只暴露 ``Activator`` 与
``ActivationError``；时间源、机器码、HTTP 传输均可注入，便于测试。
"""

from __future__ import annotations

import json
import secrets
from typing import Callable, Optional

import requests

from sealium.common import constants
from sealium.common.exceptions import ActivationError  # 重新导出，保持导入路径兼容
from sealium.common.machine_code import generate_machine_code
from sealium.common.models import ActivationRequest, ActivationResponse
from sealium.common.time_source import get_timestamp_from_api
from sealium.client.key_manager import ClientKeyManager

__all__ = ["Activator", "ActivationError"]

# HTTP 发送器签名：(url, data, headers, timeout) -> response（含 content / raise_for_status）
HttpPoster = Callable[..., object]


def _default_post(url: str, data: bytes, headers: dict, timeout: int) -> object:
    """默认 HTTP 发送实现（requests）。"""
    return requests.post(url, data=data, headers=headers, timeout=timeout)


class Activator:
    """激活器：执行完整的客户端激活流程。"""

    def __init__(
        self,
        server_url: str,
        server_public_key_pem: str,
        *,
        timestamp_provider: Callable[[], int] = get_timestamp_from_api,
        machine_code_provider: Callable[[], str] = generate_machine_code,
        http_poster: HttpPoster = _default_post,
        key_manager: Optional[ClientKeyManager] = None,
        request_timeout: int = constants.REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """
        :param server_url: 服务器激活接口 URL。
        :param server_public_key_pem: 服务端公钥 PEM 字符串。
        :param timestamp_provider: 时间戳来源（默认远程权威 API）。
        :param machine_code_provider: 机器码来源（默认 Windows WMI 指纹）。
        :param http_poster: HTTP 发送器（默认 requests）。
        :param key_manager: 自定义密钥管理器；为 ``None`` 时按公钥新建。
        :param request_timeout: HTTP 超时（秒）。
        """
        self.server_url = server_url
        self.key_manager = key_manager or ClientKeyManager(server_public_key_pem)
        self._get_timestamp = timestamp_provider
        self._get_machine_code = machine_code_provider
        self._post = http_poster
        self._timeout = request_timeout

    def activate(self, activation_code: str) -> ActivationResponse:
        """
        执行激活流程。

        :return: ``ActivationResponse`` 对象。
        :raises ActivationError: 激活过程中发生错误。
        """
        # 1. 获取机器码
        try:
            machine_code = self._get_machine_code()
        except Exception as e:
            raise ActivationError(f"获取机器码失败: {e}") from e

        # 2. 生成随机 nonce（16 字节 -> 32 个十六进制字符）
        nonce_c = secrets.token_hex(16)

        # 3. 获取权威时间戳
        try:
            timestamp = self._get_timestamp()
        except Exception as e:
            raise ActivationError(f"获取时间戳失败: {e}") from e

        # 4. 构造请求明文（不含任何密钥）
        request_obj = ActivationRequest(
            activation_code=activation_code,
            machine_code=machine_code,
            timestamp=timestamp,
            nonce=nonce_c,
        )
        request_plain = json.dumps(request_obj.to_dict()).encode("utf-8")

        # 5. 双层加密请求（自动生成临时 AES 密钥）
        try:
            encrypted_request = self.key_manager.build_encrypted_request(request_plain)
        except Exception as e:
            raise ActivationError(f"加密请求失败: {e}") from e

        # 会话 AES 密钥用毕即清，避免在长生命周期进程中残留（LOW-004）
        try:
            # 6. 发送请求
            try:
                resp = self._post(
                    self.server_url,
                    encrypted_request,
                    {"Content-Type": "application/octet-stream"},
                    self._timeout,
                )
                resp.raise_for_status()
            except requests.RequestException as e:
                raise ActivationError(f"网络请求失败: {e}") from e

            # 7. 解密响应（用同一把 AES 密钥）
            try:
                decrypted_data = self.key_manager.decrypt_response(resp.content)
            except Exception as e:
                raise ActivationError(f"解密响应失败: {e}") from e

            # 8. 解析 JSON
            try:
                response_dict = json.loads(decrypted_data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ActivationError(f"解析响应失败: {e}") from e

            # 9. 构造响应对象
            activation_response = ActivationResponse.from_dict(response_dict)

            # 10. 校验回显 nonce（防篡改 / 防重放）
            if activation_response.result == "success":
                if activation_response.nonce != nonce_c:
                    raise ActivationError("响应 nonce 不匹配，可能是重放攻击")

            return activation_response
        finally:
            self.key_manager.clear_aes_key()
