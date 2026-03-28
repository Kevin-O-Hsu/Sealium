# src/sealium/common/utils.py
"""
通用工具模块（OOP 设计）
提供机器码生成、随机数生成、时间戳获取、激活码校验等功能
适用于 Windows 平台
"""

import hashlib
import secrets
import time
import requests
import wmi

from sealium.common.constants import  TIMESTAMP_API_URL, REQUEST_TIMEOUT_SECONDS

class Utils:
    """
    静态工具类，提供常用功能
    """

    @staticmethod
    def generate_machine_code() -> str:
        """
        生成 Windows 机器码
        组合硬盘序列号和 MAC 地址，使用 SHA256 哈希
        :return: 机器码（十六进制字符串）
        """
        c = wmi.WMI()
        # 获取第一个物理磁盘序列号
        disk_serial = None
        for disk in c.Win32_DiskDrive():
            # 过滤掉非物理磁盘（如虚拟光驱），可根据实际情况调整
            if disk.InterfaceType in ("IDE", "SCSI", "SATA"):
                disk_serial = disk.SerialNumber
                break
        # 获取第一个有效的 MAC 地址
        mac = None
        for nic in c.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress:
                mac = nic.MACAddress
                break
        # 组合并哈希
        combined = f"{disk_serial or ''}{mac or ''}".encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        """
        生成随机数（十六进制字符串）
        :param length: 字节长度（默认 16 字节，即 32 个十六进制字符）
        :return: 随机十六进制字符串
        """
        return secrets.token_hex(length)

    @staticmethod
    def get_timestamp_from_api(timeout: int = REQUEST_TIMEOUT_SECONDS) -> int:
        """
        从远程 API 获取权威时间戳（Unix 秒级）
        :param timeout: 请求超时时间（秒）
        :return: 时间戳（秒）
        :raises: 请求失败时抛出异常（可根据需要捕获）
        """
        url = TIMESTAMP_API_URL
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return int(data["timestamp"])

    @staticmethod
    def get_current_timestamp() -> int:
        """
        获取本地系统当前时间戳（秒）
        :return: 本地时间戳（秒）
        """
        return int(time.time())

    @staticmethod
    def validate_activation_code(code: str) -> bool:
        """
        校验激活码格式（简单非空检查）
        可根据实际激活码生成规则扩展（如长度、字符集等）
        :param code: 激活码字符串
        :return: 是否符合格式
        """
        return bool(code and isinstance(code, str))

    @staticmethod
    def is_timestamp_valid(timestamp: int, tolerance: int = 300) -> bool:
        """
        检查时间戳是否在允许偏差范围内（使用本地时间）
        :param timestamp: 待检查的时间戳（秒）
        :param tolerance: 允许的偏差秒数（默认 300 秒 = 5 分钟）
        :return: 是否有效
        """
        now = Utils.get_current_timestamp()
        return abs(now - timestamp) <= tolerance