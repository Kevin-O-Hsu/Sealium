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
import os

if os.name == "nt":
    import wmi

    print("Running on Windows")
else:
    print("Running on Unix-like system (Linux/Mac)")

from sealium.common.constants import TIMESTAMP_API_URL, REQUEST_TIMEOUT_SECONDS


class Utils:
    """
    静态工具类，提供常用功能
    """

    @staticmethod
    def generate_machine_code() -> str:
        """
        生成高强度 Windows 机器码
        组合多种硬件标识符（CPU、主板、BIOS、硬盘、MAC、Windows 序列号等）
        使用 SHA256 哈希，提供熵值检查和容错机制
        :return: 机器码（64 位十六进制字符串）
        """
        c = wmi.WMI()
        hardware_info = []

        # 1. CPU 信息（权重高）
        try:
            for processor in c.Win32_Processor():
                cpu_id = getattr(processor, "ProcessorId", None)
                if cpu_id:
                    hardware_info.append(("cpu", cpu_id.strip()))
                    break
        except Exception:
            pass

        # 2. 主板信息（权重高）
        try:
            for board in c.Win32_BaseBoard():
                serial = getattr(board, "SerialNumber", None)
                product = getattr(board, "Product", None)
                if serial or product:
                    hardware_info.append(
                        ("board", f"{serial or ''}{product or ''}".strip())
                    )
                    break
        except Exception:
            pass

        # 3. BIOS 信息（权重高）
        try:
            for bios in c.Win32_BIOS():
                serial = getattr(bios, "SerialNumber", None)
                version = getattr(bios, "Version", None)
                if serial or version:
                    hardware_info.append(
                        ("bios", f"{serial or ''}{version or ''}".strip())
                    )
                    break
        except Exception:
            pass

        # 4. 操作系统信息（权重中）
        try:
            for os in c.Win32_OperatingSystem():
                serial = getattr(os, "SerialNumber", None)
                if serial:
                    hardware_info.append(("os", serial.strip()))
                    break
        except Exception:
            pass

        # 5. 物理硬盘信息（权重高）- 收集所有物理硬盘
        try:
            disk_count = 0
            for disk in c.Win32_DiskDrive():
                if disk_count >= 3:  # 最多取 3 块硬盘
                    break
                interface = getattr(disk, "InterfaceType", "")
                # 过滤掉虚拟光驱和 USB 设备
                if interface in ("IDE", "SCSI", "SATA", "NVMe", "RAID"):
                    serial = getattr(disk, "SerialNumber", None)
                    model = getattr(disk, "Model", None)
                    if serial or model:
                        hardware_info.append(
                            ("disk", f"{serial or ''}{model or ''}".strip())
                        )
                        disk_count += 1
        except Exception:
            pass

        # 6. MAC 地址（权重中）- 收集所有有效网卡
        try:
            mac_addresses = []
            for nic in c.Win32_NetworkAdapterConfiguration():
                if nic.MACAddress:
                    mac = nic.MACAddress.replace(":", "").replace("-", "").upper()
                    # 过滤掉虚拟网卡和回环地址
                    if (
                        mac
                        and not mac.startswith("000000000000")
                        and not mac.startswith("FFFFFFFFFFFF")
                    ):
                        mac_addresses.append(mac)
            # 排序后取前 3 个（保证一致性）
            mac_addresses.sort()
            for mac in mac_addresses[:3]:
                hardware_info.append(("mac", mac))
        except Exception:
            pass

        # 7. 机箱序列号（权重中）
        try:
            for chassis in c.Win32_SystemEnclosure():
                serial = getattr(chassis, "SerialNumber", None)
                if serial:
                    hardware_info.append(("chassis", serial.strip()))
                    break
        except Exception:
            pass

        # 8. 显示器信息（权重低）
        try:
            for monitor in c.Win32_DesktopMonitor():
                name = getattr(monitor, "Name", None)
                pnpid = getattr(monitor, "PNPDeviceID", None)
                if name or pnpid:
                    hardware_info.append(
                        ("monitor", f"{name or ''}{pnpid or ''}".strip())
                    )
                    break
        except Exception:
            pass

        # 9. 计算机名和用户名（权重低）
        try:
            for computer in c.Win32_ComputerSystem():
                name = getattr(computer, "Name", None)
                username = getattr(computer, "UserName", None)
                if name or username:
                    hardware_info.append(
                        ("computer", f"{name or ''}{username or ''}".strip())
                    )
                    break
        except Exception:
            pass

        # 检查是否收集到足够的硬件信息
        if len(hardware_info) < 3:
            # 如果信息太少，添加系统时间作为补充（降低安全性但保证可用性）
            hardware_info.append(("fallback", str(time.time())))

        # 10. 构建组合字符串（带类型标签，防止位置交换攻击）
        combined_parts = []
        for info_type, info_value in sorted(hardware_info, key=lambda x: x[0]):
            # 格式：类型：值；类型：值；...
            combined_parts.append(f"{info_type}:{info_value}")

        combined = "|".join(combined_parts).encode("utf-8")

        # 11. 生成 SHA256 哈希
        machine_code = hashlib.sha256(combined).hexdigest()

        # 12. 熵值检查（确保不是全 0 或简单重复）
        unique_chars = len(set(machine_code))
        if unique_chars < 10:  # 熵值过低
            # 添加额外盐值重新哈希
            salt = secrets.token_hex(16)
            combined_with_salt = combined + salt.encode("utf-8")
            machine_code = hashlib.sha256(combined_with_salt).hexdigest()

        return machine_code

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
