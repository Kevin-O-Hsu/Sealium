# src/sealium/common/utils.py
"""
通用工具模块（OOP 设计）
提供机器码生成、随机数生成、时间戳处理、激活码格式校验等功能
"""

import hashlib
import os
import platform
import secrets
import socket
import time
import uuid


class Utility:
    """工具类，所有方法均为静态方法"""

    @staticmethod
    def generate_machine_code() -> str:
        """
        生成机器码
        组合硬件信息（主机名、MAC地址、硬盘序列号等）并哈希
        返回 64 位十六进制字符串（SHA256）
        """
        # 获取主机名
        hostname = socket.gethostname()

        # 获取 MAC 地址（使用 uuid.getnode()，可能返回虚拟MAC，但简单可用）
        mac = uuid.getnode()
        mac_hex = hex(mac)

        # 获取硬盘序列号（尝试多种方式，如果失败则使用默认值）
        disk_serial = Utility._get_disk_serial()

        # 获取系统信息
        system = platform.system()
        release = platform.release()
        processor = platform.processor()

        # 组合原始信息
        raw = f"{hostname}|{mac_hex}|{disk_serial}|{system}|{release}|{processor}"
        # 计算 SHA256
        machine_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return machine_hash

    @staticmethod
    def _get_disk_serial() -> str:
        """
        尝试获取硬盘序列号
        使用标准库，如果失败则返回默认值
        """
        try:
            if platform.system() == "Windows":
                import wmi
                c = wmi.WMI()
                for disk in c.Win32_PhysicalMedia():
                    if disk.SerialNumber:
                        return disk.SerialNumber.strip()
            elif platform.system() == "Linux":
                # 尝试读取 /etc/machine-id 或 /var/lib/dbus/machine-id
                machine_id_paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
                for path in machine_id_paths:
                    if os.path.exists(path):
                        with open(path, "r") as f:
                            return f.read().strip()
            elif platform.system() == "Darwin":  # macOS
                # 使用 system_profiler 获取硬件 UUID
                import subprocess
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True,
                    text=True
                )
                for line in result.stdout.split("\n"):
                    if "Hardware UUID" in line:
                        return line.split(":")[-1].strip()
        except Exception:
            pass
        # 默认返回一个随机标识（避免空值）
        return "UNKNOWN_DISK_SERIAL"

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        """
        生成随机数（十六进制字符串）
        :param length: 字节数，默认16字节，返回32字符的十六进制字符串
        :return: 十六进制随机字符串
        """
        random_bytes = secrets.token_bytes(length)
        return random_bytes.hex()

    @staticmethod
    def get_current_timestamp() -> int:
        """
        获取当前 Unix 时间戳（秒）
        :return: 秒级时间戳整数
        """
        return int(time.time())

    @staticmethod
    def is_valid_activation_code(code: str) -> bool:
        """
        校验激活码格式
        :param code: 激活码字符串
        :return: 是否符合格式
        """
        if not isinstance(code, str):
            return False
        # 示例：激活码应为 32 位十六进制字符（可通过配置调整）
        # 可根据实际业务修改规则
        if len(code) != 32:
            return False
        # 只允许十六进制字符（大小写均可）
        try:
            int(code, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_timestamp_valid(timestamp: int, tolerance: int = 300) -> bool:
        """
        校验时间戳是否在允许偏差内
        :param timestamp: 客户端时间戳（秒）
        :param tolerance: 允许偏差（秒），默认5分钟
        :return: 是否有效
        """
        now = Utility.get_current_timestamp()
        diff = abs(now - timestamp)
        return diff <= tolerance

    @staticmethod
    def get_public_key_hash(public_key_pem: bytes) -> str:
        """
        计算公钥哈希（用于标识或缓存）
        :param public_key_pem: PEM 格式公钥（字节）
        :return: SHA256 十六进制字符串
        """
        return hashlib.sha256(public_key_pem).hexdigest()