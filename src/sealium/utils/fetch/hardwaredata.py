import platform
import os
import subprocess
import winreg
from typing import Optional

class HardwareData:
    def __init__(self):
        """初始化硬件数据对象，自动获取所有硬件信息"""
        self.system_volume_serial: Optional[str] = self.get_system_volume_serial()
        self.system_volume_name: Optional[str] = self.get_system_volume_name()
        self.computer_name: Optional[str] = self.get_computer_name()
        self.cpu_type: Optional[str] = self.get_cpu_type()
        self.bios_info: Optional[str] = self.get_bios_info()
        self.windows_serial: Optional[str] = self.get_windows_serial()
        self.disk_serial: Optional[str] = self.get_disk_serial()
        self.windows_username: Optional[str] = self.get_windows_username()
    
    @staticmethod
    def get_system_volume_serial() -> Optional[str]:
        """获取系统卷标序列号（使用Windows API）"""
        try:
            # 使用 Windows API 获取卷序列号
            import ctypes
            from ctypes import wintypes
            
            # 定义函数原型
            kernel32 = ctypes.windll.kernel32
            GetVolumeInformationW = kernel32.GetVolumeInformationW
            GetVolumeInformationW.argtypes = [
                wintypes.LPCWSTR,  # lpRootPathName
                wintypes.LPWSTR,   # lpVolumeNameBuffer
                wintypes.DWORD,    # nVolumeNameSize
                ctypes.POINTER(wintypes.DWORD),  # lpVolumeSerialNumber
                ctypes.POINTER(wintypes.DWORD),  # lpMaximumComponentLength
                ctypes.POINTER(wintypes.DWORD),  # lpFileSystemFlags
                wintypes.LPWSTR,   # lpFileSystemNameBuffer
                wintypes.DWORD     # nFileSystemNameSize
            ]
            GetVolumeInformationW.restype = wintypes.BOOL
            
            # 准备缓冲区
            volume_name_buffer = ctypes.create_unicode_buffer(256)
            file_system_name_buffer = ctypes.create_unicode_buffer(256)
            volume_serial_number = wintypes.DWORD()
            max_component_length = wintypes.DWORD()
            file_system_flags = wintypes.DWORD()
            
            # 调用 API
            result = GetVolumeInformationW(
                "C:\\",
                volume_name_buffer,
                256,
                ctypes.byref(volume_serial_number),
                ctypes.byref(max_component_length),
                ctypes.byref(file_system_flags),
                file_system_name_buffer,
                256
            )
            
            if result:
                # 格式化为十六进制字符串
                serial = volume_serial_number.value
                return f"{serial:08X}"
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_system_volume_name() -> Optional[str]:
        """获取系统卷标名称（使用Windows API）"""
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            GetVolumeInformationW = kernel32.GetVolumeInformationW
            GetVolumeInformationW.argtypes = [
                wintypes.LPCWSTR,  # lpRootPathName
                wintypes.LPWSTR,   # lpVolumeNameBuffer
                wintypes.DWORD,    # nVolumeNameSize
                ctypes.POINTER(wintypes.DWORD),  # lpVolumeSerialNumber
                ctypes.POINTER(wintypes.DWORD),  # lpMaximumComponentLength
                ctypes.POINTER(wintypes.DWORD),  # lpFileSystemFlags
                wintypes.LPWSTR,   # lpFileSystemNameBuffer
                wintypes.DWORD     # nFileSystemNameSize
            ]
            GetVolumeInformationW.restype = wintypes.BOOL
            
            volume_name_buffer = ctypes.create_unicode_buffer(256)
            file_system_name_buffer = ctypes.create_unicode_buffer(256)
            volume_serial_number = wintypes.DWORD()
            max_component_length = wintypes.DWORD()
            file_system_flags = wintypes.DWORD()
            
            result = GetVolumeInformationW(
                "C:\\",
                volume_name_buffer,
                256,
                ctypes.byref(volume_serial_number),
                ctypes.byref(max_component_length),
                ctypes.byref(file_system_flags),
                file_system_name_buffer,
                256
            )
            
            if result and volume_name_buffer.value:
                return volume_name_buffer.value
            return "本地磁盘"  # 默认名称
        except Exception:
            return None
    
    @staticmethod
    def get_computer_name() -> Optional[str]:
        """获取计算机名称（使用环境变量）"""
        try:
            return os.environ.get('COMPUTERNAME', platform.node())
        except Exception:
            return platform.node()
    
    @staticmethod
    def get_cpu_type() -> Optional[str]:
        """获取CPU类型（使用注册表）"""
        try:
            # 从注册表获取CPU信息
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            cpu_name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
            winreg.CloseKey(key)
            return cpu_name.strip()
        except Exception:
            return platform.processor()
    
    @staticmethod
    def get_bios_info() -> Optional[str]:
        """获取主板BIOS信息（使用注册表）"""
        try:
            # 获取BIOS版本
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                r"HARDWARE\DESCRIPTION\System\BIOS")
            bios_version = winreg.QueryValueEx(key, "BIOSVersion")[0]
            winreg.CloseKey(key)
            
            if isinstance(bios_version, list):
                return " ".join(bios_version)
            return str(bios_version)
        except Exception:
            return None
    
    @staticmethod
    def get_windows_serial() -> str:
        """
        Windows Product Serial Number
        """
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

            # Open registry key, force 64-bit view (safe for 32-bit Python on 64-bit Windows)
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )

            try:
                # Query the ProductId value
                product_id, _ = winreg.QueryValueEx(key, "ProductId")
            finally:
                # Always close the registry key handle
                winreg.CloseKey(key)

            # Validate result
            if isinstance(product_id, str) and product_id.strip():
                return product_id.strip()
            else:
                raise ValueError("ProductId is empty or invalid")

        except FileNotFoundError:
            raise FileNotFoundError(
                "Registry path not found. Ensure you're running on Windows "
                "and the key exists under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            )
        except PermissionError:
            raise PermissionError(
                "Insufficient permissions to read registry. Try running as Administrator."
            )
        except OSError as e:
            raise OSError(f"OS-level registry error: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error while reading Windows ProductId: {e}")
    
    @staticmethod
    def get_disk_serial() -> Optional[str]:
        """获取硬盘序列号（使用PowerShell）"""
        try:
            # 使用 PowerShell 获取物理磁盘序列号
            cmd = [
                'powershell', 
                '-Command', 
                'Get-PhysicalDisk | Select-Object -First 1 SerialNumber | Format-List'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                output = result.stdout.strip()
                # 提取序列号
                lines = output.split('\n')
                for line in lines:
                    if 'SerialNumber' in line:
                        serial = line.split(':', 1)[1].strip()
                        if serial:
                            return serial
            return None
        except Exception:
            # 备用方法：使用不同的PowerShell命令
            try:
                cmd = [
                    'powershell', 
                    '-Command', 
                    '(Get-WmiObject -Class Win32_DiskDrive | Select-Object -First 1).SerialNumber'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    serial = result.stdout.strip()
                    if serial:
                        return serial
                return None
            except Exception:
                return None
    
    @staticmethod
    def get_windows_username() -> Optional[str]:
        """获取Windows用户名（使用环境变量）"""
        try:
            return os.environ.get('USERNAME', os.environ.get('USER', None))
        except Exception:
            return None
    
    def __str__(self) -> str:
        """返回硬件信息的字符串表示"""
        return f"""Hardware Data:
- System Volume Serial: {self.system_volume_serial}
- System Volume Name: {self.system_volume_name}
- Computer Name: {self.computer_name}
- CPU Type: {self.cpu_type}
- BIOS Info: {self.bios_info}
- Windows Serial: {self.windows_serial}
- Disk Serial: {self.disk_serial}
- Windows Username: {self.windows_username}"""
    
    def to_dict(self) -> dict:
        """返回硬件信息的字典表示"""
        return {
            'system_volume_serial': self.system_volume_serial,
            'system_volume_name': self.system_volume_name,
            'computer_name': self.computer_name,
            'cpu_type': self.cpu_type,
            'bios_info': self.bios_info,
            'windows_serial': self.windows_serial,
            'disk_serial': self.disk_serial,
            'windows_username': self.windows_username
        }

# 使用示例
if __name__ == "__main__":
    # 创建硬件数据对象
    hw_data = HardwareData()
    
    # 打印所有信息
    print(hw_data)
    
    # 或者以字典形式获取
    print("\n字典形式:")
    print(hw_data.to_dict())