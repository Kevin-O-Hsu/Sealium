# tests/test_hardwaredata.py

import unittest
from unittest.mock import patch, MagicMock
import sys
import winreg
from subprocess import CompletedProcess
from sealium.utils.fetch import HardwareData


class TestHardwareDataUnit(unittest.TestCase):
    """单元测试：模拟所有外部依赖，确保逻辑分支正确"""

    @patch('sealium.utils.fetch.hardwaredata.ctypes.windll.kernel32.GetVolumeInformationW', side_effect=Exception("API崩溃"))
    def test_get_system_volume_serial_exception_returns_none(self, mock_api):
        result = HardwareData.get_system_volume_serial()
        self.assertIsNone(result)

    @patch('sealium.utils.fetch.hardwaredata.ctypes.windll.kernel32.GetVolumeInformationW')
    @patch('sealium.utils.fetch.hardwaredata.ctypes.create_unicode_buffer')
    def test_get_system_volume_name_success(self, mock_buffer, mock_api):
        mock_vol_buf = MagicMock()
        mock_vol_buf.value = "OS"
        mock_fs_buf = MagicMock()

        mock_buffer.side_effect = [mock_vol_buf, mock_fs_buf]
        mock_api.return_value = True

        result = HardwareData.get_system_volume_name()
        self.assertEqual(result, "OS")

    @patch('sealium.utils.fetch.hardwaredata.ctypes.windll.kernel32.GetVolumeInformationW', return_value=False)
    def test_get_system_volume_name_api_fail_returns_default(self, mock_api):
        result = HardwareData.get_system_volume_name()
        self.assertEqual(result, None)

    @patch('sealium.utils.fetch.hardwaredata.ctypes.windll.kernel32.GetVolumeInformationW', side_effect=Exception("模拟异常"))
    def test_get_system_volume_name_exception_returns_none(self, mock_api):
        result = HardwareData.get_system_volume_name()
        self.assertIsNone(result)

    @patch.dict('sealium.utils.fetch.hardwaredata.os.environ', {"COMPUTERNAME": "DEVBOX"})
    def test_get_computer_name_from_env(self):
        result = HardwareData.get_computer_name()
        self.assertEqual(result, "DEVBOX")

    @patch.dict('sealium.utils.fetch.hardwaredata.os.environ', {}, clear=True)
    @patch('sealium.utils.fetch.hardwaredata.platform.node', return_value="host-fallback")
    def test_get_computer_name_fallback_to_platform_node(self, mock_node):
        result = HardwareData.get_computer_name()
        self.assertEqual(result, "host-fallback")

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey')
    @patch('sealium.utils.fetch.hardwaredata.winreg.QueryValueEx')
    @patch('sealium.utils.fetch.hardwaredata.winreg.CloseKey')
    def test_get_cpu_type_success(self, mock_close, mock_query, mock_open):
        mock_query.return_value = ["Intel(R) Core(TM) i9-12900K", 1]
        result = HardwareData.get_cpu_type()
        self.assertEqual(result, "Intel(R) Core(TM) i9-12900K")
        mock_open.assert_called_once_with(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        )

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey', side_effect=Exception("注册表错误"))
    @patch('sealium.utils.fetch.hardwaredata.platform.processor', return_value="ARM64 Family")
    def test_get_cpu_type_fallback_to_platform_processor(self, mock_processor, mock_open):
        result = HardwareData.get_cpu_type()
        self.assertEqual(result, "ARM64 Family")

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey')
    @patch('sealium.utils.fetch.hardwaredata.winreg.QueryValueEx')
    @patch('sealium.utils.fetch.hardwaredata.winreg.CloseKey')
    def test_get_bios_info_list_joined(self, mock_close, mock_query, mock_open):
        mock_query.return_value = [["Dell Inc.", "1.5.6"], 1]
        result = HardwareData.get_bios_info()
        self.assertEqual(result, "Dell Inc. 1.5.6")

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey')
    @patch('sealium.utils.fetch.hardwaredata.winreg.QueryValueEx')
    @patch('sealium.utils.fetch.hardwaredata.winreg.CloseKey')
    def test_get_bios_info_string(self, mock_close, mock_query, mock_open):
        mock_query.return_value = ["American Megatrends v5.12", 1]
        result = HardwareData.get_bios_info()
        self.assertEqual(result, "American Megatrends v5.12")

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey', side_effect=Exception("BIOS键不存在"))
    def test_get_bios_info_exception_returns_none(self, mock_open):
        result = HardwareData.get_bios_info()
        self.assertIsNone(result)

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey')
    @patch('sealium.utils.fetch.hardwaredata.winreg.QueryValueEx')
    @patch('sealium.utils.fetch.hardwaredata.winreg.CloseKey')
    def test_get_windows_serial_success(self, mock_close, mock_query, mock_open):
        mock_query.return_value = ["00330-80000-00000-AA999", 1]
        result = HardwareData.get_windows_serial()
        self.assertEqual(result, "00330-80000-00000-AA999")

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey')
    @patch('sealium.utils.fetch.hardwaredata.winreg.QueryValueEx', return_value=["", 1])
    @patch('sealium.utils.fetch.hardwaredata.winreg.CloseKey') # Mock closekey
    def test_get_windows_serial_empty_raises_valueerror(self, mock_close, mock_query, mock_open):
        with self.assertRaises(ValueError) as cm:
            HardwareData.get_windows_serial()
        self.assertIn("ProductId is empty", str(cm.exception))

    @patch('sealium.utils.fetch.hardwaredata.winreg.OpenKey', side_effect=FileNotFoundError)
    def test_get_windows_serial_file_not_found_raises(self, mock_open):
        with self.assertRaises(FileNotFoundError) as cm:
            HardwareData.get_windows_serial()
        self.assertIn("Registry path not found", str(cm.exception))

    @patch('sealium.utils.fetch.hardwaredata.subprocess.run')
    def test_get_disk_serial_primary_method_success(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="SerialNumber : SAMSUNG_ABC123XYZ\nOther: data"
        )
        result = HardwareData.get_disk_serial()
        self.assertEqual(result, "SAMSUNG_ABC123XYZ")



    @patch('sealium.utils.fetch.hardwaredata.subprocess.run')
    def test_get_disk_serial_fallback_method_success(self, mock_run):
        calls = []

        def fake_run(*args, **kwargs):
            call_num = len(calls)
            calls.append(args)
            if call_num == 0:
                return CompletedProcess(args=[], returncode=1, stdout="", stderr="")
            else:
                return CompletedProcess(args=[], returncode=0, stdout="HDD-SERIAL-789\n", stderr="")

        mock_run.side_effect = fake_run
        result = HardwareData.get_disk_serial()
        self.assertEqual(len(calls), 2)
        self.assertEqual(result, "HDD-SERIAL-789")
        
    @patch('sealium.utils.fetch.hardwaredata.subprocess.run', side_effect=Exception("PowerShell全挂"))
    def test_get_disk_serial_all_methods_fail_returns_none(self, mock_run):
        result = HardwareData.get_disk_serial()
        self.assertIsNone(result)

    @patch.dict('sealium.utils.fetch.hardwaredata.os.environ', {"USERNAME": "admin_user"})
    def test_get_windows_username_success(self):
        result = HardwareData.get_windows_username()
        self.assertEqual(result, "admin_user")

    @patch.dict('sealium.utils.fetch.hardwaredata.os.environ', {"USER": "linux_fallback"}, clear=True)
    def test_get_windows_username_fallback_to_user(self):
        result = HardwareData.get_windows_username()
        self.assertEqual(result, "linux_fallback")

    @patch.dict('sealium.utils.fetch.hardwaredata.os.environ', {}, clear=True)
    def test_get_windows_username_returns_none_if_no_env(self):
        result = HardwareData.get_windows_username()
        self.assertIsNone(result)

    # 测试初始化和数据结构

    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_system_volume_serial', return_value="VOL-SN-001")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_system_volume_name', return_value="系统保留")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_computer_name', return_value="SERVER-01")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_cpu_type', return_value="Xeon Platinum")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_bios_info', return_value="HP v2.34")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_windows_serial', return_value="WIN-ENT-KEY-001")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_disk_serial', return_value="NVME-SN-5678")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_windows_username', return_value="sysadmin")
    def test_hardware_data_init_and_to_dict(self, *mocks):
        hw = HardwareData()
        data = hw.to_dict()

        expected = {
            "system_volume_serial": "VOL-SN-001",
            "system_volume_name": "系统保留",
            "computer_name": "SERVER-01",
            "cpu_type": "Xeon Platinum",
            "bios_info": "HP v2.34",
            "windows_serial": "WIN-ENT-KEY-001",
            "disk_serial": "NVME-SN-5678",
            "windows_username": "sysadmin",
        }

        self.assertEqual(data, expected)

    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_system_volume_serial', return_value="1234ABCD")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_system_volume_name', return_value="C盘")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_computer_name', return_value="DESKTOP-ABC")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_cpu_type', return_value="Core i5")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_bios_info', return_value="Lenovo v1.8")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_windows_serial', return_value="OEM-KEY-XYZ")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_disk_serial', return_value="WD-WX123456")
    @patch('sealium.utils.fetch.hardwaredata.HardwareData.get_windows_username', return_value="alice")
    def test_str_representation_contains_all_fields(self, *mocks):
        hw = HardwareData()
        output = str(hw)

        self.assertIn("1234ABCD", output)
        self.assertIn("C盘", output)
        self.assertIn("DESKTOP-ABC", output)
        self.assertIn("Core i5", output)
        self.assertIn("Lenovo v1.8", output)
        self.assertIn("OEM-KEY-XYZ", output)
        self.assertIn("WD-WX123456", output)
        self.assertIn("alice", output)


# ====================== 集成测试（仅在 Windows 上运行） ======================

IS_WINDOWS = sys.platform == "win32"


@unittest.skipUnless(IS_WINDOWS, "集成测试仅在 Windows 系统上运行")
class TestHardwareDataIntegration(unittest.TestCase):
    """在真实 Windows 环境中运行，验证返回值结构和基本有效性"""

    def setUp(self):
        self.hw = HardwareData()

    def test_computer_name_is_non_empty_string(self):
        self.assertIsInstance(self.hw.computer_name, str)
        self.assertGreater(len(self.hw.computer_name.strip()), 0)

    def test_cpu_type_is_string_or_none(self):
        if self.hw.cpu_type is not None:
            self.assertIsInstance(self.hw.cpu_type, str)

    def test_windows_username_is_non_empty_string(self):
        self.assertIsInstance(self.hw.windows_username, str)
        self.assertGreater(len(self.hw.windows_username.strip()), 0)

    def test_system_volume_serial_is_valid_hex_or_none(self):
        if self.hw.system_volume_serial:
            self.assertIsInstance(self.hw.system_volume_serial, str)
            self.assertEqual(len(self.hw.system_volume_serial), 8)
            # 验证是否为合法十六进制
            try:
                int(self.hw.system_volume_serial, 16)
            except ValueError:
                self.fail(f"非法十六进制序列号: {self.hw.system_volume_serial}")

    def test_to_dict_returns_complete_structure(self):
        d = self.hw.to_dict()
        self.assertIsInstance(d, dict)
        expected_keys = {
            "system_volume_serial",
            "system_volume_name",
            "computer_name",
            "cpu_type",
            "bios_info",
            "windows_serial",
            "disk_serial",
            "windows_username",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_str_representation_is_meaningful(self):
        s = str(self.hw)
        self.assertIsInstance(s, str)
        self.assertGreater(len(s), 100)  # 应包含多个字段信息

    def test_windows_serial_not_empty(self):
        try:
            self.assertIsInstance(self.hw.windows_serial, str)
            self.assertGreater(len(self.hw.windows_serial.strip()), 0)
        except (PermissionError, FileNotFoundError, RuntimeError) as e:
            self.skipTest(f"跳过测试：无法读取 ProductId - {e}")

    def test_disk_serial_can_be_string_or_none(self):
        if self.hw.disk_serial is not None:
            self.assertIsInstance(self.hw.disk_serial, str)


if __name__ == '__main__':
    unittest.main(verbosity=2)