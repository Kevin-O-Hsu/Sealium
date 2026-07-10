# src/sealium/common/hardware/native_surfaces.py
"""
ctypes 原生硬件采集（最难 spoof 的表面）。

* **SMBIOS 固件表**（``GetSystemFirmwareTable('RSMB')``）：一次拿到 BIOS / System /
  Board / Chassis / Processor 的固件级原始值。WMI 的 ``Win32_*`` 底层也读 SMBIOS，
  但 spoof 工具可 hook WMI provider 改返回值、却几乎改不到固件表 —— 直接读固件表
  即绕过 WMI spoof。这是 spoof 最难攻破的表面。
* **磁盘底层属性**（``IOCTL_STORAGE_QUERY_PROPERTY`` via ``DeviceIoControl``）：
  经 DeviceIoControl 直接向存储驱动查询，比 ``Win32_DiskDrive`` 底层、且统一覆盖
  SATA / NVMe。

每个采集器独立 fail-soft；非 Windows 抛 ``RuntimeError``（模块导入零副作用，
``ctypes.windll`` 仅在 Windows 绑定）。
"""

from __future__ import annotations

import ctypes
import os
import struct
import uuid as _uuid
from ctypes import wintypes

from sealium.common.hardware.types import RawSurface

# ---------------------------------------------------------------------------
# 仅 Windows 绑定 kernel32 并声明签名（避免 ctypes 默认 int 截断 64 位 handle）
# ---------------------------------------------------------------------------
if os.name == "nt":
    _kernel32 = ctypes.windll.kernel32

    _kernel32.GetSystemFirmwareTable.restype = wintypes.DWORD
    _kernel32.GetSystemFirmwareTable.argtypes = [
        wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL
    _kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
else:
    _kernel32 = None

# INVALID_HANDLE_VALUE 作为 64 位无符号值
_INVALID_HANDLE_VALUE = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1

# 'RSMB' 作为 FirmwareTableProviderSignature。注意 MSVC 多字符常量 'RSMB' 的值是
# 'R' 在高位（'R'*2^24 + 'S'*2^16 + 'M'*2^8 + 'B' = 0x52534D42），故用大端解包。
# 用小端（0x424D5352）会得 ERROR_INVALID_FUNCTION。
_RSMB = struct.unpack(">I", b"RSMB")[0]

# IOCTL_STORAGE_QUERY_PROPERTY
_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
_PROPERTY_STANDARD_QUERY = 0
_STORAGE_DEVICE_PROPERTY = 0


# ===========================================================================
# SMBIOS 固件表
# ===========================================================================
def _get_raw_smbios() -> bytes:
    """通过 GetSystemFirmwareTable('RSMB') 取原始 SMBIOS 固件表字节。失败返回 b""。"""
    size = _kernel32.GetSystemFirmwareTable(_RSMB, 0, None, 0)
    if size <= 0:
        return b""
    buf = (ctypes.c_ubyte * size)()
    got = _kernel32.GetSystemFirmwareTable(_RSMB, 0, buf, size)
    if got <= 0:
        return b""
    return bytes(buf[:got])


def _iter_smbios_structures(table: bytes):
    """遍历 SMBIOS 表，逐个 yield ``(type, formatted_bytes, strings_list)``。"""
    i = 0
    n = len(table)
    while i + 4 <= n:
        stype = table[i]
        flen = table[i + 1]  # SMBIOS Length：formatted area 字节数（单字节，offset 1）
        if flen < 4:
            break
        formatted = table[i : i + flen]
        # string-set：从 i+flen 到 \x00\x00 终止符
        j = i + flen
        end = j
        while end + 1 < n:
            if table[end] == 0 and table[end + 1] == 0:
                break
            end += 1
        blob = table[j:end]
        strings = (
            [s.decode("latin-1") for s in blob.split(b"\x00")] if blob else []
        )
        yield stype, formatted, strings
        i = end + 2  # 跳过 \x00\x00
        if stype == 127:  # end-of-table marker
            break


def _string_at(formatted: bytes, strings: list[str], offset: int) -> str | None:
    """``offset`` 处的 1-based 字符串索引 → 对应字符串；越界/空返回 None。"""
    if offset >= len(formatted):
        return None
    idx = formatted[offset]
    if idx == 0 or idx > len(strings):
        return None
    val = strings[idx - 1]
    return val or None


def _uuid_from(formatted: bytes) -> str | None:
    """Type1 UUID（offset 8, 16 bytes, mixed-endian）→ 标准字符串。全0/全F 视无效。"""
    if len(formatted) < 24:
        return None
    raw = bytes(formatted[8:24])
    if raw == b"\x00" * 16 or raw == b"\xff" * 16:
        return None
    try:
        return str(_uuid.UUID(bytes_le=raw))  # SMBIOS 2.6+ mixed-endian
    except ValueError:
        return None


def _processor_id(formatted: bytes) -> str | None:
    """Type4 ProcessorID（offset 8, 8 bytes）→ 大写 hex，与 WMI Win32_Processor.ProcessorId 一致。

    SMBIOS 存为 QWORD：低 DWORD = EAX、高 DWORD = EDX（均 little-endian）；而 WMI
    ``ProcessorId`` 为 ``EDX + EAX`` 拼接。故按 EDX 在前输出，使两源交叉验证一致。
    """
    if len(formatted) < 16:
        return None
    eax = int.from_bytes(bytes(formatted[8:12]), "little")
    edx = int.from_bytes(bytes(formatted[12:16]), "little")
    if eax == 0 and edx == 0:
        return None
    return f"{edx:08X}{eax:08X}"


def _parse_smbios(table: bytes) -> list[RawSurface]:
    """解析 SMBIOS 表，产出 bios/system_uuid/board/chassis/cpu 原生表面。"""
    surfaces: list[RawSurface] = []
    for stype, formatted, strings in _iter_smbios_structures(table):
        try:
            if stype == 0:  # BIOS Information（bios 由原生独占）
                vendor = _string_at(formatted, strings, 4) or ""
                version = _string_at(formatted, strings, 5) or ""
                val = f"{vendor}{version}".strip()
                if val:
                    surfaces.append(RawSurface("bios", val, "smbios"))
            elif stype == 1:  # System Information
                uid = _uuid_from(formatted)
                if uid:
                    surfaces.append(RawSurface("system_uuid", uid, "smbios"))
            elif stype == 2:  # Baseboard
                product = _string_at(formatted, strings, 5) or ""
                serial = _string_at(formatted, strings, 7) or ""
                val = f"{serial}{product}".strip()
                if val:
                    surfaces.append(RawSurface("board", val, "smbios"))
            elif stype == 3:  # Chassis
                serial = _string_at(formatted, strings, 7) or ""
                if serial:
                    surfaces.append(RawSurface("chassis", serial, "smbios"))
            elif stype == 4:  # Processor
                pid = _processor_id(formatted)
                if pid:
                    surfaces.append(RawSurface("cpu", pid, "smbios"))
        except Exception:
            continue
    return surfaces


def collect_smbios_surfaces() -> list[RawSurface]:
    """采集 SMBIOS 固件表面。失败返回空列表（fail-soft）。"""
    try:
        raw = _get_raw_smbios()
    except Exception:
        return []
    if len(raw) < 8:
        return []
    # RawSMBIOSData 头 8 字节（Used/Major/Minor/Rev/Length(DWORD)），其后是表数据
    length = struct.unpack_from("<I", raw, 4)[0]
    table = raw[8 : 8 + length]
    return _parse_smbios(table)


# ===========================================================================
# 磁盘 IOCTL_STORAGE_QUERY_PROPERTY
# ===========================================================================
class _StoragePropertyQuery(ctypes.Structure):
    _fields_ = [
        ("PropertyId", ctypes.c_ulong),
        ("QueryType", ctypes.c_ulong),
        ("AdditionalParameters", ctypes.c_byte),
    ]


def _read_ansi(buf, offset: int) -> str | None:
    """从 buf 的 offset 处读 ANSI 字符串（到 ``\\0``）。offset<=0 表示无。"""
    if offset <= 0 or offset >= len(buf):
        return None
    end = offset
    while end < len(buf) and buf[end] != 0:
        end += 1
    return bytes(buf[offset:end]).decode("latin-1").strip() or None


def _query_drive(index: int) -> RawSurface | None:
    """查询 ``\\\\.\\PhysicalDrive{index}`` 的存储属性，返回 disk 原生表面。失败返回 None。"""
    handle = _kernel32.CreateFileW(
        f"\\\\.\\PhysicalDrive{index}",
        0x80,  # FILE_READ_ATTRIBUTES：普通用户即可查询属性
        0x03,  # FILE_SHARE_READ | FILE_SHARE_WRITE
        None,
        3,  # OPEN_EXISTING
        0,
        None,
    )
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        return None
    try:
        query = _StoragePropertyQuery(
            PropertyId=_STORAGE_DEVICE_PROPERTY, QueryType=_PROPERTY_STANDARD_QUERY
        )
        buf = (ctypes.c_ubyte * 8192)()
        returned = wintypes.DWORD(0)
        ok = _kernel32.DeviceIoControl(
            handle,
            _IOCTL_STORAGE_QUERY_PROPERTY,
            ctypes.byref(query),
            ctypes.sizeof(query),
            buf,
            ctypes.sizeof(buf),
            ctypes.byref(returned),
            None,
        )
        if not ok or returned.value < 28:
            return None
        # STORAGE_DEVICE_DESCRIPTOR 偏移（均为 DWORD）：
        # VendorIdOffset@12, ProductIdOffset@16, ProductRevisionOffset@20, SerialNumberOffset@24
        vendor_off = struct.unpack_from("<I", buf, 12)[0]
        product_off = struct.unpack_from("<I", buf, 16)[0]
        serial_off = struct.unpack_from("<I", buf, 24)[0]
        vendor = _read_ansi(buf, vendor_off) or ""
        product = _read_ansi(buf, product_off) or ""
        serial = _read_ansi(buf, serial_off) or ""
        val = (serial or f"{vendor}{product}").strip()  # 序列号优先，缺则退用厂商+型号
        if not val:
            return None
        return RawSurface("disk", val, "storage_ioctl", slot=str(index))
    except Exception:
        return None
    finally:
        _kernel32.CloseHandle(handle)


def collect_disk_ioctl_surfaces() -> list[RawSurface]:
    """遍历物理盘（0..15），逐个查询存储属性。任一盘失败跳过。"""
    surfaces: list[RawSurface] = []
    for index in range(16):
        sf = _query_drive(index)
        if sf is not None:
            surfaces.append(sf)
    return surfaces


def collect_native_surfaces() -> list[RawSurface]:
    """采集全部原生表面（SMBIOS + 磁盘 IOCTL）。非 Windows 抛 ``RuntimeError``。"""
    if os.name != "nt":
        raise RuntimeError("原生硬件采集仅支持 Windows 平台")
    surfaces: list[RawSurface] = []
    surfaces.extend(collect_smbios_surfaces())
    surfaces.extend(collect_disk_ioctl_surfaces())
    return surfaces
