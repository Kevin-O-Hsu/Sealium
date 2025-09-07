import platform
import sys
import struct

print("=" * 50)
print("🔍 Python 位数检测报告")
print("=" * 50)
print(f"🐍 Python 路径: {sys.executable}")
print(f"🏛️  架构: {platform.architecture()[0]}")
print(f"💻 机器类型: {platform.machine()}")
print(f"📏 指针大小: {struct.calcsize('P') * 8} 位")
print(f"🔢 sys.maxsize: {sys.maxsize:,}")
print(f"✅ 是否64位: {sys.maxsize > 2**32}")
print("=" * 50)