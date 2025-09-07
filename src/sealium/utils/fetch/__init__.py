import sys

if sys.platform.startswith("linux"):
    pass
elif sys.platform.startswith("win"):
    from .hardwaredata_win import WinHardwareData as HardwareData
