from abc import ABC, abstractmethod
from typing import Optional

class HardWareDataABC(ABC):
    
    def __init__(self):
        self.system_volume_serial: Optional[str] = self.get_system_volume_serial()
        self.system_volume_name: Optional[str] = self.get_system_volume_name()
        self.computer_name: Optional[str] = self.get_computer_name()
        self.cpu_type: Optional[str] = self.get_cpu_type()
        self.bios_info: Optional[str] = self.get_bios_info()
        self.windows_serial: Optional[str] = self.get_windows_serial()
        self.disk_serial: Optional[str] = self.get_disk_serial()
        self.computer_username: Optional[str] = self.get_computer_username()
        
    @abstractmethod
    def get_system_volume_serial() -> str | None:
        pass
    
    @abstractmethod
    def get_system_volume_name() -> str | None:
        pass
    
    @abstractmethod
    def get_computer_name() -> str | None:
        pass
    
    @abstractmethod
    def get_cpu_type() -> str | None:
        pass
    
    @abstractmethod
    def get_bios_info() -> str | None:
        pass
    
    def get_windows_serial() -> str | None:
        raise NotImplementedError("This method is only available on Windows.")
    
    @abstractmethod
    def get_disk_serial() -> str | None:
        pass
    
    @abstractmethod
    def get_computer_username() -> str | None:
        pass