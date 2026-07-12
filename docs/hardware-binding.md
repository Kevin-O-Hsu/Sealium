# 硬件绑定原理

硬件绑定把一个激活码锁定到一台物理机器，防止激活码被复制到多台机器滥用。Sealium 的硬件
绑定在 **1.3.0** 全面重构：从"整体哈希精确匹配"升级为"**分量指纹 + 原生多表面交叉验证 +
加权阈值匹配**"，同时更难被 spoof、且换少量硬件仍认得是同一台机器。

## 为什么要重构

旧方案（≤1.2.x）：把 CPU/主板/BIOS/磁盘/MAC 等 9 类硬件拼在一起做一次 SHA-256，得到一个
64 位十六进制"机器码"，服务端用字符串精确相等比对。两个问题：

1. **太脆**：换一张网卡、加一块硬盘 → 整个哈希变 → 服务端判"另一台机器" → 用户被迫重新激活。
2. **易被 spoof**：只采集 WMI 一层 `Win32_*`。spoof 工具 hook WMI provider 改掉返回的序列号
   即可骗过——而 WMI 之下还有更底层的固件真相它改不到。

## 新方案总览

```
                        ┌─────────────────────────────────┐
  采集（客户端，仅 Windows）│  多条独立、越底层越好的路径取值  │
                        └──────────────┬──────────────────┘
                                       ▼
            SMBIOS 固件表  磁盘 IOCTL   WMI 多表面   TPM
            (Type0/1/2/    (STORAGE_   (Win32_*/    (Win32_Tpm)
             3/4/17)        QUERY_      MSFT_*)
                            PROPERTY)
                                       ▼
                    交叉验证：同一硬件多源值比对
                    不一致 → spoof_score ↑
                                       ▼
                    每类硬件逐项哈希 → Component
                                       ▼
                    MachineFingerprint（components + spoof_score）
                                       │ 上报
                                       ▼
            服务端 matches(bound, incoming):
              spoof 先决 → 核心门槛(core_min) → 加权相似度(threshold)
```

设计哲学（对标专业硬件指纹工具）：**同一硬件从尽可能多、尽可能底层、互相独立的路径取值；
任一路径的值被 spoof 改动，就在交叉验证中暴露**。

## 采集表面

### 原生表面（最难 spoof）—— `hardware/native_surfaces.py`（ctypes）

| 表面 | Windows API | 采集内容 |
|---|---|---|
| **SMBIOS 固件表** | `GetSystemFirmwareTable('RSMB')` | 一次拿到 Type0(BIOS)/Type1(系统UUID)/Type2(主板)/Type3(机箱)/Type4(CPU ProcessorID)/Type17(内存) 的**固件级原始值** |
| **磁盘底层属性** | `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` | 经驱动层查询每块物理盘序列号/型号，统一覆盖 SATA 与 NVMe |

> **为什么原生重要**：WMI 的 `Win32_BaseBoard`/`Win32_BIOS` 底层也是读 SMBIOS，但 spoof 工具
> 可以 hook WMI provider 改返回值，却几乎改不到固件表本身。直接读 SMBIOS 固件表 = 绕过 WMI spoof。

实现注意（踩过的坑，已修复）：
- `'RSMB'` 作为 provider signature 是 MSVC 多字符常量顺序（`0x52534D42`，'R' 在高位），不是小端。
- SMBIOS 结构头的 `Length` 字段是**单字节**（offset 1），不是 WORD——误读会吞掉后续结构。
- CPU `ProcessorID` 在 SMBIOS 是 QWORD（低 EAX、高 EDX），WMI 是 `EDX+EAX` 顺序，需对齐。

### WMI 多表面（交叉源）—— `hardware/wmi_surfaces.py`

WMI 作为"第二意见"交叉源：`Win32_Processor`、`Win32_BaseBoard`、`Win32_ComputerSystemProduct.UUID`、
`Win32_PhysicalMemory`、`Win32_DiskDrive`、`MSFT_PhysicalDisk`、`Win32_NetworkAdapterConfiguration`(MAC)、
`Win32_SystemEnclosure`、`Win32_Tpm`。每个查询独立 `try/except` **fail-soft**——任一来源失败只跳过。

### TPM

`Win32_Tpm`（`root\CIMv2\Security\MicrosoftTpm`）的 SpecVersion + ManufacturerVersion。无 TPM 自动跳过。
（真正的 EK 公钥采集作为可选后续增强，未在本次实现。）

## 交叉验证与 spoof 检测 —— `hardware/cross_validate.py`

对**同一物理设备**从多条路径取到的值做比对：

- **磁盘**：用盘序（`Win32_DiskDrive.Index` ↔ `MSFT_PhysicalDisk.DeviceId` ↔ `\\.\PhysicalDriveN`）
  关联同一块盘，比对 `IOCTL` / `Win32_DiskDrive` / `MSFT_PhysicalDisk` 三源的序列号。规范化后
  若不一致 → `spoof_score += 0.25`（单盘多源不一致是强 spoof 信号）。
- **主板/BIOS/系统UUID/CPU**：SMBIOS 值 vs WMI 值交叉。
- **占位符检测**：核心类值命中厂商占位符黑名单（`To be filled by O.E.M.` / `Default string` /
  全 0 / 全 F 等）→ 该分量**不产出** + `spoof_score += 0.1`。

`spoof_score ∈ [0, 1]`，规范化前会 trim/大写/去全部空白（抹平"序列号每字符间插空格"等格式差异）。

> **重要定位**：`spoof_score` 是**软信号**——它由客户端计算并上报，恶意客户端可篡改为 0 绕过。
> 真正的 spoof **硬防线**是下文的"核心门槛"：spoof 通常伴随核心类占位符 → 核心分量缺失 →
> 核心匹配数不足 → 自然判异机。服务端无法重采硬件（纯在线架构），故 spoof_score 只作辅助。

## 分量指纹数据结构 —— `fingerprint.py`

```python
@dataclass(frozen=True)
class Component:
    category: str      # cpu|board|bios|system_uuid|disk|mac|memory|tpm|chassis
    value: str         # sha256(category + pepper + 规范化后的原始值)；绝不存原始串号
    is_core: bool      # 是否核心类（参与 core_min 门槛）

@dataclass(frozen=True)
class MachineFingerprint:
    version: int = 1
    components: tuple[Component, ...] = ()
    spoof_score: float = 0.0
```

**逐项哈希而非聚合**是新方案的根基：每类硬件单独哈希，才能做"加权部分匹配"，实现换少量
硬件仍认同一台。

**为什么用固定 pepper、绝不用随机盐**：随机盐每次运行不同 → 同一台机器两次激活产生不同
`value` → 既破坏幂等（重激活失败）又破坏服务端比对。pepper 是客户端运行时读取的固定值（默认为内置常量，可由
`MACHINE_ID_PEPPER` 环境变量覆盖以便打包定制），**部署后不可变**。

## 匹配算法 —— `matches(bound, incoming, policy)`

```
1. spoof 先决：incoming.spoof_score > spoof_max(默认 0.5) → 直接判否
2. 逐类别相似度 sim：
     单值类(cpu/board/bios/system_uuid/tpm/chassis) → 值相等 1.0，否则 0.0
     多值类(disk/mac/memory) → 集合重叠率 = |交集| / |bound 基准集|
3. matched_core = 核心类中 sim==1.0 的个数
4. weighted_sum = Σ (weight_i × sim_i)
5. 双门槛：matched_core ≥ core_min  且  weighted_sum ≥ threshold
```

### 默认权重表

| 类别 | is_core | weight | 来源 |
|---|---|---|---|
| cpu | ✓ | 0.30 | ProcessorID（SMBIOS Type4 + WMI 交叉） |
| board | ✓ | 0.25 | 主板序列号+型号（SMBIOS Type2 + WMI） |
| bios | ✓ | 0.20 | BIOS 厂商+版本（SMBIOS Type0） |
| system_uuid | ✓ | 0.15 | 系统 UUID（SMBIOS Type1 + WMI） |
| disk | ✗ | 0.05 | 物理盘序列号（IOCTL + WMI + MSFT 三源交叉） |
| mac | ✗ | 0.03 | 物理网卡 MAC |
| memory | ✗ | 0.01 | 内存序列号 |
| tpm | ✗ | 0.005 | TPM 版本 |
| chassis | ✗ | 0.005 | 机箱序列号 |

核心类权重和 0.95，外围 0.05，总 1.00。**核心类权重高、漂移门槛严；外围类允许更换。**

### 默认策略

| 参数 | 默认 | 含义 |
|---|---|---|
| `threshold` | 0.70 | 加权相似度门槛 |
| `core_min` | 3 | 核心类（共 4 类）至少匹配几个 |
| `spoof_max` | 0.5 | spoof_score 超此直接拒 |

### 实际效果举例

| 场景 | 判定 |
|---|---|
| 同一台机器重激活（指纹完全一致） | ✅ 同机（幂等成功） |
| 换了网卡 / 加了硬盘 / 换了内存（核心类不变） | ✅ 同机（外围漂移容忍） |
| 换了 CPU（核心类变 1 个，仍 ≥3） | ✅ 同机 |
| 换了主板（连带 BIOS + 系统 UUID 变，核心类失 3 个） | ❌ 异机（需重新激活，符合预期） |
| 整机不同（核心类全不同） | ❌ 异机 |
| 采集到 spoof（核心类占位符 → 分量缺失 → 核心 < 3） | ❌ 异机 |

## 客户端如何采集

```python
from sealium.common.machine_code import generate_machine_code

fp = generate_machine_code()   # 返回 MachineFingerprint；非 Windows 抛 RuntimeError
# fp 可直接作为 Activator 的 machine_code_provider 返回值
```

若采集到的核心类有效分量过少（如某些虚拟机/精简系统），`generate_machine_code` 会：
- 提供了 `fallback_secret_provider`（如每安装一次的随机密钥）→ 注入为 `system_uuid` 核心分量，仍可生成稳定指纹；
- 未提供 → **fail-safe 抛 `SealiumError`**，绝不生成不可靠指纹。

## 服务端如何比对

服务端不重采硬件、不持有 pepper，只比对客户端上报的分量哈希。`ActivationService` 在已绑定
记录的重激活路径上调用 `matches(bound, incoming, policy)` 判定同机/异机。`policy` 来自
`ServerConfig.machine_id_policy`（见 [配置参考](configuration.md)）。

## 升级与迁移

**1.3.0 是 breaking change**：

- 旧客户端发送的"整体哈希字符串"机器码会被服务端 `from_dict` **拒绝**（machine_code 必须是
  指纹 JSON 对象）。
- 旧数据库里 `bound_machine_code` 列存的是旧 hex 字符串，新版本无法解析 → **需清库重建**
  （用户已确认不做老版本兼容）。
- 客户端升级到 1.3.0 后，首次激活会以新的分量指纹绑定；此后同机重激活走相似度匹配。

## 平台支持

- **客户端采集仅 Windows**：`SMBIOS`/`IOCTL`/`WMI` 均为 Windows API。非 Windows 调用
  `generate_machine_code()` 抛 `RuntimeError`（服务端比对逻辑跨平台，因为只处理指纹结构）。
- 每个采集源独立 fail-soft：某类硬件在某机型采不到（如无 TPM、NVMe 盘无 SMART WMI 类）只跳过，
  不影响指纹生成。

## 可选后续增强（未实现）

更贴近专业工具全表面的能力，工作量较大，按需迭代：
- NVMe Identify Controller Serial、SCSI INQUIRY VPD 0x80/0x83、ATA PASSTHROUGH SMART 的 ctypes 手写。
- TPM EK 公钥（TBS API）。
- GPU UUID（NVAPI）。

当前磁盘交叉验证已用 `IOCTL + Win32_DiskDrive + MSFT_PhysicalDisk` 三源，足够暴露单层 spoof。
