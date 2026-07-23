# 客户端集成指南

本篇面向**把 Sealium 激活嵌入自己应用的开发者**。

## 1. 安装

```bash
pip install sealium
```

Python ≥ 3.9。Windows 上自动装 `wmi`（机器码采集需要）；非 Windows 客户端无法采集硬件
指纹（采集仅支持 Windows，见 [硬件绑定 §平台支持](hardware-binding.md#平台支持)）。

## 2. 取得服务端公钥

向服务端运维索取 `server_public.pem`，随你的客户端一起分发（打包进可执行文件、或放在安装
目录）。客户端**只需要公钥**，不需要、也不应持有任何私钥。

```python
with open("server_public.pem", "r") as f:
    server_public_key_pem = f.read()
```

## 3. 最小激活示例

```python
from sealium.client.activator import Activator, ActivationError

activator = Activator(
    server_url="https://activation.example.com/v1/activation",
    server_public_key_pem=server_public_key_pem,
)

try:
    response = activator.activate("用户输入的激活码")
    if response.result == "success":
        print(f"✅ 激活成功，授权至 {response.authorized_until}")
        print(f"   功能: {response.features}")
    else:
        print(f"❌ 激活失败: {response.error_msg}")
except ActivationError as e:
    # 网络、加密、解析、nonce 校验等流程性错误
    print(f"⚠️ 激活过程出错: {e}")
```

`activate()` 一次调用完成：采集硬件指纹 → 取权威时间戳 → 双层加密 → 发请求 → 解密响应 →
校验回显 nonce → 返回 `ActivationResponse`。

## 4. 响应对象

```python
@dataclass
class ActivationResponse:
    result: str                      # "success" 或 "error"
    authorized_until: str | None     # "YYYY-MM-DD"（永久为 "永久"）
    features: list[str] | None       # 授权功能列表
    nonce: str | None                # 回显的客户端 nonce
    error_msg: str | None            # result 为 error 时的提示
```

## 5. 错误处理

两类错误要分开处理：

| 类型 | 信号 | 含义 | 建议 |
|---|---|---|---|
| **业务拒绝** | `response.result == "error"` | 激活码无效/已过期/已被他机占用/时间戳超窗等 | 按 `error_msg` 提示用户 |
| **流程异常** | 抛 `ActivationError` | 网络失败、加解密失败、响应解析失败、nonce 不匹配（疑似重放/篡改） | 提示稍后重试；nonce 不匹配应警惕 |

常见业务错误（`error_msg`）：

| `error_msg` | 原因 |
|---|---|
| `激活码格式无效` | 输入不是合法字符串 |
| `请求时间戳无效，请同步时间` | 客户端时间与权威 API 偏差超 300 秒 |
| `请求已被使用，请勿重复发送` | (code, nonce) 重复（防重放） |
| `激活码无效或已被使用` | 码不存在 / 已过期 / **已被其他设备绑定**（三者对外不可区分） |

> 出于安全，"码不存在"与"已被他机占用"合并为同一提示，避免攻击者枚举有效激活码。

## 6. 依赖注入（测试/定制）

`Activator` 的每个外部依赖都能注入，便于测试或定制：

```python
Activator(
    server_url=...,
    server_public_key_pem=...,
    timestamp_provider=lambda: 1700000000,       # 固定时间戳（测试）
    machine_code_provider=my_collector,          # 自定义指纹（测试/非默认采集）
    http_poster=my_poster,                        # 自定义 HTTP（如走代理）
    request_timeout=10,                           # 超时秒数
)
```

> **时间源与隐私（重要）**：默认 `timestamp_provider` 指向第三方
> `https://aisenseapi.com/services/v1/timestamp`——每次 `activate()` 都会向其发请求，泄漏客户端
> 公网 IP 与「用户正在激活」这一行为，且该 API 不可达时激活会失败（单点）。若不希望依赖该
> 第三方，**注入你自己的 `timestamp_provider`**（指向你自有、多源冗余的时间服务，或内网时间源），
> 即可同时消除第三方隐私泄漏与单点依赖，并便于你自行实施证书 pinning。时间戳仅用于 ±300s
> 防重放窗口，不影响授权截止判定（详见 [安全模型](security.md#已知限制务必了解)）。

```python
def my_timestamp() -> int:
    # 你的自有权威时间源（HTTP/HTTPS/NTP），返回 Unix 秒时间戳
    ...

activator = Activator(..., timestamp_provider=my_timestamp)
```

## 7. 授权持久化（你的应用负责）

Sealium 的激活是**纯在线**的：每次调用 `activate()` 都会请求服务端验证。Sealium **不**提供
本地授权文件存储/离线校验——拿到 `ActivationResponse` 后如何持久化（如保存 `authorized_until`、
`features`）和何时再次激活（如每次启动、或定期），由**你的应用**决定。

典型做法：

```python
resp = activator.activate(code)
if resp.result == "success":
    # 由你的应用保存到本地配置/加密存储
    save_license_locally(resp.authorized_until, resp.features)
```

> 如果你需要离线校验（授权期内不联网放行），需在应用层自行实现：保存授权截止时间，启动时
> 本地检查是否过期，到期再调 `activate()` 续期。注意本地校验的强度取决于你保护这份授权数据
> 的方式（建议绑定到机器指纹加密存储）。

## 8. 非客户端采集

如果你的客户端不在 Windows 上、或想用自定义采集逻辑：

```python
from sealium.common.fingerprint import MachineFingerprint, Component

def my_provider() -> MachineFingerprint:
    # 自行构造指纹（例如从你的许可服务器下发、或其它采集方式）
    return MachineFingerprint(components=(...,), spoof_score=0.0)

activator = Activator(..., machine_code_provider=my_provider)
```

注意：自定义指纹的 `Component.value` 是逐项哈希，必须与服务端 bound 的指纹用**相同的 pepper**
计算才能匹配（pepper 由客户端打包时决定，见 [硬件绑定原理](hardware-binding.md)）。

## 9. 配置客户端硬件指纹 pepper（分发前必做）

客户端采集硬件指纹时，每类硬件原始值都按 `sha256(category + pepper + raw)` 逐项哈希
（原理见 [硬件绑定](hardware-binding.md)）。这个 pepper **默认是源码里的公开常量**
`"sealium-v1-hardware-fingerprint-pepper"`——任何人都能从 PyPI / 源码看到。**不改它，
你的发行就和所有用默认值的发行指纹互通，彩虹表 / 跨发行碰撞防护形同虚设。** 每个发行
**必须**在分发前设自己的私有 pepper。

### 它是什么、怎么读

- pepper 是**运行时环境变量** `MACHINE_ID_PEPPER`：客户端进程启动时由
  `os.environ.get("MACHINE_ID_PEPPER", <内置默认>)` 读取**一次**并固化进模块。
- **时机铁律**：必须在 Python 解释器启动、`import sealium` 之前，该变量就已存在于进程
  环境块。**import 之后再设环境变量无效**（模块属性已求值，实测不会更新）。
- 客户端整条激活链路都读这一个变量（采集层不传显式 pepper，直接走模块默认值）。
- **pepper 纯属客户端侧**：服务端只比对客户端上报的哈希分量，**不读、也不需要知道**
  你的 pepper。它的意义仅在于让"你的发行"的指纹与别人不同（域分隔）。

> ⚠️ **别和另一个 pepper 搞混**：`MACHINE_ID_PEPPER`（本节，客户端硬件指纹）与
> `SEALIUM_SECURITY__CODE_HASH_PEPPER`（[服务端激活码存储哈希](configuration.md#9-客户端配置)）
> 是**两个完全不同的东西**——作用域、读取方、默认值都不同。**不要**把它们当成
> "客户端服务端共用一个 pepper"。

### 配置方式（任选其一，不限定工具）

**方式 A — 改源码默认值（最可靠，与封装工具解耦，推荐）**

把 `src/sealium/common/fingerprint.py` 里这行的默认字符串改成你的私有值，再打包进 exe：

```python
# 改前
_PEPPER = os.environ.get("MACHINE_ID_PEPPER", "sealium-v1-hardware-fingerprint-pepper")
# 改后（换成你的私有随机串）
_PEPPER = os.environ.get("MACHINE_ID_PEPPER", "你的私有随机串")
```

pepper 随二进制分发，**完全不依赖运行时环境变量机制**——Nuitka / Enigma Virtual Box /
PyInstaller 任何打包工具都适用。代价：升级 sealium 后需重新 patch 这一行。

**方式 B — 进程启动前注入环境变量**

在主 exe 启动前把变量塞进进程环境块，例如启动器（`.bat` / 小 C 程序 / NSIS·Inno 安装器）：

```bat
:: launcher.bat —— 在主程序启动前设好环境变量
set MACHINE_ID_PEPPER=你的私有随机串
start "" your_app.exe
```

或封装工具自带的"注入进程环境变量"能力——**前提是它确实提供这个功能**（见下方注意）。

> **关于 Enigma Virtual Box**：EVB（免费版）的核心能力是**文件系统 + 注册表虚拟化**
> （把 exe + 依赖打成单文件），**没有可靠证据表明它内置"打包时注入进程环境变量"的功能**。
> 而注册表虚拟化也**不能**可靠地变成进程环境变量——进程环境变量由父进程在 `CreateProcess`
> 时传入，不是程序自己读注册表得来的。因此用 EVB 封装时**强烈建议走方式 A**：把 pepper
> 烧进二进制，绕开环境变量的不确定性。用的是功能更全的 Enigma Protector 时，同样优先方式 A。

### 部署后不可变

pepper 一旦被任何客户端用来生成过指纹、并被服务端绑定，**绝不能再改**：改它 = 所有已
绑定记录的哈希失配 = **全员强制重新激活**。选定一个值就永久保持。

### 自测：确认 pepper 真的生效

无论用哪种方式，配置 / 打包后务必对比——同一输入、不同 pepper，输出必须不同：

```bash
# 终端1：默认 pepper
python -c "from sealium.common.fingerprint import hash_component as h; print(h('cpu','TEST123'))"
# 终端2：你的私有 pepper（新进程，启动前注入）
MACHINE_ID_PEPPER=你的私有值 python -c "from sealium.common.fingerprint import hash_component as h; print(h('cpu','TEST123'))"
# Windows cmd 等价： set MACHINE_ID_PEPPER=你的私有值 && python -c "..."
```

两次输出**不同** → pepper 生效；**相同** → 仍在用公开默认值，回头检查注入是否在
`import sealium` 之前完成。

## 10. 安全建议

- **公钥随客户端分发，但定期轮换**：更换服务端密钥对后，分发新公钥，旧客户端在升级公钥前无法激活。
- **不要把激活服务暴露公网**：置于反向代理后，启用 TLS（见 [服务端部署 §5](server-guide.md#5-反向代理与-tls生产必备)）。
- **客户端防破解**属于你的应用范围：Sealium 提供密码学绑定，但客户端代码本身的反调试/反逆向/
  完整性校验需你自行加固（打包成可执行文件、代码混淆/虚拟化等）。

## 下一步

- [硬件绑定原理](hardware-binding.md)：机器码如何生成与匹配。
- [故障排查](troubleshooting.md)：激活失败的排查路径。
