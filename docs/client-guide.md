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
| `激活码已过期` | 码已过截止日期 |

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

## 9. 安全建议

- **公钥随客户端分发，但定期轮换**：更换服务端密钥对后，分发新公钥，旧客户端在升级公钥前无法激活。
- **不要把激活服务暴露公网**：置于反向代理后，启用 TLS（见 [服务端部署 §5](server-guide.md#5-反向代理与-tls生产必备)）。
- **客户端防破解**属于你的应用范围：Sealium 提供密码学绑定，但客户端代码本身的反调试/反逆向/
  完整性校验需你自行加固（打包成可执行文件、代码混淆/虚拟化等）。

## 下一步

- [硬件绑定原理](hardware-binding.md)：机器码如何生成与匹配。
- [故障排查](troubleshooting.md)：激活失败的排查路径。
