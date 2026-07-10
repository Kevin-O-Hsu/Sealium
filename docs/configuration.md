# 配置参考

Sealium 服务端全部配置经**环境变量**驱动，由 `ServerConfig.from_env()` 在导入时读取（不做
I/O，校验在启动 `lifespan` 时显式进行）。客户端无服务端配置（只内置公钥）。

## 服务端配置项

### 路径与存储

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `DATABASE_PATH` | `<project_root>/data/database.db` | SQLite 数据库路径；自动创建，权限 `0600` |
| `SERVER_PRIVATE_KEY_PATH` | `<project_root>/data/server_private.pem` | 服务端 RSA 私钥路径 |
| `SERVER_PUBLIC_KEY_PATH` | *(空)* | 公钥路径（可选，仅调试用） |
| `SERVER_PRIVATE_KEY_PASSPHRASE` | *(空)* | 私钥落盘口令；非空则启动时用它解密私钥 |

### 网络

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `HOST` | `0.0.0.0` | 监听地址；生产建议 `127.0.0.1`（置于反代后） |
| `PORT` | `8000` | 监听端口 |
| `API_PREFIX` | `/v1` | API 前缀 |
| `ACTIVATION_PATH` | `/activation` | 激活接口路径（完整路由 = `API_PREFIX` + `ACTIVATION_PATH`） |
| `CORS_ORIGINS` | `*` | 逗号分隔的允许来源；原生客户端无需浏览器凭据，`allow_credentials` 已关 |

### 时间与防重放

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `TIME_STAMP_TOLERANCE_SECONDS` | `300` | 客户端时间戳允许偏差（秒）；超此拒绝 |
| `REPLAY_CACHE_SIZE` | `10000` | 防重放 `(code,nonce)` 缓存容量（LRU） |

### 限流

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `True` | 是否启用限流 |
| `RATE_LIMIT_MAX_REQUESTS` | `60` | 每 IP 每窗口最大请求数 |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | 限流窗口（秒） |

超限返回 `429` + `Retry-After: <window>`。进程内固定窗口；多 worker 各自独立（见
[服务端部署 §7](server-guide.md#7-多-worker-注意)）。

### 日志与调试

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `LOG_FORMAT` | `%(asctime)s - %(name)s - %(levelname)s - %(message)s` | 日志格式 |
| `DEBUG` | `False` | 调试模式：开启 `/docs`/`/redoc`/`/openapi.json`、`/debug/config`、热重载。**生产必须 `False`** |

### 硬件绑定策略（1.3.0 新增）

这些控制服务端如何判定"是否同一台机器"（见 [硬件绑定原理](hardware-binding.md)）：

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MACHINE_ID_THRESHOLD` | `0.70` | 加权相似度门槛 |
| `MACHINE_ID_CORE_MIN` | `3` | 核心类（cpu/board/bios/system_uuid）至少匹配几个 |
| `MACHINE_ID_SPOOF_MAX` | `0.5` | `spoof_score` 超此直接判异机 |

调宽（更易认同一台机器，但防破解变弱）：降低 `MACHINE_ID_THRESHOLD` / `MACHINE_ID_CORE_MIN`。
调严（换一点硬件就要重激活，防破解更强）：提高之。**改这些会让已绑定记录的判定结果变化**，
一般不在运行中调整。

## 客户端配置

客户端 `Activator` 无环境变量，参数全部构造时传入。唯一相关的全局项：

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MACHINE_ID_PEPPER` | *(内置常量)* | 逐项哈希的 pepper。**仅客户端生成指纹时读**；服务端不读（服务端只比对哈希、不重算）。**部署后不可变**：改它会让所有已绑定记录失配、强制全员重激活。 |

打包客户端时可设 `MACHINE_ID_PEPPER` 为你的私有值，使不同发行的客户端指纹互不通用。

## 配置示例

`.env`（配合 `python-dotenv` 或 systemd `EnvironmentFile`）：

```dotenv
# 网络
HOST=127.0.0.1
PORT=8000

# 安全
SERVER_PRIVATE_KEY_PASSPHRASE=change-me-long-random
DEBUG=False

# 时间与防重放
TIME_STAMP_TOLERANCE_SECONDS=300
REPLAY_CACHE_SIZE=10000

# 限流
RATE_LIMIT_ENABLED=True
RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_WINDOW_SECONDS=60

# 硬件绑定（默认值已合理，通常不改）
MACHINE_ID_THRESHOLD=0.70
MACHINE_ID_CORE_MIN=3
MACHINE_ID_SPOOF_MAX=0.5

# 日志
LOG_LEVEL=INFO
```

systemd unit 片段：

```ini
[Service]
EnvironmentFile=/etc/sealium/sealium.env
ExecStart=/path/to/uvicorn sealium.server.app:app --host 127.0.0.1 --port 8000
User=sealium
```

## 校验

启动时若私钥文件不存在，`ServerConfig.validate()` 抛错（注入加密器的测试/调试模式跳过此校验）。
其余配置在 `from_env` 解析时即校验类型（非法数字等会立即报错）。
