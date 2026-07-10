# 配置参考

> 🎯 **零配置开箱即用**——无需任何配置文件就能跑：
>
> ```bash
> pip install sealium
> python -m sealium.scripts.generate_keys
> python -m sealium.scripts.generate_activation_codes --count 10
> python -m sealium.server.run
> ```
>
> 默认值齐全（监听 `0.0.0.0:8000`，数据落 `./data/`）。**配置文件是可选的**——
> 仅当需要覆盖默认值时才用。本篇讲的就是"需要时怎么配"。

Sealium 服务端采用工业级配置：TOML 配置文件（`sealium.toml`）为主载体，环境变量
覆盖敏感项与部署差异，pydantic-settings 提供类型与范围校验。

> ⚠️ **1.4.0 起 breaking**：旧的裸环境变量（`HOST`/`PORT`/`DATABASE_PATH`/…）已废弃。
> 迁移见文末 [§从旧版迁移](#从旧版迁移13x--140)。

---

## 最简路径（无需配置文件）

```bash
pip install sealium
python -m sealium.scripts.generate_keys          # 生成 RSA 密钥对到 ./data/
python -m sealium.scripts.generate_activation_codes --count 10  # 生成激活码
python -m sealium.server.run                      # 启动，监听 0.0.0.0:8000
```

完。不创建任何配置文件，全部用内置默认值。

## 需要配置时：一键生成模板

想覆盖默认值（端口、绑定地址、限流、机器码策略等），在**当前目录**生成配置模板：

```bash
python -m sealium.server.config_cli init      # 生成 ./sealium.toml（模板内嵌，pip 安装即可用）
# 编辑 sealium.toml
python -m sealium.server.config_cli check     # 自检
python -m sealium.server.run
```

> `init` 把模板写在你**当前所在的目录**（运行服务的工作目录），不是 site-packages。
> 模板作为代码常量内嵌，pip 安装后一定能用——**不依赖仓库里的任何文件**。

私钥口令等敏感项用**环境变量**，不写进 `sealium.toml`：

```bash
export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE="a-long-random-passphrase"
```

---

## 配置来源与优先级

从高到低，前者覆盖后者：

| 优先级 | 来源 | 用途 |
|---|---|---|
| 1 | 构造参数 `ServerConfig(server=…)` | 程序化注入（测试 / 嵌入式） |
| 2 | 环境变量 `SEALIUM_<SECTION>__<KEY>` | 部署差异、敏感项、容器/systemd 注入 |
| 3 | `.env` 文件（与 2 同语义） | 本地开发、敏感项文件化 |
| 4 | `sealium.toml` 配置文件 | 结构化主配置（可注释、可 review、可版本化） |
| 5 | 内置默认值 | **零配置开箱即用** |

不创建 `sealium.toml` 也能启动（全部走默认）；TOML 仅作覆盖。

---

## TOML 全 schema（`sealium.toml`）

`config_cli init` 生成的模板即下表各项（带注释）。逐项说明：

### `[server]` 网络与路由

| 键 | 默认 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 监听地址；生产建议 `127.0.0.1`（置于反代后） |
| `port` | `8000` | 监听端口（1–65535） |
| `debug` | `false` | 调试模式：开 `/docs`/`/redoc`/`/openapi.json`、`/debug/config`、热重载。**生产必须 `false`** |
| `api_prefix` | `/v1` | API 前缀 |
| `activation_path` | `/activation` | 激活路径（完整路由 = `api_prefix` + `activation_path`） |

### `[paths]` 存储与密钥

相对路径**相对配置文件所在目录**解析（部署可整体搬迁）。

| 键 | 默认 | 说明 |
|---|---|---|
| `database` | `data/database.db` | SQLite 数据库路径；自动创建，权限 `0600` |
| `private_key` | `data/server_private.pem` | 服务端 RSA 私钥路径 |
| `public_key` | *(空)* | 公钥路径（可选，仅调试用） |

### `[security]` 时间、防重放、口令

| 键 | 默认 | 说明 |
|---|---|---|
| `timestamp_tolerance_seconds` | `300` | 客户端时间戳允许偏差（秒），超此拒绝 |
| `replay_cache_size` | `10000` | 防重放 `(code,nonce)` 缓存容量（LRU + TTL） |
| `private_key_passphrase` | *(空)* | **私钥口令：不要写进 TOML**，见下 [§敏感字段](#敏感字段隔离) |

### `[rate_limit]` 限流（进程内固定窗口）

超限返回 `429` + `Retry-After`。多 worker 各进程独立（弱一致）；全局精确需注入 Redis。

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 是否启用限流 |
| `max_requests` | `60` | 每 IP 每窗口最大请求数 |
| `window_seconds` | `60` | 窗口大小（秒） |

### `[machine_id]` 同机判定策略

控制服务端如何判定"是否同一台机器"（见 [硬件绑定原理](hardware-binding.md)）。

| 键 | 默认 | 说明 |
|---|---|---|
| `threshold` | `0.70` | 加权相似度门槛（0–1） |
| `core_min` | `3` | 核心类（cpu/board/bios/system_uuid）至少匹配几个 |
| `spoof_max` | `0.5` | `spoof_score` 超此直接判异机 |

调宽（更易认同一台机器，但防破解变弱）：降 `threshold` / `core_min`。调严（换一点
硬件就要重激活）：提高之。**改这些会让已绑定记录的判定结果变化**，一般不在运行中调整。

### `[logging]` 日志

| 键 | 默认 | 说明 |
|---|---|---|
| `level` | `INFO` | 日志级别 |
| `format` | `%(asctime)s - %(name)s - %(levelname)s - %(message)s` | 日志格式 |

### `[cors]` CORS

| 键 | 默认 | 说明 |
|---|---|---|
| `origins` | `["*"]` | TOML 数组；原生客户端（octet-stream）无需浏览器凭据，`allow_credentials` 已关 |

---

## 环境变量覆盖

任何 TOML 字段都可被环境变量覆盖，命名规则：

```
SEALIUM_<SECTION>__<KEY>
```

双下划线 `__` 分隔嵌套层级。例：

| 环境变量 | 覆盖 |
|---|---|
| `SEALIUM_SERVER__PORT` | `[server] port` |
| `SEALIUM_SERVER__HOST` | `[server] host` |
| `SEALIUM_RATE_LIMIT__MAX_REQUESTS` | `[rate_limit] max_requests` |
| `SEALIUM_MACHINE_ID__THRESHOLD` | `[machine_id] threshold` |
| `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` | `[security] private_key_passphrase`（敏感） |

大小写不敏感。优先级高于 TOML，低于构造参数。这是**不改配置文件**就能覆盖单项的
最简方式（容器、systemd、临时测试都适用）：

```bash
SEALIUM_SERVER__PORT=9000 python -m sealium.server.run
```

## `.env` 文件

`.env`（当前目录）与环境变量同语义，适合放敏感项与本地开发差异。它就是一个普通文本
文件，每行一个变量，自己创建即可：

```bash
cat > .env <<'EOF'
SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=your-long-random-passphrase
EOF
```

容器 / systemd 用真正的环境变量或 `EnvironmentFile`，效果相同。

## 配置文件查找

`sealium.toml` 的查找路径由环境变量 `SEALIUM_CONFIG` 指定，缺省 `./sealium.toml`
（当前工作目录）。命令行也可指定：

```bash
python -m sealium.server.run --config /etc/sealium/sealium.toml
python -m sealium.server.config_cli --config /etc/sealium/sealium.toml check
```

文件不存在时回退默认值（零配置开箱即用）。

---

## 敏感字段隔离

**私钥口令**（`[security] private_key_passphrase`）必须经环境变量 / `.env` 注入，
**绝不写入 `sealium.toml`**：

- 类型为 `pydantic.SecretStr`，`repr`/序列化/`/debug/config` 输出**不回显明文**
  （以 `<set>`/`<unset>` 表示）。

```bash
# 生成带口令的私钥
python -m sealium.scripts.generate_keys --passphrase "a-long-random-passphrase"
# 启动时注入同名口令（.env 或环境变量）
export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE="a-long-random-passphrase"
```

---

## 配置管理 CLI（`config_cli`）

```bash
python -m sealium.server.config_cli init              # 当前目录生成 sealium.toml 模板（--force 覆盖）
python -m sealium.server.config_cli check             # 加载 + 业务校验，退出码反映健康
python -m sealium.server.config_cli show              # 脱敏打印生效配置 + 来源
```

- `init`：模板内嵌为代码常量，pip 安装后**一定可用**（不依赖仓库文件）。生成的
  `sealium.toml` 在当前目录。
- `check`：纳入部署脚本 / CI 门禁；失败返回非零退出码。
- `show`：路径已解析为绝对路径，口令脱敏。

---

## 校验

- **类型 / 范围**：pydantic 在配置构造时即校验（`port` 范围、`threshold` 越界、
  `replay_cache_size` 为正等），非法值立即 `ValidationError` 并聚合报错。
- **业务校验**：`ServerConfig.validate()` 检查私钥文件存在，由应用 `lifespan` 在
  启动时调用（注入加密器的测试 / 调试模式跳过）。`config_cli check` 可独立触发。

---

## 客户端配置

客户端 `Activator` 无服务端配置，参数全部构造时传入。唯一相关的全局项：

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MACHINE_ID_PEPPER` | *(内置常量)* | 逐项哈希的 pepper。**仅客户端生成指纹时读**；服务端不读。**部署后不可变**：改它会让所有已绑定记录失配、强制全员重激活 |

> `MACHINE_ID_PEPPER` 属 common 层（硬件指纹），不参与服务端 TOML 配置，保持原名
> （不带 `SEALIUM_` 前缀）。打包客户端时可设为私有值，使不同发行的客户端指纹互不通用。

---

## 从旧版迁移（1.3.x → 1.4.0+）

1.4.0 起，旧的裸环境变量全部废弃。**最简单的迁移：什么都不用做**——零配置开箱即用。
若曾用旧环境变量自定义过，按下表迁移到 `sealium.toml`（或对应 `SEALIUM_*` 环境变量）：

| 旧环境变量（1.3.x） | 新位置 |
|---|---|
| `HOST` | `[server] host` |
| `PORT` | `[server] port` |
| `DEBUG` | `[server] debug` |
| `API_PREFIX` | `[server] api_prefix` |
| `ACTIVATION_PATH` | `[server] activation_path` |
| `CORS_ORIGINS` | `[cors] origins`（TOML 数组） |
| `DATABASE_PATH` | `[paths] database` |
| `SERVER_PRIVATE_KEY_PATH` | `[paths] private_key` |
| `SERVER_PUBLIC_KEY_PATH` | `[paths] public_key` |
| `SERVER_PRIVATE_KEY_PASSPHRASE` | 环境变量 `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` |
| `TIME_STAMP_TOLERANCE_SECONDS` | `[security] timestamp_tolerance_seconds` |
| `REPLAY_CACHE_SIZE` | `[security] replay_cache_size` |
| `RATE_LIMIT_ENABLED` | `[rate_limit] enabled` |
| `RATE_LIMIT_MAX_REQUESTS` | `[rate_limit] max_requests` |
| `RATE_LIMIT_WINDOW_SECONDS` | `[rate_limit] window_seconds` |
| `LOG_LEVEL` | `[logging] level` |
| `LOG_FORMAT` | `[logging] format` |
| `MACHINE_ID_THRESHOLD` | `[machine_id] threshold` |
| `MACHINE_ID_CORE_MIN` | `[machine_id] core_min` |
| `MACHINE_ID_SPOOF_MAX` | `[machine_id] spoof_max` |

需要配置文件时：

```bash
python -m sealium.server.config_cli init    # 生成 sealium.toml
# 按上表把旧值填入，或直接用 SEALIUM_* 环境变量覆盖
python -m sealium.server.config_cli check   # 自检
python -m sealium.server.run
```
