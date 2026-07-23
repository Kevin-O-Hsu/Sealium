# 配置参考

> 本篇是 Sealium 服务端配置的**唯一权威参考**：每个字段、`.env`、环境变量、常见部署场景
> 都集中在这里。**部署流程**（安装、生成密钥、生成激活码、启动、反向代理）见
> [服务端部署指南](server-guide.md)；本篇只回答"怎么配"。

---

## 1. 30 秒快速开始

**零配置**即可跑（内置默认值齐全）：

```bash
pip install sealium
python -m sealium.scripts.generate_keys
python -m sealium.scripts.generate_activation_codes --count 10
python -m sealium.server.run
```

默认监听 `127.0.0.1:8000`，数据落 `./data/`。**无需任何配置文件。**

需要覆盖默认值时，一键生成全套模板（结构化配置 + 敏感项）：

```bash
python -m sealium.server.config_cli init     # 在当前目录生成 sealium.toml + .env
# 编辑 sealium.toml（端口/限流/策略等）和 .env（口令/pepper 等敏感项）
python -m sealium.server.config_cli check    # 自检（退出码反映健康）
python -m sealium.server.run
```

> `init` 同时生成 `sealium.toml` 和 `.env` 两个模板；两者均被 `.gitignore` 忽略，不会入库。
> 模板内嵌为代码常量，pip 安装后**一定可用**，不依赖仓库文件。

---

## 2. 配置来源与优先级

从高到低，前者覆盖后者：

| 优先级 | 来源 | 用途 |
|---|---|---|
| 1 | 构造参数 `ServerConfig(server=…)` | 程序化注入（测试 / 嵌入式集成） |
| 2 | 环境变量 `SEALIUM_<SECTION>__<KEY>` | 部署差异、容器 / systemd 注入 |
| 3 | `.env` 文件（与 2 同语义） | 本地开发、敏感项文件化 |
| 4 | `sealium.toml` | 结构化主配置（可注释、可 review、可版本化） |
| 5 | 内置默认值 | 零配置开箱即用 |

**一句话原则**：结构化配置放 `sealium.toml`，**敏感项（私钥口令、哈希 pepper）放 `.env` 或环境变量**，
其余用默认。不创建任何文件也能启动。

---

## 3. 完整字段参考（`sealium.toml`）

`config_cli init` 生成的模板即下表各项（带注释）。按 section 逐项说明。

### `[server]` 网络与路由

| 键 | 默认 | 说明 |
|---|---|---|
| `host` | `127.0.0.1` | 监听地址。**默认仅回环**（安全默认，同机反代转发）；反向代理跨机/容器时设 `0.0.0.0`（或内网 IP）并务必置于反代之后 |
| `port` | `8000` | 监听端口（1–65535） |
| `debug` | `false` | 调试模式：开启 `/docs`/`/redoc`/`/openapi.json`、`/debug/config`（仅回环）、uvicorn 热重载，并在启动时打印显著警告。**生产必须 `false`** |
| `api_prefix` | `/v1` | API 前缀 |
| `activation_path` | `/activation` | 激活路径（完整路由 = `api_prefix` + `activation_path`，默认 `/v1/activation`） |
| `trusted_proxies` | `["127.0.0.1","::1"]` | 反代部署下受信任的代理 IP（HIGH-001）：仅这些 TCP 对端写入的 `X-Forwarded-For` 才被限流采信解析真实客户端 IP。默认仅回环（同机反代）；跨机/容器反代务必加入反代所在 IP |
| `allowed_hosts` | `["*"]` | Host 头白名单（LOW-006）：`["*"]` 不校验；配具体域名（如 `["activation.example.com"]`）后启用 TrustedHostMiddleware 防 Host 投毒 / 路由混淆 |

### `[paths]` 存储与密钥

相对路径**相对配置文件所在目录**解析（部署目录可整体搬迁而不破坏路径）。

| 键 | 默认 | 说明 |
|---|---|---|
| `database` | `data/database.db` | SQLite 数据库路径；首次启动自动创建，Linux 下权限收紧 `0600` |
| `private_key` | `data/server_private.pem` | 服务端 RSA 私钥路径（由 `generate_keys` 生成） |
| `public_key` | *(空)* | 公钥路径（可选，仅调试用；默认取私钥同目录的 `server_public.pem`） |

### `[security]` 时间窗口、防重放、敏感项

| 键 | 默认 | 说明 |
|---|---|---|
| `timestamp_tolerance_seconds` | `300` | 客户端时间戳允许偏差（秒），超此拒绝（防伪造/过期请求） |
| `replay_cache_size` | `10000` | 防重放 `(code, nonce)` 缓存容量（LRU + TTL，逐条淘汰） |
| `private_key_passphrase` | *(空)* | **私钥口令：SecretStr，必须走 `.env`/环境变量，绝不写入 TOML**（见 §4） |
| `code_hash_pepper` | *(空)* | **激活码哈希 pepper：SecretStr，必须走 `.env`/环境变量，绝不写入 TOML**（见 §4） |

> 后两项是 `pydantic.SecretStr`：`repr` / 序列化 / `/debug/config` 输出**都不回显明文**
> （以 `<set>` / `<unset>` 表示），防止落日志或进调试端点。

### `[rate_limit]` 限流（进程内固定窗口）

超限返回 `429` + `Retry-After`。多 worker 各进程独立（弱一致）；全局精确需注入 Redis（见 §6.3）。

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 是否启用限流 |
| `max_requests` | `60` | 每 IP 每窗口最大请求数 |
| `window_seconds` | `60` | 窗口大小（秒） |

### `[machine_id]` 同机判定策略

控制服务端如何判定"是否同一台机器"（原理见 [硬件绑定](hardware-binding.md)）。

| 键 | 默认 | 说明 |
|---|---|---|
| `threshold` | `0.70` | 加权相似度门槛（0–1） |
| `core_min` | `3` | 核心类（cpu/board/bios/system_uuid）至少匹配几个 |
| `spoof_max` | `0.5` | `spoof_score` 超此直接判异机 |

调宽（更易认同一台机器，但防破解变弱）：降 `threshold` / `core_min`。调严（换一点硬件就要重激活）：
提高之。**改这些会让已绑定记录的判定结果变化**，一般不在运行中调整。

### `[logging]` 日志

| 键 | 默认 | 说明 |
|---|---|---|
| `level` | `INFO` | 日志级别（`DEBUG`/`INFO`/`WARNING`/`ERROR`） |
| `format` | `%(asctime)s - %(name)s - %(levelname)s - %(message)s` | 日志格式（Python `logging` 格式串） |

### `[cors]` CORS

| 键 | 默认 | 说明 |
|---|---|---|
| `origins` | `["*"]` | TOML 数组。原生客户端（octet-stream）无需浏览器凭据，`allow_credentials` 已硬编码关闭 |

> 环境变量传 `origins` 需用 JSON 数组字面量，如
> `SEALIUM_CORS__ORIGINS='["https://a.com","https://b.com"]'`。

---

## 4. 敏感项与 `.env` 配置

两个 `SecretStr` 字段**必须经 `.env` 或环境变量注入**，绝不写入 `sealium.toml`：

| 字段（`[security]`） | 环境变量 | 必要性 | 说明 |
|---|---|---|---|
| `private_key_passphrase` | `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` | 生产**强烈建议** | 私钥口令，需与 `generate_keys --passphrase` 一致。未设则私钥明文落盘（Windows 下 `0600` 不生效，务必设置） |
| `code_hash_pepper` | `SEALIUM_SECURITY__CODE_HASH_PEPPER` | 生产**建议** | 激活码哈希 pepper（见下） |

### `code_hash_pepper`（MEDIUM-002）

激活码以 `HMAC-SHA256(code, pepper)` 哈希后存入 DB（不再存明文），DB 文件泄露也无法还原可用码。
pepper 是部署私有随机串：

- **未设时**回退到源码内固定默认值（仍安全——激活码本身 128 位高熵，pepper 公开也不影响预像阻力），
  但多部署共用默认值缺乏唯一性，**生产建议设为随机值**。
- **部署后不可变**：改 pepper = 已生成的激活码全部失配、需重新 `generate_activation_codes`。
- **生成与查询必须同 pepper**：`generate_activation_codes` 与激活服务都从配置取同一个 pepper
  （已由代码保证，见 `app.py` 装配与 `generate_activation_codes.py`）。

### 完整 `.env` 模板

`config_cli init` 自动生成 `.env`，内容如下（填入你的随机值后保存）：

```bash
# Sealium 敏感项与部署差异（.env）
# .env 已被 .gitignore 忽略，不会入库——填入真实密钥后保持本地。
# 优先级：构造参数 > 环境变量 > .env > sealium.toml > 默认值。

# ══ 安全敏感项（务必改为你的随机值） ══
# 服务端私钥口令：与 generate_keys --passphrase 一致。
SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=REPLACE_WITH_LONG_RANDOM_PASSPHRASE
# 激活码哈希 pepper（MEDIUM-002）；部署后不可变。
SEALIUM_SECURITY__CODE_HASH_PEPPER=REPLACE_WITH_DEPLOY_UNIQUE_RANDOM

# ══ 部署差异（按需取消注释；结构化配置建议放 sealium.toml） ══
# SEALIUM_SERVER__HOST=0.0.0.0        # 默认 127.0.0.1；反代跨机/容器时设 0.0.0.0
# SEALIUM_SERVER__PORT=8000
# SEALIUM_SERVER__DEBUG=false
# SEALIUM_RATE_LIMIT__MAX_REQUESTS=60
# SEALIUM_RATE_LIMIT__WINDOW_SECONDS=60
# SEALIUM_SECURITY__TIMESTAMP_TOLERANCE_SECONDS=300
# SEALIUM_SECURITY__REPLAY_CACHE_SIZE=10000
```

> 也可以不用 `.env`，直接用真正的环境变量（`export SEALIUM_…=…`），或 systemd 的
> `EnvironmentFile=/path/to/.env`，效果相同。

---

## 5. 环境变量速查表

任何 TOML 字段都可被环境变量覆盖，命名规则 `SEALIUM_<SECTION>__<KEY>`（双下划线 `__` 分嵌套，
大小写不敏感）。优先级高于 TOML，低于构造参数。

| 环境变量 | 覆盖 | 默认 |
|---|---|---|
| `SEALIUM_SERVER__HOST` | `[server] host` | `127.0.0.1` |
| `SEALIUM_SERVER__PORT` | `[server] port` | `8000` |
| `SEALIUM_SERVER__DEBUG` | `[server] debug` | `false` |
| `SEALIUM_SERVER__API_PREFIX` | `[server] api_prefix` | `/v1` |
| `SEALIUM_SERVER__ACTIVATION_PATH` | `[server] activation_path` | `/activation` |
| `SEALIUM_PATHS__DATABASE` | `[paths] database` | `data/database.db` |
| `SEALIUM_PATHS__PRIVATE_KEY` | `[paths] private_key` | `data/server_private.pem` |
| `SEALIUM_PATHS__PUBLIC_KEY` | `[paths] public_key` | *(空)* |
| `SEALIUM_SECURITY__TIMESTAMP_TOLERANCE_SECONDS` | `[security] timestamp_tolerance_seconds` | `300` |
| `SEALIUM_SECURITY__REPLAY_CACHE_SIZE` | `[security] replay_cache_size` | `10000` |
| `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` | `[security] private_key_passphrase`（敏感） | *(空)* |
| `SEALIUM_SECURITY__CODE_HASH_PEPPER` | `[security] code_hash_pepper`（敏感） | *(空)* |
| `SEALIUM_RATE_LIMIT__ENABLED` | `[rate_limit] enabled` | `true` |
| `SEALIUM_RATE_LIMIT__MAX_REQUESTS` | `[rate_limit] max_requests` | `60` |
| `SEALIUM_RATE_LIMIT__WINDOW_SECONDS` | `[rate_limit] window_seconds` | `60` |
| `SEALIUM_MACHINE_ID__THRESHOLD` | `[machine_id] threshold` | `0.70` |
| `SEALIUM_MACHINE_ID__CORE_MIN` | `[machine_id] core_min` | `3` |
| `SEALIUM_MACHINE_ID__SPOOF_MAX` | `[machine_id] spoof_max` | `0.5` |
| `SEALIUM_LOGGING__LEVEL` | `[logging] level` | `INFO` |
| `SEALIUM_LOGGING__FORMAT` | `[logging] format` | *(见 §3)* |
| `SEALIUM_CORS__ORIGINS` | `[cors] origins`（JSON 数组） | `["*"]` |

不改配置文件就能覆盖单项（容器、systemd、临时测试都适用）：

```bash
SEALIUM_SERVER__PORT=9000 python -m sealium.server.run
```

---

## 6. 场景配方

### 6.1 生产加固（Linux + 反向代理）

最小可用生产配置：私钥口令 + pepper + 回环监听 + 反代 TLS。

`.env`（**必改两项随机值**）：
```bash
SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
SEALIUM_SECURITY__CODE_HASH_PEPPER=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
```

`sealium.toml`（默认值已是生产就绪，通常只需确认）：
```toml
[server]
host = "127.0.0.1"   # 同机反代转发到回环；跨机/容器反代才改 0.0.0.0
debug = false
[rate_limit]
enabled = true
```

反向代理（nginx + TLS + HSTS）配置见 [部署指南 §5](server-guide.md#5-反向代理与-tls生产必备)。
部署前自检：`python -m sealium.server.config_cli check`。

### 6.2 容器 / systemd 部署

容器与 systemd 推荐用**环境变量**注入（不依赖 `.env` 文件挂载）。

docker-compose 片段：
```yaml
services:
  sealium:
    image: your-sealium-image
    environment:
      SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE: ${SEALIUM_PASSPHRASE}
      SEALIUM_SECURITY__CODE_HASH_PEPPER: ${SEALIUM_PEPPER}
      SEALIUM_SERVER__HOST: "0.0.0.0"   # 容器内需对外（反代在另一容器/主机）
    volumes:
      - ./data:/app/data   # 持久化数据库与私钥
    ports:
      - "127.0.0.1:8000:8000"   # 仅对宿主回环暴露，由宿主反代转发
```

systemd 单元片段：
```ini
[Service]
Environment=SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE=...
Environment=SEALIUM_SECURITY__CODE_HASH_PEPPER=...
Environment=SEALIUM_SERVER__HOST=127.0.0.1
# 或用 EnvironmentFile=/etc/sealium/sealium.env
ExecStart=/usr/bin/python -m sealium.server.run
```

### 6.3 多 worker + Redis（可选）

单进程（`python -m sealium.server.run` 默认）下，防重放与限流都是进程内实现，**无需额外组件**。

`uvicorn --workers N` / gunicorn 多进程时，防重放缓存与限流计数器**各 worker 独立**，会因进程隔离
而弱化（攻击者轮询命中不同 worker 即可绕过单进程额度）。多 worker **必须**注入共享后端（如 Redis）
实现 `create_app` 的 `replay_guard` / `rate_limiter`：

```python
from sealium.server.app import create_app
# 自定义实现 ReplayStore / RateLimiter 协议的 Redis 后端后注入
app = create_app(replay_guard=..., rate_limiter=...)
```

> 单进程部署是默认且推荐方式；仅在高可用 / 多实例需求下才需多 worker + Redis。

---

## 7. 配置管理 CLI（`config_cli`）

```bash
python -m sealium.server.config_cli init    # 当前目录生成 sealium.toml + .env 模板（--force 覆盖）
python -m sealium.server.config_cli check   # 加载 + 业务校验（私钥文件存在等），退出码反映健康
python -m sealium.server.config_cli show    # 脱敏打印生效配置 + 来源（口令/pepper 显示 <set>/<unset>）
```

- `init`：两个模板均内嵌为代码常量，pip 安装后**一定可用**（不依赖仓库文件）。
- `check`：纳入部署脚本 / CI 门禁；失败返回非零退出码。
- `show`：路径已解析为绝对路径，敏感项脱敏。

---

## 8. 配置文件查找

`sealium.toml` 的查找路径由环境变量 `SEALIUM_CONFIG` 指定，缺省 `./sealium.toml`（当前工作目录）。
命令行也可指定：

```bash
python -m sealium.server.run --config /etc/sealium/sealium.toml
python -m sealium.server.config_cli --config /etc/sealium/sealium.toml check
```

文件不存在时回退默认值（零配置开箱即用）。`.env` 固定从当前工作目录读取。

---

## 9. 客户端配置

客户端 `Activator` 无服务端配置文件，参数全部构造时传入。唯一相关的全局项是硬件指纹 pepper：

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MACHINE_ID_PEPPER` | *(无——未设则抛错)* | 逐项哈希的 pepper。**仅客户端生成指纹时读**；服务端不读。**强制配置（LOW-003）**：未设时客户端生成指纹抛 `RuntimeError`，杜绝使用源码公开默认值导致跨发行指纹互通。**部署后不可变**：改它会让所有已绑定记录失配、强制全员重激活。详见 [客户端集成 §9](client-guide.md#9-配置客户端硬件指纹-pepper分发前必做) |

> `MACHINE_ID_PEPPER` 属 common 层（硬件指纹），不参与服务端 TOML 配置，保持原名（不带 `SEALIUM_`
> 前缀）。打包客户端时可烧进源码或经启动器注入私有值，使不同发行的客户端指纹互不通用。

---

## 10. 从旧版迁移（1.3.x → 1.4.0+）

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
| `SERVER_PRIVATE_KEY_PASSPHRASE` | `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` |
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
python -m sealium.server.config_cli init    # 生成 sealium.toml + .env
# 按上表把旧值填入，或直接用 SEALIUM_* 环境变量覆盖
python -m sealium.server.config_cli check   # 自检
python -m sealium.server.run
```

> **1.4.x 后续 breaking（安全加固）**：
> - 激活码改哈希存储（`code_hash_pepper`）：旧版明文库不兼容，升级后需重新 `generate_activation_codes`。
> - 默认 `host` 改为 `127.0.0.1`（原 `0.0.0.0`）：依赖旧默认的部署需显式设 `host = "0.0.0.0"`。
