# 服务端部署指南

本篇面向**运维**：从零部署 Sealium 激活服务到生产。

## 1. 安装

```bash
pip install sealium
```

需要 Python ≥ 3.13。Windows 上会自动装 `wmi`（仅服务端若同机调试采集才需要；纯服务端部署
在 Linux 也完全可用，因为服务端只比对指纹、不采集硬件）。

## 2. 生成服务端密钥对

```bash
python -m sealium.scripts.generate_keys \
    --private-key data/server_private.pem \
    --public-key  data/server_public.pem \
    --key-size 4096
```

- **私钥** `server_private.pem`：只留在服务器，权限自动收紧为 `0600`，**永不分发、永不提交**。
- **公钥** `server_public.pem`：随客户端分发（客户端只需要它）。

建议给私钥加口令加密落盘：

```bash
python -m sealium.scripts.generate_keys --passphrase "a-long-random-passphrase"
# 启动时通过环境变量（或 .env）提供同名口令：
export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE="a-long-random-passphrase"
```

> 不提供 `--passphrase` 则私钥明文存储（向后兼容，不推荐用于生产）。

## 3. 生成激活码

激活码是 128 位随机数（32 个十六进制字符），生成后写入服务端数据库：

```bash
# 生成 100 个永久激活码
python -m sealium.scripts.generate_activation_codes --count 100

# 生成 50 个到 2026-12-31 到期、带功能标记的码，输出到文件
python -m sealium.scripts.generate_activation_codes \
    --count 50 \
    --expires 2026-12-31 \
    --features premium,enterprise \
    --output codes.txt
```

| 参数 | 说明 |
|---|---|
| `--count` | 数量（默认 10） |
| `--expires` | `YYYY-MM-DD` 或 `permanent`（默认永久） |
| `--features` | 功能列表，逗号分隔（如 `premium,enterprise`） |
| `--db` | 数据库路径（默认读配置 `[paths] database`） |
| `--output` | 输出到文件（可选） |
| `--no-print` | 不打印到控制台 |

也可作为库调用：

```python
from sealium.scripts.generate_activation_codes import generate_activation_codes

codes = generate_activation_codes(
    count=10,
    expires_at="2026-12-31",
    features=["premium"],
)
```

## 4. 启动服务（零配置开箱即用）

无需任何配置文件，3 行命令即可运行：

```bash
pip install sealium
python -m sealium.scripts.generate_keys
python -m sealium.scripts.generate_activation_codes --count 10
python -m sealium.server.run
```

默认监听 `0.0.0.0:8000`，数据落在当前目录 `./data/`（自动创建）。**设计上置于反向代理/
防火墙之后**，不要裸暴露公网。

健康检查：`GET /health` → `{"status":"ok","service":"activation"}`。
激活接口：`POST /v1/activation`（`application/octet-stream`，见 [协议](protocol.md)）。

### 需要覆盖默认值时（可选）

生成配置模板到当前目录，按需编辑：

```bash
python -m sealium.server.config_cli init      # 生成 sealium.toml 模板
python -m sealium.server.config_cli check     # 自检
python -m sealium.server.run
```

也可用环境变量覆盖单项（`SEALIUM_<SECTION>__<KEY>`）：

```bash
SEALIUM_SERVER__PORT=9000 python -m sealium.server.run
# 或指定配置文件：
python -m sealium.server.run --config /etc/sealium/sealium.toml
```

敏感项（私钥口令）只用环境变量，**不写进配置文件**：

```bash
export SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE="a-long-random-passphrase"
```

默认 `[server] host = "0.0.0.0"`；生产建议绑定本机（`SEALIUM_SERVER__HOST=127.0.0.1`
或 `sealium.toml` 里 `[server] host = "127.0.0.1"`）。完整配置项见
[配置参考](configuration.md)。

## 5. 反向代理与 TLS（生产必备）

业务负载已由应用层混合加密端到端保护，但仍应在反向代理终止 TLS 以隐藏元信息：

```nginx
server {
    listen 443 ssl http2;
    server_name activation.example.com;

    ssl_certificate     /etc/ssl/activation.crt;
    ssl_certificate_key /etc/ssl/activation.key;
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;   # 限流按此 IP 聚合
    }
}
```

并把服务端绑定到本机：在 `sealium.toml` 设 `[server] host = "127.0.0.1"`（或环境变量 `SEALIUM_SERVER__HOST=127.0.0.1`）。

## 6. 数据库

- 默认 SQLite 文件 `./data/database.db`，权限 `0600`。
- 表结构极简（见 [架构 §目录结构](architecture.md)）；切换路径用 `[paths] database`（见 [配置参考](configuration.md)）。
- 表在首次连接时自动创建，无需手动迁移。
- 高并发写考虑定期备份 + WAL 模式（如需）。

## 7. 多 worker 注意

`uvicorn --workers N` / gunicorn 多进程时：
- **防重放缓存**（`replay_guard`）和**限流**（`rate_limit`）都是**进程内**计数，各 worker 独立。
- 若需全局一致（精确防重放、精确限流），把 `create_app` 的 `replay_guard` / `rate_limiter`
  注入为共享后端实现（如 Redis）。

单实例或弱一致场景下，进程内实现已足够。

## 8. 调试

`[server] debug = true`（或 `SEALIUM_SERVER__DEBUG=true`）时：
- 自动开启 `/docs`、`/redoc`、`/openapi.json`（生产请保持 `false`，避免泄露接口结构）。
- `/debug/config` 可查看当前生效配置（**脱敏**：私钥口令以 `<set>`/`<unset>` 表示）。
- uvicorn 开启热重载。

无需启动服务也能查看 / 校验配置：`python -m sealium.server.config_cli show|check`。

## 9. 版本升级

升级 `sealium` 后重启服务即可。注意两个 breaking change：

- **1.3.0** 硬件绑定：旧 `bound_machine_code`（整体哈希字符串）无法被新版本解析，
  需清库重建激活码（见 [硬件绑定](hardware-binding.md)）。
- **1.4.0** 配置系统：旧的裸环境变量（`HOST`/`PORT`/`DATABASE_PATH`/…）废弃，
  改为 `sealium.toml` + `SEALIUM_*` 环境变量（见 [配置参考 §迁移](configuration.md#从旧版迁移13x--140)）。

## 下一步

- [配置参考](configuration.md)：TOML schema 与环境变量覆盖。
- [安全模型](security.md)：部署加固清单。
- [故障排查](troubleshooting.md)：常见错误。
