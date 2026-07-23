# 服务端部署指南

本篇面向**运维**：从零部署 Sealium 激活服务到生产。

## 1. 安装

> **默认与推荐部署方式：Linux + 反向代理（nginx 等）。** 服务端进程为明文 HTTP、`0600`
> 文件权限按 Linux 语义保证，设计为置于反向代理 + TLS 之后；默认仅监听回环 `127.0.0.1`。
> 服务端只在指纹比对（不采集硬件），故 Linux 部署完全可用；仅客户端采集需 Windows。
> Windows 作服务端部署的差异见 §5.1。

```bash
pip install sealium
```

需要 Python ≥ 3.9。Windows 上会自动装 `wmi`（仅服务端若同机调试采集才需要；纯服务端部署
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
```

启动时经 `.env` 或环境变量 `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE` 提供同名口令；口令、
激活码哈希 pepper 等敏感项的完整配置见 [配置参考 §4](configuration.md#4-敏感项与-env-配置)。

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

默认监听 `127.0.0.1:8000`（仅回环），数据落在当前目录 `./data/`（自动创建）。**设计上置于
反向代理/防火墙之后**，不要裸暴露公网。同机反代直接转发到回环即可；反代跨机/容器时设
`host = "0.0.0.0"`（见 §5）。

健康检查：`GET /health` → `{"status":"ok","service":"activation"}`。
激活接口：`POST /v1/activation`（`application/octet-stream`，见 [协议](protocol.md)）。

### 需要覆盖默认值时

一键生成全套配置模板（结构化配置 + 敏感项），编辑后自检：

```bash
python -m sealium.server.config_cli init      # 生成 sealium.toml + .env（当前目录）
python -m sealium.server.config_cli check     # 自检
python -m sealium.server.run
```

**所有字段、`.env`、环境变量、场景配方（生产加固 / 容器 / 多 worker + Redis）的完整说明见
[配置参考](configuration.md)。** 本篇聚焦部署流程，不重复字段细节。

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
        # 用标准 X-Forwarded-For 链（追加本跳 $remote_addr）。应用层据此做限流
        # 分桶（HIGH-001）。切勿只设 X-Real-IP——应用层不读取 X-Real-IP。
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> **限流与真实客户端 IP（HIGH-001）**：应用层限流**不会**直接用 TCP 对端地址——
> 那在反代后恒为代理 IP，会让所有限流并入单一全局桶（一个攻击者即可耗尽全局
> 额度拒绝所有合法激活）。Sealium 经配置项 `[server] trusted_proxies` 受控解析
> `X-Forwarded-For`：仅当请求的 TCP 对端在 `trusted_proxies` 内时，才采信其写入
> 的 XFF 链解析真实客户端 IP。默认 `["127.0.0.1", "::1"]` 覆盖同机反代场景。
> **反向代理跨机/容器时，务必把反代所在 IP 加入 `trusted_proxies`**，否则限流仍
> 按代理 IP 聚合。不要把 `trusted_proxies` 设为 `"*"` 或全网——那会让任意直连
> 攻击者伪造 XFF 绕过限流。

服务端默认已绑定回环 `127.0.0.1`（与上面 `proxy_pass http://127.0.0.1:8000` 对齐），同机反代
无需改。仅当反向代理在另一台机器或容器内时，才设 `[server] host = "0.0.0.0"`（或内网 IP），
并确保该端口只对反代可达。

### 5.1 Windows 服务端部署差异（非默认）

Sealium 服务端默认部署在 Linux。若必须在 Windows 上运行服务端，注意以下差异：

- **文件权限**：`os.chmod(0600)` 在 NTFS 上不生效（只切换只读位，不约束 ACL）。私钥与
  SQLite 文件对同机其他用户默认可读——务必用 `icacls` 收紧 ACL，或更简单：**给私钥加口令
  加密**（`--passphrase` + `SEALIUM_SECURITY__PRIVATE_KEY_PASSPHRASE`），这是 Windows 上唯一
  可靠的私钥保护。
- **激活码已哈希存储**（MEDIUM-002）：SQLite 文件即便被读出，也无法直接获得可用激活码。
- **服务化**：用 NSSM/Windows Service 包装 `python -m sealium.server.run`，而非裸控制台。

## 6. 数据库

- 默认 SQLite 文件 `./data/database.db`，权限 `0600`。
- 表结构极简（见 [架构 §目录结构](architecture.md)）；切换路径用 `[paths] database`（见 [配置参考](configuration.md)）。
- 表在首次连接时自动创建，无需手动迁移。
- 高并发写考虑定期备份 + WAL 模式（如需）。

## 7. 多 worker 注意

`uvicorn --workers N` / gunicorn 多进程时：
- **防重放缓存**（`replay_guard`）和**限流**（`rate_limit`）都是**进程内**计数，各 worker 独立。
- **多 worker 必须**注入共享后端（如 Redis）实现 `create_app` 的 `replay_guard` / `rate_limiter`，
  否则防重放与限流都会因进程隔离而弱化（攻击者轮询命中不同 worker 即可绕过单进程额度）。

单进程（默认）下进程内实现已足够，无需额外组件。

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
