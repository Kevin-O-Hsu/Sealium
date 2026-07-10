# 系统架构

## 设计目标

1. **客户端零长期密钥**：客户端只内置服务端**公钥**，不持有任何私钥——逆向客户端拿不到能伪造响应的密钥材料。
2. **端到端加密**：业务负载（激活码、机器码、授权结果）始终在 RSA+AES 混合加密包内传输，即使中间经过反向代理/日志也只能看到密文。
3. **服务端无状态偏好**：除 SQLite 存储激活码 + 进程内防重放/限流外，服务端不依赖外部有状态服务即可单实例运行；有状态组件均可注入替换为共享后端（Redis）。
4. **可注入、可测试**：所有运行时依赖（加密器、存储、时间源、机器码采集、HTTP）都能从外部注入，测试套件完全离线运行。
5. **无导入副作用**：`import sealium` 不发起网络请求、不读硬件、不连数据库、不打日志——所有 I/O 推迟到显式调用或服务端 lifespan。

## 分层

```
┌─────────────────────────────────────────────────────────┐
│  你的应用（客户端）            │  运维（服务端）          │
│  - sealium.client.Activator    │  - sealium.server.app    │
└──────────────┬─────────────────┴──────────┬──────────────┘
               │                            │
   ┌───────────▼──────────┐    ┌────────────▼─────────────┐
   │  sealium.client      │    │  sealium.server          │
   │  - activator         │◄──►│  - app (FastAPI 工厂)     │
   │  - key_manager       │HTTPS│  - routes/activation     │
   │    (混合加密组包)     │    │  - activation_service    │
   └───────────┬──────────┘    │  - database (SQLite)     │
               │               │  - replay_guard / rate_limit │
               │               │  - crypto_transport      │
   ┌───────────▼───────────────┴──────────┐
   │  sealium.common  (客户端+服务端共享)   │
   │  - crypto      RSA-4096 / AES-256-GCM │
   │  - models      ActivationRequest/Response/Code │
   │  - fingerprint MachineFingerprint / matches     │
   │  - machine_code 采集 → 分量指纹        │
   │  - hardware/    原生 SMBIOS/IOCTL + WMI 多表面 │
   │  - time_source  权威时间戳              │
   │  - exceptions / constants              │
   └────────────────────────────────────────┘
```

## 目录结构

```
src/sealium/
├── __init__.py            # 零副作用；__version__ 动态读 metadata
├── common/                # 客户端与服务端共享
│   ├── crypto.py          #   RSA-4096-OAEP / AES-256-GCM 原语
│   ├── models.py          #   ActivationRequest/Response/Code 数据模型
│   ├── fingerprint.py     #   机器指纹抽象 + matches 匹配算法（1.3.0 新增）
│   ├── machine_code.py    #   采集 → 分量指纹编排
│   ├── hardware/          #   硬件表面采集（1.3.0 新增）
│   │   ├── native_surfaces.py  # ctypes: SMBIOS 固件表 + 磁盘 IOCTL
│   │   ├── wmi_surfaces.py     # WMI 多表面（交叉源）
│   │   ├── cross_validate.py   # 多源交叉验证 + spoof 计分
│   │   └── types.py            # RawSurface
│   ├── time_source.py     #   权威时间戳
│   ├── exceptions.py      #   SealiumError 层次
│   └── constants.py       #   密钥尺寸、超时等
├── client/                # 客户端
│   ├── activator.py       #   Activator：激活流程编排
│   └── key_manager.py     #   混合加密组包/拆包
├── server/                # 服务端
│   ├── app.py             #   FastAPI 应用工厂 + lifespan
│   ├── run.py             #   python -m sealium.server.run 启动入口
│   ├── config.py          #   ServerConfig（环境变量驱动）
│   ├── database.py        #   SQLite + ActivationCodeStorage
│   ├── activation_service.py  # 激活业务核心（纯领域服务）
│   ├── replay_guard.py    #   防重放（进程内）
│   ├── rate_limit.py      #   限流（进程内固定窗口）
│   ├── crypto_transport.py#   解包/加密响应
│   ├── deps.py            #   FastAPI 依赖注入
│   └── routes/activation.py #  薄 HTTP 层
└── scripts/               # 运维 CLI
    ├── generate_keys.py           # 生成服务端 RSA 密钥对
    └── generate_activation_codes.py # 批量生成激活码入库
```

## 激活数据流（一次成功激活）

```
客户端                                服务端
  │  1. 采集硬件 → MachineFingerprint       │
  │  2. 生成 nonce_C（16 字节随机）          │
  │  3. 取权威时间戳 timestamp               │
  │  4. 组装明文请求 JSON                    │
  │     {activation_code, machine_code,      │
  │      timestamp, nonce}                   │
  │  5. 生成临时 AES-256 密钥                │
  │  6. AES-GCM 加密请求明文                 │
  │  7. RSA-OAEP 加密 AES 密钥               │
  │  8. 组装二进制包                         │
  │ ──────── POST /v1/activation ──────────► │
  │       (application/octet-stream)         │ 9.  解包：RSA 解 AES 密钥
  │                                          │ 10. AES-GCM 解请求明文
  │                                          │ 11. 时间戳窗口校验
  │                                          │ 12. 防重放 (code,nonce)
  │                                          │ 13. 查激活码
  │                                          │ 14. 原子绑定机器指纹
  │                                          │      (UNUSED→USED 条件 UPDATE)
  │                                          │ 15. 组装响应明文
  │                                          │ 16. 用同一 AES 密钥加密响应
  │ ◄──────── 二进制响应包 ──────────────── │
  │ 17. AES-GCM 解响应                       │
  │ 18. 校验回显 nonce == nonce_C            │
  │ 19. 取 authorized_until / features       │
```

关键安全点：步骤 14 的"检查未用 → 置已用"被压缩成单条带 `WHERE status=UNUSED` 的
`UPDATE`，多线程/多进程并发抢绑同一激活码时只有第一个 `UPDATE` 命中（`rowcount==1`），
杜绝"一码多机"。机器码的**相似度匹配只发生在已绑定后的重激活路径**（幂等判定），首次
绑定直接存入 incoming 指纹、不做比对——因此原子性不受相似度算法影响。

## 关键设计原则

### 无导入副作用

`import sealium`、`import sealium.server.app` 都不执行任何 I/O：不读私钥、不连数据库、
不读硬件、不请求网络。服务端资源在 FastAPI `lifespan` 启动时才初始化并挂到
`app.state`。这让单元测试可以纯内存、离线运行。

### 依赖可注入

- `Activator(server_url, server_public_key_pem, timestamp_provider=..., machine_code_provider=..., http_poster=...)`
- `ActivationService(storage, replay_guard, tolerance, now_provider=..., machine_id_policy=...)`
- `create_app(config=..., encryptor=..., storage=..., replay_guard=..., rate_limiter=..., now_provider=...)`

测试时注入固定时间、注入指纹采集器、用 `TestClient` 桥接 HTTP，即可完全离线驱动整条
激活链路（见 `tests/`）。

### Fail-safe

- 硬件特征过少（核心类有效分量 < 2）且无 fallback 时，**抛错而非生成不可靠指纹**——绝不
  注入 `time.time()` 这类每次都变的值，否则同一机器每次激活得到不同机器码。
- 加密失败、解密失败、nonce 不匹配一律收敛为 `ActivationError`，不向调用方泄漏内部异常。

### 单一真值源

- 版本号只在 `pyproject.toml`，`__version__` 动态读 `importlib.metadata`。
- 硬件类别权重表只在 `fingerprint.DEFAULT_WEIGHTS`，采集层与匹配层共用。
