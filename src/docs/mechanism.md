# Sealium 激活验证模块技术方案

## 1. 激活码生成（服务端）

- 激活码由服务端随机生成，采用 128 位高强度随机数，编码为十六进制字符串（32 字符）。
- 数据库记录字段：
  - `activation_code`：激活码字符串（主键）
  - `bound_machine_code`：绑定的机器码（未绑定为 NULL）
  - `activated_at`：激活时间（ISO 格式）
  - `expires_at`：授权截止时间（ISO 格式，永久为 NULL）
  - `features`：授权功能列表（JSON 格式存储）
  - `status`：激活状态（0-未激活，1-已激活）

## 2. 密钥准备

- 服务端生成 RSA 密钥对（4096 位）：
  - 私钥 `server_private.pem`：服务端持有，用于解密客户端请求中的 AES 密钥
  - 公钥 `server_public.pem`：分发给客户端，用于加密临时 AES 密钥
- **客户端不再持有任何长期私钥**，仅部署服务端公钥。
- **密钥分发**：
  - 服务端部署：`server_private.pem`
  - 客户端部署：`server_public.pem`

## 3. 激活流程（HTTPS 传输）

### 3.1 客户端构造请求（双层加密）

1. 获取机器码 `MachineCode`：组合硬盘序列号和 MAC 地址，使用 SHA256 哈希生成 64 位十六进制字符串
2. 生成随机数 `Nonce_C`（16 字节，32 位十六进制字符串）
3. 获取权威时间戳 `Timestamp`（Unix 秒级，从 `https://aisenseapi.com/services/v1/timestamp` 获取）
4. 构造明文请求体：
   ```json
   {
     "activation_code": "用户输入的激活码",
     "machine_code": "MachineCode",
     "timestamp": Timestamp,
     "nonce": Nonce_C
   }
   ```
5. **第一层加密（业务数据）**：生成临时 AES-256 密钥和随机 Nonce，使用 AES-GCM 模式加密请求明文，得到 `(ciphertext, tag)`。
6. **第二层加密（密钥传输）**：使用服务端公钥（RSA-OAEP-SHA256）加密临时 AES 密钥，得到 `encrypted_aes_key`。
7. 组装数据包：`encrypted_aes_key`（固定长度 512 字节） + `aes_nonce`（12 字节） + `ciphertext` + `tag`（16 字节）。
8. 通过 HTTPS 将二进制数据包发送至服务端激活接口 `POST /v1/activation`，Content-Type 为 `application/octet-stream`。

### 3.2 服务端验证

1. 解析数据包，分离出 `encrypted_aes_key`、`aes_nonce`、`ciphertext`、`tag`。
2. 使用服务端私钥解密 `encrypted_aes_key`，得到临时 AES 密钥。
3. 使用 AES-GCM 解密 `(ciphertext, tag)`，得到请求明文 JSON。
4. **时间戳校验**：计算 `|服务器当前时间 - Timestamp|`，若超过配置的容忍度（默认 300 秒），返回错误。
5. **防重放检查**：记录已使用的 `(activation_code, nonce)` 组合，若重复则拒绝。
6. **激活码校验**：
   - 查询数据库，确认激活码存在
   - 若状态为“已使用”，检查绑定的机器码是否与请求的机器码一致
     - 一致：返回成功（已激活，幂等）
     - 不一致：返回“激活码已被其他设备使用”
   - 若激活码已过期，返回“激活码已过期”
7. **绑定**：
   - 更新激活码状态为“已激活”
   - 绑定机器码、记录激活时间
   - 写入授权截止时间和功能列表
8. 构造响应明文：
   ```json
   {
     "result": "success",
     "authorized_until": "2026-12-31",
     "features": ["premium", "enterprise"],
     "nonce": Nonce_C
   }
   ```
   > 注：响应的 `nonce` 字段直接返回客户端请求中的 `nonce`，用于客户端验证。
9. **加密响应**：使用步骤 2 中得到的同一个临时 AES 密钥，生成新的随机 Nonce，用 AES-GCM 加密响应明文，得到 `(resp_nonce, resp_ciphertext, resp_tag)`。
10. 组装响应包：`resp_nonce`（12 字节） + `resp_ciphertext` + `resp_tag`（16 字节）。
11. 通过 HTTPS 返回二进制数据包，Content-Type 为 `application/octet-stream`。

### 3.3 客户端处理响应

1. 使用之前生成的临时 AES 密钥，解析响应包：提取 `nonce`、`ciphertext`、`tag`，进行 AES-GCM 解密，得到响应明文 JSON。
2. 解析 JSON 为 `ActivationResponse` 对象。
3. 若 `result == "success"`，验证 `nonce` 字段与请求时发送的 `Nonce_C` 一致。
4. 将授权信息（截止时间、功能列表）加密存储于本地（使用机器码派生的 AES 密钥加密）。
5. 记录绑定状态。

## 4. 后续启动验证

- **本地验证**：客户端每次启动时读取本地授权文件，检查是否过期
- **离线可用**：授权有效期内可直接放行，无需联网
- **异步心跳**（可选）：定期向服务端发送心跳请求，携带机器码和授权信息，服务端校验机器码是否匹配，若不匹配则通知客户端重新激活

## 5. 安全机制

| 安全措施 | 实现方式 |
|---------|---------|
| **通信加密** | 双层加密：RSA-4096 加密临时 AES 密钥 + AES-256-GCM 加密业务数据 |
| **防重放攻击** | 时间戳校验（±300 秒）+ nonce 记录 |
| **激活码防伪** | 128 位随机数，概率不可枚举 |
| **机器码绑定** | SHA256（硬盘序列号 + MAC 地址），防止跨机使用 |
| **本地授权保护** | 机器码派生 AES 密钥加密存储 |
| **防篡改** | 响应中的 nonce 验证（回显客户端 nonce） |
| **幂等性** | 同一机器重复激活返回成功，避免误报 |
| **无客户端私钥** | 彻底移除客户端长期私钥，降低逆向破解风险 |

## 6. 错误处理

| 错误场景 | 服务端返回 | 客户端行为 |
|---------|-----------|-----------|
| 请求数据为空 | 直接返回空响应（400） | 提示用户 |
| 解密失败（格式错误） | 直接返回空响应（400） | 提示错误 |
| 激活码格式无效 | `{"result":"error","error_msg":"激活码格式无效"}` | 提示用户重新输入 |
| 时间戳过期 | `{"result":"error","error_msg":"请求时间戳无效，请同步时间"}` | 提示用户同步时间 |
| 重放攻击 | `{"result":"error","error_msg":"请求已被使用，请勿重复发送"}` | 提示重试 |
| 激活码不存在 | `{"result":"error","error_msg":"激活码不存在"}` | 提示无效激活码 |
| 激活码已被其他设备使用 | `{"result":"error","error_msg":"激活码已被其他设备使用"}` | 提示已在其他设备激活 |
| 激活码已过期 | `{"result":"error","error_msg":"激活码已过期"}` | 提示购买新激活码 |
| 数据库更新失败 | `{"result":"error","error_msg":"数据库更新失败"}` | 提示联系客服 |

## 7. 防破解增强

- **代码虚拟化**：客户端关键逻辑（机器码生成、AES 密钥生成、加解密）使用虚拟化保护
- **反调试检测**：检测调试器、模拟器、HOOK 框架
- **代码完整性校验**：计算自身关键代码段哈希，防止静态修改
- **本地授权加密**：使用机器码派生密钥加密授权文件，防止跨机复制

## 8. 配置管理

服务端配置支持环境变量覆盖：

| 配置项 | 环境变量 | 默认值 |
|-------|---------|------------------------------|
| 数据库路径 | `DATABASE_PATH` | `./data/database.db` |
| 服务端私钥路径 | `SERVER_PRIVATE_KEY_PATH` | `./data/server_private.pem` |
| 时间戳容忍度 | `TIME_STAMP_TOLERANCE_SECONDS` | `300` |
| 防重放缓存大小 | `REPLAY_CACHE_SIZE` | `10000` |
| API 前缀 | `API_PREFIX` | `/v1` |
| 激活接口路径 | `ACTIVATION_PATH` | `/activation` |

> 注：不再需要 `CLIENT_PUBLIC_KEY_PATH` 配置。

## 9. 数据库表结构

```sql
CREATE TABLE IF NOT EXISTS activation_codes (
    code TEXT PRIMARY KEY,
    bound_machine_code TEXT,
    activated_at TEXT,
    expires_at TEXT,
    features TEXT,
    status INTEGER NOT NULL DEFAULT 0
);
```

## 10. 客户端 API

```python
from sealium.client.activator import Activator, ActivationError

# 初始化（只需服务端公钥）
activator = Activator(
    server_url="https://your-server.com/v1/activation",
    server_public_key_pem=server_pub_key
)

# 激活
try:
    response = activator.activate(activation_code)
    if response.result == "success":
        print(f"激活成功，有效期至 {response.authorized_until}")
        print(f"功能: {response.features}")
    else:
        print(f"激活失败: {response.error_msg}")
except ActivationError as e:
    print(f"错误: {e}")
```

## 11. 服务端部署

```bash
# 1. 生成服务端密钥对
openssl genrsa -out data/server_private.pem 4096
openssl rsa -in data/server_private.pem -pubout -out data/server_public.pem

# 2. 将服务端公钥分发给客户端（客户端只需此文件）

# 3. 启动服务
uvicorn sealium.server.app:app --host 0.0.0.0 --port 8000

# 4. 生成激活码
python -c "from sealium.scripts.generate_activation_codes import generate_activation_codes; generate_activation_codes(10)"
```

## 12. 测试验证

运行集成测试：
```bash
pytest tests/test_activation_flow.py -v
pytest tests/test_activation_plus.py -v
```
