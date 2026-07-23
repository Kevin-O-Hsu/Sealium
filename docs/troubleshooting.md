# 故障排查

## 快速诊断流程

```
激活失败
  │
  ├─ 抛 ActivationError？ ──→ 流程性错误（网络/加密/解析/nonce）→ 见 §流程异常
  │
  └─ response.result == "error"？ ──→ 业务拒绝 → 按 error_msg 见 §业务错误
```

## 业务错误（`response.error_msg`）

| `error_msg` | 根因 | 处理 |
|---|---|---|
| `激活码格式无效` | 输入非字符串/为空 | 检查用户输入 |
| `请求时间戳无效，请同步时间` | 客户端时间与权威 API 偏差 > 300s | 同步系统时间；检查能否访问权威时间 API |
| `请求已被使用，请勿重复发送` | 同一 `(code, nonce)` 重复提交 | 重新发起（会生成新 nonce） |
| `激活码无效或已被使用` | 码不存在 / 已过期 / **已被其他设备绑定** | 见下"此码已被占用？" |
| `激活码已过期` | 码超过截止日期 | 生成新码 |
| `激活失败，请稍后重试` | 服务端数据库异常（兜底） | 看服务端日志；稍后重试 |
| `请求格式错误: ...` | 请求体非法（如 machine_code 不是指纹对象） | 客户端版本过旧（< 1.3.0）？升级客户端 |

### "激活码无效或已被使用"——是码错了还是被别的机器占了？

这条提示合并了三种情况（安全设计，防枚举）。排查：

1. **确认码确实存在且未过期**：在服务端数据库查 `SELECT * FROM activation_codes WHERE code=?`。
2. **看 `status`**：
   - `0`（UNUSED）：码没被激活过 → 是"码不存在"（手输错）或时间戳/防重放问题。
   - `1`（USED）：已被激活 → 看 `bound_machine_code`，与本机指纹比对（见下）。
3. **比对机器指纹**：若 `status=USED` 但本机确定是首次激活，说明此码被他机绑了（码泄漏/被复制）。

## 机器码相关问题

### 换了硬件后被拒（"已被其他设备使用"）

这是**核心类**变动超过门槛所致。默认策略：核心类（CPU/主板/BIOS/系统UUID）至少匹配 3 个。
换了主板（连带 BIOS + 系统 UUID）会让核心类失 3 个 → 判异机。

- 若属于合理硬件更换，需在服务端**重置该激活码**（删库记录或重新生成）让用户重新激活。
- 若想更宽松（换少量核心硬件仍认同一台），在 `sealium.toml` 调 `[machine_id] core_min` / `threshold`
  （见 [配置参考](configuration.md)）——注意这会降低防破解强度。

### spoof_score 偏高 / 采集异常

在客户端诊断实际采集结果：

```python
from sealium.common.machine_code import generate_machine_code
from sealium.common.hardware import collect_surfaces

raws = collect_surfaces()
from collections import Counter
print(dict(Counter((r.category, r.source) for r in raws)))   # 各表面来源

fp = generate_machine_code()
print("核心类:", sorted({c.category for c in fp.components if c.is_core}))
print("spoof_score:", fp.spoof_score)
```

- `spoof_score > 0.5` → 交叉验证检测到多源不一致。若非真 spoof，可能是某来源格式差异（已在
  采集层规范化抹平常见差异；仍有问题请提 issue 附上 `collect_surfaces()` 输出）。
- 核心类 < 4 → 某类硬件采不到（如虚拟机无 SMBIOS、无 TPM）。核心有效分量 < 2 时
  `generate_machine_code()` 抛 `SealiumError`——需提供 `fallback_secret_provider`。

### `RuntimeError: 原生硬件采集仅支持 Windows 平台`

客户端在非 Windows 上调用默认采集。非 Windows 客户端须自定义 `machine_code_provider`
（见 [客户端集成 §8](client-guide.md#8-非客户端采集)）。

## 流程异常（抛 `ActivationError`）

`ActivationError` 的消息指明哪一步失败：

| 消息含 | 根因 | 处理 |
|---|---|---|
| `获取机器码失败` | 采集抛错（平台不支持/特征过少无 fallback） | 见上"机器码相关" |
| `获取时间戳失败` | 权威时间 API 不可达 | 检查网络/代理；或注入自有 `timestamp_provider` |
| `加密请求失败` | 公钥无效/数据异常 | 确认 `server_public_key_pem` 正确 |
| `网络请求失败` | 连不上服务端 | 检查 `server_url`、网络、TLS、反代 |
| `解密响应失败` | 响应被篡改/密钥不匹配 | 疑似中间人或服务端异常 |
| `解析响应失败` | 响应明文非合法 JSON | 服务端版本不匹配/异常 |
| `响应 nonce 不匹配` | 响应被重放或篡改 | **警惕**：可能重放攻击 |

## 时间同步

时间戳偏差超 `[security] timestamp_tolerance_seconds`（默认 300s）即拒。

- 客户端时间戳取自 `https://aisenseapi.com/services/v1/timestamp`，**非本地时钟**。
- 若该 API 在你的网络环境不可达，激活会失败（`获取时间戳失败`）。可注入自定义
  `timestamp_provider=lambda: <你自己的权威时间>`。

## 限流 429

```
HTTP 429, Retry-After: 60
```

每 IP 在 `[rate_limit] window_seconds`（默认 60s）内超过 `[rate_limit] max_requests`（默认 60 次）。
正常激活不会触发；若客户端有"启动即重试"逻辑，可能误触——加退避或调大限额。

## 服务端排查

```bash
# 健康检查
curl https://activation.example.com/health

# 看配置（仅 [server] debug = true；脱敏，私钥口令以 <set>/<unset> 表示）。
# /debug/config 仅限本机回环访问（LOW-004），需在服务器本机访问：
curl http://127.0.0.1:8000/debug/config
# 无需启动服务也能查看 / 校验配置：
python -m sealium.server.config_cli show|check

# 查某激活码状态（直接查库）
sqlite3 data/database.db "SELECT code, status, activated_at, expires_at FROM activation_codes WHERE code='<CODE>';"

# 看日志（审计只记短哈希）
# grep "激活拒绝" /var/log/sealium.log
```

## 仍无法解决

收集以下信息后提 issue：

1. `sealium` 版本（`pip show sealium`）。
2. 客户端操作系统。
3. `error_msg` 或 `ActivationError` 完整消息。
4. （如涉及机器码）`collect_surfaces()` 与 `generate_machine_code()` 的输出。
5. 服务端相关日志行（短哈希即可）。
