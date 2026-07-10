# Sealium 文档

Sealium 是一套面向生产环境的**软件许可证生成、在线激活与硬件绑定**方案：服务端用
FastAPI 提供激活接口，客户端只需内置服务端**公钥**即可完成激活；所有业务负载经
RSA-4096 + AES-256-GCM 混合加密端到端保护。

本目录是 Sealium 的完整文档。按角色选择入口：

## 按角色快速入口

| 我想要… | 先读这篇 |
|---|---|
| 5 分钟跑通一次激活 | [客户端集成指南](client-guide.md) |
| 把激活服务部署到服务器 | [服务端部署指南](server-guide.md) |
| 搞懂硬件绑定/机器码怎么防破解 | [硬件绑定原理](hardware-binding.md) |
| 理解加密协议与数据包格式 | [加密与传输协议](protocol.md) |
| 查全部环境变量与默认值 | [配置参考](configuration.md) |
| 评估安全模型与已知限制 | [安全模型](security.md) |
| 排查激活失败 | [故障排查](troubleshooting.md) |
| 通览整体设计与模块职责 | [系统架构](architecture.md) |

## 文档总览

- **[系统架构](architecture.md)** —— 客户端/服务端/共享层分层、模块职责、激活数据流、关键设计原则（无导入副作用、依赖可注入、fail-safe）。
- **[加密与传输协议](protocol.md)** —— 双层混合加密、数据包二进制格式、时间戳窗口、防重放、nonce 回显校验。
- **[硬件绑定原理](hardware-binding.md)** —— 分量指纹、原生多表面（SMBIOS 固件表/磁盘 IOCTL）与 WMI 的交叉验证、加权相似度 + 核心门槛阈值匹配、spoof 防御。**1.3.0 重构核心**。
- **[服务端部署指南](server-guide.md)** —— 安装、密钥生成、激活码生成、启动、反向代理/TLS、多 worker、限流。
- **[客户端集成指南](client-guide.md)** —— 安装、激活调用、错误处理、把激活嵌入你的应用。
- **[配置参考](configuration.md)** —— 全部环境变量、默认值、调优建议。
- **[安全模型](security.md)** —— 威胁假设、对策矩阵、最佳实践、已知限制。
- **[故障排查](troubleshooting.md)** —— 常见错误码、机器码漂移、时间同步、限流 429 等。

## 版本与兼容性

- 当前版本：见 [`pyproject.toml`](../pyproject.toml) 或 `pip show sealium`。
- Python ≥ 3.9。
- 硬件绑定在 **1.3.0** 重构为分量指纹（**breaking change**）：旧的整体哈希机器码不再受支持。详见 [硬件绑定原理 §迁移](hardware-binding.md#升级与迁移)。
- 协议层（加密、请求/响应结构）自 1.x 起稳定。
