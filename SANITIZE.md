# 发布前脱敏说明

本仓库内容由生产环境副本导出。发布前执行了机械替换，**三类被替换原文均不写入本文件**，只登记其 sha256 前缀以便核对：

| 原文类型 | sha256(原文) 前 16 位 | 替换为 | 理由 |
|---|---|---|---|
| 微信 openid（收件人标识） | `4eacaa1bc88a0ed4` | `<openid>` | 个人身份标识 |
| 微信适配器实例 id | `95072fb552985867` | `weixin_personal_demo` | 保留 `weixin` 前缀语义（通道能力判定依赖它），去掉部署实例名 |
| 短信/日志中出现的 10 位数字标识（原为具体数字） | `a8ac50c310d396a0` | `9000000000` | 保持「纯数字可被指纹归一化」的语义不变 |

复跑核对方式（替换逻辑与上表一一对应）：对全仓执行 `grep -rc` 时，三个 sha256 前缀对应的原文**必须 0 命中**；替换后的占位符允许存在。

**整目录排除**的 AstrBot 运行时产物（`.gitignore` 已固化）：`data/`、`outbox/`、`failed/`、`remediation/`、`*.sqlite3*`、`tail_state.json`、`counters.json`。
其中 `data/` 曾在开发过程中混入一份 AstrBot 主配置副本（含 dashboard 口令哈希），已在发布前从工作目录与运行目录**双向删除**，并加入 `.gitignore` 防止复发。

代码不内嵌任何密钥：`remediation_env_refs` 只引用环境变量**名**；`dsh-headless-overlay.yml` 用 `apiKeyEnv` 间接引用凭据，不含明文；`sk-`/`api_key=` 等词仅出现在「掩码规则」的文档与正则里。
