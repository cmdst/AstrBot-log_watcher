# 发布前脱敏说明

本仓库内容由生产环境副本导出。**已发布的版本执行过机械替换**，被替换的原文不写入本文件（也不进入 git 历史以外的任何文档），只登记替换目标与理由，便于复核：

| 原文类型 | 替换为 | 理由 |
|---|---|---|
| 微信 openid（收件人标识） | `<openid>` / `<openid>@im.wechat`（截断形态同样替换） | 个人身份标识 |
| 微信适配器实例 id | `weixin_personal_demo` | 保留 `weixin` 前缀语义（通道能力判定依赖它），去掉部署实例名 |
| 日志与用例里的 10 位数字标识（QQ 号 / 群号等） | `9000000000` / `9000000001` / `9000000002` | 保持「纯数字可被指纹归一化」的语义不变 |

复核方式（只读）：

```bash
# 以下模式在仓库内必须 0 命中（占位符不算）
git grep -nE "@im\.wechat|o9cq" -- . | grep -v "<openid>"
git grep -nE "\b900000000[0-9]\b" -- . >/dev/null && echo "占位符在位"
```

**整目录排除**的 AstrBot 运行时产物（`.gitignore` 已固化）：`data/`、`outbox/`、`failed/`、`remediation/`、`*.sqlite3*`、`tail_state.json`、`counters.json`。
其中 `data/` 曾在开发过程中混入一份 AstrBot 主配置副本（含 dashboard 口令哈希），已在发布前从工作目录与运行目录**双向删除**，并加入 `.gitignore` 防止复发。
`remediation/` 是 v2.2.0 及更早版本的**历史轨迹目录**（v2.3.0 起冻结、只读；清理走 `tools/prune_legacy_artifacts.py`，默认干跑）。

代码不内嵌任何密钥：v2.3.0 已删除自动修复通道与其配置（`remediation.env_refs` / `dsh-headless-overlay.yml` / 子进程凭据都不再存在）；`sk-` / `api_key=` / `Bearer …` 等词仅出现在「掩码规则」的文档与正则里。
