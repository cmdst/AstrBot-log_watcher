# log_watcher v2

扫描 AstrBot 日志 → **AI 威胁分级** → **按级路由**（静默 / 摘要 / 即时告警 / 调用 `dsh` headless
紧急修复）→ **结果回执**。

> 运行、排障、回滚、回执样例与逐项验收：见 [`runbook.md`](runbook.md)。
> 架构与接口契约：`.agent-teams/logwatch-ops/architecture.md`。

## 它做什么

1. **采集**：每 `poll_interval_seconds` 秒扫一次日志目录（可配 glob），按等级列表 + 忽略关键字
   收集命中行与前后文，窗口重叠/相邻的多条命中合并成一段。
2. **分级**：本地规则表（磁盘满、OOM、未捕获异常、数据库锁、导入失败…三族规则 + 指纹）先判；
   配了 provider 时再交给 LLM（`classify_mode: auto`）。LLM 不可用/超时/输出非法 → 保守降级，
   代码里 `source=degraded` 且等级不低于 `fallback_severity`。
3. **路由**：`IGNORE` 静默 / `LOW` 摘要聚合 / `MEDIUM` 起即时告警 / `HIGH` 修复候选 /
   `CRITICAL` 紧急修复；预算闸（单轮/分钟/小时/日）、去重窗口、突发合并、静默时段与穿透等级都在这一层。
4. **投递**：按**通道能力表**选段型（只发 Plain 文本），按通道长度分片，失败进重试队列
   （指数退避，绝不静默丢），失败残留落 `failed/` 供人工取证。
5. **紧急修复**（默认关）：`remediate_enable=true` 且过闸后调用 `dsh` headless，在指定工作区里
   诊断并尝试修复。
6. **回执**：见下一节。

## 回执契约（硬要求）

> 用户要求：**紧急修复之后必须在会话中推送「选择的方案 + 结果」**。

**每一次修复尝试都向 `target_sessions` 推一条回执**，无一例外 —— 包括没修成的那些：
`ok` / `skipped` / `blocked` / `unavailable` / `timeout` / `failed` / `cancelled` / `rejected`。

回执固定包含（`remediate.build_receipt` 是唯一实现）：

| 段 | 内容 |
|---|---|
| 渠道 | 投递到哪个会话（unified_msg_origin） |
| **方案** | `profile` + **overlay 文件名**（含来源：bundled/手动） + **权限级别**（`read-only`/`workspace-write`） + 工作区路径 |
| 判定 | 严重度 + 指纹 + component + **新指纹/已知指纹** |
| 诊断结论 | 根因（+ dsh 给出的证据，最多 3 条） |
| **改动清单** | 改动了哪些文件；**没有改动时显式写「未改动任何文件」** |
| 建议动作 | dsh 结论里的 actions + 是否需要人工介入 |
| 轨迹 | 本次 run 的 JSONL 轨迹路径（未创建子进程时写明「无轨迹」） |
| 拦下原因 / 后续怎么办 | **只在非成功终态出现**：写明被哪一道闸拦下（`off`/`cooldown`/`daily_limit`/`storm`/`busy`/`credential`…）以及下一步怎么做 |

三条边界，写清楚以免误读：

- `remediation_receipt=false` 会关掉回执 —— **不建议**，关掉等于修复结果不可见。
- `target_sessions` 为空时没有可推送的会话（此时连告警也发不出去，只会扫描）。
- 修复默认关（`remediation_enable=false`）：命中修复候选时会立刻收到一条 `skipped`（拦下原因
  `off`）的回执，**同一指纹每进程只提示一次**，避免每次命中都刷屏；其余闸门的拦截每次都发。
- 回执走的是同一个 `Context.send_message`，所以**通道本身送不出去时回执也送不出去**：会进重试
  队列（最多 `delivery_max_attempts` 次）并留失败残留，不会静默丢。真实样例与通道现状见
  [`runbook.md §6`](runbook.md)。

## 前置条件

1. **AstrBot 必须开启文件日志**：WebUI → 配置文件 → 系统 → `log_file_enable`（默认为关）。
   关闭时磁盘上根本没有 `astrbot.log`，插件每 10 分钟打一条 warning。
2. 全局 `log_level` 决定哪些等级会写进文件：全局是 `INFO` 时不会有 `DEBUG` 行。
3. 想用 LLM 分级（可选）：配置 `classify_provider_id` 填一个可用的 AstrBot provider id；
   留空则 `auto` 模式等同于 `local`（本地规则），不会报错、也不会静默失效 —— 判定摘要里会写
   `local-mode` + `llm-unconfigured` 标签。
4. 想用紧急修复（默认关）：需要 `dsh` 可用 + headless 路由可用。**路由已由插件自带**
   （见下），所以正常情况下只要把 `remediation_enable` 打开即可。

### dsh 路由：插件自带 overlay（既定事实）

- 文件：`dsh-headless-overlay.yml`，与插件**同目录**；调用 `dsh` 时以
  `--patch <overlay>` 叠加在 profile 之上，**不改动任何 profile**（`~/.dsh/profiles/` 保持原样）。
- 路径按 `__file__` 解析为绝对路径，**不依赖 cwd**。
- 配置 `remediation_patch_overlay` 留空 = 用自带 overlay（日志与回执里来源显示 `bundled`）；
  填路径 = 手动覆盖。overlay 缺失时回落到 profile 自身配置并打 warning。
- **删除该文件即完全失效**（可回滚）：headless 路由随之不可用，修复会以 `unavailable` 终态结束，
  但**仍会发回执**。
- 实测：不带 overlay `dsh --profile headless` → `exit=1 / MISSING_CREDENTIAL`；带 overlay →
  `exit=0`（约 10s）。修 overlay 不需要重启 AstrBot（每次调用重新读取）。

### 权限语义：固定 `workspace-write`

- 子进程权限级别只允许 `read-only` / `workspace-write`，由 `remediation_permission_mode` 选择
  （默认 `workspace-write`）。写 `danger-full-access` 会被强制回落并 warning，**插件不提供该选项**。
- 语义：只允许改**当前工作区**（`remediation_workdir`，默认 `/root/AstrBot`）内的文件。
  实测：区内写成功；区外写被拦并返回 `[sandbox: file access denied under workspace-write mode]`，
  文件不会生成。
- 子进程环境里**不会携带任何 `sandbox_permissions` 提权键**（`FORBIDDEN_ENV_KEYS` 硬剔除，
  无头场景无人审批，也不重试提权）。
- 本插件不重启 AstrBot、不 `git push`。

## 通道能力：weixin_oc 只发 Plain 文本（既定事实）

实测（2026-10-14，本机 AstrBot v4.28.2 + `weixin_personal_demo` 适配器）：

- `File`（文件/附件）段：服务端返回 `ret=-2, errcode=0, errmsg=prepare failed` → 发送失败；
- `Node` / `Nodes`（合并转发/聊天记录）段：适配器不处理，**静默丢弃**（消息看起来"发出去了"但什么也没到）；
- `Plain`（纯文本）：是唯一能进的段型。

因此 **v2 只发 Plain 文本**（`send_mode: auto`），长内容按通道长度上限分片；旧配置里的
`send_mode: file`/`forward` 会被映射为文本并在日志里留一条 degradation 提示。README 与
CHANGELOG 里 v1 关于 `forward` 形态可用的说法已删除。

## 配置

全部键（80 个可见键 + 兼容键，含中文 hint 与误配后果）见 `_conf_schema.json` 与
[`runbook.md §3`](runbook.md)。最常用的几个：

| 配置项 | 默认 | 推荐 | 说明 |
|---|---|---|---|
| `target_sessions` | `[]` | 填 1 个群/私聊 | 告警与**修复回执**都发到这里；留空 = 只扫描 |
| `send_mode` | `auto` | 不动 | 只按通道能力选（weixin_oc 上就是 Plain 文本） |
| `levels` | `["ERROR","CRITICAL"]` | 不动 | 加 `WARNING` 会引入每天上千条噪声 |
| `classify_enable` | `true` | 不动 | 关掉会退回"按等级直灌" |
| `classify_provider_id` | `""` | 有 provider 就填 | 留空 = 只用本地规则 |
| `notify_min_severity` | `MEDIUM` | 不动 | 低于它的判定只进摘要或静默 |
| `unmatched_severity` | `LOW` | 不动（要旧行为才填 `MEDIUM`） | 「谁都不认识」的 ERROR 判成几级：默认只进摘要，不再即时推 |
| `transient_severity` | `MEDIUM` | 嫌 provider 抖动吵就填 `LOW` | 可恢复抖动（503/重试中）判成几级；默认保持验收基线 TRANS-01 |
| `remediation_enable` | **`false`** | 确认前置条件后再开 | 总开关；开着才有紧急修复 |
| `remediation_permission_mode` | `workspace-write` | 不动 | 只接受 `read-only`/`workspace-write` |
| `remediation_daily_limit` | `5` | 不动 | 每日修复上限（跨重启持久） |

## 状态与磁盘

- 状态库：`<plugin_data>/log_watcher.sqlite3`（WAL，`user_version=2`），可被 `state_db_path` 覆盖。
  库不可用时降级为 JSON 内存态（进度/计数/待发落盘），**修复闸强制关闭**（fail-closed）。
- 摘录：`outbox/`（`excerpt_mode: ledger_only` 下每轮一个单文件台账），受
  `outbox_max_bytes` + `keep_excerpt_files` + `outbox_max_age_hours` 三条上限取更严者约束。
- 失败残留：`failed/`（发送失败的摘录文本，供人工取证）。
- 修复轨迹：`remediation/`，由 `prune_artifacts()` 周期清理，**调用者是插件自己**：每轮
  `_commit_round()` 里在独立线程调用一次（`main.py` 的 `_prune_artifacts_hook()`），不需要
  外部 cron。三个保留键：`remediation_artifact_keep`（默认 50 个）/`remediation_artifact_max_age`
  （默认 7 天）/`remediation_artifact_max_bytes`（默认 64 MiB）。轨迹默认过凭据掩码
  （`remediation_trace_raw=true` 才留原文，风险自负）。

## 已知限制

- **出站告警摘录不做凭据掩码**（F18，未修）：要把原始日志发出去才能定位问题，属功能固有取舍；
  轨迹侧已掩码，聊天侧没有。担心日志里有密钥请用 `exclude_keywords` 过滤。另外
  **轨迹默认掩码**（`sk-…`/`api_key=…`/`Bearer …`/`token=…` → `<masked>`）。
- 主动消息直接走 `Context.send_message`，不经过回复装饰链（分段回复、气泡、TTS 等不生效），
  也不触发 `after_message_sent`。
- 只读磁盘日志文件，解析依赖 AstrBot 的 loguru 格式（`[时间] [模块] [等级] …`），同时兼容标准
  logging 的 ` - ERROR - ` 形态；多行堆栈的续行按普通上下文行处理。
- 片段要等「后面不可能再有命中与它重叠」才发出（最后一条命中之后 `context_after + context_before`
  行），日志持续输出时延迟约等于这个行数；文件停更时下一轮扫描直接收尾并注明「末尾片段后文未凑齐」。
- QQ/微信客户端的文本没有等宽字体与加粗，摘录里命中行用 `>>` 标记。
- 收发都依赖通道本身可用：通道挂掉时告警与回执都会进重试队列并留失败残留（不会静默丢）。

## 未实现的功能（明写，不默认省略）

- `architecture.md §8.7` 规划的 `/lw status`、`/lw ack <指纹>`、`/lw silence <分钟>`、
  `/lw remediate <指纹>` 管理命令与 `admin_users` 白名单 **本版本未实现**：插件不注册任何命令
  处理器（保持零事件入口）。schema 里的 `admin_users` 只是一个前向兼容占位键，填了不会生效。
  需要这些命令请在后续版本里单独实现（实现后需用非白名单用户调用一次并确认被拒且留日志）。

## 开发与测试

```bash
cd /root/AstrBot/data/plugins/log_watcher
PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q      # 295 passed
```

测试全部离线：不联网、不 spawn 真 `dsh`（`asyncio.create_subprocess_exec` 被替身顶掉）、
不写插件目录。分层：

| 文件 | 覆盖 |
|---|---|
| `tests/test_log_reader.py` | 等级规整、片段合并与边界、摘录切片、增量读取 |
| `tests/test_detect.py` | 指纹、抑制与回声过滤 |
| `tests/test_classify.py` | 本地规则、判定形状、注入用例（`tests/classify_cases.json`） |
| `tests/test_engine.py` | LLM 契约、超时/异常/非法输出降级、知识库、调用预算 |
| `tests/test_deliver.py` | 通道能力表、分片、降级、重试退避 |
| `tests/test_store.py` | SQLite v2 schema、迁移、保留清理、磁盘治理 |
| `tests/test_remediate.py` | argv/env、任务注入、JSONL 解析、看门狗、闸门、轨迹、回执 |
