# log_watcher v2 运行手册（runbook）

适用版本：`metadata.yaml` → `version: 2.0.0`（2026-10-14 集成收口版）
适用环境：本机 AstrBot（`/root/AstrBot`，venv 在 `/root/AstrBot/.venv`，实测 AstrBot v4.28.2）

**命令约定**：本容器 PATH 里没有裸 `python`，所有 Python 命令统一前缀
`PATH=/root/AstrBot/.venv/bin:$PATH`（下文简写 `$PY`）。插件目录
`cd /root/AstrBot/data/plugins/log_watcher`。

```bash
export PY="PATH=/root/AstrBot/.venv/bin:$PATH python"
```

---

## 1. 部署与生效

### 1.1 改完代码要不要重启 AstrBot？

**结论：不需要重启 AstrBot 进程，但必须让插件重新加载一次（WebUI 重载插件）。**

- Python 模块在 AstrBot 进程内被缓存：**只把文件写到磁盘上，运行中的插件不会改变行为**。
- WebUI → 插件管理 → 找到「日志监听」→ 点重载（或停用再启用）。重载会重新导入模块，
  插件自己的 `initialize()` 重新执行，并打印一行启动日志（这就是验收标志）。
- 重载**不需要**动 `data/config/`（配置由 `AstrBotConfig` 自动补齐），也不需要重启 AstrBot 服务。

**证据（本机真实日志，非推断）**：同一个 AstrBot 进程（PID 2433752，2026-10-13 启动）在
2026-10-14 之间被反复重载插件，每次打印的启动行都来自当时的磁盘代码：

```
# 旧代码（v1，main.py:104，形态 file）
[2026-10-14 02:45:29.661] [log_watcher] [INFO] [v4.28.2] [log_watcher.main:104]: 日志监听启动：… 形态 file，间隔 30s，会话 ['weixin_personal_demo:FriendMessage:o9cq…@im.wechat']
# 新代码（v2，main.py:172/183，形态 auto(file→text) + 状态 SQLite + 分级/修复/overlay 一行）
[2026-10-14 05:50:17.797] [log_watcher] [INFO] [v4.28.2] [log_watcher.main:172]: 日志监听启动：… 形态 auto(file→text)，间隔 30s，会话 {'weixin_personal_demo:FriendMessage:o9cq…@im.wechat': 'weixin_oc'}；状态 SQLite，分级 auto（provider 未配置），修复 关闭；…
```

进程号没变、时间点不同 ⇒ **同一进程内热重载**，不是重启。

### 1.2 本轮（t18）改动的生效状态 —— 重要

| 项 | 状态 |
|---|---|
| 磁盘上的代码/文档/schema | 已是最终版（t18 交付） |
| 运行中 AstrBot 加载的版本 | **05:50:17 那一版**（早于 t17/t18 的改动），因此**当前生产里还没有**：七段回执的 `build_receipt` 补字段、`prune_artifacts` 周期清理、新 `_conf_schema.json`、`metadata 2.0.0` |
| 本任务是否重载/重启 | **没有**（任务明令：不重启 AstrBot、不改 `data/config/`） |

⇒ 想让本轮改动生效：WebUI 重载一次插件即可。重载后应看到启动行里的
`overlay …/dsh-headless-overlay.yml（bundled）`（t17 起才有这个字段）；
另外在 WebUI 插件详情页里能看到全部 80 个配置键（旧版只有 12 个）。

### 1.3 验收一条重载是否成功

```bash
# 看启动行（最近一次重载）：含 overlay 与修复状态
grep -a "日志监听启动" /root/AstrBot/data/logs/astrbot.log | tail -1
# 期望：形态 auto… 状态 SQLite… 分级 auto… 修复 关闭；… overlay <插件目录>/dsh-headless-overlay.yml（bundled）
```

---

## 2. 前置条件与自检

| 前置 | 检查命令 | 期望 |
|---|---|---|
| AstrBot 文件日志开启（`log_file_enable`） | `ls -l /root/AstrBot/data/logs/astrbot.log` | 文件存在且持续增长；否则插件每 10 分钟一条 warning |
| 全局 `log_level` 覆盖你要的等级 | `grep -a "\[ERRO\]" /root/AstrBot/data/logs/astrbot.log \| tail -1` | 有该等级的行；全局 INFO 时不会有 DEBUG 行 |
| 提醒会话填对 | `grep -A3 target_sessions /root/AstrBot/data/config/log_watcher_config.json` | 形如 `BOT1:group:10001` / `平台: FriendMessage:xxx@im.wechat` |
| LLM 分级（可选） | 插件启动行里 `分级 auto（provider 已配置/未配置）` | 未配置时会以本地规则工作，判定里带 `llm-unconfigured` 标签 |
| dsh 可用（仅修复需要） | `which dsh && dsh --version` | `/usr/local/bin/dsh`、`0.2.0-rc.2`（本机实测） |
| headless 路由（仅修复需要） | 见 §5.3 的手动验证命令 | 带 overlay `exit=0`；不带 overlay `exit=1 / MISSING_CREDENTIAL` |

**注意**：`classify_mode: auto` + 没配 provider ≠ 故障。它会退到本地规则并在判定正文里说明原因
（`local-mode`、`llm-unconfigured`），不会静默失效。生产日志里也能看到这个形态
（`data/plugin_data/log_watcher/failed/*.txt` 的告警头即 05:50 前后真实产生）。

---

## 3. 配置速查

- **权威来源**：`_conf_schema.json`（80 个可见键 + 兼容键，每键都带中文 hint 与「误配后果」）。
  WebUI 插件详情页按分组渲染：基础/主动提醒、日志扫描、AI 威胁分级、通知预算/聚合/静默、
  投递重试、状态/磁盘、紧急修复、自反馈/管理白名单。
- **默认值来源**：与代码里的 `config.get(key, default)` 逐条对齐（本节的默认值即 schema 的默认值）。
- 新键在插件下次加载时由 `AstrBotConfig` 自动写进 `data/config/log_watcher_config.json`，
  **不需要手改 JSON**。
- `send_mode` 默认已从 `file` 改为 `auto`；老配置里的 `file`/`txt`/`attachment` 会被映射成文本
  并把这条映射写进日志（`历史配置 file（txt 附件）已废弃…`）。

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `log_with_bot_id` | bool | `false` | 开启后插件日志会带 [platform:平台ID]，多 Bot 环境便于定位；平台 ID 取自提醒会话的 unified_msg_origin 前缀。 |
| **=== 主动提醒 ===** | | | |
| `target_sessions` | list | `[]` | 命中日志时把提醒主动发到这些会话。**列表即优先级**：第 1 个是主出口，只有它失败才发第 2 个（不是双发）。填 unified_msg_origin：群 BOT1:group:10001、私聊 BOT1:private:10002。 |
| `send_mode` | string | `"auto"` | auto = 按通道能力选（默认）；text = 只发纯文本分片；forward = 优先合并转发（通道不支持时自动退回文本）。注意：旧配置里的 file/txt 会被映射成 text —— weixin_oc 通道只有 Plain 文本能送达，File 会被服务端 prepare 失败、No… |
| `prefer_forward` | bool | `false` | 通道同时支持文本与转发时优先用合并转发。 |
| `notify_min_severity` | string | `"MEDIUM"` | 即时告警的最低等级（五级）。低于它的判定只进摘要或静默。 |
| `include_excerpt` | bool | `true` | 告警里是否附日志摘录正文。 |
| `max_excerpt_chars` | int | `6000` | 单条摘录字符上限（200-20000，代码夹紧）。 |
| `max_chars_per_message` | int | `0` | 覆盖通道分片长度；0 = 按通道能力表（推荐）。上限 8000（硬顶）。 |
| **=== 日志扫描 ===** | | | |
| `log_dir` | string | `""` | 留空 = 用 AstrBot 自己的日志目录（跟随 log_file_path，默认 <data>/logs），一般不用改。 |
| `file_pattern` | string | `"*.log"` | 目录里扫哪些文件，glob 写法。默认只读当前日志文件；填 astrbot.log* 会把轮转出来的历史文件也扫一遍。 |
| `levels` | list | `["ERROR", "CRITICAL"]` | 只提醒列表里的等级，可填 DEBUG/INFO/WARNING/ERROR/CRITICAL（也认短名 DBUG/WARN/ERRO/CRIT，内部统一规整为规范长名）。 |
| `exclude_keywords` | list | `[]` | 行里包含任一关键字就不算命中（仍会作为前后文出现在摘录里）。本插件自己的日志固定被忽略，避免自触发循环。 |
| `poll_interval_seconds` | int | `30` | 扫描间隔秒（5-86400）。也是「文件末尾的报错等不到后文」的最长等待时间。 |
| `start_from_end` | bool | `true` | 开启（默认）= 跳过文件已有内容，不重放历史；关闭 = 从文件开头读。 |
| `context_before` | int | `5` | 0-200。命中行前面带几行日志。 |
| `context_after` | int | `5` | 0-200。命中行后面带几行日志（堆栈就靠它带出来）；前后文连成一片的多条命中会合并成一段，不会重复前文。同样也是发出的延迟（见 poll_interval_seconds）。 |
| `max_lines_per_poll` | int | `200` | 20-5000。一轮最多展开多少行（含前后文），超出的只在汇总里计数。 |
| **=== AI 威胁分级 ===** | | | |
| `classify_enable` | bool | `true` | 分级总开关。关闭后按日志等级直接触发（噪声 8.9:1 会直灌聊天）。 |
| `classify_mode` | string | `"auto"` | auto = 配了 provider 走 LLM、否则本地规则；local = 永不调 LLM（最省、可离线）；llm = LLM 优先、失败降级。 |
| `classify_provider_id` | string | `""` | AstrBot 的 provider id，供 llm_generate 使用。 |
| `classify_timeout_seconds` | int | `20` | 5-300，单次 LLM 判定超时。 |
| `classify_system_prompt` | text | `""` | 覆盖内置提示词（留空用 prompts/classify_system.md）。 |
| `fallback_severity` | string | `"MEDIUM"` | 降级地板（五级）：LLM 不可用/超时/输出非法时取 max(本地判定, 该值)。 |
| `unmatched_severity` | string | `"LOW"` | 本地模式「有 ERROR 等级但没有任何规则能解释」的等级。默认 LOW = 只进摘要、不即时推送；填 `MEDIUM` 恢复旧行为（2026-10-16 重放：全天 95 条即时推送＝未匹配错误 41 条 ＋ 可恢复抖动 54 条，两族都曾被判 MEDIUM 直推）。**这个键必须同时进 `main._engine_config()` 白名单**，否则生产链路上被静默丢弃（2026-10-18 漏过一次，见 §7.2 / §10）。 |
| `transient_severity` | string | `"MEDIUM"` | 本地模式可恢复抖动（上游 503 / 框架重试中）的等级。默认 MEDIUM = 验收基线（用例 TRANS-01，notes 写着「压成 LOW = 漏报」）；填 `LOW` = 抖动只进摘要。 |
| `llm_max_block_lines` | int | `80` | 5-500，送 LLM 的最大行数。 |
| `llm_max_calls_per_round` | int | `5` | 0-1000，单轮 LLM 调用上限（0 = 不限，不推荐）。 |
| `llm_max_calls_per_hour` | int | `60` | 0-100000，每小时 LLM 调用上限（0 = 不限）。 |
| `noise_shortcut` | bool | `true` | 已知噪声短路（asyncio 回调异常等直接判 IGNORE，不付 token）。 |
| `kb_enabled` | bool | `true` | 指纹知识库：同一指纹复用上次判定。 |
| `kb_max_entries` | int | `500` | 50-100000，知识库条数上限（超出由 prune 清理）。 |
| `new_pattern_escalate` | bool | `false` | 新指纹升一级（见 architecture §4.3）。 |
| `route_map` | dict | `{}` | 等级→路由覆写，如 {"MEDIUM": "digest"}。非法值会被忽略并 warning；CRITICAL→store 被强制拒绝。 |
| `llm_provider_id`（隐藏） | string | `""` | 兼容键：为空时用 classify_provider_id；非空时优先级更高（旧配置迁移用）。 |
| `chat_provider_id`（隐藏） | string | `""` | 兼容键：同 llm_provider_id，仅在前两者都为空时生效。一般不用改。 |
| `llm_timeout`（隐藏） | int | `20` | 兼容键：等同 classify_timeout_seconds（engine 内部别名，最低优先级）。一般不用改。 |
| `provider_id`（隐藏） | string | `""` | 兼容键：内部短名，最低优先级。一般不用改。 |
| **=== 通知预算 / 聚合 / 静默 ===** | | | |
| `dedupe_window_seconds` | int | `900` | 0-604800，同指纹冷却窗口：窗口内重复命中不再单独告警。 |
| `digest_interval_seconds` | int | `1800` | 60-86400，LOW 级摘要聚合间隔。 |
| `digest_max_items` | int | `50` | 1-500，单个摘要桶最多条目数。 |
| `max_alerts_per_round` | int | `5` | 0-100，单轮发送上限。 |
| `max_alerts_per_minute` | int | `12` | 0-600，分钟预算。 |
| `max_alerts_per_hour` | int | `80` | 0-5000，小时预算。 |
| `max_alerts_per_day` | int | `300` | 0-50000，日预算（跨重启持久化）。 |
| `burst_window_seconds` | int | `60` | 1-3600，突发窗口长度。 |
| `burst_threshold` | int | `8` | 1-500，窗口内达到多少条告警就合并成一条突发消息。 |
| `burst_min_severity` | string | `"MEDIUM"` | 参与突发合并的最低等级（五级）。 |
| `silence_ranges` | list | `[]` | 静默时段（本机时区，支持跨夜），如 ["23:00-07:00"]。格式错会被忽略并 warning。 |
| `silence_min_severity` | string | `"HIGH"` | ≥ 此等级的告警可穿透静默时段（五级）。 |
| `channel_overrides` | dict | `{}` | 按通道覆盖能力，如 {"weixin_oc": {"max_chars": 1000}}。 |
| **=== 投递重试 ===** | | | |
| `delivery_max_attempts` | int | `4` | 1-20，单条消息最多重试次数（失败进重试队列，绝不静默丢）。 |
| `delivery_base_delay_seconds` | int | `5` | 1-600，重试退避基数（指数退避起点，秒）。 |
| `delivery_retry_batch` | int | `5` | 1-50，每轮最多重发多少条待重试消息。 |
| **=== 状态 / 磁盘 ===** | | | |
| `state_db_path` | string | `""` | 留空 = <plugin_data>/log_watcher.sqlite3（推荐）。 |
| `fingerprint_ttl_hours` | int | `72` | 1-720，指纹计数与知识库条目保留时长。 |
| `history_retention_days` | int | `30` | 1-3650，alerts / remediation_runs 保留天数。 |
| `history_max_rows` | int | `20000` | 1000-1000000，alerts 行数硬上限（超出按最旧删除）。 |
| `outbox_max_bytes` | int | `33554432` | 1 MiB-1 GiB，摘录目录硬字节上限（与 keep_excerpt_files 同时生效，取更严）。 |
| `excerpt_mode` | string | `"ledger_only"` | ledger_only = 摘录进 alerts.excerpt_path 指向的单文件（推荐）；file = 每轮一个文件（旧行为）；off = 不留摘录。 |
| `keep_excerpt_files` | int | `50` | 1-1000，摘录目录保留文件数。 |
| `outbox_max_age_hours` | int | `24` | 1-720，摘录最长留存小时。 |
| `disk_report_interval_hours` | int | `24` | 1-168，磁盘占用报告的间隔（日志一行 usage）。 |
| **=== 紧急修复（dsh headless，默认关） ===** | | | |
| `remediation_enable` | bool | `false` | 修复总开关，默认关。开启前必须先把 headless 凭据/路由配好（插件自带 dsh-headless-overlay.yml 已默认叠加），否则每次都是 unavailable（只发回执，不修）。 |
| `remediation_dsh_command` | string | `"dsh"` | dsh 可执行文件/绝对路径。 |
| `remediation_profile` | string | `"headless"` | 传给 dsh 的 --profile 值。 |
| `remediation_patch_overlay` | string | `""` | 留空 = 用插件自带的 dsh-headless-overlay.yml（与插件同目录，绝对路径解析，不依赖 cwd，以 --patch 叠加，不改任何 profile）。删除该文件即完全失效（可回滚）。填路径 = 手动覆盖。 |
| `remediation_workdir` | string | `"/root/AstrBot"` | 子进程 cwd = 工作区根。 |
| `remediation_timeout_seconds` | int | `900` | 30-3600，看门狗超时（超时会 kill 整个进程组并回收）。默认 900 的依据与「超时 vs 卡死」的判据见 §5.5。 |
| `remediation_max_concurrency` | int | `1` | 1-4，并发闸；建议恒为 1。 |
| `remediation_cooldown_seconds` | int | `3600` | 0-86400，同指纹冷却，冷却期内不重复修复（会发 blocked 回执）。 |
| `remediation_daily_limit` | int | `5` | 0-100，每日修复次数上限（跨重启持久）。 |
| `remediation_permission_mode` | string | `"workspace-write"` | 子进程权限级别，只允许 read-only / workspace-write（只改当前工作区）。danger-full-access 会被强制回落并 warning，本插件不提供该选项；子进程也不会携带任何sandbox_permissions 提权键（无头场景无人审批）。 |
| `remediation_env_refs` | list | `[]` | 额外传给子进程的环境变量名（值取自父进程 env）。 |
| `remediation_inherit_env` | bool | `false` | 是否把父进程 os.environ 整体传给子进程。 |
| `remediation_artifact_dir` | string | `""` | 轨迹与产物目录，留空 = <plugin_data>/remediation。 |
| `remediation_artifact_keep` | int | `50` | 1-100000，轨迹目录保留文件数上限。由插件每轮自动调用 prune_artifacts() 清理（不需要手工 cron）。 |
| `remediation_artifact_max_age` | int | `604800` | 0-315360000，轨迹最长留存秒数（默认 7 天）。同样由每轮的 prune_artifacts() 执行。 |
| `remediation_artifact_max_bytes` | int | `67108864` | 0-1 TiB，轨迹目录字节上限。同样由每轮的 prune_artifacts() 执行。 |
| `remediation_max_output_bytes` | int | `262144` | 4096-16777216，单个轨迹文件落盘上限（超出截断并标记）。 |
| `remediation_trace_raw` | bool | `false` | true = 轨迹保留 stdout/stderr 原文（默认 false 会做凭据掩码 <masked>）。 |
| `remediation_prompt_template` | text | `""` | 覆盖 prompts/remediate_task.md（留空用自带模板）。 |
| `remediation_receipt` | bool | `true` | 是否发修复回执。**强烈建议保持开启**：每一次修复尝试（含 skipped/blocked/unavailable/timeout/failed/cancelled/rejected）都必须回执，关掉等于修复结果不可见。 |
| `remediate_confirm_count` | int | `2` | 1-10，HIGH 级需要连续命中多少次才触发修复（见 architecture §4.2）。 |
| `remediate_confidence_threshold` | float | `0.8` | 0.0-1.0，置信度直通阈值（≥ 该值可跳过确认次数）。 |
| **=== 自反馈 / 管理白名单 ===** | | | |
| `self_log_names` | list | `["log_watcher"]` | 本插件自身日志 tag，命中时不计入告警（防自触发循环）。 |
| `self_feedback_ids` | list | `[]` | 本插件目标会话 id，用于屏蔽「适配器把自己的发送失败记成别人的 WARN」回声。 |
| `admin_users`（隐藏） | list | `[]` | 【本版本未实现】architecture §8.7 规划的 /lw status/ack/silence/remediate 管理命令与白名单尚未接线：当前版本不注册任何命令处理器（零事件入口），填了也不会生效。保留该键只为配置前向兼容，详见 README「未实现的功能」。 |

### 3.0 老配置里残留的 `send_mode: "file"` 会怎样

不会报错：`deliver.py` 把 `file`/`txt`/`attachment` 映射成文本并记一条 degradation 提示
（`历史配置 file（txt 附件）已废弃…`）。但 WebUI 的下拉选项里已经没有 `file`，所以**存下来的旧值
会一直留在 `data/config/log_watcher_config.json` 里**（实测：用真实 `AstrBotConfig` 加载本 schema +
现有生产配置，`send_mode` 仍是 `'file'`，其余 79 个新键被自动补成默认值）。
建议在 WebUI 下拉里改成 `auto` 把这个残值清掉。

### 3.1 推荐起步配置（照抄即可）

```jsonc
{
  "target_sessions": ["<你的会话 UMO>"],   // 必填，否则只扫描不发送（回执也发不出）
  "levels": ["ERROR", "CRITICAL"],         // 别加 WARNING（每天上千条噪声）
  "send_mode": "auto",                     // weixin_oc 上就是 Plain 文本
  "classify_enable": true,
  "classify_provider_id": "",              // 有 provider 再填；留空走本地规则
  "notify_min_severity": "MEDIUM",
  "remediation_enable": false,             // 先关着看几天告警质量，再决定要不要开
  "remediation_receipt": true              // 永远保持 true
}
```

### 3.2 三个「改之前先想清楚」的键

| 键 | 为什么 |
|---|---|
| `remediation_enable` | 打开后插件会真的在 `remediation_workdir` 里调 `dsh` 改文件（权限 `workspace-write`）。先确认 §5 的前置条件与闸门数值 |
| `remediation_env_refs` / `remediation_inherit_env` | 会把父进程环境变量交给子 agent（可能含 token）。默认空/关，推荐用 profile 侧凭据 |
| `exclude_keywords` | 出站告警摘录**不做凭据掩码**（见 §10 F18），日志里含密钥的行只能靠它挡 |

---

## 4. 日常运维

### 4.1 看什么日志

```bash
LOG=/root/AstrBot/data/logs/astrbot.log
grep -a "\[log_watcher\]" $LOG | tail -50                      # 插件全部输出
grep -aE "修复回执|修复未触发|修复闸|清理修复轨迹" $LOG | tail  # 修复与回执
grep -aE "投递提示|投递失败|重试|耗尽" $LOG | tail -30           # 投递与重试
```

关键短语：`日志监听启动`（重载成功）、`命中 N 条日志`（本轮投递）、`投递失败已入重试队列`、
`重试耗尽，标记放弃`、`修复未触发（<闸名>）`、`修复回执：<status>`、`清理修复轨迹：{...}`、
`已把 N 个数据文件/目录权限收窄到 0600/0700`。

### 4.2 状态库随手查

```bash
cd /root/AstrBot/data/plugin_data/log_watcher
sqlite3 log_watcher.sqlite3 "PRAGMA user_version;"            # 2
sqlite3 log_watcher.sqlite3 ".tables"                          # alerts file_progress meta pattern_kb pending_delivery rate_windows remediation_runs
sqlite3 log_watcher.sqlite3 "select count(*), max(ts) from alerts;"
sqlite3 log_watcher.sqlite3 "select run_id,status,exit_code,started_at from remediation_runs order by rowid desc limit 5;"
sqlite3 log_watcher.sqlite3 "select fingerprint,severity,decision,route,summary from alerts order by rowid desc limit 10;"
```

没有 `sqlite3` CLI 时用 `$PY -c "import sqlite3;print(sqlite3.connect('log_watcher.sqlite3').execute('pragma user_version').fetchone())"`。

### 4.3 磁盘与清理（谁在清什么）

| 目录 | 内容 | 清理者 | 上限键 |
|---|---|---|---|
| `outbox/` | 摘录台账（`excerpt_mode: ledger_only` 下每轮一个文件） | `DiskGovernor`（每轮） | `outbox_max_bytes` + `keep_excerpt_files` + `outbox_max_age_hours`（取更严） |
| `failed/` | 发送失败的摘录（人工取证用） | `DiskGovernor`（同上） | 同上 |
| `remediation/` | 修复轨迹 JSONL（默认已掩码） | **插件自己**：`main._commit_round()` 每轮在独立线程调用 `remediate.prune_artifacts()` | `remediation_artifact_keep` / `_max_age` / `_max_bytes` |
| `log_watcher.sqlite3` | 状态库（WAL） | `SqliteStore.prune()`（每轮） | `history_retention_days` / `history_max_rows` / `fingerprint_ttl_hours` / `kb_max_entries` |

轨迹清理**不需要外部 cron**：`main.py` 的 `_prune_artifacts_hook()`（第 1054 行）在每轮
`_commit_round()`（第 1000 行）里调用一次 `prune_artifacts(cfg, now=now)`，条数/年龄/字节三闸
取更严者；有删除时打一条 `清理修复轨迹：{...}`。状态库不可用时也会清（修复恰恰常发生在那种时候）。

```bash
ls -l /root/AstrBot/data/plugin_data/log_watcher/outbox | wc -l    # 本机实测 50（= keep 上限）
du -sh /root/AstrBot/data/plugin_data/log_watcher/                  # 本机实测 5.2M
ls -l /root/AstrBot/data/plugin_data/log_watcher/remediation        # 期望空或仅最近几次
```

### 4.4 手动重跑一轮（不重启）

插件没有管理命令（见 §10「/lw 未实现」）。想立刻看一轮结果，最小动作是**重载插件**，
或调小 `poll_interval_seconds`（下限 5）后重载：

```bash
# 只读观察，不改配置：等下一个扫描周期，然后看日志
sleep 35; grep -a "\[log_watcher\]" /root/AstrBot/data/logs/astrbot.log | tail -5
```

---

## 5. 紧急修复通道（三项既定事实）

### 5.1 ① 路由由插件自带：`dsh-headless-overlay.yml`

- 位置：与插件同目录 `/root/AstrBot/data/plugins/log_watcher/dsh-headless-overlay.yml`
  （按 `__file__` 解析为绝对路径，**不依赖 cwd**；`remediate.resolve_overlay`，remediate.py:259）。
- 调用形态（真实 argv，来自本轮干跑记录）：
  ```
  dsh --profile headless --patch /root/AstrBot/data/plugins/log_watcher/dsh-headless-overlay.yml --json -- -
  ```
  即 `--patch` **叠加**在 profile 之上，**不修改任何 profile 文件**（`~/.dsh/profiles/` 保持原样）。
- 配置 `remediation_patch_overlay` 留空 = 用自带 overlay（回执里来源写 `bundled`）；填路径 = 手动覆盖；
  文件缺失 = 回落 profile 自身配置 + warning。
- **回滚开关 = 删文件**：删掉 `dsh-headless-overlay.yml` 后 headless 路由立即失效，
  修复会以 `unavailable` 终态结束（**仍然发回执**）。改 overlay 不需要重启 AstrBot（每次调用重新读）。
- 实测：不带 overlay `dsh --profile headless` → `exit=1 / MISSING_CREDENTIAL`；带 overlay → `exit=0`（约 10s）。
  根因（为什么必须自带 overlay）：headless profile 的 `cordis.patch.yml` 是空的 `[]`，
  既没有 agent-default-model 也没有 provider 配置。详见与 `findings-dsh.md`。

### 5.2 ② 权限固定 `workspace-write`

- 只接受 `read-only` / `workspace-write`（`remediation_permission_mode`，remediate.py:220 `permission_mode()`）；
  写 `danger-full-access` 会被强制回落并 warning，**插件不提供该选项**，代码/配置里不出现该值。
- 语义：**只允许改当前工作区**（`remediation_workdir`，默认 `/root/AstrBot`）。
  实测：区内写成功；区外写被拦并返回 `[sandbox: file access denied under workspace-write mode]`，文件不生成。
- 子进程环境里**不带任何提权键**：`FORBIDDEN_ENV_KEYS`（remediate.py:78）硬剔除
  `sandbox_permissions` / `SANDBOX_PERMISSIONS` / `DSH_SANDBOX_PERMISSIONS` /
  `AGENT_SANDBOX_PERMISSIONS` / `DSH_PERMISSION_ESCALATE`，且 `DSH_PERMISSION_MODE` 最后写入、
  不可被 `remediation_inherit_env` 覆盖。无头场景无人审批 ⇒ **不重试提权**。
- 本插件不重启 AstrBot、不 `git push`。

### 5.3 前置条件自检（两条命令，人工执行一次）

```bash
# a) 不带 overlay：应当失败（证明「必须带 overlay」不是猜测）
dsh --profile headless --json -- - <<< "只回复 OK" ; echo "exit=$?"      # 期望 exit=1，报 MISSING_CREDENTIAL
# b) 带 overlay：应当成功
dsh --profile headless --patch /root/AstrBot/data/plugins/log_watcher/dsh-headless-overlay.yml --json -- - <<< "只回复 OK" ; echo "exit=$?"
#    期望 exit=0（约 10s），stdout 是 JSONL 事件流
```

> 注意：`b` 是一次**真实的** headless 调用（会消耗额度）。本轮任务只做离线干跑，
> 没有执行真调用；上面两条是留给你手动的验证命令。

### 5.4 闸门枚举（回执里的「拦下原因」就是这些值）

| 闸门 reason | 回执 status | 含义 / 怎么解 |
|---|---|---|
| `off` | `skipped` | 修复总开关关着（默认）。要修才开 `remediation_enable` |
| `not_candidate` | `skipped` | 该判定的路由不是修复候选（等级不够或路由被覆写） |
| `confirm_count` | `skipped` | 未达到 `remediate_confirm_count` 次连续命中 |
| `busy` | `blocked` | 并发闸被占**或状态库不可写**（fail-closed） |
| `cooldown` | `blocked` | 同指纹还在 `remediation_cooldown_seconds` 内 |
| `daily_limit` | `blocked` | 当天已达 `remediation_daily_limit` |
| `storm` | `blocked` | 突发/风暴抑制中 |
| `credential` | `unavailable` | headless 凭据/路由缺失（要配 provider 或恢复 overlay） |
| 非上表（执行器终态） | `failed`/`timeout`/… | 已过闸，是子进程自己失败/超时/被取消，回执会写「非闸门拦截（已通过修复闸，执行器终态 X）」 |

### 5.5 超时还是卡死：别用「空轨迹」判断

**实测（2026-10-18）**：同一个真实修复任务，直接 `dsh` 跑 = **284.32 s**（exit 0 / 150 事件 /
9 步 / 39 次工具调用），走插件 runner = **308.0 s**（`status=ok`）。所以
`remediation_timeout_seconds` 的默认值从 300 抬到 **900**：300 是「约一半概率死在收尾前」，
不是安全余量。

**为什么超时看着像卡死**：`asyncio.wait_for(proc.communicate())` 被取消时**内部缓冲区不返回**，
于是轨迹里只剩那行 JSON 元数据、stdout 为空 —— 那**不是**「dsh 没输出」。

**唯一可信的判据**：用同一条 argv / 同一份 env 与工作区手工跑一次并计时：

```bash
time dsh --profile headless --patch <副本>/dsh-headless-overlay.yml --json -- - <<< "只回复 OK"; echo "exit=$?"
```

手工跑得完、插件跑超时 ⇒ **看门狗太小**（调 `remediation_timeout_seconds`）；
手工跑也迟迟不结束 ⇒ 才是真卡死（看轨迹 JSONL 的最后事件）。

---

## 6. 回执契约与真实样例

### 6.1 契约（用户硬要求）

> **每一次修复尝试都必须向 `target_sessions` 推送一条回执**，含没修成的那些；
> **「未改动」不许省略**；**被闸拦下必须写明被哪一道闸拦下 + 后续怎么办**。

代码落点：`remediate.build_receipt`（remediate.py:1610）是唯一实现；`main._receipt_plan`（main.py:811）
构造某出口的回执计划，`main._send_receipt`（main.py:854）按**出口链**投出去；两条调用路径覆盖全部终态：

| 路径 | 覆盖状态 | 代码位置 |
|---|---|---|
| 闸门拦截 | `skipped` / `blocked` / `unavailable` | `main._maybe_remediate` → `_send_terminal_receipt` |
| 执行器返回（含异常兜底） | `ok` / `failed` / `timeout` / `unavailable` / `rejected` | `main._maybe_remediate` → `_send_receipt` |

**出口链与重试**（2026-10-18 运营方定案）：`deliver.outlet_order`（deliver.py:473）保序去重，
列表第 1 个是主出口；`deliver.deliver_over_outlets`（deliver.py:499）逐个出口试
`delivery_max_attempts` 次（默认 **2** = 初投 + 1 次重试，配置里可改），用尽才切下一个出口，
**第一个成功就停**（不再"两处都收到"）；全部失败才按主出口入队一次。

**出口策略的三条硬约束**（同日定案，都已在代码里）：

1. **至少两条出口**：`target_sessions` 不足两条 ⇒ 插件**停摆**（不扫描/不投递/不修复），
   日志打 ERROR ＋ 在状态目录写 `CONFIG-INVALID.txt`（含原因与怎么恢复）；配置合格后重启即恢复，
   合格时会把旧痕迹删掉。为什么不是"拒绝加载"：核心 loader 对实例化阶段的异常不保证醒目，
   而停摆＋状态目录里的文件是运营方**会看到的地方**。
2. **只校验条数，不校验可达性**：写两条不通的出口同样算"合格"（可达性只能靠真发一条探针来验）。
   ⇒ **摘要里长期没有成功记录 = 出口可疑**，别把"很安静"当成"没事"。
3. **纯抖动封顶**：本地锚点只有 `transient:` 族、且**没有任何** `failure:` 族标签时，最终等级封顶
   MEDIUM（`classify.clamp_transient_escalation`，挂在 `engine.classify` 这个公开入口收口，
   附 `transient-escalation-capped` 标签）⇒ 模型抬到 HIGH/CRITICAL 也**不会**触发自动修复。
   带 `failure:` 证据的（例如那次 GMI `import-error`）**不受影响**；人工覆写（`source=manual`）永不封顶。

**未送达汇总行**（Q14=c，2026-10-18 二次修正）：投递条目耗尽转 `abandoned` 的同时，**下一条成功投递**
的尾部会带一行「最近 24 小时未送达：待重试 N 条、已放弃 M 条（最高 X 级，最早 Y 小时前）」——
既不静默丢失、也不刷屏。

- **口径是最近一个窗口（默认 24 h），不是终身**：终身计数会把 2026-10-14~18 那 81 条历史债**永远**
  挂在每条消息尾部（实测：终身 81 / 24 h 内只有 6）⇒ 那是噪声不是信息。窗口内的最高等级由
  `store.pending_stats()["recent_max_severity"]` 给出（含 `pending`/`degraded`/`abandoned`）。
- 计数为 0 的那一项不出现（只剩一项时读起来清楚）。
- **会话标识不进日志**：`deliver.mask_session()` 把 ``平台:类型:<ID>`` 掩成 ``平台:类型:（ID 已隐）``，
  用在启动横幅与「找不到会话」报错里 —— 因为 astrbot.log 正是插件自己要扫的那份日志。
  要看真实出口请读插件配置，不要靠日志。

**`remediation_runs.receipt_sent` 的含义与更新时机**（2026-10-18 起）：

- 含义：**首次投递就把回执交给了通道**才为 1。判定规则＝`deliver.delivered`（**任一出口**
  的 `DeliveryOutcome.ok` 为真；空列表 = 没告诉人）；`main._mark_receipt_sent` 在投递成功后补写那一列。
- 为什么不是 `finish` 写的：finish 发生在回执**之前**（回执要等 run 结束），设计里留的
  「发完再覆盖」此前一直没人接 ⇒ 该字段恒 0（7/7 行），看上去像「从没通知过运营方」。
- 不会置 1 的两种情况：进 `pending_delivery` 的重试（重试发的是投递计划，不再经过回执构造）；
  闸门拦下的终态回执（它**没有** `remediation_runs` 行 —— 行由 `ledger.begin` 在真跑时创建）。
| 子进程被取消（插件重载/关闭） | `cancelled` | `remediate.run_remediation` 的 `CancelledError` 分支：先回收进程组、补账、再透传取消；`_send_receipt` 由调用方中断时不再发送（这是唯一不发回执的状态，原因见 §10.3） |

边界（明确写下来，不藏着）：`remediation_receipt=false` 关掉回执（不建议）；
`target_sessions` 为空则没有可推送对象（此时告警也发不出）；`off`/`not_candidate` 两种拦截
**同一指纹每进程只提示一次**（避免默认关闭状态下每轮刷屏），其余闸门每次都发。

### 6.2 真实样例（本轮亲手跑出来的，非手写）

复现方式（离线，不 spawn 真 `dsh`、不写生产目录）：用替身顶掉
`asyncio.create_subprocess_exec`，喂一段真实形态的 `dsh --json` JSONL 事件流给**真实的**
`remediate.run_remediation()`，再用 `main._send_receipt` 的真实调用形状（**不传 conclusion**）
调 `build_receipt` —— 完整可复制脚本见 §6.5。

下面样例是逐字粘贴的原始输出。**样例里的 `/tmp/...` 路径是当时的临时路径**（临时目录按磁盘
纪律收工已删），它同时说明一件事：回执的「轨迹」字段是**插件落盘的真实路径**，可在该路径上
直接 `cat` 到 JSONL 轨迹（含 header + stdout + stderr）。

**样例 A：成功且改了文件（`ok`）**

```
【修复回执｜ok】
渠道：BOT1:group:10001
方案：dsh headless 诊断+修复｜profile=headless｜overlay=dsh-headless-overlay.yml（bundled）｜权限=workspace-write｜工作区=/root/AstrBot
判定：CRITICAL｜指纹 b32e0961d3556624｜组件 db.py｜新指纹
诊断结论：状态库写入失败引发 sqlite 锁争用，磁盘满加剧（Errno 28）
证据：astrbot.log:09:00:01 sqlite3.OperationalError: database is locked；astrbot.log:09:00:02 Errno 28 No space left on device
改动清单：已改动：astrbot/core/db.py
建议动作：清理 /tmp 陈旧会话文件；调大重试退避
人工介入：不需要
耗时 0.0s  exit=0
轨迹：/tmp/scribe-t18/fake-out/remediation/run-run-stub-1.jsonl
```

**样例 B：成功但没改文件（`ok` + `changed=false`）**

```
【修复回执｜ok】
渠道：BOT1:group:10001
方案：dsh headless 诊断+修复｜profile=headless｜overlay=dsh-headless-overlay.yml（bundled）｜权限=workspace-write｜工作区=/root/AstrBot
判定：CRITICAL｜指纹 b32e0961d3556624｜组件 db.py｜新指纹
诊断结论：状态库写入失败引发 sqlite 锁争用，磁盘满加剧（Errno 28）
证据：astrbot.log:09:00:01 sqlite3.OperationalError: database is locked；astrbot.log:09:00:02 Errno 28 No space left on device
改动清单：未改动任何文件
建议动作：清理 /tmp 陈旧会话文件；调大重试退避
人工介入：不需要
耗时 0.0s  exit=0
轨迹：/tmp/scribe-t18/fake-out/remediation/run-run-stub-1.jsonl
```

**样例 C：子进程失败（`failed`，exit=2）**

```
【修复回执｜failed】
渠道：BOT1:group:10001
方案：dsh headless 诊断+修复｜profile=headless｜overlay=dsh-headless-overlay.yml（bundled）｜权限=workspace-write｜工作区=/root/AstrBot
判定：CRITICAL｜指纹 b32e0961d3556624｜组件 db.py｜新指纹
诊断结论：状态库写入失败引发 sqlite 锁争用，磁盘满加剧（Errno 28）
证据：astrbot.log:09:00:01 sqlite3.OperationalError: database is locked；astrbot.log:09:00:02 Errno 28 No space left on device
改动清单：未改动任何文件（本次未创建子进程或子进程未写入工作区）
建议动作：清理 /tmp 陈旧会话文件；调大重试退避
人工介入：需要
耗时 0.0s  exit=2
轨迹：/tmp/scribe-t18/fake-out/remediation/run-run-stub-1.jsonl
拦下原因：非闸门拦截（已通过修复闸，执行器终态 failed）
后续怎么办：执行失败：看轨迹里的错误码与 stderr；必要时人工介入
```

**样例 D：headless 凭据/路由缺失（`unavailable`）**

```
【修复回执｜unavailable】
渠道：BOT1:group:10001
方案：dsh headless 诊断+修复｜profile=headless｜overlay=dsh-headless-overlay.yml（bundled）｜权限=workspace-write｜工作区=/root/AstrBot
判定：CRITICAL｜指纹 b32e0961d3556624｜组件 db.py｜新指纹
诊断结论：未取到结构化结论（轨迹见下）
证据：见轨迹（未取到结构化 evidence）
改动清单：未改动任何文件（本次未创建子进程或子进程未写入工作区）
建议动作：见轨迹结论（无结构化 actions）
人工介入：需要
耗时 0.0s  exit=-
轨迹：/tmp/scribe-t18/fake-out/remediation/run-run-stub-1.jsonl
拦下原因：非闸门拦截（已通过修复闸，执行器终态 unavailable）
后续怎么办：headless 凭据/路由缺失：按运行手册 §前置条件配好凭据或 overlay 后重载插件再试
```

**样例 E：闸门拦下（`skipped`，`off`）—— 真实插件循环里跑出来的**

复现方式：`/tmp/scribe-t18/dryrun.py`，用假 Context（只记录不发送）+ 补丁
`StarTools.get_data_dir` 指向 `/tmp`，**跑真实的** `LogWatcherPlugin.initialize()` →
一轮 `_scan_once()`（造一段 `No space left on device` + `database is locked` 的日志）→
分级（`local`）→ 路由（`emergency`）→ 闸门（`off`）→ 回执。原始输出
`/tmp/scribe-t18/dryrun.txt`。

```
【AstrBot 日志告警｜CRITICAL】
命中 2 条 ERROR/CRITICAL（共 4 行摘录）
时间：2026-10-14 09:00:01.000 ~ 2026-10-14 09:00:02.000
来源：astrbot.log
指纹：b32e0961d3556624
标签：failure:database-error、failure:disk-full、local-mode、level:CRITICAL
研判：本地模式判定 CRITICAL（置信度 0.90，指纹 b32e0961d355）：命中 failure:database-error、failure:disk-full、level:CRITICAL；…
—— 命中行 ——
[2026-10-14 09:00:01.000] [Core] [ERRO] [db.py:44]: sqlite3.OperationalError: database is locked
[2026-10-14 09:00:02.000] [Core] [CRIT] [log.py:20]: OSError: [Errno 28] No space left on device
```

紧接着第二条（回执）：

```
【修复回执｜skipped】
渠道：BOT1:group:10001
方案：dsh headless 诊断+修复｜profile=headless｜overlay=dsh-headless-overlay.yml（bundled）｜权限=workspace-write｜工作区=/root/AstrBot
判定：CRITICAL｜指纹 b32e0961d3556624｜组件 db.py｜新指纹
诊断结论：修复闸拦截（off）：未创建子进程
证据：见轨迹（未取到结构化 evidence）
改动清单：未改动任何文件（本次未创建子进程或子进程未写入工作区）
建议动作：见轨迹结论（无结构化 actions）
人工介入：不需要
耗时 0.0s  exit=-
轨迹：（无轨迹：未创建子进程）
拦下原因：off
后续怎么办：本次不满足修复条件（未创建子进程）；同指纹继续命中会按重复次数/置信度重新评估
```

干跑原始日志（同一轮）：

```
[Plug] 投递提示：已触发紧急修复流程，修复结论会作为回执单独发送
[Plug] 命中 2 条日志（1 段），投递 1 个会话，成功：是
[Plug] 修复未触发（off）：指纹 b32e0961d3556624 CRITICAL
=== 干跑投递消息（不真发送）=== sent_count=2 llm_calls=0
```

`sent_count=2` = 告警 1 条 + 回执 1 条；`llm_calls=0` = `classify_mode=local` 下**没有任何网络调用**。

### 6.3 哪些字段来自 dsh，哪些是插件补的

| 回执字段 | 来源 |
|---|---|
| 渠道 | **插件**：`main._send_receipt(session, …)` 的 target_sessions |
| 方案（profile/overlay 名+来源/权限/工作区） | **插件**：`resolve_overlay()` + `permission_mode()` + `remediation_workdir` |
| 判定（严重度/指纹/component/新旧指纹） | **插件**：`ThreatVerdict`（本地规则或 LLM 判定产出） |
| 诊断结论（根因） | **dsh 结论 JSON** 的 `root_cause`（经 `conclusion_from_trace()` 从轨迹恢复）；取不到时退回 `run.summary` 首段 |
| 证据（最多 3 条） | **dsh 结论 JSON** 的 `evidence[]` |
| 建议动作（最多 5 条） | **dsh 结论 JSON** 的 `actions[]` |
| 改动清单（文件列表） | **dsh 结论 JSON** 的 `changed` + `changed_files[]`；无改动时写「未改动任何文件」= **插件措辞** |
| 人工介入（需要/不需要） | **插件策略**：`failed/blocked/unavailable/timeout/rejected` → 需要 |
| 耗时 / exit code | **插件**：`run_remediation` 实测的子进程指标 |
| 轨迹路径 | **插件**：`_write_trace()` 落盘路径（未创建子进程时写「无轨迹」） |
| 拦下原因 / 后续怎么办 | **插件**：闸门 reason + `_TERMINAL_ADVICE` 建议表 |

dsh 侧结论的形状（提示词要求子 agent 在 `final` 文本里给一段 JSON）：
`root_cause` / `cause_category` / `evidence[]` / `actions[]` / `changed` / `changed_files[]` /
`verification` / `confidence` / `stopped_reason`（`remediate._normalize_conclusion`）。

### 6.4 本轮为此修的三个集成缺陷（都能复现）

| # | 症状 | 根因 | 修复 |
|---|---|---|---|
| 1 | `ok` 回执的「证据」「建议动作」永远是「见轨迹（未取到结构化 evidence）」，即使 dsh 明明给了证据 | `main._send_receipt` 只拿得到 `RemediationRun`，**不传 conclusion**，而结论 JSON 只存在轨迹里 | 新增 `conclusion_from_trace()`（remediate.py:765），`build_receipt` 在 `conclusion` 缺省时从 `run.log_path` 恢复（remediate.py:1649 附近） |
| 2 | dsh 报 `changed=true` 但没列文件名时，回执写成「**未改动任何文件**」（与结论相反） | `changed` 只能从 `run.artifact` 反推，空列表 ⇒ 误判为无改动 | 同上的轨迹恢复 + `summarize_run` 对「已改动但未列名」显式写「（未列出文件名，见轨迹）」（remediate.py:828） |
| 3 | 执行器终态（failed/timeout/unavailable）回执写「**拦下原因：ok**」 | `main` 传 `gate_reason="ok"`（闸确实放行了），`build_receipt` 原样打印 | `build_receipt` 把 `ok`/空 视为「非闸门拦截（已通过修复闸，执行器终态 X）」（remediate.py:1709） |

三条都有回归测试：`tests/test_remediate.py` 的
`test_receipt_recovers_conclusion_from_trace` / `test_receipt_does_not_claim_no_change_when_changed_without_files` /
`test_receipt_names_executor_terminal_state_not_gate_ok`。

### 6.5 复现方法（可复制粘贴，离线）

```python
# /tmp/repro_receipt.py —— 不 spawn 真 dsh、不写生产目录；输出即 §6.2 样例 A
import asyncio, json, sys, time
sys.path[:0] = ["/root/AstrBot/data/plugins", "/root/AstrBot"]
from log_watcher import remediate
from log_watcher.classify import Route, Severity
from log_watcher.models import RemediationGate, ThreatVerdict

CONCLUSION = {"root_cause": "状态库写入失败引发 sqlite 锁争用", "cause_category": "resource",
              "evidence": ["astrbot.log:09:00:01 database is locked"],
              "actions": ["清理陈旧会话文件"], "changed": True,
              "changed_files": ["astrbot/core/db.py"], "verification": "pytest -q"}

class Proc:                      # 假子进程：喂一段真实形态的 dsh --json 事件流
    returncode, pid = 0, 1
    async def communicate(self, _=None):
        events = [{"type": "session", "sessionId": "s1", "cwd": "/root/AstrBot"},
                  {"type": "final", "text": "```json\n" + json.dumps(CONCLUSION, ensure_ascii=False) + "\n```"}]
        return ("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n").encode(), b""
    def kill(self): pass
    async def wait(self): return 0

def ledger():                    # run_remediation 用 to_thread 调 can_start ⇒ 必须同步
    class L:
        def can_start(self, *_a, **_k): return RemediationGate(True, "ok")
        def begin(self, *_a, **_k): return "stub"
        def previous_runs(self, *_a, **_k): return ""
        def finish(self, *_a, **_k): return None
    return L()

async def main():
    asyncio.create_subprocess_exec = lambda *a, **k: asyncio.sleep(0, result=Proc())
    cfg = {"remediation_enable": True, "remediation_dsh_command": sys.executable,
           "remediation_profile": "headless", "remediation_workdir": "/root/AstrBot",
           "remediation_artifact_dir": "/tmp/repro-artifacts"}
    v = ThreatVerdict(severity=Severity.CRITICAL, fingerprint="b32e0961d3556624", component="db.py",
                      route=Route.EMERGENCY, is_new_pattern=True)
    run = await remediate.run_remediation(v, cfg, ledger=ledger(), now=time.time())
    print(remediate.build_receipt(run, v, cfg=cfg, channel="BOT1:group:10001", gate_reason="ok"))

asyncio.run(main())
```

```bash
PATH=/root/AstrBot/.venv/bin:$PATH python /tmp/repro_receipt.py   # 输出 §6.2 样例 A
```

> 本节样例由本轮临时脚本产生（`/tmp/scribe-t18/`，按磁盘纪律收工已删），脚本要点已内联在上面，
> 可原样复现；样例里的轨迹路径是当时的临时路径。
> 上面这段片段用的结论文本比 §6.2 样例 A 的短（`CONCLUSION` 自己填），所以「诊断结论/证据/建议动作」的字面内容会不同 —— 结构、段落顺序与字段来源完全一致。


---

## 7. 常见故障与处置

| 症状（日志/回执） | 原因 | 处置 |
|---|---|---|
| 没有任何告警，日志里也没有命中 | `levels` 与全局 `log_level` 不匹配；或 `log_dir`/`file_pattern` 扫不到文件 | 调 `levels`；`ls` 日志目录确认文件；看 `未配置 levels` / `找不到日志文件` warning |
| 告警发了但群里看不到 | 通道本身失败（如 weixin_oc 的 `prepare failed`） | 看 `weixin_oc(...): sendmessage failed ... errmsg=...`；若是 `context token missing`，先给机器人发一条消息刷新 context_token；失败残留见 `failed/` |
| `历史配置 file（txt 附件）已废弃…` | 配置里还是 `send_mode: file` | 改成 `auto`（或不管，插件已按文本发） |
| 回执里「后续怎么办：headless 凭据/路由缺失」 | 真调 dsh 后凭据/路由不可用，或 overlay 被删 | §5.3 两条命令验证；恢复 `dsh-headless-overlay.yml` 或配 provider，然后重载插件 |
| 回执里 `拦下原因：cooldown/daily_limit/storm/busy` | 被闸门拦下（预期行为） | 等冷却/改 `remediation_cooldown_seconds` / `remediation_daily_limit`；`busy` 还要看状态库是否可写 |
| 回执里 `非闸门拦截（已通过修复闸，执行器终态 timeout）` | 看门狗超时，进程组已被 kill 回收 | 调大 `remediation_timeout_seconds`，或先人工查轨迹 JSONL 的最后事件 |
| 状态库不可用 / 修复被强制关闭 | `state_db_path` 不可写（权限、磁盘满、schema 版本过高） | 看 error 日志；修磁盘/权限；插件会退回 JSON 内存态，告警照发、修复关（fail-closed） |
| 磁盘一直涨 | 摘录或轨迹没有按预期清理 | 看 `清理修复轨迹：{...}` 与 `磁盘占用 … 是否超限`；调 `outbox_max_bytes`/`keep_excerpt_files`/`outbox_max_age_hours`/`remediation_artifact_*` |
| 自反馈放大（自己发的失败被当成新告警） | `self_feedback_ids` 没填 | 填上目标会话 id（或把 `levels` 去掉 `WARNING`） |
| 想看插件到底收到了哪些配置 | 启动行只打印摘要 | WebUI 插件详情页；或 `cat /root/AstrBot/data/config/log_watcher_config.json` |

---

## 8. 回滚

插件目录**不在 git 里**（`/root/AstrBot/.gitignore:23` 忽略了 `data`），所以回滚靠文件级备份。
v1.0.0 的原始副本在团队快照目录：
`/root/AstrBot/.agent-teams/logwatch-ops/source-snapshots/recovered-v1.0.0/`。

### 8.1 回滚前：先把现在这一版备份下来（必做）

```bash
TS=$(date +%Y%m%d-%H%M%S)
mkdir -p /root/backups/log_watcher
cp -a /root/AstrBot/data/plugins/log_watcher /root/backups/log_watcher/v2-$TS
cp -a /root/AstrBot/data/config/log_watcher_config.json /root/backups/log_watcher/config-$TS.json
cp -a /root/AstrBot/data/plugin_data/log_watcher /root/backups/log_watcher/data-$TS
ls -l /root/backups/log_watcher/            # 确认三份都在
```

### 8.2 只停用修复（最小回滚，不动代码）

1. WebUI 插件详情页把 `remediation_enable` 关掉；或直接删掉路由 overlay：
   ```bash
   mv /root/AstrBot/data/plugins/log_watcher/dsh-headless-overlay.yml \
      /root/backups/log_watcher/dsh-headless-overlay.yml.bak
   ```
   ⇒ headless 路由立即失效（每次调用重读文件，不用重启 AstrBot），告警与回执链路不受影响。
2. 想彻底停掉插件：WebUI 停用 `log_watcher`。

### 8.3 回滚到 v1.0.0 代码（完整回滚）

```bash
PLUG=/root/AstrBot/data/plugins/log_watcher
SNAP=/root/AstrBot/.agent-teams/logwatch-ops/source-snapshots/recovered-v1.0.0
# 1) 备份（§8.1 已完成）
# 2) 先把 v2 独有文件移走（不要直接 rm，留证据）
mkdir -p /root/backups/log_watcher/v2-only
for f in classify.py detect.py engine.py deliver.py models.py store.py remediate.py \
         dsh-headless-overlay.yml runbook.md; do
  [ -e "$PLUG/$f" ] && mv "$PLUG/$f" /root/backups/log_watcher/v2-only/ || true
done
[ -d "$PLUG/prompts" ] && mv "$PLUG/prompts" /root/backups/log_watcher/v2-only/prompts
[ -d "$PLUG/tests" ] && mv "$PLUG/tests" /root/backups/log_watcher/v2-only/tests
# 3) 还原 v1 文件（覆盖 main.py/log_reader.py/__init__.py/schema/metadata/README/CHANGELOG）
cp -a "$SNAP"/. "$PLUG"/
# 4) 状态与配置
mv "$PLUG/../..//plugin_data/log_watcher" /root/backups/log_watcher/data-after-v2   # 或按下条精修
#   想保留续读位置：把迁移前的 JSON 还回去
#   cp /root/backups/log_watcher/data-*/tail_state.json.migrated-* /path/tail_state.json
# else v1 会重新从文件末尾开始（start_from_end=true，不重放历史）
# 5) 重载插件，验收启动行
#   期望：… 形态 file，间隔 30s …（没有 overlay/SQLite/分级那一段）
```

⚠️ 注意：v1 会把进度写在 `tail_state.json`（v2 已把它重命名为 `tail_state.json.migrated-<时间戳>`）；
`log_watcher.sqlite3` 对 v1 无害但仍占磁盘，可移到备份目录。
`data/config/log_watcher_config.json` 里的 v2 新键对 v1 也无害（v1 只读它认识的键），
若想彻底干净，用 `config-$TS.json` 换成备份前的 v1 版本。

### 8.4 回滚验证

```bash
grep -a "日志监听启动" /root/AstrBot/data/logs/astrbot.log | tail -1     # v2 启动行含 overlay + 状态 SQLite
cd /root/AstrBot/data/plugins/log_watcher && PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q
```

---

## 9. 独立复验清单（本任务逐条实测，命令 + 结果）

| # | 判据 | 命令 | 实测结果 |
|---|---|---|---|
| 1 | 测试 ≥200 且全绿 | `cd /root/AstrBot/data/plugins/log_watcher && PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q` | **295 passed / 0 failed / exit 0**（收工前重跑） |
| 2 | schema 键 ⊇ main 读取键 | 见下方脚本 | 缺 **0** 键（main 80 键 = schema 的 80 个可见键，一一对应） |
| 3 | schema 键 ⊇ architecture §8 全表 | 同上脚本的 §8 分支 | 缺 **0** 键（§8 表格键 72 个全覆盖；`admin_users` 以「未实现」标注保留） |
| 4 | `send_mode != "file"` | `$PY -c "import json;print(json.load(open('_conf_schema.json'))['send_mode']['default'])"` | `auto` |
| 5 | 状态库存在且 `user_version=2` | `$PY -c "import sqlite3;print(sqlite3.connect('/root/AstrBot/data/plugin_data/log_watcher/log_watcher.sqlite3').execute('pragma user_version').fetchone()[0])"` | `2`（真实生产库，见 §11） |
| 6 | 生产文件无 `os.system`/`subprocess.run`/`subprocess.Popen`/`shell=True` | `grep -nE "os\.system\|subprocess\.run\|subprocess\.Popen\|shell=True" *.py`（V4 口径：只对生产文件生效，`tests/` 内离线探针豁免） | 生产文件 **0 命中** |
| 7 | 权限语义不含危险值 | `grep -rn "danger-full-access" *.py _conf_schema.json dsh-headless-overlay.yml` | 只出现在「会回落/不提供」的注释与 hint 里；无代码路径写入该值 |
| 8 | 提权键被钉死 | `$PY -c "import sys;sys.path.insert(0,'.');import remediate;print(sorted(remediate.FORBIDDEN_ENV_KEYS))"` | 5 个键，含 `sandbox_permissions` |
| 9 | 回执四段（方案/判定/改动清单/轨迹）在真实路径上存在 | 见 §6.2 样例 A/E（真实执行产物） | 全部字段齐全，「未改动任何文件」显式出现 |
| 10 | 每种终态都发回执 | `tests/test_remediate.py::test_receipt_for_every_terminal_state_names_the_gate_and_next_step` + `main.py` 两条调用点 | 7 种终态断言通过；`cancelled` 的边界见 §10.3 |
| 11 | 工厂外无副作用 | 干跑用 `/tmp/scribe-t18` 隔离目录 + 假 Context | 生产数据目录未被本次任务写入（`remediation/` 仍为空） |
| 11b | 逐条打开文件行核对 review-1.md 的 19 条 finding（不采信报告表述） | 直接读代码行：F01 `classify.py:804` 唯一实现 + `remediate.py:479` 委托、四个注入位中性化 `remediate.py:558/582/590/593`、`REASON_MAX_CHARS=600`（`remediate.py:490`）、模板 3 处围栏声明；F02 `classify.py:834/839`（按 `__file__` 取资产）+ 围栏 `classify.py:900/902`；F04 `engine.py:497/506/715` + `main.py:348/351`；F05 `remediate.py:1162/1179/1515`（进程组回收 + `start_new_session`）；F06 `store.py:1088`（docstring 写明 grace=0 的理由）+ `main.py:205`；F08 `main.py:281` + `remediate.py:964`；F09 `store.py:59/62/66/75`；F10 轨迹 `scrub` 默认 True；F11 pattern 校验 `main.py:1539` + 越界丢弃 `main.py:1611`；F14 `classify.py:81/118`；F15 `engine.py:669/677`；F17 `detect.py:48/82/160` | 全部与 `repair-1.md` 的对应表一致，**落地为真**；F12/F16/F18/F19 仍未闭合（§10.1，如实登记） |
| 12a | 静态纪律 | `ruff check *.py tests/*.py` → **All checks passed! exit=0**；`python -m compileall -q` → exit=0；`ruff format --check` → 13 个文件「would reformat」 | 见 §10.5：format 是**前一轮就存在的**风格偏差（AstrBot 仓库 line-length=88），本任务故意不套用（会重排 100+ 行并让 findings/报告里的 `文件:行` 取证全部失效） |
| 12b | 边界用例复跑（verification-1.md §5 的 7 条 + V1/V7 + 本轮 3 个回执缺陷） | 自写临时脚本（走插件自身 reader/remediate，非手搓对象；按磁盘纪律收工已删，用例与期望值见本表） | **14/14 PASS**（含「等长重写无 inode/size 变化 ⇒ 该轮 0 行」= 已知边界）。**诚实更正**：我最初的「超长单行」断言写错了（以为不产出任何行），实测是**一行 1 MiB 截断体 + 标记，下一轮从 EOL 后续读、无残片**，已按实测改写断言；verification-1 的表述偏宽，实际语义以本次实测为准 |
| 12 | `_conf_schema.json` 能被 AstrBot 真正加载 | `$PY` 用 `astrbot.core.config.astrbot_config.AstrBotConfig(config_path=<副本>, schema=<本插件 schema>)`（与 `star_manager.py:1156` 同一代码路径） | 加载成功：**85 个真实配置键（80 可见 + 4 兼容 + 1 未实现占位）全部物化 + 8 个分组标题键**共 93 项，`admin_users=[]`、`route_map={}`、`channel_overrides={}`、`remediation_enable=false`、`remediation_permission_mode='workspace-write'`；旧 schema 已删的 `_basic_section/_scan_section/_content_section` 被自动清理；旧配置里的 `send_mode='file'` 保留（见 §3.0） |

复验脚本（判据 2/3）：

```bash
cd /root/AstrBot/data/plugins/log_watcher && PATH=/root/AstrBot/.venv/bin:$PATH python - <<'EOF'
import re, json, pathlib
schema = {k for k in json.load(open('_conf_schema.json')) if not k.startswith('_')}
src = pathlib.Path('main.py').read_text()
main_keys = set(re.findall(r'self\.config\.get\(\s*"([a-z0-9_]+)"', src))
sys_keys = set()
for p in pathlib.Path('.').glob('*.py'):
    t = p.read_text()
    sys_keys |= set(re.findall(r'(?:config|_cfg|cfg)\.get\(\s*"([a-z0-9_]+)"', t))
    sys_keys |= set(re.findall(r'(?:cfg_first|cfg_get)\([^)]*?"([a-z0-9_]+)"', t, re.S))
arch = pathlib.Path('/root/AstrBot/.agent-teams/logwatch-ops/architecture.md').read_text()
sec = arch.split('## 8. 配置项清单')[1].split('## 9.')[0]
arch_keys = set()
for line in sec.splitlines():
    # 只取 §8 表格行的**第一列**（键列）；类型列限定为合法 schema 类型，避免把默认值当键
    head = re.match(r'^\|\s*(.+?)\s*\|\s*(int|float|bool|string|text|list|dict|file|object)\s*\|', line)
    if head:
        arch_keys |= set(re.findall(r'`([a-z0-9_]+)`', head.group(1)))
for name, keys in (("main.py", main_keys), ("全部代码字面键", sys_keys), ("architecture §8", arch_keys)):
    print(f"{name}: {len(keys)} 键，缺 {sorted(keys - schema)}")
EOF
# 期望三行都是「缺 []」
```

---

## 10. 已登记未闭合项与已知边界（诚实登记，不粉饰）

### 10.1 四条未闭合 finding（来自 review-1.md，t17 已逐条说明，本轮不修）

| ID | 现状 | 风险与建议 |
|---|---|---|
| **F12** `classify.Rule` 与 `models.Rule` 双定义 | 未闭合（low） | 消费端全 duck-typing、`isinstance` 零命中，当前无活风险；统一需改 classify 规则表（`pattern: re.Pattern` → `str + is_regex=True`）与 58 条既有断言，属结构性重构 |
| **F16** `flush_burst` 窗口受轮询节奏影响 | 未闭合（待证） | 需要「假 provider 延时 ≥ 轮询间隔」的复现案例才能定论，本轮未构造出 |
| **F18** **出站告警摘录不做凭据掩码** | 未修（功能取舍） | 要发原始日志才能定位；**轨迹侧已掩码（F10），聊天侧没有**。缓解：`exclude_keywords` 过滤密钥行；或加保守掩码开关（后续版本） |
| **F19** 注入能否把 benign 指纹推进 `emergency` | 未闭合（待证） | F01/F02 的围栏与中性化已做实（注入面从「可物理逃逸围栏」降为「LLM 语义风险」）；定论需真实 provider 往返（`classify_mode=llm`），本轮未做 |

### 10.2 `/lw` 管理命令：**未实现**

`architecture.md §8.7` 规划的 `/lw status`、`/lw ack <指纹>`、`/lw silence <分钟>`、
`/lw remediate <指纹>` 与 `admin_users` 白名单**本版本没有实现**：插件不注册任何命令处理器
（保持零事件入口）。schema 里的 `admin_users` 是**前向兼容占位键**（`invisible`，已标注未实现），
填了不会生效。需要这些命令时请单独实现（实现后必须用非白名单用户调用一次，确认被拒且留日志）。

### 10.3 `cancelled` 与回执的唯一例外

`cancelled` 发生在插件重载/关闭时（`asyncio.CancelledError`）：`run_remediation` 会先按进程组
kill 并 `await` 回收子进程、补账（`ledger.finish(..., receipt_sent=receipt_sent)`），再把取消信号
原样透传。**取消路径本身不投递回执** —— 因为此时发送通道正在被拆卸，投递必然失败；
`remediation_runs` 表里会留下 `cancelled` 记录（`receipt_sent=0`），人工可查。
这是「每一次修复尝试都发回执」的唯一例外，写在这里而不是默默略过。

### 10.4 其它边界

- 采集解析依赖 AstrBot 的日志格式；非 loguru/标准 logging 格式的第三方日志可能匹配不到等级。
- `context_before`/`context_after` 决定了「末尾报错」的等待行数，也就决定了告警延迟。
- 通道自身不可用时，告警与回执都送不出去（会进重试队列 + `failed/` 残留，不静默丢）。

- **V7（low，固有边界）**：外部工具若用 `copytruncate` 把小文件**重写成等长或更长但无 inode 变化**
  的内容，`stat` 层无法与「无新增」区分 ⇒ 该轮读 0 行、这段新内容被跳过（后续轮次从旧 offset 续读，
  不会产生脏行）。真实 loguru 轮转是 rename 制（inode 变化），实测正常；只有「copytruncate + 极快写入」
  才有静默丢行的可能。规避：让日志工具用 rename 轮转，或改用 `file_pattern` 扫描轮转出的新文件。

- 插件目录下有一个**不属于插件的** `data/` 子目录（`data/cmd_config.json`、`data/t2i_templates/`，
  mtime 2026-10-14 04:44）：那是 AstrBot core 曾以「插件目录为 cwd」被导入时，把全局数据目录
  落在 cwd 的产物（不是 log_watcher 自己写的；插件运行时用的是
  `/root/AstrBot/data/plugin_data/log_watcher/`）。它与运行无关，**可以安全删除**；本轮未动它。
  另外 `main.py:101` 在 `StarTools.get_data_dir` 抛异常时会回落到 `os.getcwd()/data/plugin_data/log_watcher`
  —— 如果哪天真的看到插件数据落在插件目录里，就说明走到了这条回落路径（日志会有一条 warning）。

---

### 10.5 静态检查口径（诚实登记一处偏差）

- `ruff check`（lint）：**全绿**（`All checks passed!`，exit 0），插件与测试都无告警。
- `ruff format --check`：13 个文件「would reformat」。这是**前几轮就有的**偏差，不是本轮引入：
  插件一直按自己的排版风格写（单行断言、紧凑参数表），而 AstrBot 仓库根 `pyproject.toml`
  设了 `line-length = 88`。本任务**故意不套用** `ruff format`：它会重排 100+ 行纯格式，
  让 `review-1.md` / `repair-1.md` / 本手册里的 `文件名:行号` 取证全部错位（用户硬规则：
  已写下的取证不得改动）。要统一风格请单开一个纯格式提交，别和功能改动混在一起。
- `python -m compileall -q *.py tests/*.py`：exit 0。
- 生产代码真包导入：`sys.path` 加 `data/plugins` 后 9 个模块全部可导入（`star_manager.py` 同形路径）。

### 10.6 本轮新增的两条已知边界（2026-10-14 巡检触发）

- **摘录留存与 `alerts.excerpt_path` 不一致**：16 条告警里 6 条的 `excerpt_path` 已不存在
  （含 21:00 那条 `outbox/astrbot-log-20261014-210102.txt`），而告警文案写的是「完整摘录见日志目录」。
  投递成功的那几条会被清理、失败的那几条留在 `failed/`，所以「事后按记录回查原文」不总能做到。
  复盘请从 `data/logs/astrbot.log` 按指纹/时间重取，或调大 `keep_excerpt_files`（当前 50）与
  `outbox_max_age_hours`。
- **`engine.py` 的日志器不在 AstrBot 日志管道里（本轮只修了一半）**：`engine.py:67` 的
  `logging.getLogger("log_watcher.engine")` 产生的 INFO/WARN，在 `astrbot.log` 与 journald 里都是
  **0 条命中**（`[log_watcher.engine]`），`engine.py:741` 的「LLM 判定超时（>20s）」因此在 21:00
  那次告警里查无痕迹。本轮只在 `main.py` 补了「判定降级」一条 WARN；engine 其余日志（噪声短路、
  知识库命中、调用预算）仍然不可见。彻底修法是让 engine 也走 `astrbot.api.logger` —— 注意 loguru
  用 `{}` 占位，而 engine 现在是 `%s` 风格，必须逐条改，不能只换 logger 对象。

## 11. 本轮干跑与 provenance

### 11.1 `data/plugin_data/log_watcher/` 里的东西是谁产生的（captain 指派必须查清）

| 产物 | 产生者 | 证据 |
|---|---|---|
| `log_watcher.sqlite3`（user_version=2，WAL） | **运行中的真实 AstrBot 进程**（PID 2433752，2026-10-13 起）在 **05:50:17 重载插件**时创建 | `astrbot.log`: `[2026-10-14 05:50:17.797] [log_watcher] [INFO] [log_watcher.main:172]: 日志监听启动：… 形态 auto(file→text)… 状态 SQLite…`；文件 mtime `05:50` 一致 |
| `tail_state.json.migrated-20261014-055017` | 同一次重载触发的 v1 JSON → SQLite 迁移（时间戳就是 05:50:17） | 文件名时间戳与启动行一致 |
| `outbox/` 50 个文件 / `failed/` 5 个文件 | 真实告警投递与失败残留（weixin_oc `prepare failed`） | `astrbot.log` 07:00–08:16 的投递/重试日志 + `failed/astrbot-log-20261014-*.txt` |
| `remediation/`（空，0700） | t17 的两次非计划 headless 调用留下的轨迹**已按 t17 记录删除**，目录由 `harden_tree` 收窄权限 | `ls` 为空；t17 报告已声明 |
| 两份 t14/t15 期留存 | 由测试/干跑在 `/tmp` 隔离目录产生，**不在生产目录** | 生产目录 mtime 与干跑时间不重叠 |

结论：**是真实 AstrBot 加载过这套代码**（热重载，不是重启），不是别的路径产生的；
但**加载的是 05:50 那一版**，早于 t17/t18 的改动（§1.2）。

### 11.2 本轮干跑记录（不真发送、不真调 dsh）

| 环节 | 验证到 | 未验证 |
|---|---|---|
| 扫描 → 片段合并 → 分级（local） → 路由 → 闸门 → 回执 | ✅ 全链路（`dryrun.py`，`sent_count=2`：告警 + `skipped` 回执） | — |
| 真实平台投递 | ❌ 未验证（假 Context 只记录） | 真实 `Context.send_message` 与 weixin_oc 服务端 |
| 真实 `dsh` 调用 | ❌ 未验证（替身顶掉 `create_subprocess_exec`） | 真 headless 往返（§5.3 留给人工；本轮**没有**产生任何真实 headless 调用） |
| 执行器各终态（ok/failed/timeout/unavailable + changed/no-change） | ✅ 走真实 `run_remediation` + 真轨迹落盘 + 真 `build_receipt` | 真实 dsh 的输出格式漂移 |
| SQLite v2 迁移/保留清理/轨迹清理 | ✅ 迁移契约与保留清理有测试；轨迹清理接线为本轮新增（`main.py:1000`） | 长跑观察（需要真实运行数天） |

---

## 12. 逐文件交付清单（含关键行证据）

| 文件 | 变更 | 关键行证据 |
|---|---|---|
| `README.md` | 重写：删除「forward 可用」「32 项测试」等虚假声明；新增回执契约、overlay/权限既定事实、weixin_oc 段型事实、prune 归属、`/lw` 未实现 | 回执契约表；`weixin_oc` 章节；`未实现的功能` 章节 |
| `CHANGELOG.md` | 新增 2.0.0；1.0.0 的虚假声明就地更正为「已在 2.0.0 修正」 | `## 2.0.0 — 2026-10-14`；`已由 2.0.0 一节取代` |
| `metadata.yaml` | `version: 1.0.0 → 2.0.0`；desc 更新为完整闭环 | 第 11 行 `version: 2.0.0` |
| `_conf_schema.json` | 12 键 → **80 个可见键（= main.py 读取的 80 键，一一对应）+ 4 兼容键 + 1 未实现键，共 93 项**，每键含 type/default/中文 hint/误配后果；`send_mode` 默认 `file → auto` | `send_mode.default == "auto"`；`remediation_enable.default == false`；`remediation_permission_mode.options == ["read-only","workspace-write"]` |
| `runbook.md`（**新增**） | 本文档：部署/生效、配置速查、运维、修复通道三项事实、回执契约与真实样例、故障处置、回滚、复验清单、未闭合项、provenance、交付清单 | 全文 |
| `main.py` | ① 新增 `_prune_artifacts_hook()` 并在每轮 `_commit_round()` 调用 `prune_artifacts`（登记三个轨迹保留键的周期调用者）；②（t17 起）七段回执与全部终态投递路径 | `main.py:1000`（调用）、`main.py:1054`（hook）、`main.py:754`（`_send_receipt`）、`main.py:822`（`_send_terminal_receipt`）、`main.py:1143`/`1174`（两条调用点） |
| `remediate.py` | ① 新增 `conclusion_from_trace()`；② `build_receipt` 缺省 conclusion 时从轨迹恢复；③ `changed=true` 无文件名不再写成「未改动任何文件」；④ 执行器终态不再写「拦下原因：ok」 | `remediate.py:765`（新函数）、`remediate.py:1610`（`build_receipt`）、`remediate.py:1673`（「未改动任何文件」）、`remediate.py:1709`（非闸门拦截）、`remediate.py:78`（`FORBIDDEN_ENV_KEYS`）、`remediate.py:220`（权限回落）、`remediate.py:259`（overlay 解析）、`remediate.py:1256`（`prune_artifacts`） |
| `tests/test_remediate.py` | 新增 3 条回归测试（轨迹恢复结论 / 改动清单不撒谎 / 执行器终态闸名口径） | `test_receipt_recovers_conclusion_from_trace`、`test_receipt_does_not_claim_no_change_when_changed_without_files`、`test_receipt_names_executor_terminal_state_not_gate_ok` |
| 交付报告 | `.agent-teams/logwatch-ops/repair-1.md`（t17）、本轮复验结论随 t18 任务输出 | — |

### 12.1 复验一句话

```bash
cd /root/AstrBot/data/plugins/log_watcher && PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q
# 295 passed
```
