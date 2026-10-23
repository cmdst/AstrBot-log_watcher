# log_watcher v2.3.0 运行手册（runbook）

适用版本：`metadata.yaml` → `version: 2.3.0`（2026-10-23 收口；v2.2.0 的回滚锚点是 `591469a`，
v2.0.0 tag 在 `a4eeef4`）
适用环境：本机 AstrBot（`/root/AstrBot`，venv 在 `/root/AstrBot/.venv`；判版本见 §1）

**命令约定**：本容器 PATH 里没有裸 `python`，所有 Python 命令统一前缀
`PATH=/root/AstrBot/.venv/bin:$PATH`（下文简写 `$PY`）。插件目录
`cd /root/AstrBot/data/plugins/log_watcher`。

```bash
export PY="PATH=/root/AstrBot/.venv/bin:$PATH python"
```

> **v2.3.0 的三条硬约束**（看完全文再动手）
> 1. **每条错误都必须由模型重新下结论**：指纹知识库只作先验，不再复用旧结论；
>    人工覆写是唯一豁免，且必须可见（`judged=false` / `judge_source=manual`）。
> 2. **自动修复通道已整体移除**：没有 `dsh` 子进程、没有 overlay、没有修复配置键与回执；
>    历史轨迹/台账只读保留（清理走离线 CLI）。
> 3. **升级先迁移配置、再换代码；回滚要配置 + 状态库 + 代码成对回**（§1.3 / §8.4）。

---

## 1. 部署与生效

### 1.1 改完代码要不要重启 AstrBot？

**结论：不需要重启 AstrBot 进程，但必须让插件重新加载一次（WebUI 重载插件）。**

- Python 模块在 AstrBot 进程内被缓存：**只把文件写到磁盘上，运行中的插件不会改变行为**。
- WebUI → 插件管理 → 找到「日志监听」→ 点重载（或停用再启用）。重载会重新导入模块，
  插件自己的 `initialize()` 重新执行并打印一行启动日志（这就是验收标志）。
- 重载**不需要**动 `data/config/`（配置由 `AstrBotConfig` 自动补齐），也不需要重启 AstrBot 服务。
- 注意：**核心会在插件加载时删掉 schema 里没有的键**（`check_config_integrity()` + `save_config()`）。
  跨大版本升级时，先做 §1.3 的配置迁移，再重载新版本。

### 1.2 验收一条重载是否成功

```bash
LOG=/root/AstrBot/data/logs/astrbot.log
grep -a "日志监听启动" $LOG | tail -1
```

期望（v2.3.0 的启动行）：

```
日志监听启动：目录 …，匹配 *.log，等级 ['ERROR', 'CRITICAL']，形态 auto，间隔 30s，会话 N 条（…）；
状态 SQLite，分级 auto（provider 已配置/未配置），知识库 SqliteKnowledgeBase；
报告 开启（excerpt，≥MEDIUM）；磁盘占用 …
```

- `报告 开启（excerpt，≥MEDIUM）` 来自 `report.enabled` / `report.raw_mode` / `report.min_severity`；
  关闭时显示「报告 关闭」。
- 若状态库版本高于本实现，启动行会显示「状态 只读（状态库拒绝写入）」—— 见 §8.4，不要忽略。
- 另外确认：日志里没有本插件的 `Config key removed`、插件数据目录没有 `CONFIG-INVALID.txt`。

### 1.3 v2.3.0 的配置迁移（**先迁移、再换代码**）

v2.2.0 → v2.3.0 的配置变化：**删除 `remediation` 整组 22 个键**、**新增 `report` 组 7 个键**与
两个判定键（`classify.prior_ttl_hours` / `classify.repeat_window_seconds`），
结构从 8 组 / 82 键变成 **8 组 / 69 键**。

**本版没有需要搬运的值**：60 个既有叶子的键名与语义都没变，变化只有「删 22 + 加 9」。
顺序纪律的理由不是「值会丢」，而是：旧 schema 会在窗口内把 9 个新键当 stale 键删掉；
先迁移能让窗口里的配置**已经是新结构**（新键缺了只回落默认值，删掉的旧键本来就是本版不要的）。
另一个可执行性理由：**换版前 `$PLUG` 里还是 v2.2.0，没有 `migrate_config_v3.py`** ——
第 1、2 步必须用**库目录**里的工具（它按 `__file__` 读库里的新 schema，不碰生产配置）。

```bash
CFG=/root/AstrBot/data/config/log_watcher_config.json
PLUG=/root/AstrBot/data/plugins/log_watcher
LIB=/root/workspace/projects/AstrBot-log_watcher     # 库目录：迁移前唯一有 v3 工具/新 schema 的地方
# 0) 先备份插件目录、配置与状态库（§8.1）
# 1) 干跑体检：应列出「将删除 22 个 remediation 键、将补默认值 9 个新键、未知键 0」
python3 $LIB/tools/migrate_config_v3.py --dry-run --config $CFG
# 2) 迁移：写 $CFG.bak-pre-v2.3.0-<ts> 后原子替换
python3 $LIB/tools/migrate_config_v3.py --apply --config $CFG
# 3) 换版：用 v2.3.0 覆盖插件目录（排除 .git / __pycache__ / .pytest_cache / *.bak-*）
# 4) 复核（换版后 $PLUG 里也有新工具；只回键名，不打印配置值）
python3 $PLUG/tools/migrate_config_v3.py --verify --config $CFG --against $CFG.bak-pre-v2.3.0-*
#    仅在「换版窗口被旧 schema 清过」时，从备份重建（库目录或 $PLUG 均可）：
#    python3 $LIB/tools/migrate_config_v3.py --from-backup $CFG.bak-pre-v2.3.0-* --config $CFG
# 5) 重载插件，按 §1.2 验收
```

- **只支持 v2.2.0（分组结构）→ v2.3.0**。若部署还停在 v2.1.0 的 95 键扁平结构，先跑
  `$LIB/tools/migrate_config_v2.py`（v2.1.0 → v2.2.0，同样在换版前用库目录），再跑 v3；
  v3 工具会明确拒绝扁平结构。
- 窗口纪律：第 2–5 步之间不要在 WebUI 上碰 log_watcher 的配置页（旧 schema 会抢先清理）。
- 工具**任何模式都不打印配置值**；先拿一份配置副本到 `/tmp` 干跑最稳（不触碰生产配置）。
  仓库自带一份合成假值的 v2.2.0 样本（`$LIB/tools/fixtures/log_watcher_config_v2.2.0.sample.json`，
  82 键、无生产值），可直接拿它练干跑/落盘/复核。
- 旧 22 键的语义：它们在 v2.2.0 里真实存在、在 v2.3.0 被**明示删除**（dropped，不是 unknown），
  键名冻结在 `tests/test_config_map.py::DROPPED_IN_V230`；核心加载 v2.3.0 时也会把它们当 stale 键删掉。

---

## 2. 前置条件与自检

| 前置 | 检查命令 | 期望 |
|---|---|---|
| AstrBot 文件日志开启（`log_file_enable`） | `ls -l /root/AstrBot/data/logs/astrbot.log` | 文件存在且持续增长；否则插件每 10 分钟一条 warning |
| 全局 `log_level` 覆盖你要的等级 | `grep -a "\[ERRO\]" /root/AstrBot/data/logs/astrbot.log \| tail -1` | 有该等级的行；全局 INFO 时不会有 DEBUG 行 |
| 提醒会话填对 | `grep -A2 '"target_sessions"' /root/AstrBot/data/config/log_watcher_config.json`（在 `notify` 组内） | 形如 `BOT1:private:10002`；第 1 个是主出口 |
| LLM 分级（推荐） | 插件启动行里 `分级 auto（provider 已配置/未配置）` | 未配置时每条都会显式降级（`degraded:llm-unconfigured`），不会静默用本地结论定案 |
| 通知通路（可选探针） | 往被监听目录追加一行合成 `ERROR`（不含插件名） | 一轮内出现「本轮判定汇总」「命中 N 条日志」；失败见 §7 |

**注意**：`classify_mode: auto` + 没配 provider **不是**故障，但也不是「本地判定算数」：
会得到 `source=degraded`、`degraded:llm-unconfigured`，且**不写知识库**；配好 provider 后
下一轮自然重判（不会捡回旧的本地结论）。

---

## 3. 配置速查

- **权威来源**：`_conf_schema.json` —— **v2.3.0 起是 8 个分组 / 69 个叶子键**（分组 `object` +
  叶子带中文 hint 与「误配后果」）。WebUI 插件详情页按这 8 组渲染，
  `data/config/log_watcher_config.json` 也是同样的嵌套结构。
- 分组与叶子数：`notify` 7 + `scan` 9 + `classify` 18 + `budget` 12 + `delivery` 4 +
  `report` 7 + `state` 9 + `self_guard` 3 = **69**。
  算术：82 − 22（remediation）= 60；+ 2（classify 新增）= 62；+ 7（report 组）= 69。
- **键名映射的唯一事实源**是 `config_map.KEY_MAP`（60 条 v2.1.0 迁移契约）；v2.3.0 新增的 9 个
  叶子住在 `config_map.EXTRA_LEAVES`。schema、main 读取点、迁移工具三方由
  `tests/test_config_map.py` 钉死；**改动过的键必须同时出现在 schema / config_map / main 的
  白名单三处**（历史事故：两个等级旋钮漏进白名单被静默丢弃一整天）。
- 新键在插件下次加载时由 `AstrBotConfig` 自动写进配置；但 **v2.2.0 → v2.3.0 是结构变化，
  必须手动迁移一次**（§1.3）。
- `notify.send_mode` 默认 `auto`；老配置里的 `file`/`txt`/`attachment` 会被映射成文本并把这条
  映射写进日志（`历史配置 file（txt 附件）已废弃…`）。

### 3.1 键表

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `self_guard.log_with_bot_id` | bool | `false` | 插件日志带 [platform:平台ID]，多 Bot 环境便于定位 |
| **① 主动提醒（`notify`）** | | | |
| `notify.target_sessions` | list | `[]` | 告警会话。**列表即优先级**：第 1 个是主出口（只有它能带附件），失败才用第 2 个 |
| `notify.send_mode` | string | `"auto"` | auto 按通道能力选；text 只发文本；forward 优先合并转发（不支持则退回文本）。**报告形态（默认开）恒为单条文本：forward 只影响旧内联路径** |
| `notify.prefer_forward` | bool | `false` | 只影响旧内联路径；报告形态下无效，但会打一条 degradation 提示 |
| `notify.min_severity` | string | `"MEDIUM"` | 即时告警最低等级；低于它只进摘要或静默 |
| `notify.include_excerpt` | bool | `true` | 旧内联路径（报告关闭/低等级）是否附摘录正文 |
| `notify.max_excerpt_chars` | int | `6000` | 旧内联路径的单条摘录字符上限（200-20000） |
| `notify.max_chars_per_message` | int | `0` | 覆盖单条上限；0 = 按通道能力表（上限 8000） |
| **② 日志扫描（`scan`）** | | | |
| `scan.log_dir` / `scan.file_pattern` | string | `""` / `"*.log"` | 日志目录（空 = AstrBot 自己的）与 glob |
| `scan.levels` | list | `["ERROR","CRITICAL"]` | 只提醒列表里的等级（也认 DBUG/WARN/ERRO/CRIT 短名） |
| `scan.exclude_keywords` | list | `[]` | 行里含任一关键字就不算命中（仍作为前后文出现） |
| `scan.poll_interval_seconds` | int | `30` | 扫描间隔（5-86400）；也是「末尾报错等不到后文」的最长等待 |
| `scan.start_from_end` | bool | `true` | 跳过已有内容，不重放历史 |
| `scan.context_before` / `context_after` | int | `5` / `5` | 前后文行数（0-200）；堆栈靠 after 带出 |
| `scan.max_lines_per_poll` | int | `200` | 一轮最多展开多少行（20-5000） |
| **③ AI 威胁分级（`classify`）** | | | |
| `classify.enable` | bool | `true` | 分级总开关；关闭 = 按日志等级直接触发（会噪声直灌） |
| `classify.mode` | string | `"auto"` | auto = 有 provider 就每条过模型；local = 显式本地（永不调模型）；llm = LLM 优先、失败降级 |
| `classify.provider_id` | string | `""` | AstrBot provider id；留空 = 每条显式降级（不写库） |
| `classify.timeout_seconds` | int | `20` | 5-300，单次 LLM 判定超时 |
| `classify.system_prompt` | text | `""` | 覆盖内置提示词（空 = `prompts/classify_system.md`） |
| `classify.fallback_severity` | string | `"MEDIUM"` | 降级地板：`max(本地判定, 该值)`，且至少 MEDIUM |
| `classify.unmatched_severity` | string | `"LOW"` | 本地锚点里「谁都解释不了的 ERROR」的等级 |
| `classify.transient_severity` | string | `"MEDIUM"` | 本地锚点里可恢复抖动的等级（TRANS-01 基线） |
| `classify.max_block_lines` | int | `80` | 送 LLM 的最大行数（5-500） |
| `classify.max_calls_per_round` | int | `5` | **本轮最多判几段**；超出的排队到下一轮（不是本地定案） |
| `classify.max_calls_per_hour` | int | `60` | 每小时模型调用上限；超出的同样排队 |
| `classify.noise_shortcut` | bool | **`false`** | true = 良性噪声零 token 短路；结论标 `judged=false`（偏离「每条必过模型」） |
| `classify.kb_enabled` | bool | `true` | 知识库只作**先验**：命中会注入提示词，但**不再短路判定** |
| `classify.kb_max_entries` | int | `500` | 知识库条数上限（超出由 prune 清理） |
| `classify.prior_ttl_hours` | int | `72` | 历史先验保留期（1-720；人工覆写永不过期） |
| `classify.repeat_window_seconds` | int | `900` | `repeat_count` 统计窗口（0-604800）；**不影响判不判/发不发** |
| `classify.new_pattern_escalate` | bool | `false` | 新指纹升一级（LOW/MEDIUM 才升） |
| `classify.route_map` | dict | `{}` | 等级→路由覆写；CRITICAL→store 被强制拒绝 |
| **④ 通知预算 / 聚合 / 静默（`budget`）** | | | |
| `budget.dedupe_window_seconds` | int | `900` | 同指纹通知冷却（只决定发不发，判定照做） |
| `budget.digest_interval_seconds` / `digest_max_items` | int | `1800` / `50` | LOW 摘要聚合间隔与单桶条数 |
| `budget.max_alerts_per_round/minute/hour/day` | int | `5` / `12` / `80` / `300` | 通知预算（不取消判定） |
| `budget.burst_window_seconds` / `burst_threshold` / `burst_min_severity` | int/int/str | `60` / `8` / `"MEDIUM"` | 突发合并 |
| `budget.silence_ranges` / `silence_min_severity` | list/str | `[]` / `"HIGH"` | 静默时段与穿透等级 |
| **⑤ 投递与通道能力（`delivery`）** | | | |
| `delivery.max_attempts` | int | `4` | 单条最多重试次数（失败进队列，绝不静默丢） |
| `delivery.base_delay_seconds` | int | `5` | 指数退避基数 |
| `delivery.retry_batch` | int | `5` | 每轮最多重发多少条 |
| `delivery.channel_overrides` | dict | `{}` | 按通道覆盖能力（weixin 的 file/forward 仍被代码硬禁） |
| **⑥ 告警报告（`report`）** | | | |
| `report.enabled` | bool | `true` | 主出口发「诊断首段 + 原始日志文件」；关闭 = 旧内联摘录 |
| `report.min_severity` | string | `"MEDIUM"` | 低于它不生成报告文件（LOW 走摘要） |
| `report.raw_mode` | string | `"excerpt"` | excerpt = 本轮命中段；file = 整份日志（体积/隐私面更大，仅排障临时开） |
| `report.max_file_bytes` | int | `524288` | 单文件硬上限（4096-16777216）；超限保留头尾并写明丢弃字节数 |
| `report.keep_days` | int | `7` | 报告保留天数（1-3650） |
| `report.max_files` | int | `200` | 报告文件数上限（与天数取更严者） |
| `report.head_max_chars` | int | `1200` | 首段硬上限（300-4000，与通道单条上限取小）；超长压缩诊断、绝不切段 |
| **⑦ 状态 / 磁盘 / 留存（`state`）** | | | |
| `state.db_path` | string | `""` | 空 = `<plugin_data>/log_watcher.sqlite3` |
| `state.fingerprint_ttl_hours` | int | `72` | **只**清理通知去重状态；判定先验看 `classify.prior_ttl_hours` |
| `state.history_retention_days` / `history_max_rows` | int | `30` / `20000` | `alerts` 保留天数/行数 |
| `state.outbox_max_bytes` / `keep_excerpt_files` / `outbox_max_age_hours` | int | `33554432` / `50` / `24` | 临时摘录目录上限（取更严者） |
| `state.excerpt_mode` | string | `"ledger_only"` | ledger_only 单文件台账 / file 每轮一个 / off 不留 |
| `state.disk_report_interval_hours` | int | `24` | 磁盘占用报告间隔 |
| **⑧ 自身识别 / 自反馈（`self_guard`）** | | | |
| `self_guard.log_names` | list | `["log_watcher"]` | 自身日志 tag，命中不计入告警（防自触发） |
| `self_guard.feedback_ids` | list | `[]` | 屏蔽「适配器把自己的发送失败记成别人的 WARN」回声 |

> **已删除**：`remediation` 组 22 键（v2.3.0 整组移除）。旧配置文件里残留的这些键在迁移时由
> `tools/migrate_config_v3.py` **明示删除**（dropped）；若跳过迁移直接换版，核心会把它们当 stale 键删掉。
> 曾经的红线键（`remediation.enable` / `workdir` / `permission_mode` / `patch_overlay`）**已不存在**，
> 不要再按旧文档去配。

### 3.2 推荐起步配置（照抄即可）

```jsonc
{
  "notify": {
    "target_sessions": ["<你的主出口 UMO>", "<备用出口 UMO>"],  // 第 1 个是主出口
    "send_mode": "auto",
    "min_severity": "MEDIUM"
  },
  "scan": {
    "levels": ["ERROR", "CRITICAL"]         // 别加 WARNING（每天上千条噪声）
  },
  "classify": {
    "enable": true,
    "provider_id": "<有就填>",               // 留空 = 每条显式降级，不写库
    "noise_shortcut": false                 // 保持「每条必过模型」
  },
  "report": {
    "enabled": true,
    "raw_mode": "excerpt"                   // 不要长期开 file
  }
}
```

> 其余键不用写：`AstrBotConfig` 会按 schema 补默认值（新增键由插件下次加载时自动写入）。

### 3.3 三个「改之前先想清楚」的键

| 键 | 为什么 |
|---|---|
| `classify.noise_shortcut` | 打开后良性噪声零 token，但结论标 `judged=false` —— 偏离运营方「每条错误都走一遍 LLM」的硬要求；只作为成本逃生阀 |
| `report.raw_mode` | `file` 会把整份日志装进报告（含他人会话串；超大文件只取末尾）。默认 `excerpt`，仅排障时临时开 |
| `scan.exclude_keywords` | 出站告警文本与报告文件**都不做凭据掩码**（§10.4），日志里含密钥的行只能靠它挡 |

---

## 4. 日常运维

### 4.1 看什么日志

```bash
LOG=/root/AstrBot/data/logs/astrbot.log
grep -a "\[log_watcher\]" $LOG | tail -50                    # 插件全部输出
grep -aE "本轮判定汇总|判定降级|待判队列" $LOG | tail -30          # 判定链（main 的审计行）
grep -aE "投递提示|投递失败|重试|耗尽|报告文件未送达|附件部分失败" $LOG | tail -30  # 投递与重试
grep -aE "报告|outbox/reports" $LOG | tail -20                # 报告文件
```

关键短语：`日志监听启动`（重载成功）、`本轮判定汇总：段 N，判定路径 M（模型调用 K）…`、
`判定降级：…`、`命中 N 条日志`、`投递失败已入重试队列`、`重试耗尽，标记放弃`、
`报告文件未送达（首段文本已发）`、`附件部分失败 N 条`、`写告警报告失败`、
`报告超上限已截断`、`已把 N 个数据文件/目录权限收窄到 0600/0700`。

> engine.py 用的是标准库 logger，`LLM 预算用尽（round/hour）…` 这类细节可能**不进**
> AstrBot 的日志文件；以 main 的 `本轮判定汇总` 计数（含「待判队列 N」）为准。

### 4.2 状态库随手查

```bash
cd /root/AstrBot/data/plugin_data/log_watcher
sqlite3 log_watcher.sqlite3 "PRAGMA user_version;"     # 4
sqlite3 log_watcher.sqlite3 ".tables"                   # alerts file_progress meta pattern_kb pending_delivery rate_windows remediation_runs
sqlite3 log_watcher.sqlite3 "select count(*), max(ts) from alerts;"
sqlite3 log_watcher.sqlite3 "select judged, judge_source, count(*) from alerts group by 1,2;"
sqlite3 log_watcher.sqlite3 "select fingerprint,severity,decision,route,report_path from alerts order by rowid desc limit 10;"
sqlite3 log_watcher.sqlite3 "select run_id,status,exit_code,started_at from remediation_runs order by rowid desc limit 5;"
```

- `alerts.judged`：`1` = 过模型；`0` = 没过模型但来源已知（local/manual/degraded）；
  `-1` = 未知（升级前的历史行，**不回填**）。`alerts.judge_source`：`llm|degraded|local|manual`，`''` = 未知。
- `report_path` 指向留存件（`outbox/reports/*.log`）；`excerpt_path` 仍是临时摘录（可能已被回收）。
- `remediation_runs` 只读（v2.3.0 不再写入）；启动时 `reconcile_runs()` 把遗留 `running` 对账成 `aborted`。
- `rate_windows` 是**历史 scopes 只读表**（v2.3.0 起运行期不再产生新行；`store.push_rates` 仅作
  历史/测试保留，main 已不再调用）——别把「表里有旧行」当成限流仍在生效。

没有 `sqlite3` CLI 时用 `$PY -c "import sqlite3;print(sqlite3.connect('log_watcher.sqlite3').execute('pragma user_version').fetchone())"`。

### 4.3 磁盘与清理（谁在清什么）

| 目录 / 文件 | 内容 | 清理者 | 上限键 |
|---|---|---|---|
| `outbox/` | 临时摘录台账（成功即删） | `DiskGovernor.prune`（磁盘巡检，`state.disk_report_interval_hours` ≥1h 一次） | `state.outbox_max_bytes` + `keep_excerpt_files` + `outbox_max_age_hours`（取更严） |
| `outbox/reports/` | **告警报告**（留存件，成功不删） | `ReportStore.prune`（每次写报告 + 磁盘巡检） | `report.keep_days` / `report.max_files` /（单文件 `max_file_bytes` 截断） |
| `failed/` | 发送失败的摘录（人工取证） | `DiskGovernor.prune`（同上） | 同上 |
| `remediation/` | **历史修复轨迹**（v2.3.0 冻结只读） | **插件不再清理**；人工跑离线 CLI | `tools/prune_legacy_artifacts.py --keep/--max-age-days/--max-bytes` |
| `log_watcher.sqlite3` | 状态库（WAL，schema v4） | `SqliteStore.prune()`（每轮） | `state.history_retention_days` / `history_max_rows` / `classify.prior_ttl_hours` / `classify.kb_max_entries` |

```bash
ls -l /root/AstrBot/data/plugin_data/log_watcher/outbox/reports | tail
du -sh /root/AstrBot/data/plugin_data/log_watcher/outbox/reports
# 历史轨迹只读统计（不删）与干跑：
python3 /root/AstrBot/data/plugins/log_watcher/tools/prune_legacy_artifacts.py \
  --dir /root/AstrBot/data/plugin_data/log_watcher/remediation \
  --db /root/AstrBot/data/plugin_data/log_watcher/log_watcher.sqlite3
```

报告文件是**留存件**：`outbox/` 的「成功即删」只作用于临时摘录，不会删 `outbox/reports/*.log`。

### 4.4 手动重跑一轮（不重启）

插件没有管理命令（§10.5）。想立刻看一轮结果，最小动作是**重载插件**，或调小
`scan.poll_interval_seconds`（下限 5）后重载：

```bash
sleep 35; grep -a "\[log_watcher\]" /root/AstrBot/data/logs/astrbot.log | tail -8
```

---

## 5. 判定语义（v2.3.0）

### 5.1 每条错误都过模型；知识库只作先验

- 本地规则先算一个**锚点**（等级/tags/reason），它只进提示词（`本地规则初判…仅供参考，可推翻`）。
- `pattern_kb` 命中时把历史结论作为「历史判定（先验，仅供参考，可推翻）」注入提示词；
  **不再 return 旧结论**。模型必须基于本次片段重新下结论；`prior-confirmed` / `prior-overturned`
  标签证明模型读没读先验。
- **唯一豁免**是人工覆写（`source=manual`）：`judged=false`、`judge_source=manual`、
  `manual-override` 标签、首段写「人工覆写（非模型判定）」；人工条目永不被自动结果覆盖、永不过期。
- 同一轮内同指纹只判一次（同一次观察；复用结论但重建证据）；`begin_round()` 清空备忘录 ⇒
  **跨轮必重判**。没有 TTL 复用开关。
- 通知去重（`budget.dedupe_window_seconds`）只决定「发不发」；`repeat_count` 的统计窗口是
  `classify.repeat_window_seconds`。同一指纹连打三轮：判定 3 次、台账 3 行、通知 1 条。

### 5.2 降级形态（报告首段据此写「未取得模型诊断」）

所有降级结论同时满足：`source=degraded`、`judged=false`、`judge_source=degraded`；
等级 `max(本地, fallback_severity)` 且地板 ≥ MEDIUM；**一律不写知识库**。标签是
「裸标签 + `degraded:*` 别名」：

| 标签 | 触发 | 备注 |
|---|---|---|
| `llm-timeout` / `degraded:llm-timeout` | 模型调用超时 | 不写库 |
| `llm-error` / `degraded:llm-error` | provider 抛异常 | 不写库 |
| `llm-invalid-output` / `degraded:llm-invalid-output` | 输出非 JSON / 等级非法 / 解析异常 | 不写库 |
| `guard-error` / `degraded:guard-error` | 安全闸自身异常 | 不写库 |
| `llm-budget` / `degraded:llm-budget`（+ `llm-budget:round\|hour`、`judged-deferred`） | 轮/小时预算用尽 | **排队**到下一轮优先判；不写库 |
| `llm-unconfigured` / `degraded:llm-unconfigured` | 需要 LLM 但未配 provider/context | 不写库、不排队（配好下一轮自然重判） |
| `engine-unavailable` / `degraded:engine-unavailable` | 引擎构造失败/异常/返回非 ThreatVerdict（main 兜底） | 首次记 ERROR |
| `engine-error` / `degraded:engine-error`（+ `classify-error`） | 判定层顶层意外异常 | 不写库 |

**预算耗尽**的 reason 模板：
`LLM 判定不可用（LLM 预算用尽（round|hour），本块已排队到下一轮优先判定（预算只延迟判定，不取消判定）），保守降级为 <SEV>（降级地板 <FLOOR>，本地信号 <tags>）；指纹 <fp12>；本次未经模型判定`
**未配 provider** 的 reason 模板：
`LLM 判定不可用（模式 auto|llm 需要 LLM，但未配置 provider_id|没有可用的 Context），保守降级为 <SEV>（降级地板 <FLOOR>，本地信号 <tags>）；指纹 <fp12>；本次未经模型判定`

排障时按 `alerts.judged` / `alerts.judge_source` 统计，不要靠 tags 里混写的 `llm` / `local:*` 反推。

### 5.3 判定与通知是两个旋钮

| 想控制 | 改哪个 | 不要改 |
|---|---|---|
| 判定频率/成本 | `classify.max_calls_per_round` / `max_calls_per_hour`（只延迟、不取消） | 不要用 `budget.dedupe_window_seconds` 省钱 |
| 通知冷却 | `budget.dedupe_window_seconds` | 它不影响判定 |
| 重复计数上下文 | `classify.repeat_window_seconds` | 它不影响判定/通知 |
| 历史先验保留 | `classify.prior_ttl_hours` | `state.fingerprint_ttl_hours` 只管去重状态 |

---

## 6. 告警形态与报告文件

### 6.1 首段契约（测试逐段钉住）

`【AstrBot 日志告警｜SEV】` + 命中条数/等级 + 时间 + 来源 + `组件 ｜ 指纹（第 N 次）`
→ 诊断段（首行三选一）→ `可能原因` / `是否建议修复` / `修复建议`（静态表）
→ 人工处置清单（静态代码常量：CRITICAL / HIGH 各 3 条，MEDIUM 1 条；IGNORE/LOW 无）
→ `—— 原始日志 ——`（附件：文件名 + 体积 + 口径 + 保留天数 + **本机留存路径**；
  无附件：`完整日志见 <本机路径>`）。

- 诊断首行：模型判定 = `—— 诊断（模型判定｜置信度 0.xx）——`；
  降级/本地 = `本地规则判定，未取得模型诊断（degraded:*）`；人工覆写 = `人工覆写（非模型判定）`。
- 修复建议来自 `deliver.advice_text()` 的**静态清单**，不允许模型生成（防幻觉）；模型只写诊断理由。

### 6.2 报告文件

- 路径：`<plugin_data>/outbox/reports/alert-<YYYYmmdd-HHMMSS>-<SEV>-<fp8>.log`（0600 / 目录 0700）。
- 内容口径（首行也写）：默认「本轮命中段（含前后文、逐字，无 `>>`、无字符截断）」；
  `report.raw_mode=file` 才装整份日志。超 `report.max_file_bytes` 保留头尾并写明丢弃字节数。
- 保留：`report.keep_days`（默认 7）与 `report.max_files`（默认 200）取更严者；清理在
  **每次写报告**与**磁盘巡检**（`state.disk_report_interval_hours`，≥1h 一次）时执行；
  与 `outbox/` 的「成功即删」互不影响。
- 文件名只含时间/等级/指纹 8 位（不含会话串）；**同秒同等级同指纹会得 `-2` 后缀**，取证按 mtime 排序。

### 6.3 投递与失败

- 出口顺序 = `notify.target_sessions` 列表顺序；第 1 个是**主出口**。
- **非主出口不发文件**（代码不变式 `deliver.attachment_allowed(session, outlets, caps)`：
  只有 `outlets[0]` 且通道支持文件才为真）：备用出口只发文本 + 本机路径；weixin_oc 代码级禁用附件。
- 超长：先压缩诊断（400 → 240 → 120 → 40 → 0 字）再硬截，**绝不切成多段**；
  `split_with_markers` 只用于「报告关闭/低等级」的旧内联路径。
- 附件失败：`file_ok=False` / `partial=True`、`delivery_partial` 计数、日志一行 WARNING，
  **不整条重试**（文本已送达）；重试队列带 `attachments`，**重试会再发一次附件**（降级文案会写明）。
- 写报告失败：WARNING + 回落文本（给本机路径），绝不静默；不会产生空附件。

---

## 7. 常见故障与处置

| 现象 | 先查 | 处置 |
|---|---|---|
| 启动行「状态 只读（状态库拒绝写入）」 | `sqlite3 … "PRAGMA user_version;"` 是否 > 4 | 只回滚了代码：按 §8.4 成对回滚（还原备份库/配置） |
| 启动行没有「报告 …」字段 | 版本是否仍 2.2.0 | 重载的是旧代码；按 §1.3 换版 |
| 日志里 `Config key removed` 含本插件键 | 是否跳过配置迁移 | 从 `bak-pre-v2.3.0-*` 重建（§1.3） |
| 每次都 `判定降级：…degraded:llm-unconfigured` | `classify.provider_id` / provider 可用性 | 填 provider；这是显式降级，不是静默本地判定 |
| 预算一直排队（`待判队列 N` 增长） | `classify.max_calls_per_round/hour` 与日志风暴 | 适度调大预算，或先收敛噪声源；**不要**把预算改成 0 当默认 |
| 主出口没有附件、只有路径 | 该出口是否主出口 / 通道 `caps.file` | 这是预期：非主出口不发文件；weixin 永不发文件 |
| `报告文件未送达` / `附件部分失败` / `delivery_partial` 增长 | NapCat/OneBot 的文件能力 | 见 §10.1；先让私聊做主出口 |
| 报告文件没生成 | `report.min_severity` / `report.enabled` / 写盘失败 | 看 `写告警报告失败` WARNING；确认目录权限 |
| 长日志又被切段 | 是否关掉了 `report.enabled` | 报告关闭会回到旧内联路径（会分片）；恢复报告 |
| 收不到任何告警 | `target_sessions` 为空 / 通道 / `budget` 静默 | 看「会话 0 条」与 `suppressed_*` 计数 |

---

## 8. 回滚

### 8.1 回滚前：先把现在这一版备份下来（必做）

```bash
STAMP=$(date +%Y%m%d%H%M%S)
BK=/root/backups/logwatch-v2.3.0-$STAMP
mkdir -p $BK
cp -a /root/AstrBot/data/plugins/log_watcher $BK/plugin
cp -a /root/AstrBot/data/config/log_watcher_config.json $BK/config.json
# 状态库必须连 WAL/SHM 一起（否则状态不完整）：
cp -a /root/AstrBot/data/plugin_data/log_watcher/log_watcher.sqlite3* $BK/
ls -l $BK
```

### 8.2 v2.3.0 ⇄ v2.2.0（回滚锚点 `591469a`）

**回滚是成对的：配置 + 状态库 + 代码三者一起。只回代码会读错 schema。**

1. 停用/重载前先备份（§8.1）。
2. 还原配置：`cp <备份>/log_watcher_config.json …`（v2.2.0 的 8 组 / 82 键；**不要**把 v2.3.0 的
   69 键配置直接喂给 v2.2.0 —— `report.*` 与两个 classify 新键会被当 stale 键删掉）。
3. 还原状态库：把升级前备份的 `log_watcher.sqlite3`（含 `-wal`/`-shm`）放回；
   **必须**让 `user_version` 回到 2。为什么：v2.2.0 的 `SqliteStore` 看到 `user_version=4`
   （> 它支持的 2）会进入**只读保护**：告警仍判仍发，但进度/计数/KB/待发/台账**全部拒绝写入**。
4. 换回 v2.2.0 代码（`git checkout 591469a` 或从备份目录覆盖；排除 `.git`/`__pycache__`），
   重载插件，按 §1.2 验收（启动行版本 2.2.0，状态 SQLite，无只读提示）。
5. 若坚持保留 v2.3.0 期间产生的状态数据、只回代码：可在停服后手工
   `PRAGMA user_version = 2`（新增列保留，v2.2.0 的显式列写入仍能工作），但这会**丢掉**
   `judged/judge_source/report_path/attachments` 的语义且无法自动恢复 —— 只在明确知情时使用。
6. 配置结构与代码必须同时回：**先还原配置、再换代码**；顺序反了核心会先清掉 v2.3.0 的新键。

### 8.3 验证回滚

- 启动行：版本 2.2.0、`状态 SQLite`（无「只读」）、分级/知识库字段正常；
- `sqlite3 … "PRAGMA user_version;"` = 2；
- 写入面恢复：下一轮 `alerts` 有新行、`pending_delivery` 可入队；
- 告警仍只发文本（v2.2.0 没有报告文件形态），这是预期。

### 8.4 只回滚代码会怎样（必须知道）

| 组合 | 结果 |
|---|---|
| v2.3.0 代码 + 旧库（`user_version` = 2 或 3） | 自动迁移到 v4（补列、默认空），正常 |
| v2.2.0 代码 + v2.3.0 库（user_version=4） | **只读保护**：告警照发，台账/计数/进度/KB/待发全部不落库 |
| 只回配置不回代码 | 核心删掉 `report.*` 与新 classify 键（值回落默认） |
| 只回代码不回配置 | 同上，且旧代码不认识 `report` 组 |

---

## 9. 独立复验清单（v2.3.0）

```bash
cd /root/workspace/projects/AstrBot-log_watcher
PYTHONDONTWRITEBYTECODE=1 /root/AstrBot/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider
# 期望：308 passed / 0 failed

python3 - <<'PY'
import json
d=json.load(open('_conf_schema.json',encoding='utf-8'))
print(list(d), sum(len(v['items']) for v in d.values()))   # 8 组 / 69
PY

grep -n 'SCHEMA_VERSION = ' store.py        # 4
grep -n 'noise_shortcut' _conf_schema.json  # default: false
python3 tools/migrate_config_v3.py --dry-run --config /tmp/logwatch-v22-fixture.json | head -30
# 期望：列出 22 个 remediation 键 + 9 个补默认值键
# 能力面（收紧正则）：必须 0
grep -rnE 'remediate\(|remediation\.|RemediationGate' --include='*.py' \
  main.py engine.py deliver.py models.py classify.py | wc -l          # 期望 0
# 宽口径：允许且仅允许以下 2 行历史字面残留（逐行点名；多一行即失败）
grep -rn 'remediat\|Remediation' --include='*.py' main.py engine.py deliver.py models.py classify.py
#   期望：models.py 的 Route.REMEDIATE 枚举值（历史 alerts.route / route_map 解析）
#         classify.py 的 1 行历史注释
# 其它允许的字面：store.py 的 remediation_runs 表名（只读保留）、tools/prune_legacy_artifacts.py（离线 CLI）
```

> 探针纪律（合成日志）：往被监听目录**先建空文件再追加**一行合成 `ERROR`（首次见到的文件会
> `skip_existing`），且探针行**不能含插件自己的名字**（自回声过滤会挡掉）。

---

## 10. 已登记未闭合项与已知边界（诚实登记，不粉饰）

### 10.1 aiocqhttp「非主出口不发文件」与群文件上传未实测

代码里的不变式是 **`deliver.attachment_allowed(session, outlets, caps)`**（`main.py` 调用；
只有 `outlets[0]` 且 `caps.file` 为真才返回 True），**没有**「群出口」这个判断。含义：

- 运营方把**私聊**设为第 1 个会话（主出口）时：主出口发「文本 + `.log`」，其余出口（含群）只发文本；
- 若运营方把**群**设为第 1 个（主出口）且通道 `caps.file=True`（如 aiocqhttp/NapCat），
  代码**会尝试**发 `File` 段；而 NapCat/OneBot 的群文件通常需要 `upload_group_file`，
  **本插件从未实测过群文件上传**。失败时：文件静默不发（或平台报错）；
  首段仍显示附件名，但 **v2.3.0 起也会写「本机留存：<path>」**，可按路径去本机取
  （F5 的兜底；仍建议在实测通过前把私聊设为第 1 个会话）。
- 缓解：在实测通过前，**把私聊设为第 1 个会话**；或把 `report.enabled=false` 强制只发文本；
  观察日志 `附件部分失败` / `delivery_partial` 计数。

### 10.2 `report.raw_mode=file` 的隐私面与截断

`file` 口径会把**整份日志**装进报告文件（含其他会话的 UMO 等标识），且文件超过
`max_file_bytes` 时**只取末尾**并在正文写明丢弃字节数。默认 `excerpt`；只在排障时临时开，
用完改回。**注意默认 `excerpt` 也会把命中段逐字保留 `keep_days` 天**（默认 7）：
敏感部署可 `report.enabled=false`（回到「成功即删」的旧内联路径）或调小 `keep_days`。
出站文本与报告文件都**不做凭据掩码**（§10.4）。

### 10.3 报告文件命名与同秒后缀

文件名只含 `alert-<时间>-<等级>-<指纹8>.log`；同秒同等级同指纹得 `-2` / `-3` 后缀。
按名字取"最新"不可靠，取证请按 mtime 排序（`ls -lt outbox/reports`）。

### 10.4 出站告警文本不做凭据掩码（F18，沿用）

要把原始日志发出去才能定位问题，属功能固有取舍；担心日志里有密钥请用 `scan.exclude_keywords`
过滤。历史修复轨迹侧曾做掩码（`<masked>`），v2.3.0 轨迹只读冻结，不再产生新轨迹。

### 10.5 `/lw` 管理命令：**未实现**

`/lw status`、`/lw ack`、`/lw silence` 等**本版本未实现**：插件不注册任何命令处理器
（保持零事件入口），也没有管理白名单键（`admin_users` 已于 v2.2.0 删除）。

### 10.6 历史修复轨迹与台账：冻结、只读、离线清理

- `remediation_runs` 表/索引/列**全留**，v2.3.0 不再写入；启动对账把遗留 `running → aborted`。
- 磁盘 `remediation/` 目录冻结：插件不再读写；清理走 `tools/prune_legacy_artifacts.py`
  （默认干跑、`--apply` 才删、`--db` 只读统计、**永不删行**）。
- 旧 `Route.REMEDIATE` 枚举值保留，只为解析历史 `alerts.route` 与用户 `route_map`；
  新判定不会产出该值。

### 10.7 其它已知边界

- 片段要等「后面不可能再有命中与它重叠」才发出（`context_after + context_before` 行），
  日志持续输出时延迟约等于这个行数；文件停更时下一轮收尾并注明「后文未凑齐」。
- 收发都依赖通道本身可用：通道挂掉时告警进重试队列并留失败残留（不会静默丢）。
- QQ/微信文本没有等宽字体与加粗；命中行不再塞进首段，原始行都在报告文件里。
- 状态库不可用时走内存态：告警照发，但台账/计数/进度不落库（见启动行「状态」字段）。

---

## 11. 本轮干跑与 provenance

- 本轮（v2.3.0 整合）**未部署生产、未改 `/root/AstrBot`**：所有验证都在库目录与 `/tmp`
  （配置 fixture 为合成假值，不含任何生产值）。
- 迁移工具干跑/落盘/幂等/复核/重建都在 `/tmp` 副本上实测；生产配置**没有**被任何模式写过。
- 报告文件与附件路径均为 `<plugin_data>/outbox/reports/`；本轮未在插件目录留下产物。

---

## 12. 逐文件交付清单（v2.3.0）

| 文件 | 作用 |
|---|---|
| `main.py` | 入口 + 唯一发送者（扫描→判定→闸门→报告→投递→落库） |
| `engine.py` | 判定编排：先验注入、批内复用、预算排队、降级、审计 stats |
| `classify.py` | 本地规则锚点、提示词/先验、输出解析、安全闸、降级标签族 |
| `deliver.py` | 通道能力、诊断首段/报告段、处置清单、分片兜底、重试退避 |
| `detect.py` | 检测、指纹、通知闸门（只影响发不发） |
| `store.py` | SQLite schema v4、报告文件 `ReportStore`、保留清理、磁盘治理 |
| `models.py` | `ThreatVerdict(judged/judge_source)`、`SendPlan.attachments`、`DeliveryOutcome.partial` |
| `config_map.py` | 键名映射（KEY_MAP 60 + EXTRA_LEAVES 9）、`ConfigView` |
| `_conf_schema.json` | 8 组 / 69 键（含 report 组） |
| `tools/migrate_config_v2.py` | v2.1.0 扁平 → v2.2.0 分组（保留） |
| `tools/migrate_config_v3.py` | v2.2.0 → v2.3.0（本版新增；删 22 / 补 9） |
| `tools/prune_legacy_artifacts.py` | 历史修复轨迹离线清理（默认干跑） |
| `tests/` | 308 passed；缓存语义按新契约改写、报告/迁移/降级/门控守卫 |
| `metadata.yaml` | 版本 2.3.0、能力描述（无自动修复） |

### 12.1 复验一句话

```bash
cd /root/workspace/projects/AstrBot-log_watcher && \
PYTHONDONTWRITEBYTECODE=1 /root/AstrBot/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider
# 308 passed
```
