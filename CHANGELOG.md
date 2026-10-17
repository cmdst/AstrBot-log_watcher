# Changelog

## Unreleased

### 修复（2026-10-18 · 二）

- **⚠️ 两个等级旋钮在生产链路上被静默丢弃**（`main.py` 白名单 ＋ `detect.py` 兜底 ＋ 回归）：
  2026-10-17 加的 `unmatched_severity` / `transient_severity` 只写进了 `_conf_schema.json` 与
  `classify.py`，**漏进 `main._engine_config()`** —— 那是显式白名单（R4 的设计）⇒ `ThreatEngine`
  拿到的 cfg 里没有这两个键，`classify_block` 只能吃代码默认值。后果两条，都很硬：
  ① 运营方设 `transient_severity=LOW` **不生效**（生产噪声的下降其实只来自默认值）；
  ② 派单承诺的「`unmatched_severity=MEDIUM` 一步回滚」**失效**。
  同时 `detect.fallback_verdict` 调 `classify_block(block)` 时也没传 cfg（降级路径同样被吞）。
  **取证**：同一块日志喂 `ThreatEngine` —— 白名单形状的 cfg → `MEDIUM/notify`（回滚生效）；
  漏传形状 → `LOW/digest`（设置被吞）。回归 `test_engine_config_forwards_the_severity_knobs`
  （main 顶部 import astrbot、库内没有夹具，只能钉「源码事实」，端到端判据仍靠真跑）。
- **`remediation_runs.receipt_sent` 不再恒 0**（`main.py` ＋ `store.py` ＋ `remediate.py` ＋ `deliver.py`）：
  回执**真的**投递成功后才补写那一列 —— `deliver.all_delivered` 是判定规则（每个目标都 ok、且非空）、
  `store.remediation_mark_receipt_sent` 只动单列且幂等、`RemediationRun.run_id` 让 main 知道写哪一行。
  失败/重试不补记；闸门拦下的终态回执没有 run 行，因此无字段可置 —— 三条都写进 runbook §6.1。
  来源：fix 派单 `20261018-dispatch-dev-receipt-sent.md`。
- **`remediation_timeout_seconds` 默认 300 → 900**（`remediate.py` ＋ schema ＋ runbook §5.5）：
  实测同一个真实任务直接跑 **284.32 s**、走插件 runner **308.0 s**（ok，9 步 / 39 次工具调用）
  ⇒ 300 是「约一半概率死在收尾前」。同时记下「超时的轨迹只有元数据行、看着像卡死」的假象
  （`wait_for` 取消 `communicate()` 时缓冲区不返回）与唯一可信判据（同 argv/env 手工跑计时）。
- 评审跟进（两轴 code-review `main...0f5912f`）：参数化拒绝样本里的元字符用例改回**正确顺序**
  （否则它会被顺序规则一起拒掉，元字符检查退化了这条样本也报不出来）；补一条把
  「`--patch` 有、`--json` 无 ⇒ 不得抛异常」钉死的用例 —— 评审报的 `ValueError`「硬缺陷」
  实测不成立（短路卫兵 `"--json" in argv` 在），但要防止以后有人把它「修」成抛异常。

### 修复（2026-10-18）

- **`build_argv` 的 launcher/app 选项顺序**（`remediate.py`）：改为
  `dsh --profile <p> [--patch <ov>] --json -- -` —— `--patch` / `--dump-config` 这类是 **launcher 选项**，
  `--json` 是 **app 选项**，launcher 段必须排在 app 段之前。原顺序（`--json` 在前）在现版 dsh
  （`0.2.0-rc.2`）上被直接拒：`{"type":"error","message":"unknown option '--patch'"}`（exit 1）；
  交换后通过解析并读到 overlay。**取证**：2026-10-17 由 fix lane 在一次性 `DSH_HOME` 沙箱测出，
  dev 在同类沙箱独立复核（两条命令都真跑过，真实 profile 未改）。
  **为什么现在才发现**：profile 的 `cordis.patch.yml` 破损在 argv 解析之前先炸，这条被挡在后面 ——
  **两个独立缺陷叠加**（YAML 先、argv 后），修好 YAML 会立刻撞上这条。
- `validate_argv` 新增顺序断言（`--patch` 若出现必须排在 `--json` 之前），并把它钉成回归用例
  `tests/test_remediate.py::test_build_argv_puts_launcher_flags_before_app_flags`；
  参数化拒绝用例里补了一条「路径干净但顺序反了」的样本。
- `runbook.md` §5.1 / §5.3 两处 smoke 命令同步改正（照抄旧写法会拿到 `unknown option '--patch'`）。
  `CONTRACT_ARGV`（**无 overlay** 的形态 `[… --json -- -]`）**不变**，它本来就对。

### 变更（策略 · 2026-10-17）

- **「一行不被任何规则认识的 ERROR」不再等于一条微信**（`classify.py`）：本地模式下
  `unmatched_error` 的落点从硬编码 `MEDIUM` 改为可配的 `unmatched_severity`，**默认 `LOW`**
  （进摘要台账，不再即时推送）；「噪声规则只解释了一部分命中行」时的抬升（原
  `severity_max(…, MEDIUM)`）同步改抬到 `unmatched_severity`，否则这里留一条刷屏缝。
  **取证**：重放 2026-10-16 全天 = 98 片段 → 95 条 `notify`，其中 **95 条没有任何硬失败信号**；
  生产台账（10-14~10-17）共 85 条推送，命中硬失败规则的 **0 条**；最小复现 = 一行 ERROR + 零上下文。
  改动后同一天重放 = 56 条 notify。**可逆**：`unmatched_severity = "MEDIUM"` 一步回到旧行为（重放 95 条）。
- **新增两个等级旋钮**（`classify.py` 本地判定 + `_conf_schema.json`）：`unmatched_severity`
  （默认 `LOW`）、`transient_severity`（默认 `MEDIUM`）。为什么 `transient_severity` **默认不动**：
  验收用例 `TRANS-01-provider-retry` 的 notes 明写「压成 LOW = 漏报」，默认值属于契约，不得由实现侧下调；
  运营方要在自己通道上把 provider 抖动从「即时推送」改到「摘要」，改配置即可（实测：`transient_severity="LOW"`
  → 同日 notify 0 条、摘要 18 条；再把 `digest_interval_seconds` 调到 6 h → 合计 5 条/天）。
- 回归测试五处（`tests/test_classify.py`）：`test_unmatched_error_line_is_not_ignored`（改为 LOW+DIGEST，
  仍断言带标签与证据）、`test_unmatched_severity_is_reversible_and_typo_safe`、
  `test_noise_line_with_unmatched_error_goes_to_digest`、`test_transient_retry_keeps_contract_baseline`
  （守住 TRANS-01 基线）、`test_transient_severity_tunable_to_digest`。
- **已知未闭合**：LLM 判定不可用时的降级地板仍是 `max(本地判定, fallback_severity)`，默认 `MEDIUM`
  （由 `test_degraded_verdict_is_conservative_even_if_config_says_ignore` 钉住）⇒ provider 挂掉的那段时间，
  噪声会沿降级路径回来（台账里带 `llm-unconfigured`/`llm-timeout`/`degraded` 标签的推送占少数）。

### 新增

- **本地噪声规则 `agent-tool-path-miss`**（`classify.py`）：`computer_tools.*` 的
  `No such file or directory`（agent 把工作区文件猜成绝对路径导致的 ENOENT）归入良性噪声族 ——
  判定 `LOW` / 路由 `digest` / **整族零 LLM 调用**（`noise_shortcut`），不再按降级地板被抬成
  `MEDIUM` 并即时推送。取证：同一形态在 `astrbot.log` 10393 行（10-13 09:00）与 27153 行
  （10-14 21:00）各出现一次，两条修复前都是 `MEDIUM` + `notify`（即投进微信）
- 回归测试两处：`tests/test_classify.py::test_agent_tool_path_miss_stays_quiet`（LOW+DIGEST+噪声闸）、
  `tests/test_engine.py::test_agent_tool_path_miss_needs_zero_llm_calls`（`call_count == 0`），
  样例已进 `BENIGN_NOISE_SAMPLES` 参与既有参数化门禁

### 修复

- **判定降级现在有文件级留痕**（`main.py`）：`verdict.source == "degraded"` 时补一条
  `判定降级：<reason>` 的 WARN。此前 `engine.py` 用的是 stdlib logger
  （`logging.getLogger("log_watcher.engine")`，见 `engine.py:67`），整层日志既不在 `astrbot.log`
  也不在 journald（两边 `[log_watcher.engine]` 命中 0 条），于是 21:00 那次「LLM 判定超时（>20s）」
  对应的 `engine.py:741` WARN 哪儿都搜不到，只剩告警正文那句「调用超过 20s 未返回」
- **脱敏把一条指纹用例改成了必然失败**（`tests/test_classify.py`）：脱敏把 10 位群号替换成
  `<group_id>`，而指纹归一化只抹纯数字（`<NUM>`）—— 同一故障的两种写法因此得出两个指纹
  （`93a38500941f4924` vs `f7319243b2b71a68`，用 `normalize_for_fingerprint` 实测）。按
  `SANITIZE.md` 规定的替换（10 位数字 → `9000000000`）改回纯数字后用例恢复通过。同类写法在
  `tests/classify_cases.json:163` 仍存在（不影响门禁与本用例，**未改动**，已登记在案）

### 测试

`PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q` → **298 passed / 0 failed**
（在目录名为 `log_watcher` 的位置运行；HEAD 基线 `a4eeef4` 为 294 passed / 1 failed，丢的那条正是
上面的脱敏用例）。注：`tests/test_engine.py::test_modules_import_without_astrbot[package]` 依赖
所在目录名必须是 `log_watcher`（它 `import log_watcher.classify`），所以从
`/root/AstrBot-log_watcher` 直接跑会多一条**环境性**失败，不是代码问题。
运行副本（`data/plugins/log_watcher`，自带未脱敏测试集）**295 passed / 0 failed**：同步
`classify.py` / `main.py` 之后仍然全绿。

## 2.0.0 — 2026-10-14

v1 的定位是「按等级转发日志摘录」，v2 重建为**采集 → 分级 → 路由 → 投递 → 修复 → 回执**的闭环。
本轮（t18 集成收口）在 v2 代码之上补齐配置面与文档面，并把回执契约钉死到每一条终态路径。

### 新增

- **AI 威胁分级**：`classify.py` 本地规则（失败/噪声/瞬时三族 + 指纹）+ `engine.py` LLM 判定
  （超时、`LLMOutputError` 降级、每轮/每小时调用预算、指纹知识库、注入围栏）；提示词资产
  `prompts/classify_system.md`（预算 ≤ 2200 字符）
- **按级路由**：`IGNORE` 静默 / `LOW` 摘要聚合 / `MEDIUM` 起即时告警 / `HIGH` 交付修复候选 /
  `CRITICAL` 紧急修复；含去重窗口、分钟/小时/日预算、突发合并、静默时段与穿透等级
- **紧急修复（默认关）**：`remediate.py` 调用 `dsh` headless，固定
  `workspace-write` 权限 + 指定工作区；看门狗超时按**进程组** kill 并回收；轨迹落盘默认
  过凭据掩码（`remediation_trace_raw=true` 才留原文）；子进程不得携带任何
  `sandbox_permissions` 提权键（`FORBIDDEN_ENV_KEYS` 钉死，无头场景无人审批）
- **插件自带路由 overlay**：`dsh-headless-overlay.yml`（与插件同目录，绝对路径解析，不依赖
  cwd），调用时以 `--patch` 叠加在 profile 之上，**不改任何 profile**；删除该文件即完全失效
  （可回滚）。配置 `remediation_patch_overlay` 留空 = 用自带 overlay，填路径 = 手动覆盖
- **每一次修复尝试都回执**：`build_receipt` 固定七段 —— 渠道｜**方案**（profile + overlay 文件名
  + 权限级别 + 工作区）｜判定（严重度 + 指纹 + component + 新/旧指纹）｜诊断结论（根因/证据）｜
  **改动清单**（无改动必须显式写「未改动任何文件」）｜建议动作/人工介入｜轨迹路径；非成功终态
  另外写明「被哪一道闸拦下」与「后续怎么办」。八种状态全部覆盖：`ok` / `skipped` / `blocked` /
  `unavailable` / `timeout` / `failed` / `cancelled` / `rejected`
- **SQLite 状态库（`SCHEMA_VERSION=2`）**：WAL、启动迁移、保留清理（条数/年龄/字节三闸）、
  孤儿 run 对账（启动即把遗留 `running` 标为 `aborted`）、磁盘治理（摘录目录硬字节上限）
- **投递层**：通道能力表（`weixin_oc` 只发 Plain 文本）、按通道分片、失败进重试队列（指数退避，
  绝不静默丢）、降级重发、`pending_delivery` 落库跨重启续投
- **配置面**：`_conf_schema.json` 从 12 键补到 80 个可见键（+ 4 个兼容键 + 1 个未实现占位键），每个键带中文 hint 与
  误配后果；`send_mode` 默认改为 `auto`，旧值 `file/txt/attachment` 映射为文本并记 degradation

### 修复（相对 v1）

- v1 的 `forward`（合并转发）形态在 `weixin_oc` 上不可用：`File` 段会被服务端 `prepare failed`
  拒收、`Node/Nodes` 段被静默丢弃 —— v2 改为按通道能力选段型，只发 Plain 文本；README/CHANGELOG
  里「forward 可用」的说法已删除
- v1 的 txt 附件形态（`file`）在部分协议端需要同机能读到路径，v2 已废弃该默认形态
- 采集进度从 `tail_state.json` 迁到 SQLite（旧文件保留为 `tail_state.json.migrated-<时间戳>`）；
  状态库不可用时回退 JSON 内存态，修复闸强制关闭（fail-closed）

### 测试

`PATH=/root/AstrBot/.venv/bin:$PATH python -m pytest tests -q` → **295 passed**（8 个测试文件，
全部离线：不联网、不 spawn 真 `dsh`、不写插件目录）。

### 已知未闭合（诚实登记，未修）

- **F12** `classify.Rule` 与 `models.Rule` 双定义：消费端全 duck-typing、`isinstance` 零命中，
  当前无活风险；统一需重构规则表并改 58 条断言，留待后续版本
- **F16** `flush_burst` 窗口受轮询节奏影响：需要「假 provider 延时 ≥ 轮询间隔」的复现案例，
  本轮未构造出来，窗口语义未改
- **F18** **出站告警摘录不做凭据掩码**：要把原始日志发出去才能定位，属功能固有取舍；轨迹侧已掩码
  （F10），聊天侧没有 —— 想收窄请用 `exclude_keywords`
- **F19** 提示注入能否把 benign 指纹推进 `emergency`：注入围栏与中性化已做实（F01/F02），
  剩余属 LLM 语义风险，需真实 provider 往返才能定论

### 说明

- 依赖 AstrBot 文件日志（`log_file_enable`）与全局 `log_level`
- 主动消息走 `Context.send_message`，不经过回复装饰链（分段回复、气泡、TTS 不生效），
  也不触发 `after_message_sent`
- `architecture.md §8.7` 的 `/lw status|ack|silence|remediate` 管理命令与 `admin_users` 白名单
  **本版本未实现**：不注册任何命令处理器（零事件入口），schema 里的 `admin_users` 只是前向兼容占位
- 改完代码**不需要重启 AstrBot**，但要触发插件重载（见 `runbook.md §2`）

## 1.0.0 — 2026-10-12

### 新增

- **日志扫描**：定期扫描 AstrBot 日志目录（目录、文件名 glob 可配），按精确等级列表匹配日志行，
  等级支持 `DEBUG/INFO/WARNING/ERROR/CRITICAL` 与 `DBUG/WARN/ERRO/CRIT` 短名
- **片段合并**：前后文窗口重叠或相邻的多条命中合并成一段（`xxAxBxCxx` 整段给出，不重复前文），
  命中行以 `>>` 标出
- **续读与去重**：扫描进度落盘于 `plugin_data/log_watcher/tail_state.json`，重载/重启不重复提醒；
  日志轮转（inode 变化）与截断自动从头读，半行不丢不重
- **附件清理**：txt 摘录落在 `plugin_data/log_watcher/outbox/`，保留最新 50 个且不超过 24 小时
- **通用配置**：顶层 `log_with_bot_id`，开启后插件日志带 `[platform:平台ID]`
- **两种提醒形态**（`send_mode` 切换）：`file`（默认，txt 摘录附件）与 `forward`（合并转发）

### 形态说明（已在 2.0.0 修正）

- v1 的 `file` / `forward` 两种形态实测在 `weixin_oc` 通道上都送不出去：`File` 段被服务端
  `prepare failed`（`ret=-2`）拒收；`Node/Nodes` 段被适配器静默丢弃。v2 起默认 `send_mode: auto`，
  只发 Plain 文本；旧配置里的 `file` 会被映射为文本并记一条 degradation。
- v1 里写的测试规模落款是当时的数字，与 v2 的测试规模无关，已整段作废，以 2.0.0 一节的实测为准。
