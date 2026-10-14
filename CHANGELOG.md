# Changelog

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
