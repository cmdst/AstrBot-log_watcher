# log_watcher v2.3.0

扫描 AstrBot 日志 → **每条错误都过 AI 威胁分级** → **按级路由**（静默 / 摘要 / 即时告警 /
最高级即时告警，只通知人工）→ **诊断首段 + 原始日志文件**。

> 部署、迁移、排障、回滚、未闭合项：见 [`runbook.md`](runbook.md)。
> 版本与兼容变更：见 [`CHANGELOG.md`](CHANGELOG.md)；发布前脱敏：见 [`SANITIZE.md`](SANITIZE.md)。

## 它做什么

1. **采集**：每 `scan.poll_interval_seconds` 秒扫一次日志目录（可配 glob），按等级列表 + 忽略关键字
   收集命中行与前后文，窗口重叠/相邻的多条命中合并成一段。
2. **判定**：本地规则表先给一个**锚点**（磁盘满、OOM、未捕获异常、数据库锁、导入失败…），
   然后**每条命中都真实调用一次模型**重新下结论（`classify_mode: auto` + provider）。
   指纹知识库只把历史结论作为「先验」注入提示词，**不再短路判定**；同一轮内同指纹只判一次，
   跨轮必重判。模型超时/异常/输出非法/未配 provider/预算排队 → 显式降级
   （`source=degraded`、`degraded:*` 标签、`judged=false`），报告首段写「未取得模型诊断」。
   人工覆写（知识库 manual 条目）是唯一豁免，首段标「人工覆写（非模型判定）」。
3. **路由**：`IGNORE` 静默 / `LOW` 摘要聚合 / `MEDIUM` 起即时告警 / `CRITICAL` 最高级即时告警。
   **没有任何自动修复**：`HIGH → notify`、`CRITICAL → emergency`，只通知人工处置。
   预算闸（单轮/分钟/小时/日）、去重窗口、突发合并、静默时段与穿透等级都在这一层；
   **通知去重只影响「发不发」，不影响「判不判」**。
4. **投递**：按**通道能力表**选段型；主出口发「1 条诊断文本 + 1 个原始日志文件」，其余出口只发文本
   并给出本机路径。失败进重试队列（指数退避，绝不静默丢），失败残留落 `failed/` 供人工取证。
5. **报告**：`outbox/reports/alert-<时间>-<等级>-<指纹8>.log` 留存（默认 7 天 / 200 个），
   与 `outbox/` 的「成功即删」隔离；`notify.target_sessions` 里第 1 个是主出口。

## 告警形态（v2.3.0）

一条告警 = **1 条诊断文本 + 1 个原始日志文件**，不再被 QQ 长度切成 2~3 段。首段固定包含：

| 段 | 内容 |
|---|---|
| 头 | `【AstrBot 日志告警｜SEV】` + 命中条数/等级、时间、来源、组件、指纹（第 N 次命中） |
| 诊断 | 首行回答「这话是谁说的」：`—— 诊断（模型判定｜置信度 0.xx）——` / `本地规则判定，未取得模型诊断（degraded:*）` / `人工覆写（非模型判定）` |
| 原因/建议 | `可能原因` / `是否建议修复` / `修复建议`（来自代码里的静态表，不允许模型生成） |
| 处置清单 | 静态代码常量：CRITICAL / HIGH 各 3 条、MEDIUM 1 条（IGNORE/LOW 无），只读、可验证 |
| 原始日志 | 附件名 + 体积 + 口径 + 保留天数 + **本机留存路径**；非文件出口只写本机路径 |

- **非主出口不发文件**（代码不变式 `deliver.attachment_allowed(session, outlets, caps)`：只有
  `outlets[0]` 且通道支持文件时才为真）；其余出口只发文本 + 本机路径。weixin_oc 代码级禁用附件。
- 超长时**压缩诊断再截断**（`…（首段已截断，完整内容见报告文件）`），**绝不切段**。
- 写报告失败 → WARNING + 回落文本（给本机路径），不会静默；附件失败 → `partial=True` +
  `delivery_partial` 计数，不整条重试。

## 前置条件

1. **AstrBot 必须开启文件日志**：WebUI → 配置文件 → 系统 → `log_file_enable`（默认为关）。
   关闭时磁盘上根本没有 `astrbot.log`，插件每 10 分钟打一条 warning。
2. 全局 `log_level` 决定哪些等级会写进文件：全局是 `INFO` 时不会有 `DEBUG` 行。
3. 想用 LLM 分级（推荐）：在 `classify.provider_id` 的**下拉里选**一个 AstrBot 已配置的对话模型
   （不用手抄 provider id，v2.3.1 起）；
   留空也行 —— 会**回落到 AstrBot 当前的对话模型**（每轮现取，换了默认模型就跟着换）；
   只有连默认模型都取不到时，才显式降级为「本地规则判定，未取得模型诊断」且**不写知识库**，
   不会静默失效、也不会把本地结论冒充成模型结论。
4. 不再需要 `dsh` / headless 路由 / 任何修复前置条件（v2.3.0 已移除自动修复通道）。

## 通道能力：weixin_oc 只发 Plain 文本（既定事实）

实测（2026-10-14，本机 AstrBot v4.28.2 + `weixin_personal_demo` 适配器）：

- `File`（文件/附件）段：服务端返回 `ret=-2, errcode=0, errmsg=prepare failed` → 发送失败；
- `Node` / `Nodes`（合并转发/聊天记录）段：适配器不处理，**静默丢弃**；
- `Plain`（纯文本）：是唯一能进的段型。

因此 weixin_oc 在代码里被硬禁用 `file/forward/image`，本插件在它上面只发文本；
主出口若是 QQ/aiocqhttp 私聊，才会带 `.log` 附件（群出口/备用出口按「非主出口不发文件」处理，
群文件上传能力未实测，见 `runbook.md` §10）。

## 配置

全部键（**v2.3.0 起是 8 个分组 / 69 个键**，每个都带中文 hint 与「误配后果」）见
`_conf_schema.json` 与 [`runbook.md §3`](runbook.md)。配置是**分组嵌套**的：
`notify` 主动提醒、`scan` 日志扫描、`classify` 分级、`budget` 预算、`delivery` 投递、
`report` 告警报告、`state` 状态、`self_guard` 自身。
**从 v2.2.0 升级必须先按 [`runbook.md §1.3`](runbook.md) 迁移一次**（核心会把 schema 外的键当
stale 键清掉；工具：`tools/migrate_config_v3.py`）。

最常用的几个（写法即配置文件里的路径）：

| 配置项 | 默认 | 推荐 | 说明 |
|---|---|---|---|
| `notify.target_sessions` | `[]` | 填 1 个主出口（QQ 私聊）+ 1 个备用 | 告警发到这里；**列表即优先级**，第 1 个是主出口；留空 = 只扫描 |
| `notify.send_mode` | `auto` | 不动 | 按通道能力选段型（主出口可带文件）；报告形态恒为单条文本，`forward` 只影响旧内联路径 |
| `notify.min_severity` | `MEDIUM` | 不动 | 低于它的判定只进摘要或静默 |
| `scan.levels` | `["ERROR","CRITICAL"]` | 不动 | 加 `WARNING` 会引入每天上千条噪声 |
| `classify.provider_id` | `""` | 下拉里选一个 | 留空 = 回落 AstrBot 当前对话模型；取不到才降级（`degraded:llm-unconfigured`） |
| `classify.noise_shortcut` | **`false`** | 保持 false | true = 良性噪声零 token 短路，但结论标 `judged=false`（偏离「每条必过模型」） |
| `classify.prior_ttl_hours` | `72` | 不动 | 历史先验保留期（过期不再注入提示词；人工覆写永不过期） |
| `classify.repeat_window_seconds` | `900` | 不动 | `repeat_count` 统计窗口；不影响判不判、也不影响发不发 |
| `report.enabled` | `true` | 不动 | 关掉 = 回到内联摘录旧形态（长日志可能再裂成多段） |
| `report.raw_mode` | `excerpt` | 保持 excerpt | `file` = 整份日志（含他人会话串，且超大文件只取末尾），仅排障时临时开 |
| `report.keep_days` / `max_files` | `7` / `200` | 按磁盘调整 | 报告文件保留天数/条数，取更严者 |
| `state.fingerprint_ttl_hours` | `72` | 不动 | **只**管通知去重状态保留期；先验保留期看 `classify.prior_ttl_hours` |

## 状态与磁盘

- 状态库：`<plugin_data>/log_watcher.sqlite3`（WAL，`user_version=4`），可被 `state.db_path` 覆盖。
  库不可用时降级为 JSON 内存态（进度/计数/待发落盘），告警照发但台账不落库。
- 摘录：`outbox/`（`excerpt_mode: ledger_only` 下每轮一个单文件台账），受
  `state.outbox_max_bytes` + `state.keep_excerpt_files` + `state.outbox_max_age_hours` 三条上限取更严者约束。
- **报告文件**：`outbox/reports/`（`report.*` 三条：`keep_days` / `max_files` / `max_file_bytes`），
  与 `outbox/` 的临时摘录**生命周期隔离**（报告是留存件，供人事后对账）。
  **默认 `excerpt` 也会把命中段逐字保留 `keep_days` 天（默认 7，含日志里出现的会话串）**：
  敏感部署可 `report.enabled=false`（回到成功即删的内联路径）或调小 `keep_days`。
- 失败残留：`failed/`（发送失败的摘录文本，供人工取证）。
- 历史修复轨迹：`remediation/`（若有）**冻结只读**，v2.3.0 不再写入、不再自动清理；
  需要腾空间时跑 `python3 tools/prune_legacy_artifacts.py`（默认干跑，`--apply` 才删）。
  历史台账 `remediation_runs` 只读保留（启动对账 `running → aborted`，永不删行）。

## 已知限制

- **出站告警文本不做凭据掩码**（F18，未修）：要把原始日志发出去才能定位问题，属功能固有取舍；
  担心日志里有密钥请用 `scan.exclude_keywords` 过滤。报告文件同理（`raw_mode=file` 时隐私面更大）。
- 主动消息直接走 `Context.send_message`，不经过回复装饰链（分段回复、气泡、TTS 等不生效），
  也不触发 `after_message_sent`。
- 只读磁盘日志文件，解析依赖 AstrBot 的 loguru 格式（`[时间] [模块] [等级] …`），同时兼容标准
  logging 的 ` - ERROR - ` 形态；多行堆栈的续行按普通上下文行处理。
- 片段要等「后面不可能再有命中与它重叠」才发出（最后一条命中之后 `context_after + context_before`
  行），日志持续输出时延迟约等于这个行数；文件停更时下一轮扫描直接收尾并注明「末尾片段后文未凑齐」。
- QQ/微信客户端的文本没有等宽字体与加粗；诊断首段是纯文本（命中行不再用 `>>` 塞进正文，
  原始行都在报告文件里）。
- 收发都依赖通道本身可用：通道挂掉时告警会进重试队列并留失败残留（不会静默丢）。
- 报告文件名里的指纹只取 8 位；同秒同等级同指纹会得到 `-2` 后缀，取证请按 mtime 排序。

## 未实现的功能（明写，不默认省略）

- `/lw status`、`/lw ack <指纹>`、`/lw silence <分钟>` 等管理命令与管理白名单 **本版本未实现**：
  插件不注册任何命令处理器（保持零事件入口）。
- **自动修复**已在 v2.3.0 **整体移除**（不是默认关）：没有 `dsh` 子进程、没有 overlay、
  没有修复回执、没有修复配置键。历史轨迹与台账只作审计材料保留；不要按 v2.2.0 及更早的文档
  去配置 `remediation.*`（这些键会被核心当 stale 键删掉）。
- 群出口的文件上传（NapCat/OneBot `upload_group_file`）未实测；按「非主出口不发文件」执行，
  详见 `runbook.md` §10。

## 升级与回滚

- 升级顺序**先迁移配置、再换代码**（`runbook.md` §1.3）；配置与代码必须**成对回滚**
  （`runbook.md` §8.4）。v2.2.0 的回滚锚点是 `591469a`。
- `SCHEMA_VERSION` 已是 **4**：只回滚代码会让 v2.2.0 看到 `user_version=4` 并进入只读保护；
  回滚时要把升级前备份的状态库一起还原（详见 `runbook.md` §8.4）。

## 开发与测试

```bash
cd /root/workspace/projects/AstrBot-log_watcher
PYTHONDONTWRITEBYTECODE=1 /root/AstrBot/.venv/bin/python -m pytest tests/ -q -p no:cacheprovider   # 308 passed
```

测试全部离线：不联网、不 spawn 子进程、不写插件目录。分层：

| 文件 | 覆盖 |
|---|---|
| `tests/test_log_reader.py` | 等级规整、片段合并与边界、摘录切片、增量读取 |
| `tests/test_detect.py` | 指纹、抑制与回声过滤 |
| `tests/test_classify.py` | 本地规则、判定形状、提示词/先验注入、注入用例（`tests/classify_cases.json`） |
| `tests/test_engine.py` | LLM 契约、超时/异常/非法输出降级、知识库先验、批内复用、调用预算 |
| `tests/test_deliver.py` | 通道能力表、诊断首段/报告段、分片、降级、重试退避 |
| `tests/test_store.py` | SQLite schema v4、迁移、报告文件、保留清理、磁盘治理 |
| `tests/test_config_map.py` | schema ⇄ `KEY_MAP` ⇄ main 读取点三方一致、旧键契约冻结、迁移 CLI |
