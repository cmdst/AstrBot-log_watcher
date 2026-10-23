# Changelog

## v2.3.1（2026-10-24）

> 两处小改：**「分级用 Provider」从手填 id 改成下拉选择**，并且**留空时回落到当前对话模型**
> （配置面不变，仍是 8 组 / 69 键）。

- `classify.provider_id` 增加 `"_special": "select_provider"` —— AstrBot 的插件配置页会把它渲染成
  「已配置的对话模型」下拉框，不用再去别处手抄 provider id（对标 `astrbot_plugin_media_analysis` 的做法）。
- **留空语义变了**：不再「永不调 LLM」，而是**回落到 AstrBot 当前的对话模型**
  （`Context.get_using_provider()`，**每轮现取、不缓存** —— 在 WebUI 换了默认模型，下一轮就跟随）。
  只有连默认模型都取不到（未设置 / 类型不符 / 无 id）时才显式降级为
  `degraded:llm-unconfigured` 且**不写知识库**（C4 语义没有被回落绕过）。
  回落命中的判定会带 `provider:default-fallback` 标签，台账与报告都能看出「这次不是手选的模型」。
- 已有配置值原样保留，**无需迁移**。
- 新增守卫用例：`test_classify_provider_id_uses_provider_dropdown` —— 防止以后有人把 `_special`
  改掉，UI 悄悄退回手填而没人发现；另有 4 条回落路径用例（命中 / 无默认 / 显式优先 / 核心抛
  ValueError）。
- 上一版 2.3.0 上线时 `initialize` 的启动横幅漏了 `report_cfg` 赋值（测试没覆盖 `initialize`），
  已由热修 `bc25a2f` 修好；本版随分支一并带上，并新增 F821 静态守卫（`tests/test_static_checks.py`）
  钉住这一类「静态可判定、运行期才炸」的错误。

## v2.3.0（2026-10-23）

> 本版收口三件事，**三件都是不兼容变更**：① 指纹缓存强制失效 —— 每条错误都必须由模型重新下结论；
> ② 从代码与配置中**完整移除自动修复**（`dsh` headless 通道）；③ 告警改成「**1 条诊断首段 + 1 个原始
> 日志文件**」。配置从 8 组 / 82 键变成 **8 组 / 69 键**，状态库 `SCHEMA_VERSION` 2 → **4**。
> 分支 `feat/v2.3.0-no-cache-no-remediation`（`591469a →` 本版），未合并 `main`、未部署生产。
> 门禁 **308 passed / 0 failed**（v2.2.0 基线 340；变化逐段可对账，见文末「测试」）。

### ① 判定：指纹缓存强制失效（每条错误必过模型）

- **知识库命中不再是判决出口**。旧实现命中 `pattern_kb` 就直接返回历史结论（跳过模型、安全闸与预算
  记账）；运营方实测到「当前错误与库里旧指纹相同，插件把旧结论当成现在的结论报上来，定位被带偏」。
  v2.3.0 起 KB 条目只作「历史判定（先验，仅供参考，可推翻）」注入提示词，结论必须由模型重新给出。
  `source=manual` 的人工覆写是**唯一**豁免，且必须可见：`judged=false`、`judge_source=manual`、
  tags 带 `manual-override`、首段写「人工覆写（非模型判定）」。
- `classify.noise_shortcut` 默认 `true → **false**`：良性噪声也要过模型；显式开启时结论标
  `judged=false`（不得伪装成模型判定），保留一版作为逃生阀。
- **预算只延迟、不取消**：单轮/小时预算用尽时，该指纹进待判队列（下一轮优先），本轮返回
  `source=degraded` + `degraded:llm-budget`，**不再**用本地结论「看起来像已判」地定案。
- **未配 provider 不再写库**（真缺陷修复）：需要 LLM 但 provider/context 不可用时显式降级
  （`degraded:llm-unconfigured`）且**不写 `pattern_kb`** —— 旧实现会把本地结论永久固化，
  provider 配好后也被旧结论吃掉。
- **判定与通知去重分离**：通知去重（`budget.dedupe_window_seconds`）只决定「发不发」，判定照做；
  `repeat_count` 的统计窗口独立为 `classify.repeat_window_seconds`。同一指纹连续三轮只发一条通知，
  但判定三次（`judged=1` ×3）。
- **批内复用、跨轮重判**：同一轮内同指纹只判一次（同一次观察，复用结论但重建证据），
  `begin_round()` 清空备忘录 ⇒ 跨轮必重判；不提供 TTL 复用省钱。
- 契约：`ThreatVerdict` 增 `judged` / `judge_source`（fail-closed 默认 False；`parse_llm_verdict`
  是唯一置 True 处）；台账 `alerts` 增 `judged`（1/0/-1=未知）与 `judge_source`；降级标签统一
  `degraded:*`（llm-timeout / llm-error / llm-invalid-output / guard-error / llm-budget /
  llm-unconfigured / engine-unavailable / engine-error）。

### ② 自动修复：通道整体移除（能力面清零）

- 删除 `remediate.py`（1772 行）、`prompts/remediate_task.md`、`dsh-headless-overlay.yml`、
  `tests/test_remediate.py`、`tests/test_defaults_drift.py`、`main.py` 17 个方法（约 440 行）、
  `models.RemediationRun` / `RemediationGate`、`engine.should_remediate`、`store` 6 个账本 API、
  投递层两段「已进入修复候选」提示，以及配置里的整个 `remediation` 组（**22 个键**）。
- 路由：`HIGH → notify`、`CRITICAL → emergency`（仅最高级即时告警），两者都不再进任何修复。
  `Route.REMEDIATE` 枚举值**保留**，只为解析历史 `alerts.route` 与用户 `route_map`。
- 兼容面（只停写不删）：`remediation_runs` 表/索引/列全留，启动 `reconcile_runs()` 仍把遗留
  `running` 对账成 `aborted`；`store.prune` 只保留孤儿 `running → timeout`；磁盘 `remediation/`
  目录冻结（只读），清理能力迁到离线 CLI `tools/prune_legacy_artifacts.py`（默认干跑、`--apply`
  才删、`--db` 只读统计、**永不删台账行**）。
- 配置删除的 22 个键名**冻结**在 `tests/test_config_map.py::DROPPED_IN_V230`；离线迁移工具把它们
  归为 **dropped**（明示删除），**不是** unknown（见 `tools/migrate_config_v3.py`）。

### ③ 告警报告：诊断首段 + 原始日志文件

- 一条告警 = **1 条诊断文本 + 1 个 `.log` 附件**（主出口且通道支持文件时），不再被 QQ 长度切成
  2~3 段。首段契约：头（等级/命中/时间/来源/组件/指纹第 N 次）→ 诊断（模型判定 / 「本地规则判定，
  未取得模型诊断」/「人工覆写（非模型判定）」三选一）→ 可能原因 / 是否建议修复 / 修复建议 →
  按等级的静态人工处置清单（CRITICAL/HIGH 各 3 条、MEDIUM 1 条；代码常量，不允许模型生成）→「原始日志」段（附件名+体积+口径+
  保留天数，并且本机路径）。
- 报告文件：`<plugin_data>/outbox/reports/alert-<YYYYmmdd-HHMMSS>-<SEV>-<fp8>.log`（0600/0700），
  与 `outbox/` 的「成功即删」**生命周期隔离**；按 `report.keep_days` / `report.max_files` 清理。
  超 `report.max_file_bytes` 保留头尾并写明丢弃字节数；同秒同等级同指纹得 `-2` 后缀。
- **非主出口不发文件**（代码不变式：`deliver.attachment_allowed(...)`：仅主出口且通道支持文件）：
  其余出口只发文本 + 「完整日志见 <本机路径>」。weixin_oc 代码级禁用附件（配置也打不开）。
- **超长不切段**：先压缩诊断再硬截（`…（首段已截断，完整内容见报告文件）`），
  `split_with_markers` 只留给「报告关闭/低等级」的旧内联路径。
- 新增 `report` 组 7 键（`enabled` / `min_severity` / `raw_mode` / `max_file_bytes` / `keep_days` /
  `max_files` / `head_max_chars`）；`notify.max_chars_per_message` 仍可覆盖单条上限。
- **报告形态恒为单条文本**：`notify.send_mode=forward` / `prefer_forward=true` 只影响「旧内联路径」
  （报告关闭、低等级或无报告文件时），并会打一条 degradation 提示（不再静默失效）。
  「原始日志」段在**附件形态**下也写本机留存路径（群做主出口 / File 段静默失败时能去本机找）。
- 失败不吞：写报告失败 → WARNING + 回落文本（给本机路径）；附件失败 → `file_ok=False`、
  `partial=True`、`delivery_partial` 计数 + WARNING，**不整条重试**；待发队列带 `attachments`，
  **重试会再发一次附件**。

### 配置与状态库

- **8 组 / 69 键**：`notify` 7 + `scan` 9 + `classify` 18 + `budget` 12 + `delivery` 4 +
  `report` 7 + `state` 9 + `self_guard` 3 = **69**。
  算术：82 − 22（remediation）= 60；+ 2（`classify.prior_ttl_hours` / `classify.repeat_window_seconds`）
  = 62；+ 7（report 组）= **69**。`config_map.KEY_MAP` 仍是 60 条 v2.1.0 迁移契约，
  新增 9 条住在 `config_map.EXTRA_LEAVES`；`test_config_map.py` 的冻结断言未软化。
- `state.fingerprint_ttl_hours` **键名保留、语义收窄**为「通知去重状态保留期」；判定先验保留期
  改用 `classify.prior_ttl_hours`（默认 72），`repeat_count` 统计窗口改用
  `classify.repeat_window_seconds`（默认 900）。
- **`SCHEMA_VERSION` 2 → 4**：
  - v2 → v3（判定链）：`pattern_kb.last_judged_at` / `judge_source`，`alerts.judged` /
    `judge_source`（历史行不回填：`-1` / `''` = 未知）；
  - v3 → v4（报告）：`pending_delivery.attachments`（JSON，**重试会再发一次附件**）、
    `alerts.report_path`（留存件；`excerpt_path` 仍是临时摘录）。
  旧库 `open()` 时自动补列（吞 duplicate column）；**回滚必须连库一起回滚**：v2.2.0 代码看到
  `user_version=4` 会进只读保护（拒绝写入），见 `runbook.md` §8.4。

### 工具

- 新增 `tools/migrate_config_v3.py`：v2.2.0（8 组 / 82 键）→ v2.3.0（8 组 / 69 键），
  `--dry-run`（默认）/ `--apply` / `--verify --against` / `--from-backup`，幂等、**任何模式都不打印
  配置值**。干跑会列出将删除的 22 个 remediation 键、将补默认值的 9 个新键、未知键。
  只支持分组结构；v2.1.0 扁平结构先跑 `tools/migrate_config_v2.py`。
- `tools/prune_legacy_artifacts.py`（离线清理历史修复轨迹）：默认干跑、`--apply` 才删、
  `--db` 只读统计台账行、永不删行；`--dir/--keep/--max-age-days/--max-bytes` 可调。
- `tools/migrate_config_v2.py` 保留（v2.1.0 → v2.2.0 的旧迁移）。

### 升级顺序（**硬的**）

1. 备份插件目录、配置与状态库（`runbook.md` §8.1）；
2. **先迁移配置**：`python3 tools/migrate_config_v3.py --dry-run --config <配置>` 核对 →
   `--apply`（写 `bak-pre-v2.3.0-<ts>`）；
3. **再换插件版本**（核心会删除 schema 外的键，顺序反了值就没了）；
4. 重载插件，验收启动行（版本 2.3.0、状态 SQLite、`报告 开启（excerpt，≥MEDIUM）`）、
   无 `Config key removed`（本插件的键）、无 `CONFIG-INVALID.txt`；
5. `--verify --against <备份>` 逐叶子复核（未打印任何值）。

回滚是**成对的**：配置 + 状态库 + 代码三者一起回（锚点 v2.2.0 = `591469a`），
只回代码会因 `user_version=4` 进只读保护，见 `runbook.md` §8.4。

### 测试

- 门禁 **308 passed / 0 failed**。数量变化逐段可对账：v2.2.0 **340** →（移除自动修复）**253**
  →（判定链）**277** →（报告形态）**299** →（交付评审修复轮）**308**。随能力删除的用例逐条点名在 T5 的
  `VERIFY-v2.3.0.md`；缓存的旧语义用例是**改写**而不是删除（见 `tests/test_engine.py` 的
  `test_kb_prior_still_calls_llm` 等）。
- 关键回归：同一指纹两次分类 → 模型调用 2 次（旧 reason/severity 不复用）；`noise_shortcut`
  默认 false；未配 provider 不写 `pattern_kb`；预算耗尽排队 + `degraded:llm-budget`；批内复用
  ×1 / 跨轮重判；报告首段三分支；非主出口无附件；`SCHEMA_VERSION` 迁移 v1/v2/v3 → v4。
- 未闭合项（aiocqhttp 非主出口附件不变式、`raw_mode=file` 的隐私面等）见 `runbook.md` §10。

## v2.2.0（2026-10-19）

> 本版只做一件事：**把插件配置从「95 个扁平顶键」整成 8 个分组（`notify` / `scan` / `classify` /
> `budget` / `delivery` / `state` / `remediation` / `self_guard`）**，写得跟插件市场的插件一样
> （分组 `object` + 叶子带中文 hint 与「误配后果」），WebUI 插件详情页与
> `data/config/log_watcher_config.json` 从此都是分块可读的。**行为零变化**：默认值逐字未动、
> 内部 cfg 契约未动（`classify/deliver/detect/remediate/store` 一行没改）。

### 为什么

- 95 个顶键一条长列（外加 8 个 `_xxx_section` 文本键假装分组）：WebUI 上一屏看不完，配置文件里
  从「主动提醒」到「紧急修复」中间隔了 70 多个键，四个**红线键**（`remediation.enable` /
  `workdir` / `permission_mode` / `patch_overlay`）埋在中间（2026-10-19 面板两次把值写错键，
  与这个布局是同一类问题：找不到、容易改错）。
- 对照面：同机 29 个插件里只有 log_watcher 是纯扁平；市场插件（`pokepro` 8 组 / `livingmemory` 15 组 /
  `self_learning` 23 组 / `bilivideo` 10 组 / `image_search`、`vision_router` 的 `object`+`template_list`）
  一律分组。

### 结构

- **8 组 / 82 键**；组名已表达语境，叶子不再重复前缀（`remediation.workdir`，不是
  `remediation.remediation_workdir`）。旧扁平键 → 新路径的完整映射只有一份，在 `config_map.KEY_MAP`。
- 键名变更（改名 11 处）：`notify_min_severity`→`notify.min_severity`、`classify_*`→`classify.*`、
  `llm_max_block_lines`/`llm_max_calls_per_round`/`llm_max_calls_per_hour`→`classify.max_block_lines`/
  `max_calls_per_round`/`max_calls_per_hour`、`delivery_*`→`delivery.*`、`state_db_path`→`state.db_path`、
  `remediation_*`→`remediation.*`、`remediate_confirm_count`/`remediate_confidence_threshold`→
  `remediation.confirm_count`/`confidence_threshold`、`self_log_names`/`self_feedback_ids`→
  `self_guard.log_names`/`feedback_ids`、`log_with_bot_id`→`self_guard.log_with_bot_id`。
- **删除 13 个键**：8 个 `_xxx_section` 伪分组键 + 5 个死键（`llm_provider_id` / `chat_provider_id` /
  `llm_timeout` / `provider_id` 从未被任何代码读过；`admin_users` 的 schema 描述里写着「未实现」）。
- 新增 `config_map.py`（唯一映射 + 只读访问层 `ConfigView`：嵌套优先 → 旧扁平键兜底并告警 → 默认值）
  与 `tools/migrate_config_v2.py`（离线迁移 CLI：干跑 / 落盘 / 对照复核 / 从备份重建，**任何模式都不打印配置值**）。

### 升级要求（**顺序是硬的**）

核心 `AstrBotConfig` 会在插件加载时把 schema 里没有的键当 stale 键**删掉**（`check_config_integrity()`
+ `save_config()`），所以必须**先迁移配置、再换插件版本**：`runbook.md` §1.4 给了可直接粘贴的 5 步
（备份 → 干跑 → `--apply` → 换版 → 复核/自愈 → 重载），配置回滚见 §8.5（**代码与配置必须成对回滚**）。

### 测试

- `tests/test_config_map.py`（18 条）：schema ⇄ `KEY_MAP` ⇄ main 读取点三方一致、旧 95 键契约冻结、
  默认值不注入、迁移 CLI 的干跑/落盘/复核/重建/拒绝未知键。
- 全量门禁 **340 passed / 0 failed**（v2.1.0 基线 322 + 18）。

## v2.1.0（2026-10-19）

> 本版把 `main` 上累积的八次改动收口成一个发布点并打 tag（此前 `v2.0.0` 停在 `a4eeef4`，
> 而线上早已跑到后面的提交；`metadata.yaml` 的版本号因此长期与事实不符，2026-10-19 抬到 `2.1.0`）。
> `pin-check.sh` 从此重新可比：它比的就是这个版本号。

### 变更（2026-10-19 · 八）：轨迹上限默认 262144 → 1048576（1 MiB）

- 起因是一次**成功** run 的轨迹恰好等于旧上限 262144 字节：agent 在诊断里读了历史轨迹把输出顶到封顶，
  结尾的 `{"type":"final"}` 与 `turn_end` 都被截掉 ⇒ 按「看轨迹里有没有 final」验收会把**成功判成失败**
  （正确判据见 `runbook.md` §6.1；插件本身**流式**提取结论，账本 `summary` 不受截断影响）。
- 三处默认值同步抬高，并加**漂移守卫**测试钉住它们一致（`tests/test_remediate.py`）：
  `remediate.DEFAULT_MAX_OUTPUT_BYTES`、`main._remediate_config()` 的白名单默认值、`_conf_schema.json`。
  为什么要钉：只有**生产链路**那份（main 白名单）真正生效，另外两份是给人读的 —— 一旦漂移，
  读代码的人会得到错误结论（同类问题：2026-10-17 那两个等级旋钮被白名单吞掉一事）。
- 现网配置里该键是**显式** `262144` ⇒ **改默认值不改现网行为**，需一次配置改动（已派单）。
- 影响面：单次 run 的轨迹上限 ×4（仍受 `remediation_artifact_bytes` 目录上限与 `prune_artifacts()` 约束；
  修复 run 本身稀疏，磁盘影响很小）。

## Unreleased

### 运维文档（2026-10-19 · 七）：轨迹截断的验收判据 ＋ 两条会被误读的「绿灯」

真实误判风险来自一次运行良好的 run：`r20261018-234346-9503f842`（**ok / exit 0 / 511.2 s**）
的轨迹文件**恰好等于上限 262144 字节** —— agent 在诊断里读了历史轨迹（含 21:11 那次失败记录），
把输出顶到封顶，结尾的 `{"type":"final"}` 与 `turn_end` **都不在文件里**。

- `runbook.md` §6.1 新增「轨迹被输出上限截断时怎么验收」：正确判据＝账本 `status='ok'` ＋
  `summary` 非空（插件**流式**提取，不受截断影响）＋ `receipt_sent` 的**写回≠送达**语义 ＋
  arena 之外零写入；文件尾的 `…（已截断）` 标记可用于**事后**判读。想保住整份轨迹就把
  `remediation_max_output_bytes` 调到 `1048576`（面板保存即可）。
- 同节补一条：`dsh --profile headless --dump-config` **exit 0 只证明"能组合"、不渲染提示词**
  ⇒ 它绿 ≠ 真能跑（2026-10-18 的 `{{cwd}}` 与 `MISSING_CREDENTIAL` 两处阻断都是真跑才暴露的）。
- 本次**只改文档**，未动一行业务代码、未改默认值（`remediation_max_output_bytes` 生产配置里
  显式为 262144，改**默认值**不影响现网、只会制造库与副本的 schema 差异，故留给配置侧）。

### 修复（2026-10-18 · 六）：把「启用凭据服务」并进库里的 `dsh-headless-overlay.yml`

dsh 升到 **0.2.1-rc.2** 后，headless profile 里 `credentials` 条目是 `disabled: true`（web 那份没禁）
⇒ overlay 里 `apiKeyEnv: CODECOMMAND_API_KEY` 无法从 `~/.dsh/.credentials.yaml` 解析，
**自动修复通道以 `MISSING_CREDENTIAL` 秒退**（修复链在真实候选上暴露的第二处阻断，fix 当晚定位）。

- 生产副本由 fix 就地在文件末尾追加了 8 行（显式启用 `@deepseek-ai/dsh-credentials-local`，
  **不含任何明文密钥**）——但**那是插件自带文件、库里有同名件**：不回填的话，**下次覆盖就把这处修复抹掉**。
- 本提交把那 8 行**原样**并进库（`sed -n '54,61p'` 直取，先 `head -53 | diff` 证明库是副本的前缀才追加）；
  复核：库与生产副本 **sha256 均为 `fd6f5e06…`、逐字节一致（61 行）**，`dsh --profile headless --dump-config`
  **exit 0**（stderr 0 字节）。
- **没有**跑付费的真实最小调用：库文件现在与 fix 刚验过的那份（exit 0 / 8.5 s / `CHANNEL-OK`）**逐字节相同**，
  字节相等即证据可迁移；不为验收烧配额。
- 教训（已进下级手册 §7-17）：**插件自带的 profile 叠加件也在"库 vs 生产副本"的对照面里** ——
  只对照 `.py` 与 `_conf_schema.json` 会漏掉它，而它的漂移同样会在下一次覆盖时静默回退。

### 修复（2026-10-18 · 五）：上线自检发现的两处自伤

部署当晚（06:22 出口迁移上线）做**自己的验收**时量出两件，都不是别人的问题：

- **汇总行报终身计数 = 噪声**：`pending_delivery` 里 2026-10-14~18 那 **81 条**历史债（63 MEDIUM /
  9 HIGH / 9 LOW）是终身累计，会把「已放弃 81 条」**永远**挂在每条消息尾部。改成**最近一个窗口**
  （默认 24 h；实测同刻窗口内只有 6 条）：`store.pending_stats(now, window=…)` 新增
  `recent_*` 系列（`recent_active` / `recent_abandoned` / `recent_max_severity` / `recent_oldest_age`
  / `window_hours`，内存态 `PendingQueue.stats` 同步），汇总行文字改为「最近 N 小时未送达：…」，
  计数为 0 的那一项不再出现。
- **会话标识被写进日志**：启动横幅原来打印 `caps`（键就是完整会话串）⇒ 运营方的会话 ID 进了
  `astrbot.log` —— 而那份日志**正是插件自己要扫的**。新增 `deliver.mask_session()`（``平台:类型:<ID>``
  → ``平台:类型:（ID 已隐）``，解析不出三段则原样返回），用于启动横幅（改为只报出口条数与平台能力）
  与「找不到会话」报错。
- 回归：`mask_session` 五条形状 + `pending_stats` 的窗口口径（三天前的条目不进 `recent_*`）。
- 证据：临时副本 **319 passed**；库内 318 passed / 1 failed（唯一失败＝已知目录名环境性）。

### 变更（2026-10-18 · 三）：告警出口从「双发」改为「按优先级 fallback」

**背景**：运营方定案**放弃微信**（被动回复窗口：每次入站只放行 1–3 条主动消息；我复算的现场数
＝497 次平台拒收、92 条入队、82 条耗尽、**0 次重试成功**），改以 **QQ 为主力**（私聊主、测试群备）。

- `deliver.outlet_order`（deliver.py:473）：出口列表**即优先级** —— 保序、去空白、去重。
- `deliver.deliver_over_outlets`（deliver.py:499）：主出口成功即停；每个出口最多
  `delivery_max_attempts` 次尝试（**默认 4 → 2** = 初投 + 1 次重试，配置里可改）；用尽才切下一个
  出口；全部失败才按主出口入队一次。为什么改：旧实现是「每个目标都发一遍」⇒ 两个出口都通时
  **两处都收到**（重复打扰），出口死掉时又各自堆 `abandoned`（历史 81 条）。
- `deliver.delivered`（deliver.py:487）：`receipt_sent` 的判定从「全部目标成功」改成
  「**任一出口成功**」—— fallback 语义下成功路径通常只有一条记录，用旧的「全部成功」会把
  「主失败、备成功」误判成没送达（字段会恒 0）。
- 回归 5 条：顺序/去重、主成功不碰备用、用尽切备用（退避与事件序列都钉住）、全失败只给一次
  `give_up`、空计划与构造异常不带走整条链路。
- 文档：`runbook.md` §4 配置表与 §6.1（代码落点 + 出口链 + `receipt_sent` 判定）、
  schema 两个键的 hint 同步。

### 变更（2026-10-18 · 四）：出口策略的三条硬约束 ＋ 未送达汇总行 ＋ 纯抖动封顶

运营方在同日的第三轮问答（Q14–Q18）上定案，一炉四件：

- **至少两条出口（Q15=b）**：`target_sessions` 不足两条 ⇒ **加载但停摆** ——
  `main._check_outlet_policy`（ERROR 日志 ＋ 状态目录写 `CONFIG-INVALID.txt`，含原因与恢复方法；
  合格时自动删掉旧痕迹）、`main._loop` 不启动扫描线程。判据抽成纯函数
  `deliver.has_redundant_outlets`（**只校验条数**：写两条不通的出口也算合格 —— 可达性只能靠
  真发探针验，这条限制已写进 runbook §6.1）。
- **未送达汇总行（Q14=c）**：转 `abandoned` 的同时，**下一条成功投递**的尾部带一行
  「历史未送达：待重试 N 条、已放弃 M 条（**最高 X 级**，最早 Y 小时前）」；
  `store.pending_stats()` 新增 `max_severity`（PendingQueue 内存态同步）。
- **纯抖动封顶（Q11=b）**：`classify.clamp_transient_escalation` —— 本地锚点只有 `transient:` 族
  **且**没有任何 `failure:` 族标签时，等级封顶 MEDIUM（重算 `route_map` 去向、附
  `transient-escalation-capped` 标签与理由）；人工覆写（`source=manual`）永不封顶。
  挂在 `engine.classify` 这个**公开入口**收口（KB/噪声/LLM/降级各分支都汇到它）。
  **为什么规则这么窄**：那次**有价值的** GMI 修复（`9215dd87`）的块同时带
  `local:failure:import-error` 与 `local:local-mode:unmatched-error` ⇒ 按"未匹配错误"封顶会正好
  挡住它（我最初的想法已被自己的数据否掉）。
- 连带：`test_engine.py::test_degraded_result_is_not_cached` 的等级断言按新策略改成 MEDIUM
  （它关心的是缓存语义 —— `call_count`/tags 照旧逐字断言；同时新增
  `transient-escalation-capped` 标签断言）。
- 证据：临时副本 **318 passed**；库内 317 passed / 1 failed（唯一失败＝已知目录名环境性）。

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
  回执**真的**投递成功后才补写那一列 —— `deliver.delivered` 是判定规则（任一出口 ok）、
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
