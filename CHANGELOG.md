# Changelog

本文件记录 `log_watcher` 的版本变更。版本线：
`v2.0.0`（初版）→ `v2.1.0` → `v2.2.0` → `v2.3.0` → **`v2.3.1`（当前）**。

> 升级前请先读 [`runbook.md`](runbook.md) 的部署与回滚章节；**配置与代码必须成对升降**。

---

## v2.3.1 — 2026-10-24

### 新增

- **分级用 Provider 改成下拉选择**：`classify.provider_id` 带 `_special: select_provider`，
  配置页直接列出 AstrBot 已配置的对话模型，不用再手抄 provider id。
- **留空回落到当前对话模型**：`classify.provider_id` 为空时，每轮现取
  `Context.get_using_provider()` 作为判定模型（不缓存，换默认模型即跟随），
  命中的判定带 `provider:default-fallback` 标签。连默认模型都取不到时仍显式降级
  （`degraded:llm-unconfigured`）且**不写知识库**。

### 修复

- **启动横幅 `NameError`**：`initialize()` 用了未赋值的 `report_cfg`，导致 v2.3.0 首装时
  `Failed to load plugin log_watcher`。已在读取报告配置处补上赋值。

### 工程

- 新增 **F821 静态守卫**（`tests/test_static_checks.py`）：用 ruff 扫运行时模块的未定义名，
  这类错误测试期静默、启动时才炸。
- 新增 `test_classify_provider_id_uses_provider_dropdown`：防止 `_special` 被删后
  配置页悄悄退回手填。
- 门禁 **315 passed**。

---

## v2.3.0 — 2026-10-23

> 三处**不兼容变更**。配置 8 组 / 82 键 → **8 组 / 69 键**，状态库 `SCHEMA_VERSION` 2 → **4**。

### 1. 判定：指纹缓存强制失效

- **知识库不再短路判定**。旧实现命中 `pattern_kb` 就直接返回历史结论（跳过模型、安全闸与预算记账），
  运营中会把「旧错误的结论」当成「这次错误的结论」报出来。现在知识库条目只作为
  「历史判定（先验，可推翻）」注入提示词，**结论必须由模型重新给出**；
  同一轮内同指纹只判一次，**跨轮必重判**。
- `classify.noise_shortcut` 默认 `true → false`：良性噪声也要过模型；显式开启时结论标
  `judged=false`，不伪装成模型判定。
- **预算只延迟、不取消**：单轮/小时预算用尽时该指纹进待判队列，本轮返回
  `degraded:llm-budget`，不再用本地结论「看起来像已判」地定案。
- **未配 provider 不再写库**：显式降级（`degraded:llm-unconfigured`）且不写 `pattern_kb`，
  避免把本地猜测永久固化成先验。
- **人工覆写是唯一豁免且必须可见**：`judged=false`、`judge_source=manual`、
  tags 带 `manual-override`，报告首段写「人工覆写（非模型判定）」。
- 新增审计列：`pattern_kb.last_judged_at` / `judge_source`、`alerts.judged` / `judge_source`。

### 2. 移除自动修复通道

- 删除 `remediate.py`（约 1772 行）、`prompts/remediate_task.md`、`dsh-headless-overlay.yml`、
  相关测试（79 条）与 **22 个 `remediation.*` 配置键**；高危告警只通知人工。
- 历史 `remediation_runs` 表与 `remediation/` 轨迹目录**只停写不删**（审计材料）；
  需要腾空间时用 `tools/prune_legacy_artifacts.py`（默认干跑，`--apply` 才删，不删台账行）。
- 路由语义：`HIGH → notify`、`CRITICAL → emergency`（仅最高级即时告警），都不再进入修复。

### 3. 告警 = 1 条诊断首段 + 1 个原始日志文件

- 新增 `report` 组（7 键：`enabled` / `min_severity` / `raw_mode` / `max_file_bytes` /
  `keep_days` / `max_files` / `head_max_chars`）。
- 主出口发「1 条诊断文本 + 1 个 `.log` 附件」，不再被聊天软件长度限制切成 2~3 段；
  非主出口只发文本并给出本机留存路径（`deliver.attachment_allowed` 是唯一门控：
  只有第一个出口且通道支持文件才为真）。
- 首段结构固定：头 → 诊断（模型/降级/人工三态）→ 可能原因 / 是否建议修复 / 修复建议
  → 处置清单 → 原始日志（附件名、体积、口径、保留、本机路径）。
- 超长时**压缩诊断再截断**，绝不切段；写报告失败回落文本并告警，不静默。
- 状态库 `SCHEMA_VERSION 3 → 4`：`pending_delivery.attachments`、`alerts.report_path`。

### 测试

- 门禁 340 → **299 passed**（删除 82 条修复相关用例，新增判定与报告用例）。
- 后续在三轮评审中补齐附件门控、报告段预算、死代码等 14 项问题。

---

## v2.2.0 — 2026-10-19

### 变更

- **配置结构重构**：95 个扁平顶键 → **8 个分组 / 82 个叶子键**（`notify` / `scan` / `classify` /
  `budget` / `delivery` / `state` / `remediation` / `self_guard`），每个叶子带中文 hint 与「误配后果」。
- 新增 `config_map.py`（键名映射的唯一事实源 + 只读访问层）与 `tools/migrate_config_v2.py`
  （离线迁移 CLI：干跑 / 落盘 / 对照复核 / 从备份重建，**任何模式都不打印配置值**）。
- 删除 8 个 `_xxx_section` 伪分组键与 5 个死键；改名 11 处（如 `notify_min_severity` →
  `notify.min_severity`）。

### 升级要求

核心在插件加载时会把 schema 里没有的键当 stale 键**删掉**，因此必须**先迁移配置、再换代码**；
配置与代码**必须成对回滚**（`runbook.md` §1.4 / §8.5）。

### 测试

- 全量 **340 passed**（v2.1.0 基线 322 + 18 条配置结构守卫）。

---

## v2.1.0 — 2026-10-19

把此前累积的改动收口成一个发布点（此前 `v2.0.0` 停在早期提交，版本号与事实不符）：

- **噪声治理**：新增 `classify.unmatched_severity` / `transient_severity` 两个等级旋钮，
  只对「纯 transient 族」封顶，不误伤带 `failure:` 标签的真实故障。
- **修复执行器 argv 顺序**：launcher 选项必须排在 app 选项之前，`validate_argv()` 同时拒错序。
- **回执送达写回**：`receipt_sent` 改成「任一出口成功」才写。
- **出口 fallback**：按优先级逐个出口尝试，主成功即停；全失败才入队，未送达有汇总行。
- **轨迹上限**：默认 262144 → 1048576（1 MiB）。
- 配置白名单补漏：两个等级旋钮此前被 `_engine_config()` 吞掉，修复后设置才真正生效。

### 测试

- 全量 **322 passed**。

---

## v2.0.0 — 2026-10-17（初版）

- 首次成型的 v2 架构：**采集 → 分级 → 路由 → 投递**。
- 数值化的威胁分级（本地规则锚点 + 模型判定）、指纹去重、摘要聚合、即时告警与静默时段。
- 投递按通道能力表选段型，失败进重试队列。
