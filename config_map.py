"""插件配置的键映射与访问层（v2.2.0 起：配置按组分块，见 `_conf_schema.json`）。

为什么单开这个模块：**新旧键名的映射只能有一份**。本仓库已经吃过「同一事实写多份」的亏 ——
两个等级旋钮（`unmatched_severity` / `transient_severity`）当时只写进了 schema 与消费方，
漏了 `main._engine_config()` 的显式白名单，生产链路上被静默丢弃一整天（父手册 §3 第 8 条）。
所以这次结构改造只留一处映射，三方共用：

- `main.py` 以点号路径读配置（嵌套优先 → 旧扁平键兜底 → 默认值）；
- `tools/migrate_config_v2.py` 用它把旧扁平配置搬进新结构（不另写第二份映射）；
- `tests/test_config_map.py` 用它钉住「schema 叶子 ≡ KEY_MAP ≡ main.py 读到的路径」三方一致。

键名约定：组名已经表达了语境，叶子**不再重复前缀**（对标 `astrbot_plugin_pokepro` /
`astrbot_plugin_livingmemory` 等市场插件的写法）：写 `notify.send_mode`，
而不是 `notify.notify_send_mode`。

本模块只依赖标准库，不导入 astrbot，可离线单测。
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

#: 顶层分组顺序（= `_conf_schema.json` 的分组顺序 = WebUI 与配置文件的渲染顺序）。
GROUPS: tuple[str, ...] = (
    "notify",
    "scan",
    "classify",
    "budget",
    "delivery",
    "state",
    "self_guard",
)

#: 新点号路径 -> 旧扁平键名（v2.1.0 及更早的 `_conf_schema.json` 顶层键）。
#: 迁移脚本与运行期兜底读取都以它为准；加键时必须同时改这里、`_conf_schema.json` 与 main.py。
KEY_MAP: dict[str, str] = {
    # ---- notify：主动提醒 ----
    "notify.target_sessions": "target_sessions",
    "notify.send_mode": "send_mode",
    "notify.prefer_forward": "prefer_forward",
    "notify.min_severity": "notify_min_severity",
    "notify.include_excerpt": "include_excerpt",
    "notify.max_excerpt_chars": "max_excerpt_chars",
    "notify.max_chars_per_message": "max_chars_per_message",
    # ---- scan：日志扫描 ----
    "scan.log_dir": "log_dir",
    "scan.file_pattern": "file_pattern",
    "scan.levels": "levels",
    "scan.exclude_keywords": "exclude_keywords",
    "scan.poll_interval_seconds": "poll_interval_seconds",
    "scan.start_from_end": "start_from_end",
    "scan.context_before": "context_before",
    "scan.context_after": "context_after",
    "scan.max_lines_per_poll": "max_lines_per_poll",
    # ---- classify：AI 威胁分级 ----
    "classify.enable": "classify_enable",
    "classify.mode": "classify_mode",
    "classify.provider_id": "classify_provider_id",
    "classify.timeout_seconds": "classify_timeout_seconds",
    "classify.system_prompt": "classify_system_prompt",
    "classify.fallback_severity": "fallback_severity",
    "classify.unmatched_severity": "unmatched_severity",
    "classify.transient_severity": "transient_severity",
    "classify.max_block_lines": "llm_max_block_lines",
    "classify.max_calls_per_round": "llm_max_calls_per_round",
    "classify.max_calls_per_hour": "llm_max_calls_per_hour",
    "classify.noise_shortcut": "noise_shortcut",
    "classify.kb_enabled": "kb_enabled",
    "classify.kb_max_entries": "kb_max_entries",
    "classify.new_pattern_escalate": "new_pattern_escalate",
    "classify.route_map": "route_map",
    # ---- budget：通知预算 / 聚合 / 静默 ----
    "budget.dedupe_window_seconds": "dedupe_window_seconds",
    "budget.digest_interval_seconds": "digest_interval_seconds",
    "budget.digest_max_items": "digest_max_items",
    "budget.max_alerts_per_round": "max_alerts_per_round",
    "budget.max_alerts_per_minute": "max_alerts_per_minute",
    "budget.max_alerts_per_hour": "max_alerts_per_hour",
    "budget.max_alerts_per_day": "max_alerts_per_day",
    "budget.burst_window_seconds": "burst_window_seconds",
    "budget.burst_threshold": "burst_threshold",
    "budget.burst_min_severity": "burst_min_severity",
    "budget.silence_ranges": "silence_ranges",
    "budget.silence_min_severity": "silence_min_severity",
    # ---- delivery：投递与通道能力 ----
    "delivery.max_attempts": "delivery_max_attempts",
    "delivery.base_delay_seconds": "delivery_base_delay_seconds",
    "delivery.retry_batch": "delivery_retry_batch",
    "delivery.channel_overrides": "channel_overrides",
    # ---- state：状态 / 磁盘 / 留存 ----
    "state.db_path": "state_db_path",
    "state.fingerprint_ttl_hours": "fingerprint_ttl_hours",
    "state.history_retention_days": "history_retention_days",
    "state.history_max_rows": "history_max_rows",
    "state.outbox_max_bytes": "outbox_max_bytes",
    "state.excerpt_mode": "excerpt_mode",
    "state.keep_excerpt_files": "keep_excerpt_files",
    "state.outbox_max_age_hours": "outbox_max_age_hours",
    "state.disk_report_interval_hours": "disk_report_interval_hours",
    # ---- self_guard：自身识别 / 自反馈 ----
    "self_guard.log_with_bot_id": "log_with_bot_id",
    "self_guard.log_names": "self_log_names",
    "self_guard.feedback_ids": "self_feedback_ids",
}

#: 旧版里存在、v2.2.0 起**不再保留**的键：8 个伪分组标题 + 5 个死键。
#: 死键的四条是历史兼容残留（`main._classify_provider_id()` 只读 `classify_provider_id`，
#: 这四条从未被任何代码读过）；`admin_users` 的 schema 描述里自己写着「未实现」。
DROPPED_LEGACY_KEYS: tuple[str, ...] = (
    "_主动提醒_section",
    "_日志扫描_section",
    "_AI 威胁分级_section",
    "_通知预算 / 聚合 / 静默_section",
    "_投递重试_section",
    "_状态 / 磁盘_section",
    "_紧急修复（dsh headless，默认关）_section",
    "_自反馈 / 管理白名单_section",
    "llm_provider_id",
    "chat_provider_id",
    "llm_timeout",
    "provider_id",
    "admin_users",
)

#: v2.3.0 新增、**在 v2.1.0 里没有旧扁平对应键**的叶子路径。
#: 为什么不塞进 `KEY_MAP`：那 82 条是「旧扁平键 → 新路径」的迁移契约（95 条旧键的口径
#: 被 `tests/test_config_map.py` 冻结）。新键没有旧值可搬，塞进去会污染迁移契约，
#: 让老配置每次体检都报一堆「missing」。所以另立一份，schema 叶子 = KEY_MAP ∪ EXTRA_LEAVES。
EXTRA_LEAVES: tuple[str, ...] = (
    # 历史先验保留期（判定侧；与 state.fingerprint_ttl_hours 的「去重状态保留期」分开）
    "classify.prior_ttl_hours",
    # repeat_count 的统计窗口（只喂判定上下文；通知去重窗口是 budget.dedupe_window_seconds）
    "classify.repeat_window_seconds",
)


def all_paths() -> set[str]:
    """全部可知的点号路径（schema 叶子必须与它双射）。"""
    return set(KEY_MAP) | set(EXTRA_LEAVES)


#: 旧扁平键 -> 新点号路径（迁移与对照用）。
LEGACY_TO_PATH: dict[str, str] = {legacy: path for path, legacy in KEY_MAP.items()}


class _Missing:
    """取值哨兵：区分「键不存在」与「键存在但值为 None/空」。"""

    __slots__ = ()


_MISSING = _Missing()


class ConfigView:
    """只读配置访问层：点号路径取值，回退旧扁平键，再回退默认值。

    兼容面：**只有运行期兜底**。核心 `AstrBotConfig.check_config_integrity()` 会在插件加载时
    把 schema 里没有的键判定为 stale 并删除（随后 `save_config()`），所以旧扁平键正常路径下
    根本进不到插件手里 —— 兜底只在「配置被手工改回旧形态且核心未清理」这类场景生效，
    命中时会打一条 WARNING（每个路径一次），提示跑迁移脚本。
    """

    __slots__ = ("_raw", "_warned")

    def __init__(self, raw: Mapping[str, Any] | None) -> None:
        self._raw: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        self._warned: set[str] = set()

    # ---------- 读 ----------

    def get(self, path: str, default: Any = None) -> Any:
        """按点号路径取值；嵌套缺失则回退旧扁平键；都没有才用 default。"""
        nested = self._nested(path)
        if nested is not _MISSING:
            return nested
        legacy = self._legacy(path)
        if legacy is not _MISSING:
            self._note_legacy(path)
            return legacy
        return default

    def raw(self) -> Mapping[str, Any]:
        """原始配置（只读用途，例如整体快照与排障）。"""
        return self._raw

    def _nested(self, path: str) -> Any:
        node: Any = self._raw
        for part in path.split("."):
            if not isinstance(node, Mapping) or part not in node:
                return _MISSING
            node = node[part]
        return node

    def _legacy(self, path: str) -> Any:
        legacy = KEY_MAP.get(path)
        if legacy is None:
            return _MISSING
        if isinstance(self._raw, Mapping) and legacy in self._raw:
            return self._raw[legacy]
        return _MISSING

    def _note_legacy(self, path: str) -> None:
        if path in self._warned:
            return
        self._warned.add(path)
        logger.warning(
            f"配置里出现旧扁平键 {KEY_MAP.get(path, '')!r}（未迁移）：本次按旧值生效。"
            "请运行 tools/migrate_config_v2.py 把配置搬进分组结构，否则下次插件加载时"
            "核心会把这些旧键当 stale 键删掉（值回落默认）。"
        )

    # ---------- 诊断 ----------

    def legacy_hits(self) -> tuple[str, ...]:
        """本视图实际走过的旧键路径（测试与自检用）。"""
        return tuple(sorted(self._warned))


def nested_paths(flat: Mapping[str, Any]) -> dict[str, Any]:
    """旧扁平配置 -> 新分组结构（只搬 `KEY_MAP` 里的键，不注入默认值）。

    返回新结构（缺失的键不出现，交由核心按 schema 补默认），不做写盘。
    """
    nested: dict[str, Any] = {group: {} for group in GROUPS}
    for path, legacy in KEY_MAP.items():
        if legacy in flat:
            group, leaf = path.split(".", 1)
            nested[group][leaf] = flat[legacy]
    return {group: items for group, items in nested.items() if items}


def flatten(nested: Mapping[str, Any]) -> dict[str, Any]:
    """新分组结构 -> 旧扁平结构（对照与回滚核对用，不用于回写旧版）。"""
    flat: dict[str, Any] = {}
    for path, legacy in KEY_MAP.items():
        group, leaf = path.split(".", 1)
        bucket = nested.get(group)
        if isinstance(bucket, Mapping) and leaf in bucket:
            flat[legacy] = bucket[leaf]
    return flat


def migration_report(flat: Mapping[str, Any]) -> dict[str, list[str]]:
    """迁移前的体检：哪些旧键无法映射、哪些新路径缺值、哪些键会被丢弃。

    只回键名，不回值（配置里可能有会话串与凭据形状串）。
    """
    unknown = sorted(
        key for key in flat if key not in LEGACY_TO_PATH and key not in DROPPED_LEGACY_KEYS
    )
    missing = sorted(legacy for legacy in KEY_MAP.values() if legacy not in flat)
    dropped = sorted(key for key in flat if key in DROPPED_LEGACY_KEYS)
    return {"unknown": unknown, "missing": missing, "dropped": dropped}


def diff_effective(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    """逐路径对照两份配置（旧扁平 vs 新分组）的取值，回不一致的路径名。

    迁移的验收判据就是它：**82/82 一致**才算没丢值。只回键名，不回值。
    """
    mismatched: list[str] = []
    for path, legacy in KEY_MAP.items():
        group, leaf = path.split(".", 1)
        bucket = after.get(group)
        has_after = isinstance(bucket, Mapping) and leaf in bucket
        has_before = legacy in before
        if has_before != has_after or (
            has_after and before.get(legacy) != bucket.get(leaf)  # type: ignore[union-attr]
        ):
            mismatched.append(path)
    return sorted(mismatched)
