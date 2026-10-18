"""配置结构改造（v2.2.0）的三方一致守卫 + 迁移脚本的行为测试。

为什么单开一个文件：加配置键要同时改三处（`_conf_schema.json` / `config_map.KEY_MAP` / `main.py`
的读取点），漏一处就是**静默故障** —— 本仓库已经吃过一次：两个等级旋钮只写进了 schema 与消费方，
漏了 `main._engine_config()` 的显式白名单，生产链路上被丢弃一整天（父手册 §3 第 8 条）。
本文件把三处钉在一起，并且把 v2.1.0 的旧键集合**冻结**成迁移契约：任何键的搬迁缺失都会红。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_PLUGIN_DIR = Path(__file__).resolve().parents[1]
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))
_TOOLS_DIR = _PLUGIN_DIR / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import config_map  # noqa: E402
import migrate_config_v2 as migrate  # noqa: E402

#: v2.1.0 `_conf_schema.json` 的 95 个顶层键（顺序照抄自 `git show e346ec9:_conf_schema.json`）。
#: 这是**迁移契约**：82 个可见键搬进分组，8 个伪分组标题 + 5 个死键丢弃，一个都不能多、不能少。
LEGACY_KEYS_V210: tuple[str, ...] = (
    'log_with_bot_id',
    '_主动提醒_section',
    'target_sessions',
    'send_mode',
    'prefer_forward',
    'notify_min_severity',
    'include_excerpt',
    'max_excerpt_chars',
    'max_chars_per_message',
    '_日志扫描_section',
    'log_dir',
    'file_pattern',
    'levels',
    'exclude_keywords',
    'poll_interval_seconds',
    'start_from_end',
    'context_before',
    'context_after',
    'max_lines_per_poll',
    '_AI 威胁分级_section',
    'classify_enable',
    'classify_mode',
    'classify_provider_id',
    'classify_timeout_seconds',
    'classify_system_prompt',
    'fallback_severity',
    'unmatched_severity',
    'transient_severity',
    'llm_max_block_lines',
    'llm_max_calls_per_round',
    'llm_max_calls_per_hour',
    'noise_shortcut',
    'kb_enabled',
    'kb_max_entries',
    'new_pattern_escalate',
    'route_map',
    'llm_provider_id',
    'chat_provider_id',
    'llm_timeout',
    'provider_id',
    '_通知预算 / 聚合 / 静默_section',
    'dedupe_window_seconds',
    'digest_interval_seconds',
    'digest_max_items',
    'max_alerts_per_round',
    'max_alerts_per_minute',
    'max_alerts_per_hour',
    'max_alerts_per_day',
    'burst_window_seconds',
    'burst_threshold',
    'burst_min_severity',
    'silence_ranges',
    'silence_min_severity',
    'channel_overrides',
    '_投递重试_section',
    'delivery_max_attempts',
    'delivery_base_delay_seconds',
    'delivery_retry_batch',
    '_状态 / 磁盘_section',
    'state_db_path',
    'fingerprint_ttl_hours',
    'history_retention_days',
    'history_max_rows',
    'outbox_max_bytes',
    'excerpt_mode',
    'keep_excerpt_files',
    'outbox_max_age_hours',
    'disk_report_interval_hours',
    '_紧急修复（dsh headless，默认关）_section',
    'remediation_enable',
    'remediation_dsh_command',
    'remediation_profile',
    'remediation_patch_overlay',
    'remediation_workdir',
    'remediation_timeout_seconds',
    'remediation_max_concurrency',
    'remediation_cooldown_seconds',
    'remediation_daily_limit',
    'remediation_permission_mode',
    'remediation_env_refs',
    'remediation_inherit_env',
    'remediation_artifact_dir',
    'remediation_artifact_keep',
    'remediation_artifact_max_age',
    'remediation_artifact_max_bytes',
    'remediation_max_output_bytes',
    'remediation_trace_raw',
    'remediation_prompt_template',
    'remediation_receipt',
    'remediate_confirm_count',
    'remediate_confidence_threshold',
    '_自反馈 / 管理白名单_section',
    'self_log_names',
    'self_feedback_ids',
    'admin_users',
)


def _schema() -> dict:
    return json.loads((_PLUGIN_DIR / "_conf_schema.json").read_text(encoding="utf-8"))


def _leaves(schema: dict) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for group, spec in schema.items():
        for leaf, leaf_spec in spec["items"].items():
            out.append((f"{group}.{leaf}", leaf_spec))
    return out


def _main_src() -> str:
    return (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")


# ---------- schema 形状 ----------


def test_schema_is_object_groups_in_declared_order() -> None:
    schema = _schema()
    assert tuple(schema) == config_map.GROUPS, "顶层分组与 config_map.GROUPS 必须逐字一致"
    for group, spec in schema.items():
        assert spec["type"] == "object", f"{group} 必须是 object（分组靠它渲染）"
        assert spec.get("description") and spec.get("hint"), f"{group} 缺 description/hint"
        assert isinstance(spec.get("items"), dict) and spec["items"], f"{group} 的 items 不能为空"


def test_schema_leaves_match_key_map_exactly() -> None:
    leaves = {path for path, _ in _leaves(_schema())}
    assert leaves == set(config_map.KEY_MAP), "schema 叶子与 KEY_MAP 必须双射"
    assert len(leaves) == 82


def test_every_leaf_keeps_description_hint_and_default() -> None:
    missing_desc = [path for path, spec in _leaves(_schema()) if not spec.get("description")]
    missing_hint = [path for path, spec in _leaves(_schema()) if not spec.get("hint")]
    missing_default = [path for path, spec in _leaves(_schema()) if "default" not in spec]
    assert not missing_desc, missing_desc
    assert not missing_hint, missing_hint
    assert not missing_default, missing_default


def test_leaf_description_carries_the_key_name() -> None:
    """WebUI 标签要能对上文档与日志：描述里必须出现叶子键名（市场插件的写法）。"""
    missing = [
        path
        for path, spec in _leaves(_schema())
        if path.split(".", 1)[1] not in spec["description"]
    ]
    assert not missing, missing


def test_no_pseudo_section_keys_left() -> None:
    """旧版用 `_xxx_section` 文本键假装分组；改成分组后必须一个都不剩。"""
    flat = [path for path, _ in _leaves(_schema())]
    assert not [key for key in flat if key.split(".", 1)[1].startswith("_")]
    assert not [key for key in config_map.KEY_MAP.values() if key.startswith("_")]


# ---------- 迁移契约 ----------


def test_migration_contract_covers_all_95_legacy_keys() -> None:
    assert len(LEGACY_KEYS_V210) == 95
    assert len(set(LEGACY_KEYS_V210)) == 95
    assert set(LEGACY_KEYS_V210) == set(config_map.KEY_MAP.values()) | set(
        config_map.DROPPED_LEGACY_KEYS
    ), "旧键要么被搬进新结构，要么在 DROPPED_LEGACY_KEYS 里明示丢弃"


def test_baseline_schema_keys_equal_the_frozen_contract() -> None:
    """与基线提交逐键对照（没有 git / 基线提交时跳过；生产副本里没有 .git，故用 skip）。"""
    try:
        raw = subprocess.run(
            ["git", "-C", str(_PLUGIN_DIR), "show", "e346ec9:_conf_schema.json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("没有 git 或基线提交 e346ec9（从临时副本跑测试时会这样）")
    assert tuple(json.loads(raw)) == LEGACY_KEYS_V210


def test_dropped_keys_are_only_sections_and_dead_keys() -> None:
    dropped = set(config_map.DROPPED_LEGACY_KEYS)
    assert len(dropped) == 13
    assert sum(1 for key in dropped if key.startswith("_")) == 8, "8 个伪分组标题"
    assert {"llm_provider_id", "chat_provider_id", "llm_timeout", "provider_id"} <= dropped
    assert "admin_users" in dropped


# ---------- main.py 读取点 ----------


def test_main_reads_only_mapped_dotted_paths() -> None:
    src = _main_src()
    assert 'self.config.get(' not in src, "读取点必须走 self.cfg（点号路径），不能再用扁平键"
    paths = set(__import__("re").findall(r'self\.cfg\.get\(\s*"([^"]+)"', src))
    assert paths, "没扫到任何读取点？正则或写法变了"
    unknown = sorted(paths - set(config_map.KEY_MAP))
    assert not unknown, f"main.py 读了 KEY_MAP 之外的路径：{unknown}"
    assert "self.cfg = config_map.ConfigView(" in src, "ConfigView 必须挂到 self.cfg"


# ---------- 访问层行为 ----------


def test_configview_prefers_nested_and_falls_back_to_legacy() -> None:
    nested = config_map.ConfigView({"notify": {"send_mode": "forward"}})
    assert nested.get("notify.send_mode", "auto") == "forward"
    assert nested.get("notify.prefer_forward", False) is False
    assert nested.legacy_hits() == ()

    legacy = config_map.ConfigView({"send_mode": "text", "target_sessions": ["a"]})
    assert legacy.get("notify.send_mode", "auto") == "text"
    assert legacy.get("notify.target_sessions", []) == ["a"]
    assert legacy.legacy_hits() == ("notify.send_mode", "notify.target_sessions")

    both = config_map.ConfigView({"send_mode": "text", "notify": {"send_mode": "forward"}})
    assert both.get("notify.send_mode") == "forward", "嵌套（新结构）优先于旧扁平键"


def test_configview_tolerates_empty_and_odd_config() -> None:
    assert config_map.ConfigView(None).get("scan.levels", ["ERROR"]) == ["ERROR"]
    assert config_map.ConfigView({"scan": "oops"}).get("scan.levels", ["ERROR"]) == ["ERROR"]


# ---------- 迁移函数 ----------


def _flat_sample() -> dict:
    """合成样本：键齐全、值都是可辨识的假值（**不含任何真实会话串**）。"""
    sample: dict[str, object] = {}
    for index, key in enumerate(LEGACY_KEYS_V210):
        sample[key] = f"v{index:03d}" if not key.startswith("_") else ""
    return sample


def test_nested_paths_and_flatten_roundtrip() -> None:
    flat = _flat_sample()
    nested = config_map.nested_paths(flat)
    assert len(nested) == 8
    assert sum(len(items) for items in nested.values()) == 82
    assert config_map.flatten(nested) == {
        key: value for key, value in flat.items() if key in config_map.LEGACY_TO_PATH
    }
    assert config_map.diff_effective(flat, nested) == []


def test_nested_paths_does_not_inject_defaults() -> None:
    nested = config_map.nested_paths({"send_mode": "text"})
    assert nested == {"notify": {"send_mode": "text"}}, "缺失的键交给核心按 schema 补默认，脚本不代填"


def test_migration_report_flags_unknown_missing_and_dropped() -> None:
    flat = _flat_sample()
    flat["谁家的键"] = 1
    del flat["send_mode"]
    report = config_map.migration_report(flat)
    assert report["unknown"] == ["谁家的键"]
    assert report["missing"] == ["send_mode"]
    assert sorted(report["dropped"]) == sorted(config_map.DROPPED_LEGACY_KEYS)


def test_diff_effective_reports_changed_and_missing_paths() -> None:
    flat = _flat_sample()
    nested = config_map.nested_paths(flat)
    nested["notify"]["send_mode"] = "改过了"
    del nested["scan"]["levels"]
    assert config_map.diff_effective(flat, nested) == ["notify.send_mode", "scan.levels"]


# ---------- 迁移 CLI ----------


def _write_legacy(path: Path, flat: dict) -> None:
    """按核心的口径写（utf-8-sig + 缩进 2），确保脚本要处理 BOM。"""
    path.write_text(json.dumps(flat, ensure_ascii=False, indent=2), encoding="utf-8-sig")


def test_migrate_cli_plan_apply_verify_and_noop(tmp_path: Path) -> None:
    config = tmp_path / "log_watcher_config.json"
    flat = _flat_sample()
    _write_legacy(config, flat)
    before = config.read_bytes()

    assert migrate.run(["--config", str(config)]) == migrate.EXIT_OK
    assert config.read_bytes() == before, "干跑不得写盘"
    assert migrate.find_backups(config) == [], "干跑不得写备份"

    assert migrate.run(["--config", str(config), "--apply"]) == migrate.EXIT_OK
    after = json.loads(config.read_text(encoding="utf-8-sig"))
    assert set(after) == set(config_map.GROUPS)
    backups = migrate.find_backups(config)
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8-sig")) == flat

    assert migrate.run(["--config", str(config), "--apply"]) == migrate.EXIT_ALREADY
    assert len(migrate.find_backups(config)) == 1, "重复运行不得再写一份备份"

    assert (
        migrate.run(["--config", str(config), "--verify", "--against", str(backups[0])])
        == migrate.EXIT_OK
    )

    tampered = json.loads(config.read_text(encoding="utf-8-sig"))
    tampered["notify"]["send_mode"] = "被改过"
    config.write_text(json.dumps(tampered, ensure_ascii=False, indent=2), encoding="utf-8-sig")
    assert (
        migrate.run(["--config", str(config), "--verify", "--against", str(backups[0])])
        == migrate.EXIT_MISMATCH
    )


def test_migrate_cli_repairs_from_backup_and_refuses_unknown(tmp_path: Path) -> None:
    config = tmp_path / "log_watcher_config.json"
    flat = _flat_sample()
    flat["谁家的键"] = 1
    _write_legacy(config, flat)

    assert migrate.run(["--config", str(config), "--apply"]) == migrate.EXIT_UNEXPECTED
    assert json.loads(config.read_text(encoding="utf-8-sig")) == flat, "拒绝写盘时文件必须原样"

    assert (
        migrate.run(["--config", str(config), "--apply", "--allow-unknown"]) == migrate.EXIT_OK
    )
    backup = migrate.find_backups(config)[0]

    # 换版窗口里被旧 schema 清回扁平：从备份重建
    _write_legacy(config, {"send_mode": "auto"})
    assert migrate.run(["--config", str(config), "--verify"]) == migrate.EXIT_MISMATCH
    assert (
        migrate.run(["--config", str(config), "--from-backup", str(backup)]) == migrate.EXIT_OK
    )
    rebuilt = json.loads(config.read_text(encoding="utf-8-sig"))
    assert rebuilt["notify"]["send_mode"] == flat["send_mode"]
    assert "谁家的键" not in json.dumps(rebuilt, ensure_ascii=False)


def test_migrate_cli_unusable_file(tmp_path: Path) -> None:
    assert migrate.run(["--config", str(tmp_path / "nope.json")]) == migrate.EXIT_UNUSABLE
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert migrate.run(["--config", str(broken)]) == migrate.EXIT_UNUSABLE
