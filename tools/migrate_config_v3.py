#!/usr/bin/env python3
"""log_watcher 配置迁移：v2.2.0（8 组 / 82 键）→ v2.3.0（8 组 / 69 键）。

**为什么必须离线迁移、而且必须先于换版**：核心 `AstrBotConfig` 在插件加载时会把 schema 里
没有的键判为 stale 键并从配置文件里删掉（`check_config_integrity()` + `save_config()`）。
v2.3.0 删掉了整个 `remediation` 组（22 个键）、新增了 `report` 组（7 个键）与两个判定键
（`classify.prior_ttl_hours` / `classify.repeat_window_seconds`），所以正确顺序是
**先跑本脚本、再换插件版本**（部署顺序见 `runbook.md` §1.3 / `handoff/lanes/dev/`）。

本脚本做三件事（**任何模式都不打印配置值**，只回键名与计数）：

1. 删除 `remediation` 组（22 个键）—— 这 22 个旧扁平键名是 v2.3.0 的冻结契约
   （`tests/test_config_map.py::DROPPED_IN_V230` 的同名单）；本脚本把它们归为
   **dropped**（明示删除），**不是** unknown（配置写错/第三方残留）；
2. 补齐 v2.3.0 新增的 9 个叶子：`classify.prior_ttl_hours`、`classify.repeat_window_seconds`
   与 `report` 组 7 键；补的值来自 `_conf_schema.json` 的默认值（唯一事实源）；
3. 其余键**原值保留**（只搬结构，不改值）。

用法（默认干跑，不写盘）：

    # 1) 干跑体检：列出将删除的 22 个键、将补默认值的 9 个键、未知键
    python3 tools/migrate_config_v3.py --dry-run --config <v2.2.0 配置副本>

    # 2) 落盘：先写 <配置>.bak-pre-v2.3.0-<ts> 备份，再原子替换（utf-8-sig + 缩进 2）
    python3 tools/migrate_config_v3.py --apply --config <配置>

    # 3) 对照复核：逐叶子比对当前文件与备份（只回不一致的键名）
    python3 tools/migrate_config_v3.py --verify --config <配置> --against <备份>

    # 4) 换版窗口里被旧 schema 抢先清过时，从备份重建
    python3 tools/migrate_config_v3.py --from-backup <备份> --config <配置>

退出码：0 成功 / 2 有未知键或结构不可迁移（**拒绝写盘**）/ 3 复核不一致 /
4 已是 v2.3.0（no-op）/ 5 文件不可用。

**不碰生产配置**：本脚本只操作 `--config` 指定的文件（默认相对当前目录的
`data/config/log_watcher_config.json`）。升级前请先把配置复制到 /tmp 做干跑；
在真实配置上 `--apply` 之前，必须已经完成 §8.1 的备份。

只支持 v2.2.0（分组结构）→ v2.3.0。若仓库/部署还停在 v2.1.0 的 95 键扁平结构，
先跑 `tools/migrate_config_v2.py` 升到 v2.2.0，再跑本脚本（脚本会明确拒绝扁平结构）。

仓库自带一份**合成假值**的 v2.2.0 样本（`tools/fixtures/log_watcher_config_v2.2.0.sample.json`，
82 键、不含任何生产值），可直接用来练干跑/落盘/复核：

    python3 tools/migrate_config_v3.py --dry-run --config \
        tools/fixtures/log_watcher_config_v2.2.0.sample.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PLUGIN_DIR = _HERE.parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import config_map  # noqa: E402

#: 迁移前备份的文件名后缀（只写一次；重复运行复用最早的备份，避免把中间态当原始态）。
BACKUP_TAG = "bak-pre-v2.3.0"
_RESTORE_TAG = "bak-pre-restore-v2.2.0"
_DEFAULT_RELATIVE = Path("data") / "config" / "log_watcher_config.json"

EXIT_OK = 0
EXIT_UNEXPECTED = 2
EXIT_MISMATCH = 3
EXIT_ALREADY = 4
EXIT_UNUSABLE = 5

#: v2.3.0 删除的 22 个旧扁平键 → v2.2.0 分组结构里的叶子名。
#: 这份名单与 `tests/test_config_map.py::DROPPED_IN_V230` 是**同一事实**的两处表述：
#: 测试冻结「旧扁平键名」（迁移契约），本脚本需要「叶子名」（在嵌套配置里定位）。
#: 它们**不是** unknown：v2.2.0 的 schema 里确实有这些键，v2.3.0 明确删除。
REMOVED_V230_FLAT: dict[str, str] = {
    "remediation_enable": "enable",
    "remediation_dsh_command": "dsh_command",
    "remediation_profile": "profile",
    "remediation_patch_overlay": "patch_overlay",
    "remediation_workdir": "workdir",
    "remediation_timeout_seconds": "timeout_seconds",
    "remediation_max_concurrency": "max_concurrency",
    "remediation_cooldown_seconds": "cooldown_seconds",
    "remediation_daily_limit": "daily_limit",
    "remediation_permission_mode": "permission_mode",
    "remediation_env_refs": "env_refs",
    "remediation_inherit_env": "inherit_env",
    "remediation_artifact_dir": "artifact_dir",
    "remediation_artifact_keep": "artifact_keep",
    "remediation_artifact_max_age": "artifact_max_age",
    "remediation_artifact_max_bytes": "artifact_max_bytes",
    "remediation_max_output_bytes": "max_output_bytes",
    "remediation_trace_raw": "trace_raw",
    "remediation_prompt_template": "prompt_template",
    "remediation_receipt": "receipt",
    "remediate_confirm_count": "confirm_count",
    "remediate_confidence_threshold": "confidence_threshold",
}
REMOVED_GROUP = "remediation"


def _load_schema() -> dict:
    """读 `_conf_schema.json`（默认值的唯一事实源）。"""
    with open(_PLUGIN_DIR / "_conf_schema.json", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or tuple(data) != config_map.GROUPS:
        raise ValueError("_conf_schema.json 的分组与 config_map.GROUPS 不一致")
    return data


def _schema_defaults(schema: dict) -> dict[str, dict[str, object]]:
    """逐叶子默认值：``{group: {leaf: default}}``（只用于补新键，不回显值）。"""
    return {
        group: {leaf: spec["default"] for leaf, spec in spec_group["items"].items()}
        for group, spec_group in schema.items()
    }


# ---------- 读写 ----------


def load_json(path: Path) -> dict:
    """读配置（核心写盘带 BOM，按 utf-8-sig 读以免 JSONDecodeError）。"""
    with open(path, encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} 顶层不是对象（{type(data).__name__}）")
    return data


def write_json_atomic(path: Path, data: dict) -> None:
    """按核心的口径写回：utf-8-sig + 缩进 2 + 原子替换（临时文件同目录）。"""
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        dir=str(directory), prefix=f".{path.name}.", suffix=".tmp"
    )
    committed = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        committed = True
    finally:
        if not committed:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def find_backups(config: Path) -> list[Path]:
    """已有的 v2.2.0 迁移前备份（按名字排序，最早的在前）。"""
    parent = config.parent
    if not parent.is_dir():
        return []
    return sorted(parent.glob(f"{config.name}.{BACKUP_TAG}-*"))


def ensure_backup(config: Path, before: dict) -> Path:
    """确保迁移前备份存在；已存在则复用最早的（不覆盖、不多写）。"""
    existing = find_backups(config)
    if existing:
        return existing[0]
    stamp = time.strftime("%Y%m%d%H%M%S")
    backup = config.with_name(f"{config.name}.{BACKUP_TAG}-{stamp}")
    write_json_atomic(backup, before)
    return backup


# ---------- 结构判定 ----------


def is_grouped(data: dict) -> bool:
    """是否已是 v2.2.0+ 的分组结构（出现任一分组键即认为是）。"""
    return any(group in data for group in config_map.GROUPS)


def is_v230(data: dict) -> bool:
    """是否已是 v2.3.0 终态：8 组都在、没有 remediation 组、69 个目标叶子齐全。"""
    if REMOVED_GROUP in data:
        return False
    if any(group not in data or not isinstance(data.get(group), dict) for group in config_map.GROUPS):
        return False
    nested = {
        f"{group}.{leaf}" for group, items in data.items() if isinstance(items, dict) for leaf in items
    }
    return config_map.all_paths() <= nested


def inspect(data: dict, targets: dict[str, dict[str, object]]) -> dict[str, list[str]]:
    """体检（只回键名）：dropped / fill / unknown / missing_groups。"""
    dropped = [
        f"{REMOVED_GROUP}.{leaf}"
        for legacy, leaf in REMOVED_V230_FLAT.items()
        if leaf in (data.get(REMOVED_GROUP) or {})
    ]
    fill: list[str] = []
    unknown: list[str] = []
    for group, items in data.items():
        if group == REMOVED_GROUP:
            continue
        if group not in config_map.GROUPS:
            unknown.append(group)
            continue
        if not isinstance(items, dict):
            unknown.append(group)
            continue
        allowed = targets.get(group, {})
        for leaf in items:
            if leaf not in allowed:
                unknown.append(f"{group}.{leaf}")
    for group, leaves in targets.items():
        current = data.get(group)
        bucket = current if isinstance(current, dict) else {}
        for leaf in leaves:
            if leaf not in bucket:
                fill.append(f"{group}.{leaf}")
    missing_groups = [group for group in config_map.GROUPS if not isinstance(data.get(group), dict)]
    return {"dropped": dropped, "fill": fill, "unknown": unknown, "missing_groups": missing_groups}


def migrate(data: dict, targets: dict[str, dict[str, object]]) -> dict:
    """执行迁移：按 schema 顺序重建 8 组；保留旧值、删 remediation、补新键默认值。"""
    out: dict[str, dict] = {}
    for group in config_map.GROUPS:
        current = data.get(group) if isinstance(data.get(group), dict) else {}
        bucket: dict[str, object] = {}
        for leaf, default in targets[group].items():
            bucket[leaf] = current[leaf] if leaf in current else default
        out[group] = bucket
    return out


# ---------- 各模式 ----------


def _print_plan(config: Path, data: dict, info: dict[str, list[str]]) -> None:
    leaves = sum(
        len(items) for items in data.values() if isinstance(items, dict)
    )
    print(f"配置文件：{config}")
    print(f"当前形态：v2.2.0 分组结构（{len(data)} 个顶层键 / {leaves} 个叶子）")
    print(f"将删除  ：{len(info['dropped'])} / {len(REMOVED_V230_FLAT)} 个键（remediation 整组）")
    for path in info["dropped"]:
        group, leaf = path.split(".", 1)
        legacy = next((k for k, v in REMOVED_V230_FLAT.items() if v == leaf), "")
        print(f"  - {path}（旧扁平键 {legacy}）")
    print(f"将补默认值：{len(info['fill'])} 个键（v2.3.0 新增；值来自 _conf_schema.json）")
    for path in info["fill"]:
        print(f"  + {path}")
    if info["missing_groups"]:
        print(f"缺组  ：{info['missing_groups']}（会按 schema 补齐）")
    if info["unknown"]:
        print(f"未知键：{len(info['unknown'])} {info['unknown']}")


def do_plan(config: Path, targets: dict[str, dict[str, object]]) -> int:
    data = load_json(config)
    if not is_grouped(data):
        print(
            f"配置文件：{config}\n❌ 仍是 v2.1.0 的扁平结构（或根本不是本插件配置）。"
            "\n请先跑 tools/migrate_config_v2.py 升到 v2.2.0，再跑本脚本。"
        )
        return EXIT_UNEXPECTED
    if is_v230(data):
        print(f"配置文件：{config}\n已是 v2.3.0（8 组 / 69 键），无需迁移。")
        print("复核：--verify --against <bak-pre-v2.3.0-*>")
        return EXIT_ALREADY
    info = inspect(data, targets)
    _print_plan(config, data, info)
    if info["unknown"]:
        print("\n⚠️ 有未知键：默认拒绝写盘。先确认上面列出的键名。")
        return EXIT_UNEXPECTED
    print("\n[干跑] 未写盘。确认后加 --apply 落盘（会先写一份 bak-pre-v2.3.0-<ts> 备份）。")
    return EXIT_OK


def do_apply(
    config: Path,
    targets: dict[str, dict[str, object]],
    *,
    allow_unknown: bool,
    source: dict | None = None,
) -> int:
    data = source if source is not None else load_json(config)
    if not is_grouped(data):
        print(
            f"配置文件：{config}\n❌ 不是 v2.2.0 分组结构；先跑 tools/migrate_config_v2.py。"
        )
        return EXIT_UNEXPECTED
    if is_v230(data):
        print(f"配置文件：{config}\n已是 v2.3.0，无需迁移（no-op）。")
        return EXIT_ALREADY
    info = inspect(data, targets)
    if source is None:
        _print_plan(config, data, info)
    if not allow_unknown and info["unknown"]:
        print("\n⚠️ 有未知键：拒绝写盘（要强行继续，加 --allow-unknown 并自行承担）。")
        return EXIT_UNEXPECTED
    if source is None:
        backup = ensure_backup(config, data)
    else:
        stamp = time.strftime("%Y%m%d%H%M%S")
        backup = config.with_name(f"{config.name}.{_RESTORE_TAG}-{stamp}")
        if config.exists():
            write_json_atomic(backup, load_json(config))
    nested = migrate(data, targets)
    write_json_atomic(config, nested)
    leaves = sum(len(items) for items in nested.values())
    print(f"\n备份：{backup}")
    print(f"已写入：{config}（{len(nested)} 组 / {leaves} 叶子，utf-8-sig + 缩进 2 + 原子替换）")
    print(f"删除 {len(info['dropped'])} 个键；补默认值 {len(info['fill'])} 个键；未知键 {len(info['unknown'])} 个")
    print(f"下一步复核：python3 {Path(__file__).resolve()} --verify --config {config} --against {backup}")
    return EXIT_OK


def do_verify(
    config: Path, against: Path | None, targets: dict[str, dict[str, object]]
) -> int:
    current = load_json(config)
    if not is_v230(current):
        print(f"配置文件：{config}\n❌ 不是 v2.3.0 终态（8 组 / 69 键）：迁移没生效或被旧 schema 清回。")
        if REMOVED_GROUP in current:
            print("  仍存在 remediation 组 ⇒ 还没跑 --apply。")
        return EXIT_MISMATCH
    leaves = sum(len(items) for items in current.values())
    if against is None:
        print(f"配置文件：{config}\n✅ v2.3.0 结构在位（{len(current)} 组 / {leaves} 叶子）；未给 --against，跳过逐值对照。")
        return EXIT_OK
    before = load_json(against)
    if not is_grouped(before) or is_v230(before):
        print(f"❌ 对照备份不是 v2.2.0 结构：{against}")
        return EXIT_UNUSABLE
    mismatched: list[str] = []
    checked = 0
    for group, leaves_ in targets.items():
        old = before.get(group) if isinstance(before.get(group), dict) else {}
        new = current.get(group) if isinstance(current.get(group), dict) else {}
        for leaf in leaves_:
            if leaf not in old:
                continue  # v2.3.0 新增键：备份里本来就没有，不参与等值对照
            checked += 1
            if old.get(leaf) != new.get(leaf):
                mismatched.append(f"{group}.{leaf}")
    print(f"对照：{against}（v2.2.0） vs {config}（v2.3.0）")
    if mismatched:
        print(f"❌ 不一致 {len(mismatched)} / {checked}：{mismatched}")
        return EXIT_MISMATCH
    print(f"✅ 一致 {checked} / {checked}（逐叶子等值；未打印任何值）")
    print(f"   另有 {len(REMOVED_V230_FLAT)} 个 remediation 键按契约删除、"
          f"{sum(len(v) for v in targets.values()) - checked} 个新键按默认值补齐。")
    return EXIT_OK


def do_from_backup(
    config: Path, backup: Path, targets: dict[str, dict[str, object]]
) -> int:
    data = load_json(backup)
    if not is_grouped(data) or is_v230(data):
        print(f"备份 {backup} 不是 v2.2.0 结构（需要迁移前备份）；中止。")
        return EXIT_UNUSABLE
    print(f"从备份重建：{backup}")
    return do_apply(config, targets, allow_unknown=True, source=data)


# ---------- 入口 ----------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "log_watcher 配置迁移（v2.2.0 的 8 组 / 82 键 → v2.3.0 的 8 组 / 69 键）；"
            "默认干跑，不打印任何配置值。"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=f"插件配置文件路径（默认 {_DEFAULT_RELATIVE}，相对当前目录）",
    )
    parser.add_argument("--dry-run", action="store_true", help="干跑体检（默认行为）")
    parser.add_argument(
        "--apply", action="store_true", help="落盘（会先写 bak-pre-v2.3.0-<ts> 备份）"
    )
    parser.add_argument("--verify", action="store_true", help="复核当前文件是否已是 v2.3.0、与备份等值")
    parser.add_argument("--against", type=Path, help="--verify 的对照备份（v2.2.0）")
    parser.add_argument(
        "--from-backup", type=Path, help="从 v2.2.0 迁移前备份重建（换版窗口被旧 schema 清过时用）"
    )
    parser.add_argument("--allow-unknown", action="store_true", help="有未知键也继续（默认拒绝）")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = args.config or _DEFAULT_RELATIVE
    try:
        targets = _schema_defaults(_load_schema())
    except (OSError, ValueError, KeyError) as exc:
        print(f"❌ 读 schema 失败：{type(exc).__name__}: {exc}")
        return EXIT_UNUSABLE
    if args.from_backup is not None:
        if not args.from_backup.is_file():
            print(f"❌ 找不到备份：{args.from_backup}")
            return EXIT_UNUSABLE
        try:
            return do_from_backup(config, args.from_backup, targets)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            print(f"❌ 备份/配置不可用：{type(exc).__name__}")
            return EXIT_UNUSABLE
    if not config.is_file():
        print(f"❌ 找不到配置文件：{config}（用 --config 指定）")
        return EXIT_UNUSABLE
    try:
        if args.verify:
            return do_verify(config, args.against, targets)
        if args.apply:
            return do_apply(config, targets, allow_unknown=args.allow_unknown)
        return do_plan(config, targets)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"❌ 配置不可用：{type(exc).__name__}: {exc}")
        return EXIT_UNUSABLE


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
