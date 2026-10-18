#!/usr/bin/env python3
"""log_watcher 配置迁移：v2.1.0 的扁平键 → v2.2.0 的分组结构。

**这个脚本为什么存在**：核心 `AstrBotConfig` 在插件加载时会把 schema 里没有的键判为 stale 键并
**从配置文件里删掉**（`astrbot_config.py` 的 `check_config_integrity()` + 随后的 `save_config()`）。
所以「先换版、再迁移」= 值已经没了。正确顺序是**先迁移配置、再换插件版本**（部署顺序见
`runbook.md` §1；派单在 `handoff/lanes/dev/`）。

用法（默认只干跑，不写盘；**任何模式都不打印配置值**，只回键名与计数）：

    # 1) 干跑体检：82 个键是否都能映射、有没有意料之外的键
    python3 tools/migrate_config_v2.py --config /root/AstrBot/data/config/log_watcher_config.json

    # 2) 落盘：先写 <配置>.bak-pre-v2.2.0-<ts>（原始扁平文件），再原子替换
    python3 tools/migrate_config_v2.py --config <配置> --apply

    # 3) 对照复核：逐叶子比对当前文件与备份，只回不一致的键名
    python3 tools/migrate_config_v2.py --config <配置> --verify --against <备份>

    # 4) 换版窗口里被旧 schema 抢先清过时，从备份重建
    python3 tools/migrate_config_v2.py --config <配置> --from-backup <备份>

退出码：0 成功 / 2 有未知键或键缺失（**拒绝写盘**）/ 3 复核不一致 / 4 已是新结构（no-op）/ 5 文件不可用。
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
BACKUP_TAG = "bak-pre-v2.2.0"

_DEFAULT_RELATIVE = Path("data") / "config" / "log_watcher_config.json"

EXIT_OK = 0
EXIT_UNEXPECTED = 2
EXIT_MISMATCH = 3
EXIT_ALREADY = 4
EXIT_UNUSABLE = 5


# ---------- 读写 ----------


def load_json(path: Path) -> dict:
    """读配置（核心写盘带 BOM，按 utf-8-sig 读以免 JSONDecodeError）。"""
    with open(path, encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} 顶层不是对象（{type(data).__name__}）")
    return data


def write_json_atomic(path: Path, data: dict) -> None:
    """按核心的口径写回：utf-8-sig + 缩进 2 + 原子替换（临时文件同目录，避免跨设备 rename）。"""
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


def is_migrated(data: dict) -> bool:
    """是否已是 v2.2.0 的分组结构（出现任一分组键即认为是）。"""
    return any(group in data for group in config_map.GROUPS)


def find_backups(config: Path) -> list[Path]:
    """已有的迁移前备份（按名字排序，最早的在前）。"""
    parent = config.parent
    if not parent.is_dir():
        return []
    return sorted(parent.glob(f"{config.name}.{BACKUP_TAG}-*"))


def ensure_backup(config: Path, flat: dict) -> Path | None:
    """确保迁移前备份存在；已存在则复用最早的（不覆盖、不多写）。"""
    existing = find_backups(config)
    if existing:
        return existing[0]
    stamp = time.strftime("%Y%m%d%H%M%S")
    backup = config.with_name(f"{config.name}.{BACKUP_TAG}-{stamp}")
    write_json_atomic(backup, flat)
    return backup


# ---------- 各模式 ----------


def _describe(flat: dict) -> tuple[dict[str, list[str]], int]:
    report = config_map.migration_report(flat)
    return report, len(config_map.LEGACY_TO_PATH)


def _print_report(config: Path, flat: dict) -> dict[str, list[str]]:
    report, expected = _describe(flat)
    print(f"配置文件：{config}")
    print(f"当前形态：旧扁平结构（{len(flat)} 键）")
    print(f"可映射  ：{expected - len(report['missing'])} / {expected}")
    print(f"将丢弃  ：{len(report['dropped'])}（伪分组标题 + 死键）")
    print(f"未知键  ：{len(report['unknown'])}" + (f" {report['unknown']}" if report["unknown"] else ""))
    print(f"缺值的键：{len(report['missing'])}" + (f" {report['missing']}" if report["missing"] else ""))
    return report


def do_plan(config: Path) -> int:
    flat = load_json(config)
    if is_migrated(flat):
        leaves = sum(
            len(flat[group]) for group in config_map.GROUPS if isinstance(flat.get(group), dict)
        )
        print(f"配置文件：{config}\n已是新结构（{len(config_map.GROUPS)} 组 / {leaves} 叶子），无需迁移。")
        print("复核：--verify --against <bak-pre-v2.2.0-*>")
        return EXIT_ALREADY
    report = _print_report(config, flat)
    if report["unknown"] or report["missing"]:
        print("\n⚠️ 有未知键或缺值：默认拒绝写盘。先确认上面列出的键名（本轮实测生产文件应两者皆 0）。")
        return EXIT_UNEXPECTED
    print("\n[干跑] 未写盘。确认后加 --apply 落盘（会先写一份 bak-pre-v2.2.0-<ts> 备份）。")
    return EXIT_OK


def do_apply(config: Path, *, allow_unknown: bool, flat: dict | None = None) -> int:
    if flat is None:
        flat = load_json(config)
    if is_migrated(flat):
        print(f"配置文件：{config}\n已是新结构，无需迁移（no-op）。")
        return EXIT_ALREADY
    report = _print_report(config, flat)
    if not allow_unknown and (report["unknown"] or report["missing"]):
        print("\n⚠️ 有未知键或缺值：拒绝写盘（要强行继续，加 --allow-unknown 并自行承担）。")
        return EXIT_UNEXPECTED
    nested = config_map.nested_paths(flat)
    backup = ensure_backup(config, flat)
    write_json_atomic(config, nested)
    leaves = sum(len(items) for items in nested.values())
    print(f"\n备份：{backup}（{len(flat)} 键，原始扁平结构）")
    print(f"已写入：{config}（{len(nested)} 组 / {leaves} 叶子，utf-8-sig + 缩进 2 + 原子替换）")
    print(f"下一步复核：python3 {Path(__file__).resolve()} --config {config} --verify --against {backup}")
    return EXIT_OK


def do_verify(config: Path, against: Path | None) -> int:
    current = load_json(config)
    if not is_migrated(current):
        print(f"配置文件：{config}\n❌ 仍是旧扁平结构：迁移没生效（或已被旧 schema 清回）。")
        return EXIT_MISMATCH
    if against is None:
        leaves = sum(
            len(current[group]) for group in config_map.GROUPS if isinstance(current.get(group), dict)
        )
        print(f"配置文件：{config}\n新结构在位（{leaves} 叶子）；未给 --against，跳过逐值对照。")
        return EXIT_OK
    before = load_json(against)
    mismatched = config_map.diff_effective(before, current)
    total = len(config_map.LEGACY_TO_PATH)
    print(f"对照：{against}（旧） vs {config}（新）")
    if mismatched:
        print(f"❌ 不一致 {len(mismatched)} / {total}：{mismatched}")
        return EXIT_MISMATCH
    print(f"✅ 一致 {total} / {total}（逐叶子等值；未打印任何值）")
    return EXIT_OK


def do_from_backup(config: Path, backup: Path) -> int:
    flat = load_json(backup)
    if is_migrated(flat):
        print(f"备份 {backup} 本身就是新结构，不是迁移前备份；中止。")
        return EXIT_UNUSABLE
    print(f"从备份重建：{backup}")
    return do_apply(config, allow_unknown=True, flat=flat)


# ---------- 入口 ----------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="log_watcher 配置迁移（v2.1.0 扁平键 → v2.2.0 分组结构）；默认干跑，不打印任何配置值。",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=f"插件配置文件路径（默认 {_DEFAULT_RELATIVE}，相对当前目录）",
    )
    parser.add_argument("--apply", action="store_true", help="落盘（会先写 bak-pre-v2.2.0-<ts> 备份）")
    parser.add_argument("--verify", action="store_true", help="复核当前文件是否已是新结构、是否与备份等值")
    parser.add_argument("--against", type=Path, help="--verify 的对照备份")
    parser.add_argument("--from-backup", type=Path, help="从迁移前备份重建（换版窗口被旧 schema 清过时用）")
    parser.add_argument("--allow-unknown", action="store_true", help="有未知键也继续（默认拒绝）")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = args.config or _DEFAULT_RELATIVE
    if not config.is_file():
        print(f"❌ 找不到配置文件：{config}（用 --config 指定）")
        return EXIT_UNUSABLE
    try:
        if args.verify:
            return do_verify(config, args.against)
        if args.from_backup:
            return do_from_backup(config, args.from_backup)
        if args.apply:
            return do_apply(config, allow_unknown=args.allow_unknown)
        return do_plan(config)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"❌ 配置不可用：{exc!r}")
        return EXIT_UNUSABLE


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
