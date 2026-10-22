#!/usr/bin/env python3
"""离线清理 v2.2.0 及更早版本的「自动修复」轨迹目录（v2.3.0 起只在离线做）。

**为什么单开一个离线脚本**：v2.3.0 移除了自动修复能力（执行器模块与 22 个配置键
一起删除，主循环里那个「每轮清理轨迹」的调用也一起没了）。但历史轨迹
（`run-<时间>-<指纹8>-<run_id>.jsonl`，首行是元数据）是**取证材料**，只能冻结、
不能随代码一起删；同时它们仍会占磁盘，将来总得有人清。

于是把这件能力挪到主循环之外：
- 插件里**一行都不留**（没有任何定时清理、没有配置键）；
- 谁要清，谁在这里跑一次（手工或自己的 cron），默认**干跑**。

清理规则沿用旧实现（取三条里更严者）：保留条数 / 最长留存 / 目录字节上限。

用法：

    # 1) 干跑：默认只看不删，打印将要删的文件与可释放字节
    python3 tools/prune_legacy_artifacts.py

    # 2) 真删（先备份或先确认上一步的输出）
    python3 tools/prune_legacy_artifacts.py --apply

    # 3) 自定义口径 / 指定目录 / 只看台账行数（只读，永不删行）
    python3 tools/prune_legacy_artifacts.py --keep 20 --max-age-days 3 --max-bytes 8MiB --apply
    python3 tools/prune_legacy_artifacts.py --dir /root/AstrBot/data/plugin_data/log_watcher/remediation
    python3 tools/prune_legacy_artifacts.py --db /root/AstrBot/data/plugin_data/log_watcher/log_watcher.sqlite3

**绝不删台账行**：`remediation_runs` 里的历史行是升级前的审计证据（v2.3.0 的
`store.reconcile_runs()` 只把遗留的 `running` 对账成 `aborted`）。`--db` 只读统计，
没有 `--delete-rows` 这种选项，以后也不要加。

退出码：0 正常 / 2 目录不存在或不可读。
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path

#: 插件包目录（本脚本在 <插件>/tools/ 下 ⇒ 上两级是插件目录）。
_PLUGIN_DIR = Path(__file__).resolve().parents[1]


def default_artifact_dir() -> Path:
    """旧默认轨迹目录：``<插件目录>/../../plugin_data/log_watcher/remediation``。

    旧实现（已删除的 `remediate.artifact_dir()`）按 ``__file__`` 推算，不依赖 cwd：
    ``<data>/plugins/log_watcher/remediate.py`` → ``<data>/plugin_data/log_watcher/remediation``。
    本脚本在 ``tools/`` 下，所以再上推一级。
    """
    return _PLUGIN_DIR.parents[1] / "plugin_data" / "log_watcher" / "remediation"


def _parse_bytes(text: str) -> int:
    """解析 ``64MiB`` / ``500MB`` / ``12345`` 这类体积写法（非法即报错退出）。"""
    raw = str(text).strip().lower().replace("_", "")
    units = {
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
    }
    for suffix, factor in sorted(units.items(), key=lambda item: -len(item[0])):
        if raw.endswith(suffix):
            number = raw[: -len(suffix)]
            try:
                return int(float(number) * factor)
            except ValueError:
                break
    try:
        return int(float(raw))
    except ValueError as exc:
        raise SystemExit(f"--max-bytes 无法解析：{text!r}（示例：64MiB / 1048576）") from exc


def plan(
    files: list[Path],
    *,
    keep: int,
    max_age_seconds: float,
    max_bytes: int,
    now: float | None = None,
) -> tuple[list[Path], dict[Path, int]]:
    """按三条规则挑出待删文件（取更严者），返回 (待删列表, 各文件字节数)。

    Args:
        files: 候选文件（调用方负责只传 ``run-*.jsonl``），按 mtime 升序。
        keep: 保留条数上限（``<=0`` 表示不按条数清）。
        max_age_seconds: 最长留存秒数（``<=0`` 表示不按年龄清）。
        max_bytes: 目录总字节上限（``<=0`` 表示不按体积清）。
        now: 当前时刻，默认系统时间。

    Returns:
        ``(doomed, sizes)``；``doomed`` 保持传入顺序（最旧的在前）。
    """
    moment = float(now if now is not None else time.time())
    sizes = {item: item.stat().st_size for item in files}
    doomed: set[Path] = set()
    if max_age_seconds > 0:
        doomed.update(
            item for item in files if moment - item.stat().st_mtime > max_age_seconds
        )
    if keep > 0 and len(files) > keep:
        doomed.update(files[: len(files) - keep])
    if max_bytes > 0:
        total = sum(sizes.values())
        for item in files:
            if total <= max_bytes:
                break
            if item in doomed:
                continue
            doomed.add(item)
            total -= sizes[item]
    return [item for item in files if item in doomed], sizes


def table_report(db_path: Path) -> list[tuple[str, int]]:
    """只读统计历史台账行的状态分布（**不删任何行**）。"""
    if not db_path.exists():
        print(f"台账不存在（跳过）：{db_path}")
        return []
    uri = f"file:{db_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        print(f"台账打不开（跳过）：{type(exc).__name__}: {exc}")
        return []
    try:
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM remediation_runs GROUP BY status ORDER BY status"
            ).fetchall()
        except sqlite3.Error as exc:
            print(f"没有历史台账表（跳过）：{type(exc).__name__}: {exc}")
            return []
    finally:
        conn.close()
    stats = [(str(row[0]), int(row[1])) for row in rows]
    print("历史台账行（只读，永不删除）：")
    if not stats:
        print("  （空）")
    for status, count in stats:
        print(f"  {status}: {count}")
    return stats


def main(argv: list[str] | None = None) -> int:
    """入口：默认干跑。"""
    parser = argparse.ArgumentParser(
        description="离线清理旧的「自动修复」轨迹目录（默认干跑；不删台账行）",
    )
    parser.add_argument(
        "--dir",
        default="",
        help="轨迹目录（默认 <data>/plugin_data/log_watcher/remediation）",
    )
    parser.add_argument("--keep", type=int, default=50, help="保留文件数上限（默认 50；<=0 关闭）")
    parser.add_argument(
        "--max-age-days", type=float, default=7.0, help="最长留存天数（默认 7；<=0 关闭）"
    )
    parser.add_argument(
        "--max-bytes", default="64MiB", help="目录字节上限（默认 64MiB；0 关闭）"
    )
    parser.add_argument("--db", default="", help="可选：同时只读打印历史台账行数")
    parser.add_argument("--apply", action="store_true", help="真的删除（默认只干跑）")
    args = parser.parse_args(argv)

    directory = Path(args.dir).expanduser() if args.dir else default_artifact_dir()
    print(f"轨迹目录：{directory}")
    if args.db:
        table_report(Path(args.db).expanduser())
    if not directory.is_dir():
        print("目录不存在或不是目录 —— 无需清理。")
        return 2
    try:
        files = sorted(
            (item for item in directory.glob("run-*.jsonl") if item.is_file()),
            key=lambda item: item.stat().st_mtime,
        )
    except OSError as exc:
        print(f"扫描失败：{type(exc).__name__}: {exc}")
        return 2
    doomed, sizes = plan(
        files,
        keep=int(args.keep),
        max_age_seconds=float(args.max_age_days) * 86400.0,
        max_bytes=_parse_bytes(args.max_bytes),
    )
    freed = sum(sizes[item] for item in doomed)
    print(
        f"候选 {len(files)} 个 / 共 {sum(sizes.values())} 字节；"
        f"待删 {len(doomed)} 个 / 可释放 {freed} 字节"
    )
    for item in doomed:
        print(f"  {'删除' if args.apply else '将删'}：{item.name}（{sizes[item]} 字节）")
    if not args.apply:
        print("干跑完成（未改动任何文件）。确认无误后加 --apply。")
        return 0
    deleted = 0
    for item in doomed:
        try:
            item.unlink()
        except OSError as exc:
            print(f"  失败（跳过）：{item.name}：{exc}")
            continue
        deleted += 1
    print(f"已删除 {deleted} 个文件，释放 {freed} 字节。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
