"""log_watcher 的状态与磁盘持久化。

本模块只依赖标准库，可离线单测。三条不变量：
1. 落盘必须原子（临时文件 + fsync + os.replace），进程被杀不会留下半个 JSON；
2. R11：状态持久化的唯一实现是 SQLite（WAL，每轮单事务，读走内存缓存），
   JSON 只作为迁移来源（`*.json.migrated-<ts>` 留痕，不删除）；
3. 成功与失败两类磁盘残留走同一套硬上限治理，并随时能报告当前占用。

SQLite 连接是单连接 + 一把 `threading.Lock` 串行化，只在 `asyncio.to_thread()` 里使用
（§9.4：禁止在事件循环里直接执行 sqlite）。打不开/损坏时进入"内存态"降级：
`SqliteStore.available` 为假，调用方改用 `PendingQueue`/`CounterStore` 的内存实现，
保证"状态库坏了也不至于让日志监听整体静默"（§9.4 第 5 条）。
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

_WINDOW_MAX_AGE = 7200.0
_WINDOW_MAX_LEN = 1024
SCHEMA_VERSION = 3
"""状态库结构版本。

- v1 → v2：补 ``alerts.excerpt_lines`` / ``remediation_runs.task_sha1|argv`` /
  ``pending_delivery.excerpt_path``；
- v2 → v3（v2.3.0 判定链）：``pattern_kb`` 补 ``last_judged_at`` / ``judge_source``
  （某指纹最后一次**真判**的时间与依据），``alerts`` 补 ``judged`` / ``judge_source``
  （台账里能区分「模型判过」与「本地/降级/人工」）。历史行**不回填**：
  ``judge_source=''``、``judged=-1`` 表示「未知」，绝不假装当时判过（假审计）。
"""
_PRUNE_DELETE_CAP = 500
#: v2.3.0：`remediation_runs` 只做历史保留与对账（不再写入）。孤儿 running 行的宽限秒数
#: 固定为旧版「2 × 默认超时 300s」，配置键随自动修复通道一并移除。
_LEGACY_RUN_GRACE = 600.0

DEFAULT_COUNTERS: dict = {
    "rounds": 0,
    "lines_read": 0,
    "hits": 0,
    "alerts_sent": 0,
    "digest_buffered": 0,
    "digest_flushed": 0,
    "suppressed_dedup": 0,
    "suppressed_silence": 0,
    "suppressed_budget": 0,
    "burst_coalesced": 0,
    "ignored": 0,
    "delivery_ok": 0,
    "delivery_degraded": 0,
    "delivery_failed": 0,
    "delivery_retries": 0,
    "delivery_abandoned": 0,
    "fingerprints": {},
    "windows": {},
    "digest_buffer": [],
    "burst": {"started": 0.0, "count": 0, "items": []},
}


FILE_MODE = 0o600
"""新建状态/摘录/轨迹文件的目标权限（F09：这些文件含日志摘录与运行轨迹）。"""

DIR_MODE = 0o700
"""插件数据目录的目标权限（F09）。"""


def secure_path(path: Path, mode: int) -> bool:
    """尽力收窄权限（F09）；失败只返回 False，绝不抛异常打断主流程。"""
    try:
        os.chmod(path, mode)
    except OSError:
        return False
    return True


def harden_tree(root: Path, *, keep_dir_mode: bool = True) -> int:
    """把既有落盘文件/目录权限收窄到 0600/0700（F09 的一次性加固，启动时调用）。

    Args:
        root: 插件数据目录。
        keep_dir_mode: 是否同时把目录收到 0700。

    Returns:
        成功收窄的文件/目录数量（失败项静默跳过）。
    """
    fixed = 0
    try:
        entries = list(Path(root).rglob("*"))
    except OSError:
        return 0
    for item in entries:
        try:
            if item.is_dir():
                if keep_dir_mode and secure_path(item, DIR_MODE):
                    fixed += 1
            elif item.is_file() and secure_path(item, FILE_MODE):
                fixed += 1
        except OSError:
            continue
    return fixed


def atomic_write_text(path: Path, text: str) -> None:
    """原子写文本：同目录临时文件 → flush+fsync → os.replace。

    Args:
        path: 目标文件路径。
        text: 要写入的内容。

    Raises:
        OSError: 目标目录不可写或替换失败时抛出（调用方决定是否降级）。
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    secure_path(target.parent, DIR_MODE)
    tmp = target.with_name(f"{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        secure_path(target, FILE_MODE)  # F09：状态/摘录/轨迹一律 0600
    finally:
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()


def atomic_write_json(path: Path, payload: object) -> None:
    """原子写 JSON（ensure_ascii=False，便于人工核对落盘内容）。"""
    atomic_write_text(
        path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    )


def read_json(path: Path, default: object = None) -> object:
    """读取 JSON；文件缺失或内容损坏时返回 default，绝不抛异常。"""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError:
        return default
    try:
        return json.loads(raw)
    except ValueError:
        return default


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _strict_int(value: object) -> int | None:
    """严格整数解析：只有整数/整数形态的字符串才算数，用于丢弃损坏的状态条目。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and float(value).is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("+-").isdigit():
            return int(text)
    return None


class TailStateStore:
    """日志读取进度（device/inode/offset/skip_to_eol）的持久化容器。

    v2 起进度以 `SqliteStore.file_progress` 为准，本类只作为**内存视图 + 迁移来源**：
    `load()` 读旧 `tail_state.json`，`export_rows()` 交给 `upsert_progress()` 落库。
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self.files: dict[str, dict] = {}

    def load(self) -> TailStateStore:
        """从 JSON 载入并逐条规整；损坏条目丢弃（下次按首启定位重新取位）。"""
        raw = read_json(self.path, {}) if self.path else {}
        files = raw.get("files") if isinstance(raw, dict) else None
        self.files = {}
        if not isinstance(files, dict):
            return self
        for key, value in files.items():
            state = self._sanitize(value)
            if state is not None:
                self.files[str(key)] = state
        return self

    @staticmethod
    def _sanitize(value: object) -> dict | None:
        if not isinstance(value, dict):
            return None
        device = _strict_int(value.get("device"))
        inode = _strict_int(value.get("inode"))
        offset = _strict_int(value.get("offset"))
        if device is None or inode is None or offset is None:
            return None
        return {
            "device": device,
            "inode": inode,
            "offset": max(0, offset),
            "skip_to_eol": bool(value.get("skip_to_eol", False)),
        }

    def get(self, key: str) -> dict | None:
        """取某文件的进度（返回副本，避免调用方误改内存状态）。"""
        state = self.files.get(key)
        return dict(state) if state else None

    def set(self, key: str, state: dict) -> None:
        """写入某文件的进度，非法 state 忽略（防止污染落盘内容）。"""
        clean = self._sanitize(state)
        if clean is not None:
            self.files[str(key)] = clean

    def export_rows(self, *, now: float | None = None) -> list[dict]:
        """导出为 `SqliteStore.upsert_progress()` 需要的行。"""
        moment = time.time() if now is None else float(now)
        return [
            {
                "path": key,
                "device": state["device"],
                "inode": state["inode"],
                "offset": state["offset"],
                "size": state.get("size", 0),
                "updated_at": moment,
            }
            for key, state in self.files.items()
        ]

    def import_rows(self, rows: Mapping[str, Mapping]) -> None:
        """从 `SqliteStore.progress()` 的结果反向装入内存视图。"""
        for key, row in (rows or {}).items():
            self.set(
                str(key),
                {
                    "device": row.get("device", 0),
                    "inode": row.get("inode", 0),
                    "offset": row.get("offset", 0),
                    "skip_to_eol": bool(row.get("skip_to_eol", False)),
                },
            )

    def save(self) -> bool:
        """原子落盘（仅迁移/兼容用；生产路径以 SQLite 为准）。"""
        if self.path is None:
            return False
        try:
            atomic_write_json(self.path, {"version": 1, "files": self.files})
        except OSError:
            return False
        return True


class CounterStore:
    """计数器与滑动窗口的**本轮内存视图**（每轮交给 SqliteStore 落库）。

    `save()/load()` 保留给迁移与离线测试；生产路径由 main 在每轮尾部
    `export_state()` → `SqliteStore.meta_set("counters_state", …)`。
    """

    def __init__(self, path: Path | None = None, data: dict | None = None):
        self.path = Path(path) if path else None
        self.data: dict = json.loads(json.dumps(DEFAULT_COUNTERS))
        if isinstance(data, dict):
            self.data.update(data)

    def load(self) -> CounterStore:
        """从磁盘载入计数器（缺字段用默认值补齐，形状永远完整）。"""
        raw = read_json(self.path, {}) if self.path else {}
        payload = raw.get("counters") if isinstance(raw, dict) else None
        if isinstance(payload, dict):
            self.import_state(payload)
        return self

    def save(self) -> bool:
        """原子落盘（迁移/兼容用），返回是否成功。"""
        if self.path is None:
            return False
        try:
            atomic_write_json(self.path, {"version": 1, "counters": self.data})
        except OSError:
            return False
        return True

    def export_state(self) -> dict:
        """导出完整状态（供 SQLite `meta` 承载，跨重启精确恢复行窗与桶）。"""
        return json.loads(json.dumps(self.data))

    def import_state(self, state: object) -> CounterStore:
        """从 SQLite/meta 状态恢复（未知键忽略，缺键用默认值补齐）。"""
        merged = json.loads(json.dumps(DEFAULT_COUNTERS))
        if isinstance(state, Mapping):
            for key, value in state.items():
                merged[key] = value
        self.data = merged
        return self

    def snapshot(self) -> dict:
        """深拷贝当前计数，用于断言「进程内 == 落盘」。"""
        return json.loads(json.dumps(self.data))

    # ---------- 标量与子字典 ----------

    def get_int(self, name: str, default: int = 0) -> int:
        """读一个整数计数。"""
        return _as_int(self.data.get(name, default), default)

    def bump(self, name: str, delta: int = 1) -> int:
        """自增一个整数计数并返回新值。"""
        current = self.get_int(name) + int(delta)
        self.data[name] = current
        return current

    def sub(self, section: str) -> dict:
        """取一个子字典（不存在则建立），用于按名细分统计。"""
        value = self.data.get(section)
        if not isinstance(value, dict):
            value = {}
            self.data[section] = value
        return value

    def bump_sub(self, section: str, key: str, delta: int = 1) -> int:
        """自增子字典里的一个计数。"""
        bucket = self.sub(section)
        current = _as_int(bucket.get(key, 0)) + int(delta)
        bucket[key] = current
        return current

    # ---------- 指纹 ----------

    def fingerprint_info(self, fingerprint: str) -> dict:
        """取某指纹的统计（不存在时返回计数为 0 的空记录）。"""
        table = self.sub("fingerprints")
        value = table.get(fingerprint)
        if not isinstance(value, dict):
            return {"first_ts": 0.0, "last_ts": 0.0, "count": 0}
        return {
            "first_ts": _as_float(value.get("first_ts")),
            "last_ts": _as_float(value.get("last_ts")),
            "count": _as_int(value.get("count")),
        }

    def touch_fingerprint(self, fingerprint: str, now: float) -> int:
        """记录一次指纹出现，返回累计出现次数。"""
        info = self.fingerprint_info(fingerprint)
        self.sub("fingerprints")[fingerprint] = {
            "first_ts": info["first_ts"] or float(now),
            "last_ts": float(now),
            "count": info["count"] + 1,
        }
        return info["count"] + 1

    def prune_fingerprints(self, now: float, older_than: float) -> int:
        """清理久未出现的指纹，返回清理条数（防止状态无序增长）。"""
        table = self.sub("fingerprints")
        dead = [
            key
            for key, value in table.items()
            if isinstance(value, dict)
            and float(now) - _as_float(value.get("last_ts")) > float(older_than)
        ]
        for key in dead:
            table.pop(key, None)
        return len(dead)

    # ---------- 滑动窗口 ----------

    def window_push(self, name: str, now: float) -> None:
        """往某个窗口追加一个时间戳（自动剪掉过期项与超长历史）。"""
        windows = self.sub("windows")
        stamps = windows.get(name)
        if not isinstance(stamps, list):
            stamps = []
        stamps.append(float(now))
        cutoff = float(now) - _WINDOW_MAX_AGE
        windows[name] = [item for item in stamps if _as_float(item) >= cutoff][
            -_WINDOW_MAX_LEN:
        ]

    def window_count(self, name: str, now: float, seconds: float) -> int:
        """统计窗口内的事件数（只读，不修改状态）。"""
        windows = self.data.get("windows")
        if not isinstance(windows, dict):
            return 0
        stamps = windows.get(name)
        if not isinstance(stamps, list):
            return 0
        floor = float(now) - float(seconds)
        return sum(1 for item in stamps if _as_float(item) >= floor)

    def window_series(self, name: str) -> list[float]:
        """取某个窗口的原始时间戳（供持久化到 rate_windows）。"""
        windows = self.data.get("windows")
        stamps = windows.get(name) if isinstance(windows, dict) else None
        return [float(item) for item in stamps] if isinstance(stamps, list) else []

    def windows_since(self, since: float) -> list[tuple[str, float]]:
        """本轮新增的窗口行（供 `SqliteStore.push_rate()` 落库）。"""
        rows: list[tuple[str, float]] = []
        windows = self.data.get("windows")
        if not isinstance(windows, dict):
            return rows
        for name, stamps in windows.items():
            if not isinstance(stamps, list):
                continue
            rows.extend((str(name), float(item)) for item in stamps if _as_float(item) >= since)
        return rows

    def prune_windows(self, now: float) -> None:
        """删掉超过最大窗口保鲜期的历史时间戳。"""
        windows = self.data.get("windows")
        if not isinstance(windows, dict):
            return
        cutoff = float(now) - _WINDOW_MAX_AGE
        for name, stamps in list(windows.items()):
            if not isinstance(stamps, list):
                del windows[name]
                continue
            kept = [item for item in stamps if _as_float(item) >= cutoff]
            if kept:
                windows[name] = kept
            else:
                del windows[name]

    # ---------- 缓冲 ----------

    def buffer(self, name: str) -> list:
        """取一个列表型缓冲（不存在则建立）。"""
        value = self.data.get(name)
        if not isinstance(value, list):
            value = []
            self.data[name] = value
        return value

    def burst_state(self) -> dict:
        """取突发抑制桶（started/count/items）。"""
        value = self.data.get("burst")
        if not isinstance(value, dict):
            value = {"started": 0.0, "count": 0, "items": []}
            self.data["burst"] = value
        value.setdefault("started", 0.0)
        value.setdefault("count", 0)
        if not isinstance(value.get("items"), list):
            value["items"] = []
        return value


@dataclass
class PendingItem:
    """一条待重试的投递（R8：失败必须留下原文分片 + 降级文本）。

    state 取值：`pending`（尚未尝试）｜`degraded`（已失败，下一轮发降级文本）｜
    `abandoned`（退避耗尽，留档不再重试）｜`sent`（已送达，可立即清理）。
    """

    item_id: str = ""
    session: str = ""
    kind: str = "text"
    chunks: list[str] = field(default_factory=list)
    text: str = ""
    fingerprint: str = ""
    severity: str = "MEDIUM"
    route: str = "notify"
    attempts: int = 0
    created_at: float = 0.0
    next_at: float = 0.0
    last_error: str = ""
    state: str = "pending"
    excerpt_path: str = ""

    def to_dict(self) -> dict:
        """序列化为可落盘（JSON 迁移 / SQLite 行）的 dict。"""
        return {
            "item_id": self.item_id,
            "session": self.session,
            "kind": self.kind,
            "chunks": list(self.chunks),
            "text": self.text,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "route": self.route,
            "attempts": self.attempts,
            "created_at": self.created_at,
            "next_at": self.next_at,
            "last_error": self.last_error,
            "state": self.state,
            "excerpt_path": self.excerpt_path,
        }

    @classmethod
    def from_dict(cls, raw: object) -> PendingItem | None:
        """从 dict 还原；同时兼容 v1 字段名（status/next_attempt_at），缺 session 的条目丢弃。"""
        if not isinstance(raw, dict):
            return None
        session = str(raw.get("session") or "").strip()
        if not session:
            return None
        text = str(raw.get("text") or "")
        chunks = raw.get("chunks")
        if not isinstance(chunks, list):
            chunks = [text] if text else []
        state = str(raw.get("state") or raw.get("status") or "pending")
        attempts = max(0, _as_int(raw.get("attempts")))
        if state == "pending" and attempts > 0:
            state = "degraded"
        if state not in {"pending", "degraded", "abandoned", "sent"}:
            state = "pending"
        if not text:
            text = "\n\n".join(str(chunk) for chunk in chunks)[:4000]
        return cls(
            item_id=str(raw.get("item_id") or uuid.uuid4().hex),
            session=session,
            kind=str(raw.get("kind") or "text"),
            chunks=[str(chunk) for chunk in chunks],
            text=text,
            fingerprint=str(raw.get("fingerprint") or ""),
            severity=str(raw.get("severity") or "MEDIUM"),
            route=str(raw.get("route") or "notify"),
            attempts=attempts,
            created_at=_as_float(raw.get("created_at")),
            next_at=_as_float(raw.get("next_at", raw.get("next_attempt_at"))),
            last_error=str(raw.get("last_error") or ""),
            state=state,
            excerpt_path=str(raw.get("excerpt_path") or ""),
        )


class PendingQueue:
    """待重试队列的内存/JSON 实现（SQLite 不可用时的降级路径 + 旧数据迁移）。"""

    def __init__(
        self,
        path: Path | None = None,
        *,
        max_items: int = 200,
        max_text_chars: int = 8000,
        max_age: float = 7 * 86400.0,
    ):
        self.path = Path(path) if path else None
        self.max_items = int(max_items)
        self.max_text_chars = int(max_text_chars)
        self.max_age = float(max_age)
        self.items: list[PendingItem] = []

    def load(self) -> PendingQueue:
        """从磁盘载入队列（损坏条目丢弃）。"""
        raw = read_json(self.path, {}) if self.path else {}
        entries = raw.get("items") if isinstance(raw, dict) else None
        self.items = []
        if isinstance(entries, list):
            for entry in entries:
                item = PendingItem.from_dict(entry)
                if item is not None:
                    self.items.append(item)
        return self

    def save(self) -> bool:
        """原子落盘（迁移/降级模式用），返回是否成功。"""
        if self.path is None:
            return False
        try:
            atomic_write_json(
                self.path, {"version": 2, "items": [item.to_dict() for item in self.items]}
            )
        except OSError:
            return False
        return True

    def add(self, item: PendingItem) -> PendingItem:
        """入队；同会话同指纹的未完成条目合并（保留更长的内容与最新错误）。"""
        if not item.item_id:
            item.item_id = uuid.uuid4().hex
        if not item.created_at:
            item.created_at = time.time()
        if len(item.text) > self.max_text_chars:
            item.text = item.text[: self.max_text_chars] + "\n…（内容过长已截断）"
        for existing in self.items:
            if (
                existing.state in {"pending", "degraded"}
                and existing.session == item.session
                and item.fingerprint
                and existing.fingerprint == item.fingerprint
            ):
                existing.last_error = item.last_error or existing.last_error
                if len(item.text) > len(existing.text):
                    existing.text = item.text
                    existing.chunks = list(item.chunks)
                return existing
        self.items.append(item)
        self.prune(time.time())
        return item

    def due(self, now: float) -> list[PendingItem]:
        """取出到期可重试的条目（按创建时间排序）。"""
        ready = [
            item
            for item in self.items
            if item.state in {"pending", "degraded"} and float(item.next_at) <= float(now)
        ]
        return sorted(ready, key=lambda item: item.created_at)

    def get(self, item_id: str) -> PendingItem | None:
        """按 id 取条目。"""
        for item in self.items:
            if item.item_id == item_id:
                return item
        return None

    def update(self, item_id: str, **fields) -> bool:
        """按字段更新条目（白名单，防止写坏形状）。"""
        item = self.get(item_id)
        if item is None:
            return False
        allowed = set(item.to_dict())
        for key, value in fields.items():
            if key in allowed:
                setattr(item, key, value)
        return True

    def mark_success(self, item_id: str) -> bool:
        """投递成功：出队。"""
        before = len(self.items)
        self.items = [item for item in self.items if item.item_id != item_id]
        return len(self.items) != before

    def mark_failure(
        self,
        item_id: str,
        now: float,
        *,
        delay: float = 0.0,
        max_attempts: int = 4,
        error: str = "",
    ) -> PendingItem | None:
        """投递失败：累加次数、转 `degraded` 并按退避安排下次重试；超限转 `abandoned`。"""
        item = self.get(item_id)
        if item is None:
            return None
        item.attempts += 1
        item.last_error = str(error)[:500]
        if item.attempts >= max(1, int(max_attempts)):
            item.state = "abandoned"
            item.next_at = float("inf")
        else:
            item.state = "degraded"
            item.next_at = float(now) + max(0.0, float(delay))
        return item

    def stats(self, now: float | None = None, *, window: float = 86400.0) -> dict:
        """队列统计（待重试/已放弃/最早条目的年龄；含 `recent_*` 窗口口径）。"""
        moment = time.time() if now is None else float(now)
        active = [item for item in self.items if item.state in {"pending", "degraded"}]
        abandoned = [item for item in self.items if item.state == "abandoned"]
        oldest = min((item.created_at for item in active), default=0.0)
        fresh = [item for item in self.items if item.created_at >= moment - float(window)]
        fresh_active = [item for item in fresh if item.state in {"pending", "degraded"}]
        fresh_oldest = min((item.created_at for item in fresh), default=0.0)
        return {
            "pending": len([item for item in active if item.state == "pending"]),
            "degraded": len([item for item in active if item.state == "degraded"]),
            "active": len(active),
            "abandoned": len(abandoned),
            "oldest_age": max(0.0, moment - oldest) if oldest else 0.0,
            "bytes": len(json.dumps([item.to_dict() for item in self.items])),
            "max_severity": (
                max((item.severity for item in active), key=_severity_rank) if active else ""
            ),
            "window_hours": round(float(window) / 3600.0, 2),
            "recent_pending": len([i for i in fresh_active if i.state == "pending"]),
            "recent_degraded": len([i for i in fresh_active if i.state == "degraded"]),
            "recent_abandoned": len([i for i in fresh if i.state == "abandoned"]),
            "recent_active": len(fresh_active),
            "recent_max_severity": (
                max((i.severity for i in fresh), key=_severity_rank) if fresh else ""
            ),
            "recent_oldest_age": max(0.0, moment - fresh_oldest) if fresh_oldest else 0.0,
        }

    def prune(self, now: float) -> int:
        """清理：放弃且超龄的条目删除；超上限时先丢放弃的，再丢最旧的待重试条目。"""
        drop = 0
        kept: list[PendingItem] = []
        for item in self.items:
            expired = (
                item.state == "abandoned" and float(now) - item.created_at > self.max_age
            )
            if expired:
                drop += 1
                continue
            kept.append(item)
        if len(kept) > self.max_items:
            kept.sort(
                key=lambda item: (item.state in {"pending", "degraded"}, item.created_at)
            )
            drop += len(kept) - self.max_items
            kept = kept[len(kept) - self.max_items :]
        self.items = kept
        return drop


_SEVERITY_ORDER = {"IGNORE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_rank(value: object) -> int:
    """等级排序（store 自用：未送达汇总行要说「最高 X 级」）。

    与 ``models.severity_rank`` 同义，但 store 这一层不 import models（保持零依赖）；
    未知等级一律当 0（比"抛异常"更适合统计路径）。
    """
    return _SEVERITY_ORDER.get(str(getattr(value, "value", value)).upper(), 0)


class DiskGovernor:
    """磁盘治理：摘录写入、送达回收、失败残留保留与硬上限清理、占用报告。

    §8.5：`prune()` 先按**字节上限**删最旧、再按**条数**、再按**年龄**，两条目录
    （outbox 成功残留 / failed 失败残留）都生效；三条规则取更严者。
    """

    def __init__(
        self,
        root: Path,
        *,
        keep: int = 50,
        max_age: float = 24 * 3600.0,
        max_bytes: int = 32 * 1024 * 1024,
        prefix: str = "astrbot-log-",
    ):
        self.root = Path(root)
        self.outbox = self.root / "outbox"
        self.failed = self.root / "failed"
        self.keep = int(keep)
        self.max_age = float(max_age)
        self.max_bytes = int(max_bytes)
        self.prefix = prefix

    def _ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        for directory in (self.root, self.outbox, self.failed):
            directory.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
            secure_path(directory, DIR_MODE)  # F09：摘录目录 0700

    def _unique_path(self, directory: Path, stamp: str, suffix: str) -> Path:
        path = directory / f"{self.prefix}{stamp}{suffix}"
        index = 2
        while path.exists():
            path = directory / f"{self.prefix}{stamp}-{index}{suffix}"
            index += 1
        return path

    def write_excerpt(self, text: str, *, stamp: str | None = None) -> Path:
        """写入一份摘录（成功后由 release 回收），返回文件路径。"""
        self._ensure()
        name = stamp or time.strftime("%Y%m%d-%H%M%S")
        path = self._unique_path(self.outbox, name, ".txt")
        atomic_write_text(path, text)
        self.prune()
        return path

    def spill(self, text: str, *, fingerprint: str = "", stamp: str | None = None) -> Path:
        """把失败的投递内容落到 failed/，供重试与人工取证使用。"""
        self._ensure()
        tag = (fingerprint or "x")[:8]
        name = f"{stamp or time.strftime('%Y%m%d-%H%M%S')}-{tag}"
        path = self._unique_path(self.failed, name, ".txt")
        atomic_write_text(path, text)
        self.prune()
        return path

    def release(self, path: Path | str) -> bool:
        """投递成功后回收文件（成功残留清理）。"""
        try:
            Path(path).unlink()
            return True
        except OSError:
            return False

    @staticmethod
    def _scan(directory: Path) -> list[dict]:
        rows: list[dict] = []
        try:
            entries = list(directory.glob("*.txt"))
        except OSError:
            return rows
        for path in entries:
            try:
                stat = path.stat()
            except OSError:
                continue
            if path.is_file():
                rows.append({"path": path, "mtime": stat.st_mtime, "size": stat.st_size})
        return rows

    def prune(self, now: float | None = None) -> dict:
        """对成功与失败两类残留统一施加硬上限，返回删除条数统计。

        顺序（§8.5）：① 总字节超 `max_bytes` → 从最旧删到达标；② 单目录条数超
        `keep` → 从最旧删到达标；③ 年龄超 `max_age` → 删。三条同时生效且互相叠加。
        """
        moment = time.time() if now is None else float(now)
        removed = {"outbox": 0, "failed": 0, "bytes": 0}
        for key, directory in (("outbox", self.outbox), ("failed", self.failed)):
            rows = self._scan(directory)
            rows.sort(key=lambda row: row["mtime"])
            # ① 字节上限（按目录）
            total = sum(row["size"] for row in rows)
            while rows and total > self.max_bytes:
                victim = rows.pop(0)
                if self._unlink(victim["path"]):
                    total -= victim["size"]
                    removed[key] += 1
                    removed["bytes"] += victim["size"]
            # ② 条数上限
            while rows and len(rows) > self.keep:
                victim = rows.pop(0)
                if self._unlink(victim["path"]):
                    removed[key] += 1
                    removed["bytes"] += victim["size"]
            # ③ 年龄上限
            for row in list(rows):
                if moment - row["mtime"] > self.max_age and self._unlink(row["path"]):
                    removed[key] += 1
                    removed["bytes"] += row["size"]
        return removed

    @staticmethod
    def _unlink(path: Path) -> bool:
        try:
            path.unlink()
            return True
        except OSError:
            return False

    def usage(self, now: float | None = None) -> dict:
        """当前占用报告（两目录分别统计，并给出最早文件年龄）。"""
        moment = time.time() if now is None else float(now)
        report = {
            "outbox": {"files": 0, "bytes": 0, "oldest_age": 0.0},
            "failed": {"files": 0, "bytes": 0, "oldest_age": 0.0},
            "files": 0,
            "bytes": 0,
            "over_limit": False,
        }
        for key, directory in (("outbox", self.outbox), ("failed", self.failed)):
            rows = self._scan(directory)
            sizes = [row["size"] for row in rows]
            report[key] = {
                "files": len(rows),
                "bytes": sum(sizes),
                "oldest_age": (
                    max(0.0, moment - min(row["mtime"] for row in rows)) if rows else 0.0
                ),
            }
            report["files"] += len(rows)
            report["bytes"] += sum(sizes)
        report["over_limit"] = report["bytes"] > self.max_bytes or any(
            report[key]["files"] > self.keep for key in ("outbox", "failed")
        )
        return report

    def report(self, now: float | None = None) -> str:
        """人类可读的占用摘要，供日志与状态回执使用。"""
        info = self.usage(now)
        return (
            f"磁盘占用 {info['bytes']}B/{info['files']} 个文件"
            f"（成功残留 {info['outbox']['files']} 个、失败残留 {info['failed']['files']} 个，"
            f"上限 {self.keep} 个/目录、{self.max_bytes}B），"
            f"是否超限：{'是' if info['over_limit'] else '否'}"
        )


_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS file_progress (
      path TEXT PRIMARY KEY, device INTEGER, inode INTEGER,
      offset INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0,
      updated_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pattern_kb (
      fingerprint TEXT PRIMARY KEY,
      severity TEXT NOT NULL,
      confidence REAL NOT NULL DEFAULT 0.5,
      component TEXT NOT NULL DEFAULT '',
      tags TEXT NOT NULL DEFAULT '[]',
      reason TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT 'llm',
      hits INTEGER NOT NULL DEFAULT 1,
      first_seen REAL NOT NULL, last_seen REAL NOT NULL,
      manual INTEGER NOT NULL DEFAULT 0,
      last_judged_at REAL NOT NULL DEFAULT 0,
      judge_source TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pattern_kb_last_seen ON pattern_kb(last_seen)",
    """
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL NOT NULL,
      fingerprint TEXT NOT NULL,
      severity TEXT NOT NULL,
      route TEXT NOT NULL DEFAULT 'notify',
      decision TEXT NOT NULL DEFAULT 'send',
      component TEXT NOT NULL DEFAULT '',
      session TEXT NOT NULL DEFAULT '',
      tags TEXT NOT NULL DEFAULT '[]',
      summary TEXT NOT NULL DEFAULT '',
      source_file TEXT NOT NULL DEFAULT '',
      hit_count INTEGER NOT NULL DEFAULT 1,
      excerpt_path TEXT NOT NULL DEFAULT '',
      excerpt_lines INTEGER NOT NULL DEFAULT 0,
      judged INTEGER NOT NULL DEFAULT -1,
      judge_source TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_fp_ts ON alerts(fingerprint, ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_decision_ts ON alerts(decision, ts DESC)",
    "CREATE TABLE IF NOT EXISTS rate_windows (scope TEXT NOT NULL, ts REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_rate_scope_ts ON rate_windows(scope, ts)",
    """
    CREATE TABLE IF NOT EXISTS pending_delivery (
      item_id TEXT PRIMARY KEY, session TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'text',
      chunks TEXT NOT NULL, text TEXT NOT NULL DEFAULT '',
      fingerprint TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'MEDIUM',
      route TEXT NOT NULL DEFAULT 'notify',
      attempts INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, next_at REAL NOT NULL,
      last_error TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending',
      excerpt_path TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pending_state_next ON pending_delivery(state, next_at)",
    """
    CREATE TABLE IF NOT EXISTS remediation_runs (
      run_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, severity TEXT NOT NULL,
      started_at REAL NOT NULL, finished_at REAL,
      status TEXT NOT NULL DEFAULT 'running', exit_code INTEGER,
      duration REAL NOT NULL DEFAULT 0, summary TEXT NOT NULL DEFAULT '',
      artifact TEXT NOT NULL DEFAULT '', log_path TEXT NOT NULL DEFAULT '',
      task_sha1 TEXT NOT NULL DEFAULT '', argv TEXT NOT NULL DEFAULT '',
      receipt_sent INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_remediation_started ON remediation_runs(started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_remediation_fp ON remediation_runs(fingerprint, started_at DESC)",
)

# v1 → v2 补列（已存在的列忽略「duplicate column」错误）
_ALTERS_V1_TO_V2: tuple[str, ...] = (
    "ALTER TABLE alerts ADD COLUMN excerpt_lines INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE remediation_runs ADD COLUMN task_sha1 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE remediation_runs ADD COLUMN argv TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE pending_delivery ADD COLUMN excerpt_path TEXT NOT NULL DEFAULT ''",
)

# v2 → v3 补列（v2.3.0 判定链；同样吞掉「duplicate column」，旧库自动补）
_ALTERS_V2_TO_V3: tuple[str, ...] = (
    "ALTER TABLE pattern_kb ADD COLUMN last_judged_at REAL NOT NULL DEFAULT 0",
    "ALTER TABLE pattern_kb ADD COLUMN judge_source TEXT NOT NULL DEFAULT ''",
    # -1 = 未知（历史行不回填；0/1 才是「没判 / 判过」）
    "ALTER TABLE alerts ADD COLUMN judged INTEGER NOT NULL DEFAULT -1",
    "ALTER TABLE alerts ADD COLUMN judge_source TEXT NOT NULL DEFAULT ''",
)

_PENDING_COLUMNS = (
    "item_id",
    "session",
    "kind",
    "chunks",
    "text",
    "fingerprint",
    "severity",
    "route",
    "attempts",
    "created_at",
    "next_at",
    "last_error",
    "state",
    "excerpt_path",
)


class SqliteStore:
    """SQLite 状态库（R11）：单连接 + 单写者 + 每轮批量事务。

    所有方法都必须由调用方包在 `asyncio.to_thread()` 里执行（§9.4 第 3 条）。
    打不开或版本高于本实现时进入降级：`available` 为假（无库）或 `readonly` 为真
    （版本过高，拒绝写入但文件不动）。
    """

    SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(self, path: Path, *, timeout: float = 3.0, wal: bool = True):
        self.path = Path(path)
        self.timeout = float(timeout)
        self.wal = bool(wal)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._writable = False
        self._error = ""
        self._version = 0
        self._imported: list[str] = []

    # ---------- 生命周期 ----------

    @property
    def available(self) -> bool:
        """连接是否可用（不可用 = 调用方应切到内存态）。"""
        return self._conn is not None

    @property
    def writable(self) -> bool:
        """是否允许写入（版本过高时为 False）。"""
        return self._conn is not None and self._writable

    @property
    def readonly(self) -> bool:
        """连接可用但拒绝写入（版本降级保护，§9.5 第 3 条）。"""
        return self._conn is not None and not self._writable

    @property
    def degraded(self) -> bool:
        """无可用连接（内存态降级）。"""
        return self._conn is None

    @property
    def last_error(self) -> str:
        """最近一次失败原因（供启动报告与日志使用）。"""
        return self._error

    @property
    def schema_version(self) -> int:
        """当前库的 `user_version`。"""
        return self._version

    @property
    def imported_json(self) -> list[str]:
        """迁移时被重命名留痕的 JSON 文件列表。"""
        return list(self._imported)

    def open(self) -> SqliteStore:
        """连接 + PRAGMA + 迁移；任何失败都降级而不是抛出。"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.path),
                timeout=self.timeout,
                isolation_level=None,
                check_same_thread=False,
            )
        except (sqlite3.Error, OSError) as exc:
            return self._degrade(f"打开状态库失败: {exc}")
        with self._lock:
            self._conn = conn
            try:
                # 先读版本（只读操作）：版本过高时一个 PRAGMA 都不写，保证文件不变
                self._version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if self._version > SCHEMA_VERSION:
                    self._writable = False
                    self._error = (
                        f"状态库版本 {self._version} > 支持 {SCHEMA_VERSION}，"
                        f"请勿降低插件版本或删除 {self.path}"
                    )
                    return self
                conn.execute(f"PRAGMA journal_mode = {'WAL' if self.wal else 'DELETE'}")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA temp_store = MEMORY")
            except sqlite3.Error as exc:
                return self._degrade(f"初始化状态库失败: {exc}")
            self._writable = True
            # F09：状态库与其 WAL/SHM 同样含敏感内容（进度/指纹/轨迹路径）
            self._harden_db_files()
            try:
                self.migrate()
            except (sqlite3.Error, OSError) as exc:
                return self._degrade(f"迁移状态库失败: {exc}")
        return self

    def _degrade(self, message: str) -> SqliteStore:
        self._error = message
        self._writable = False
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None
        return self

    def _harden_db_files(self) -> None:
        """把库文件与 WAL/SHM 收到 0600（F09）。

        WAL/SHM 是**首次写入时**才创建的，所以除了 open() 还要在每次写入后补一次。
        """
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                secure_path(candidate, FILE_MODE)

    def close(self) -> None:
        """关闭连接（幂等）。"""
        with self._lock:
            if self._conn is not None:
                with contextlib.suppress(Exception):
                    self._conn.close()
                self._conn = None
            self._writable = False

    def reconcile_runs(
        self, *, grace_seconds: float = 0.0, now: float | None = None
    ) -> int:
        """把**上一次进程遗留**的 ``running`` 行对账成 ``aborted``（F06）。

        v2.3.0 移除了自动修复能力：这张表**只读不写**，本方法保留的唯一目的是把升级前
        崩溃/重载留下的 ``running`` 行一次性收口，免得审计时把历史行误读成「还在跑」。

        启动对账的判定依据是「**本进程之外**不可能有 run 在跑」：状态库是单写者，
        当前进程刚起来、尚未发起任何 run，所以此刻所有 ``running`` 行都是孤儿 ——
        按年龄判定（例如 2×timeout）反而会把「崩溃后很快重启」的孤儿留在库里继续占闸。
        ``grace_seconds`` 只用于给多进程/共享库场景留余量，默认 0。

        Args:
            grace_seconds: 宽限秒数（只有 ``started_at < now - grace`` 的行才算孤儿）。
            now: 当前时刻，默认系统时间。

        Returns:
            被标记的行数（幂等：第二次调用为 0）。
        """
        moment = time.time() if now is None else float(now)
        cutoff = moment - max(0.0, float(grace_seconds))

        def run() -> int:
            with self._transaction() as conn:
                cursor = conn.execute(
                    "UPDATE remediation_runs SET status = 'aborted', finished_at = ?,"
                    " summary = CASE WHEN summary = '' THEN ? ELSE summary END"
                    " WHERE status = 'running' AND started_at < ?",
                    (
                        moment,
                        "进程重启对账：该 run 未正常结束（判定为 aborted）",
                        cutoff,
                    ),
                )
                return int(cursor.rowcount or 0)

        return int(self._write(run, 0) or 0)

    def checkpoint(self, *, truncate: bool = False) -> None:
        """WAL 维护（每天一次，在 to_thread 内调用）。"""
        if not self.available:
            return
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute(f"PRAGMA wal_checkpoint({'TRUNCATE' if truncate else 'PASSIVE'})")

    # ---------- 事务与底层封装 ----------

    @contextmanager
    def _transaction(self):
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def _write(self, fn, default=None):
        """写操作封装：不可写时返回 default，异常记 error 并返回 default。"""
        if not self.writable:
            return default
        with self._lock:
            try:
                result = fn()
            except sqlite3.Error as exc:
                self._error = f"状态库写入失败: {exc}"
                return default
            self._harden_db_files()
            return result

    def _read(self, fn, default=None):
        """读操作封装：不可用时返回 default，异常记 error 并返回 default。"""
        if not self.available:
            return default
        with self._lock:
            try:
                return fn()
            except sqlite3.Error as exc:
                self._error = f"状态库读取失败: {exc}"
                return default

    def migrate(self) -> int:
        """建表/补列 + JSON 一次性导入；幂等，整体单事务（§9.5）。"""
        if not self.available:
            return self._version
        with self._lock:
            with self._transaction() as conn:
                for statement in _DDL:
                    conn.execute(statement)
                version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if version < 2:
                    for statement in _ALTERS_V1_TO_V2:
                        with contextlib.suppress(sqlite3.Error):
                            conn.execute(statement)
                if version < SCHEMA_VERSION:
                    for statement in _ALTERS_V2_TO_V3:
                        with contextlib.suppress(sqlite3.Error):
                            conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    version = SCHEMA_VERSION
                pending_import = self._collect_json_import(conn)
            self._version = version
        self._finish_json_import(pending_import)
        return self._version

    # ---------- meta ----------

    def meta_get(self, key: str, default: object = None) -> object:
        """读 meta 里的 JSON 值（§9.2：counters/digest_buffer/burst_state 都在这）。"""
        row = self._read(
            lambda: self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (str(key),)
            ).fetchone()
        )
        if not row:
            return default
        try:
            return json.loads(row[0])
        except (TypeError, ValueError):
            return default

    def meta_set(self, key: str, value: object) -> bool:
        """写 meta（JSON 序列化），返回是否成功。"""
        payload = json.dumps(value, ensure_ascii=False)

        def run() -> bool:
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(key), payload),
                )
            return True

        return bool(self._write(run, False))

    # ---------- 每轮批量写 ----------

    def record_alerts(self, rows: Sequence[Mapping]) -> int:
        """批量写 alerts（单事务），返回写入行数。"""
        if not rows:
            return 0

        def run() -> int:
            with self._transaction() as conn:
                conn.executemany(
                    "INSERT INTO alerts(ts, fingerprint, severity, route, decision, component,"
                    " session, tags, summary, source_file, hit_count, excerpt_path, excerpt_lines,"
                    " judged, judge_source)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            float(row.get("ts", 0.0)),
                            str(row.get("fingerprint", "")),
                            str(row.get("severity", "MEDIUM")),
                            str(row.get("route", "notify")),
                            str(row.get("decision", "send")),
                            str(row.get("component", "")),
                            str(row.get("session", "")),
                            json.dumps(list(row.get("tags") or []), ensure_ascii=False),
                            str(row.get("summary", ""))[:2000],
                            str(row.get("source_file", "")),
                            int(row.get("hit_count", 1) or 1),
                            str(row.get("excerpt_path", "")),
                            int(row.get("excerpt_lines", 0) or 0),
                            # -1 = 未知（调用方没给 = 旧口径）；0/1 = 没判 / 判过
                            int(row.get("judged", -1)),
                            str(row.get("judge_source", "") or ""),
                        )
                        for row in rows
                    ],
                )
            return len(rows)

        return int(self._write(run, 0) or 0)

    def upsert_progress(self, rows: Sequence[Mapping]) -> int:
        """批量写 file_progress（单事务），返回写入行数。"""
        if not rows:
            return 0

        def run() -> int:
            with self._transaction() as conn:
                conn.executemany(
                    "INSERT INTO file_progress(path, device, inode, offset, size, updated_at)"
                    " VALUES(?,?,?,?,?,?)"
                    " ON CONFLICT(path) DO UPDATE SET device=excluded.device, inode=excluded.inode,"
                    " offset=excluded.offset, size=excluded.size, updated_at=excluded.updated_at",
                    [
                        (
                            str(row.get("path", "")),
                            int(row.get("device", 0) or 0),
                            int(row.get("inode", 0) or 0),
                            max(0, int(row.get("offset", 0) or 0)),
                            max(0, int(row.get("size", 0) or 0)),
                            float(row.get("updated_at", 0.0)),
                        )
                        for row in rows
                    ],
                )
            return len(rows)

        return int(self._write(run, 0) or 0)

    def bump_counters(self, deltas: Mapping[str, int]) -> None:
        """按增量累加计数器（存 meta 的 JSON 里）。"""
        if not deltas:
            return
        current = self.counters()

        def run() -> None:
            merged = dict(current)
            for key, delta in deltas.items():
                merged[str(key)] = _as_int(merged.get(str(key))) + int(delta)
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('counters', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (json.dumps(merged, ensure_ascii=False),),
                )

        self._write(run, None)

    def push_rate(self, scope: str, ts: float) -> None:
        """记录一次速率事件（sent_minute/sent_hour/sent_day/sent_burst）。"""
        self._write(
            lambda: self._conn.execute(
                "INSERT INTO rate_windows(scope, ts) VALUES(?, ?)", (str(scope), float(ts))
            )
        )

    def push_rates(self, rows: Iterable[tuple[str, float]]) -> int:
        """批量写速率事件（单事务），返回写入行数。"""
        payload = [(str(scope), float(ts)) for scope, ts in rows]
        if not payload:
            return 0

        def run() -> int:
            with self._transaction() as conn:
                conn.executemany(
                    "INSERT INTO rate_windows(scope, ts) VALUES(?, ?)", payload
                )
            return len(payload)

        return int(self._write(run, 0) or 0)

    # ---------- 读 ----------

    def progress(self) -> dict[str, dict]:
        """读全部文件进度（启动时载入内存视图）。"""
        rows = self._read(
            lambda: self._conn.execute(
                "SELECT path, device, inode, offset, size, updated_at FROM file_progress"
            ).fetchall(),
            [],
        )
        return {
            str(row[0]): {
                "device": int(row[1] or 0),
                "inode": int(row[2] or 0),
                "offset": int(row[3] or 0),
                "size": int(row[4] or 0),
                "skip_to_eol": False,
                "updated_at": float(row[5] or 0.0),
            }
            for row in rows or []
        }

    def metrics_for(
        self, fingerprints: Sequence[str], *, window: float, now: float
    ) -> dict[str, dict]:
        """批量取指纹历史（一次 IN 聚合）：window 内出现次数 + 总量 + 首末时间。"""
        wanted = [str(item) for item in fingerprints if str(item)]
        if not wanted:
            return {}
        placeholders = ",".join("?" for _ in wanted)

        def run() -> dict[str, dict]:
            rows = self._conn.execute(
                "SELECT fingerprint, COUNT(*), MIN(ts), MAX(ts),"
                " SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END)"
                f" FROM alerts WHERE fingerprint IN ({placeholders}) GROUP BY fingerprint",
                [float(now) - float(window), *wanted],
            ).fetchall()
            return {
                str(row[0]): {
                    "total": int(row[1] or 0),
                    "first_ts": float(row[2] or 0.0),
                    "last_ts": float(row[3] or 0.0),
                    "repeat_count": int(row[4] or 0),
                }
                for row in rows
            }

        return dict(self._read(run, {}) or {})

    def counters(self) -> dict:
        """读计数器（meta 里的 JSON）。"""
        value = self.meta_get("counters", {})
        return dict(value) if isinstance(value, Mapping) else {}

    def rate_count(self, scope: str, *, seconds: float, now: float) -> int:
        """统计某 scope 在窗口内的事件数。"""
        row = self._read(
            lambda: self._conn.execute(
                "SELECT COUNT(*) FROM rate_windows WHERE scope = ? AND ts >= ?",
                (str(scope), float(now) - float(seconds)),
            ).fetchone()
        )
        return int(row[0] or 0) if row else 0

    def count_rows(self, table: str) -> int:
        """表行数（usage 与测试用；表名白名单校验）。"""
        if table not in {
            "alerts",
            "file_progress",
            "pattern_kb",
            "rate_windows",
            "pending_delivery",
            "remediation_runs",
            "meta",
        }:
            return 0
        row = self._read(
            lambda: self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        )
        return int(row[0] or 0) if row else 0

    # ---------- 知识库 ----------

    @staticmethod
    def _kb_row(row) -> dict:
        return {
            "fingerprint": str(row[0]),
            "severity": str(row[1]),
            "confidence": float(row[2] or 0.0),
            "component": str(row[3] or ""),
            "tags": json.loads(row[4]) if row[4] else [],
            "reason": str(row[5] or ""),
            "source": str(row[6] or "llm"),
            "hits": int(row[7] or 1),
            "first_seen": float(row[8] or 0.0),
            "last_seen": float(row[9] or 0.0),
            "manual": bool(row[10]),
            # v3 审计列：最后一次真判时间与依据（'' / 0 = 从未真判）
            "last_judged_at": float(row[11] or 0.0),
            "judge_source": str(row[12] or ""),
        }

    def kb_lookup(self, fingerprint: str) -> dict | None:
        """按指纹取知识库条目（v2.3.0 起只作**先验**与统计，不再是判决来源）。"""
        row = self._read(
            lambda: self._conn.execute(
                "SELECT fingerprint, severity, confidence, component, tags, reason, source,"
                " hits, first_seen, last_seen, manual, last_judged_at, judge_source"
                " FROM pattern_kb WHERE fingerprint = ?",
                (str(fingerprint),),
            ).fetchone()
        )
        return self._kb_row(row) if row else None

    def kb_upsert(self, entries: Sequence[Mapping]) -> int:
        """批量写知识库；`manual=1` 的行只累加 hits/last_seen，不被覆盖。"""
        payload = [dict(entry) for entry in entries if entry.get("fingerprint")]
        if not payload:
            return 0

        def run() -> int:
            written = 0
            with self._transaction() as conn:
                for entry in payload:
                    fingerprint = str(entry["fingerprint"])
                    existing = conn.execute(
                        "SELECT manual FROM pattern_kb WHERE fingerprint = ?", (fingerprint,)
                    ).fetchone()
                    now = float(entry.get("last_seen", time.time()))
                    if existing and int(existing[0] or 0) == 1:
                        conn.execute(
                            "UPDATE pattern_kb SET hits = hits + 1, last_seen = ?"
                            " WHERE fingerprint = ?",
                            (now, fingerprint),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO pattern_kb(fingerprint, severity, confidence, component,"
                            " tags, reason, source, hits, first_seen, last_seen, manual,"
                            " last_judged_at, judge_source)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?)"
                            " ON CONFLICT(fingerprint) DO UPDATE SET"
                            " severity=excluded.severity, confidence=excluded.confidence,"
                            " component=excluded.component, tags=excluded.tags,"
                            " reason=excluded.reason, source=excluded.source,"
                            " hits=pattern_kb.hits + 1, last_seen=excluded.last_seen,"
                            # 审计列只增不减：本地/降级写库不得把上一次「真判过」的事实抹掉
                            " last_judged_at=MAX(pattern_kb.last_judged_at, excluded.last_judged_at),"
                            " judge_source=CASE WHEN excluded.judge_source = ''"
                            " THEN pattern_kb.judge_source ELSE excluded.judge_source END",
                            (
                                fingerprint,
                                str(entry.get("severity", "MEDIUM")),
                                float(entry.get("confidence", 0.5) or 0.0),
                                str(entry.get("component", "")),
                                json.dumps(list(entry.get("tags") or []), ensure_ascii=False),
                                str(entry.get("reason", ""))[:2000],
                                str(entry.get("source", "llm")),
                                int(entry.get("hits", 1) or 1),
                                float(entry.get("first_seen", now)),
                                now,
                                float(entry.get("last_judged_at", 0.0) or 0.0),
                                str(entry.get("judge_source", "") or ""),
                            ),
                        )
                    written += 1
            return written

        return int(self._write(run, 0) or 0)

    def kb_set_manual(
        self,
        fingerprint: str,
        severity: object,
        *,
        reason: str = "",
        tags: Sequence[str] = (),
        confidence: float = 1.0,
    ) -> bool:
        """人工指定某个指纹的等级（manual=1，永不被自动覆盖与清理）。"""
        if not fingerprint:
            return False
        now = time.time()

        def run() -> bool:
            with self._transaction() as conn:
                conn.execute(
                    "INSERT INTO pattern_kb(fingerprint, severity, confidence, component, tags,"
                    " reason, source, hits, first_seen, last_seen, manual, last_judged_at,"
                    " judge_source)"
                    " VALUES(?,?,?,'',?,?,'manual',1,?,?,1,0,'manual')"
                    " ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,"
                    " confidence=excluded.confidence, tags=excluded.tags, reason=excluded.reason,"
                    " source='manual', manual=1, last_seen=excluded.last_seen,"
                    " judge_source='manual'",
                    (
                        str(fingerprint),
                        str(getattr(severity, "value", severity)),
                        float(confidence),
                        json.dumps(list(tags), ensure_ascii=False),
                        str(reason)[:2000],
                        now,
                        now,
                    ),
                )
            return True

        return bool(self._write(run, False))

    def kb_prune(self, *, older_than: float, max_entries: int, now: float) -> int:
        """清理过期（非 manual）与超量条目，单表单次 ≤ 500 行。"""
        cutoff = float(now) - float(older_than)

        def run() -> int:
            removed = 0
            with self._transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM pattern_kb WHERE fingerprint IN ("
                    " SELECT fingerprint FROM pattern_kb WHERE manual = 0 AND last_seen < ?"
                    " ORDER BY last_seen LIMIT ?)",
                    (cutoff, _PRUNE_DELETE_CAP),
                )
                removed += int(cursor.rowcount or 0)
                cursor = conn.execute(
                    "DELETE FROM pattern_kb WHERE fingerprint IN ("
                    " SELECT fingerprint FROM pattern_kb WHERE manual = 0"
                    " ORDER BY last_seen DESC LIMIT ? OFFSET ?)",
                    (_PRUNE_DELETE_CAP, max(0, int(max_entries))),
                )
                removed += int(cursor.rowcount or 0)
            return removed

        return int(self._write(run, 0) or 0)

    # ---------- 待发队列 ----------

    def pending_add(self, item: PendingItem) -> PendingItem:
        """入队；同会话同指纹的未完成条目合并。"""
        if not item.item_id:
            item.item_id = uuid.uuid4().hex
        if not item.created_at:
            item.created_at = time.time()
        if not item.chunks:
            item.chunks = [item.text] if item.text else []
        if not item.text:
            item.text = "\n\n".join(item.chunks)[:4000]

        def run() -> PendingItem:
            with self._transaction() as conn:
                existing = conn.execute(
                    "SELECT item_id, text, chunks FROM pending_delivery"
                    " WHERE session = ? AND fingerprint = ? AND state IN ('pending','degraded')",
                    (item.session, item.fingerprint),
                ).fetchone()
                if existing and item.fingerprint:
                    merged_text = item.text if len(item.text) > len(existing[1] or "") else existing[1]
                    merged_chunks = item.chunks if len(item.text) > len(existing[1] or "") else None
                    if merged_chunks is None:
                        conn.execute(
                            "UPDATE pending_delivery SET text = ?, last_error = ?"
                            " WHERE item_id = ?",
                            (merged_text, item.last_error, existing[0]),
                        )
                    else:
                        conn.execute(
                            "UPDATE pending_delivery SET text = ?, chunks = ?, last_error = ?"
                            " WHERE item_id = ?",
                            (
                                merged_text,
                                json.dumps(list(merged_chunks), ensure_ascii=False),
                                item.last_error,
                                existing[0],
                            ),
                        )
                    item.item_id = str(existing[0])
                    return item
                conn.execute(
                    "INSERT INTO pending_delivery(" + ",".join(_PENDING_COLUMNS) + ")"
                    " VALUES(" + ",".join("?" for _ in _PENDING_COLUMNS) + ")",
                    self._pending_values(item),
                )
                return item

        return self._write(run, item) or item

    @staticmethod
    def _pending_values(item: PendingItem) -> tuple:
        return (
            item.item_id,
            item.session,
            item.kind,
            json.dumps(list(item.chunks), ensure_ascii=False),
            item.text,
            item.fingerprint,
            item.severity,
            item.route,
            int(item.attempts),
            float(item.created_at),
            float(item.next_at),
            item.last_error,
            item.state,
            item.excerpt_path,
        )

    @staticmethod
    def _row_to_pending(row) -> PendingItem:
        try:
            chunks = json.loads(row[3]) if row[3] else []
        except (TypeError, ValueError):
            chunks = []
        return PendingItem(
            item_id=str(row[0]),
            session=str(row[1]),
            kind=str(row[2]),
            chunks=[str(chunk) for chunk in chunks],
            text=str(row[4] or ""),
            fingerprint=str(row[5] or ""),
            severity=str(row[6] or "MEDIUM"),
            route=str(row[7] or "notify"),
            attempts=int(row[8] or 0),
            created_at=float(row[9] or 0.0),
            next_at=float(row[10] or 0.0),
            last_error=str(row[11] or ""),
            state=str(row[12] or "pending"),
            excerpt_path=str(row[13] or ""),
        )

    def pending_due(self, now: float) -> list[PendingItem]:
        """到期可重试的条目（state ∈ pending/degraded 且 next_at ≤ now）。"""
        rows = self._read(
            lambda: self._conn.execute(
                "SELECT " + ",".join(_PENDING_COLUMNS) + " FROM pending_delivery"
                " WHERE state IN ('pending','degraded') AND next_at <= ?"
                " ORDER BY created_at",
                (float(now),),
            ).fetchall(),
            [],
        )
        return [self._row_to_pending(row) for row in rows or []]

    def pending_update(self, item_id: str, **fields) -> bool:
        """按字段更新待发条目（白名单列）。"""
        patch = {key: value for key, value in fields.items() if key in _PENDING_COLUMNS}
        if not patch:
            return False

        def run() -> bool:
            columns = ", ".join(f"{key} = ?" for key in patch)
            values = []
            for key, value in patch.items():
                if key == "chunks":
                    values.append(json.dumps(list(value or []), ensure_ascii=False))
                else:
                    values.append(value)
            values.append(item_id)
            with self._transaction() as conn:
                conn.execute(
                    f"UPDATE pending_delivery SET {columns} WHERE item_id = ?", tuple(values)
                )
            return True

        return bool(self._write(run, False))

    def pending_stats(self, now: float | None = None, *, window: float = 86400.0) -> dict:
        """队列统计（与 `PendingQueue.stats()` 同形状）。

        Args:
            now: 统计时刻（默认当前时间）。
            window: 「最近」口径的窗口秒数（汇总行用；默认 24h）。
        """
        moment = time.time() if now is None else float(now)
        rows = self._read(
            lambda: self._conn.execute(
                "SELECT state, COUNT(*), MIN(created_at) FROM pending_delivery GROUP BY state"
            ).fetchall(),
            [],
        )
        counts = {str(row[0]): int(row[1] or 0) for row in rows or []}
        oldest = min(
            (float(row[2] or 0.0) for row in rows or [] if row[2] and row[0] in ("pending", "degraded")),
            default=0.0,
        )
        active = counts.get("pending", 0) + counts.get("degraded", 0)
        # 汇总行只报**最近一个窗口**（默认 24h）：终身计数会把 2026-10-14~18 那 81 条历史债
        # 永远挂在每条消息尾部（实测：终身 81 / 最近 24h 只有 6）⇒ 那是噪声，不是信息。
        recent = self._read(
            lambda: self._conn.execute(
                "SELECT state, COUNT(*), MIN(created_at), MAX("
                "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3"
                " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END)"
                " FROM pending_delivery WHERE created_at >= ? GROUP BY state",
                (moment - float(window),),
            ).fetchall(),
            [],
        )
        recent_counts = {str(row[0]): int(row[1] or 0) for row in recent or []}
        recent_active = recent_counts.get("pending", 0) + recent_counts.get("degraded", 0)
        rank_to_severity = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: ""}
        recent_worst = max(
            (int(row[3] or 0) for row in recent or []), default=0
        )
        recent_oldest = min(
            (
                float(row[2] or 0.0)
                for row in recent or []
                if row[2] and row[0] in ("pending", "degraded", "abandoned")
            ),
            default=0.0,
        )
        worst = self._read(
            lambda: self._conn.execute(
                "SELECT severity FROM pending_delivery WHERE state IN ('pending','degraded')"
                " ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3"
                " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC LIMIT 1"
            ).fetchone(),
            None,
        )
        return {
            "pending": counts.get("pending", 0),
            "degraded": counts.get("degraded", 0),
            "active": active,
            "abandoned": counts.get("abandoned", 0),
            "sent": counts.get("sent", 0),
            "oldest_age": max(0.0, moment - oldest) if oldest else 0.0,
            # 汇总行（Q14=c）要能说「最高 X 级」：没送达的里面最要紧的那条
            "max_severity": str(worst[0]) if worst and worst[0] else "",
            # 窗口口径（main 的汇总行用这几个；见 runbook §6.1）
            "window_hours": round(float(window) / 3600.0, 2),
            "recent_pending": recent_counts.get("pending", 0),
            "recent_degraded": recent_counts.get("degraded", 0),
            "recent_abandoned": recent_counts.get("abandoned", 0),
            "recent_active": recent_active,
            "recent_max_severity": rank_to_severity.get(recent_worst, ""),
            "recent_oldest_age": max(0.0, moment - recent_oldest) if recent_oldest else 0.0,
        }

    def pending_import(self, items: Sequence[Mapping]) -> int:
        """把旧 `pending.json` 的条目导入（迁移用，幂等：已存在的 item_id 跳过）。"""
        payload = [
            item
            for item in (PendingItem.from_dict(raw) for raw in items)
            if item is not None
        ]
        if not payload:
            return 0

        def run() -> int:
            written = 0
            with self._transaction() as conn:
                for item in payload:
                    exists = conn.execute(
                        "SELECT 1 FROM pending_delivery WHERE item_id = ?", (item.item_id,)
                    ).fetchone()
                    if exists:
                        continue
                    conn.execute(
                        "INSERT INTO pending_delivery(" + ",".join(_PENDING_COLUMNS) + ")"
                        " VALUES(" + ",".join("?" for _ in _PENDING_COLUMNS) + ")",
                        self._pending_values(item),
                    )
                    written += 1
            return written

        return int(self._write(run, 0) or 0)

    # ---------- 保留清理与占用 ----------

    def prune(self, *, now: float, cfg: Mapping | None = None) -> dict:
        """保留清理（§9.3），每表每次最多删 500 行，整体单事务。"""
        settings = dict(cfg or {})

        def _num(key: str, default: float) -> float:
            """显式 0 必须被尊重（0 = 关闭该保留策略），只有缺失/非法才回落默认。"""
            value = settings.get(key, default)
            if value is None:
                return float(default)
            try:
                return float(value)
            except (TypeError, ValueError):
                return float(default)

        retention = max(0.0, _num("history_retention_days", 30.0)) * 86400.0
        max_rows = max(1, int(_num("history_max_rows", 20000)))
        kb_max_entries = max(0, int(_num("kb_max_entries", 500)))
        # v2.3.0（Q5=B）：先验保留期由 classify.prior_ttl_hours 管；state.fingerprint_ttl_hours
        # 只表示「通知去重状态」的保留期，不再决定 KB 清理。旧调用方只传 fingerprint_ttl_hours
        # 时按它兜底（兼容 v2.2.0 的调用点与既有单测）。
        prior_hours = _num("prior_ttl_hours", _num("fingerprint_ttl_hours", 72.0))
        ttl = max(0.0, prior_hours) * 3600.0
        moment = float(now)
        result = {"alerts": 0, "rate": 0, "kb": 0, "pending": 0}

        def run() -> dict:
            with self._transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE ts < ?"
                    " ORDER BY ts LIMIT ?)",
                    (moment - retention, _PRUNE_DELETE_CAP),
                )
                result["alerts"] += int(cursor.rowcount or 0)
                cursor = conn.execute(
                    "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                    " ORDER BY ts DESC LIMIT ? OFFSET ?)",
                    (_PRUNE_DELETE_CAP, max_rows),
                )
                result["alerts"] += int(cursor.rowcount or 0)
                cursor = conn.execute(
                    "DELETE FROM rate_windows WHERE rowid IN (SELECT rowid FROM rate_windows"
                    " WHERE ts < ? LIMIT ?)",
                    (moment - _WINDOW_MAX_AGE, _PRUNE_DELETE_CAP),
                )
                result["rate"] += int(cursor.rowcount or 0)
                cursor = conn.execute(
                    "DELETE FROM pending_delivery WHERE item_id IN ("
                    " SELECT item_id FROM pending_delivery WHERE state = 'sent'"
                    " OR (state = 'abandoned' AND created_at < ?) LIMIT ?)",
                    (moment - 7 * 86400.0, _PRUNE_DELETE_CAP),
                )
                result["pending"] += int(cursor.rowcount or 0)
                # v2.3.0：历史 run 行是取证材料，**永不删除**；这里只保留「孤儿 running
                # 自愈成 timeout」这一条（升级前崩溃遗留的行；宽限期沿用旧默认 300s 的两倍）。
                conn.execute(
                    "UPDATE remediation_runs SET status = 'timeout', finished_at = ?"
                    " WHERE status = 'running' AND started_at < ?",
                    (moment, moment - _LEGACY_RUN_GRACE),
                )
            return result

        result = self._write(run, result) or result
        result["kb"] = self.kb_prune(older_than=ttl, max_entries=kb_max_entries, now=moment)
        return result

    def usage(self) -> dict:
        """当前占用报告：库文件大小 + 关键表行数。"""
        try:
            size = self.path.stat().st_size if self.path.exists() else 0
        except OSError:
            size = 0
        return {
            "path": str(self.path),
            "bytes": size,
            "schema_version": self._version,
            "available": self.available,
            "writable": self.writable,
            "alerts": self.count_rows("alerts"),
            "pending": self.count_rows("pending_delivery"),
            "kb": self.count_rows("pattern_kb"),
            "runs": self.count_rows("remediation_runs"),
            "rate": self.count_rows("rate_windows"),
            "last_error": self._error,
        }

    # ---------- JSON → SQLite 一次性导入（§9.5 第 4 条） ----------

    def _collect_json_import(self, conn: sqlite3.Connection) -> list[tuple[Path, str]]:
        """在迁移事务内导入旧 JSON（表为空才导），返回待重命名的文件列表。"""
        base = self.path.parent
        queue: list[tuple[Path, str]] = []
        tail = base / "tail_state.json"
        if tail.exists() and not conn.execute("SELECT 1 FROM file_progress LIMIT 1").fetchone():
            raw = read_json(tail, {})
            files = raw.get("files") if isinstance(raw, dict) else None
            if isinstance(files, dict):
                moment = time.time()
                for key, value in files.items():
                    state = TailStateStore._sanitize(value)
                    if state is None:
                        continue
                    conn.execute(
                        "INSERT OR REPLACE INTO file_progress(path, device, inode, offset, size,"
                        " updated_at) VALUES(?,?,?,?,?,?)",
                        (
                            str(key),
                            state["device"],
                            state["inode"],
                            state["offset"],
                            0,
                            moment,
                        ),
                    )
            queue.append((tail, "tail_state.json.migrated"))

        counters = base / "counters.json"
        if counters.exists() and not conn.execute(
            "SELECT 1 FROM meta WHERE key = 'counters'"
        ).fetchone():
            raw = read_json(counters, {})
            payload = raw.get("counters") if isinstance(raw, dict) else None
            if isinstance(payload, dict):
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('counters', ?)",
                    (json.dumps(payload, ensure_ascii=False),),
                )
            queue.append((counters, "counters.json.migrated"))

        pending = base / "pending.json"
        if pending.exists() and not conn.execute(
            "SELECT 1 FROM pending_delivery LIMIT 1"
        ).fetchone():
            raw = read_json(pending, {})
            entries = raw.get("items") if isinstance(raw, dict) else None
            if isinstance(entries, list):
                for entry in entries:
                    item = PendingItem.from_dict(entry)
                    if item is None:
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO pending_delivery("
                        + ",".join(_PENDING_COLUMNS)
                        + ") VALUES("
                        + ",".join("?" for _ in _PENDING_COLUMNS)
                        + ")",
                        self._pending_values(item),
                    )
            queue.append((pending, "pending.json.migrated"))
        return queue

    def _finish_json_import(self, queue: Sequence[tuple[Path, str]]) -> None:
        """迁移成功后把旧 JSON 改名留痕（不删除，取证规则）。"""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for path, _name in queue:
            target = path.with_name(f"{path.name}.migrated-{stamp}")
            try:
                os.replace(path, target)
            except OSError:
                continue
            self._imported.append(str(target))
