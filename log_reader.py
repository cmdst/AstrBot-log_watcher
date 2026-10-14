"""log_watcher 的日志解析与增量读取（纯逻辑，不导入 astrbot）。

本模块覆盖三个「改错了一眼看不出来」的静默失效面：
1. 等级解析：只有「记录头」行才算数，堆栈续行里的 ERROR 正文不算命中；
2. 片段边界：前后文窗口重叠/相邻的命中合并成一段，flush 收尾不漏尾巴；
3. 增量读取：inode 变化/截断/半行/单行超长/首启定位五种场景不丢行不重放。
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path

try:  # 包内导入（main.py 走这条）
    from .models import LogBlock
except ImportError:  # 纯逻辑直连导入（pytest / python -c 走这条）
    from models import LogBlock


# AstrBot 文件日志格式（astrbot/core/log.py 的 loguru file sink）：
# [2026-10-12 12:00:00.000] [Core] [ERRO] [v4.28.0] [file.py:12]: message
# 短等级名来自 _get_short_level_name；同时兼容标准 logging 的完整等级名。
LEVEL_ALIASES = {
    "DBUG": "DEBUG",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERRO": "ERROR",
    "ERROR": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
}

LEVEL_ORDER = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# 等级标记只可能在行首的头部区域，超过该长度后出现的 [ERROR] 视为日志正文
_HEADER_LIMIT = 120
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_BRACKET_RE = re.compile(r"\[([A-Za-z]{3,8})\]")
_PLAIN_LEVEL_RE = re.compile(
    r"(?:^|[\s\-|\[(])(DEBUG|INFO|WARNING|ERROR|CRITICAL)(?=$|[\s\-|:\]\)])"
)
_TIMESTAMP_RE = re.compile(
    r"^\s*\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]"
)
_LEADING_TAG_RE = re.compile(r"^\s*\[[^\[\]]{1,64}\]")
_PLAIN_HEADER_LEVEL_RE = re.compile(
    r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)(?=$|[\s\-|:\]\)])"
)

_ALIGN_SCAN_BYTES = 65536
# 单轮单文件最多消费的字节数：重放模式（start_from_end=false）遇到大文件时
# 避免一次性把几十万行喂给收集器阻塞事件循环，剩余部分下一轮继续
_MAX_READ_BYTES = 1 << 20
# 单轮为「跳过单行超长行的剩余部分」最多扫描的字节数，避免一轮里卡太久
_MAX_SKIP_BYTES = 4 << 20
# 单行超过读取上限时的落盘标记：跳过该行剩余字节，直到下一个换行
_OVERSIZE_NOTE = " …（单行超长，已截断）"


def strip_ansi(text: str) -> str:
    """去掉 ANSI 颜色码（WebUI 控制台日志抓取到文件时会带）。"""
    return _ANSI_RE.sub("", text)


def is_record_start(line: str) -> bool:
    """判断这一行是不是一条新日志记录的头行。

    续行（堆栈帧、缩进正文、裸异常文本）返回 False；只有头行才有资格构成命中。

    Args:
        line: 原始日志行。

    Returns:
        True 表示这是记录头行。
    """
    text = strip_ansi(line)
    if _TIMESTAMP_RE.match(text):
        return True
    # 裸等级头必须顶格（缩进行是续行/堆栈，不能算记录头）
    if _PLAIN_HEADER_LEVEL_RE.match(text):
        return True
    # 依次剥掉行首的 [tag]，若其中出现等级名则视为记录头（控制台格式）
    probe = text
    for _ in range(6):
        match = _LEADING_TAG_RE.match(probe)
        if not match:
            break
        alias = LEVEL_ALIASES.get(match.group(0).strip(" []").upper())
        if alias:
            return True
        probe = probe[match.end() :]
    return False


def _header_level(head: str) -> str | None:
    """在头部区域内找等级标记（先看 [ERRO] 这类方括号，再看裸等级词）。"""
    pos = 0
    while True:
        match = _BRACKET_RE.search(head, pos)
        if not match:
            break
        alias = LEVEL_ALIASES.get(match.group(1).upper())
        if alias:
            return alias
        pos = match.end()
    match = _PLAIN_LEVEL_RE.search(head)
    if match:
        return LEVEL_ALIASES[match.group(1)]
    return None


def parse_level(line: str, *, allow_continuation: bool = False) -> str | None:
    """解析日志行的等级，返回标准等级名；无法识别返回 None。

    Args:
        line: 原始日志行。
        allow_continuation: 为 True 时允许在续行里匹配等级（默认 False，
            续行里的 ERROR 字样是正文，不是等级）。

    Returns:
        标准等级名（DEBUG/INFO/WARNING/ERROR/CRITICAL）或 None。
    """
    text = strip_ansi(line)
    if not allow_continuation and not is_record_start(text):
        return None
    return _header_level(text[:_HEADER_LIMIT])


def parse_timestamp(line: str) -> str | None:
    """取日志行开头的 `[YYYY-MM-DD HH:MM:SS.mmm]` 时间戳。"""
    match = _TIMESTAMP_RE.match(strip_ansi(line))
    return match.group(1).replace(",", ".") if match else None


def normalize_levels(values: object) -> tuple[str, ...]:
    """把配置里的等级列表规整为标准等级名，忽略非法值。"""
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return ()
    levels: list[str] = []
    for value in values:
        alias = LEVEL_ALIASES.get(str(value).strip().upper())
        if alias and alias not in levels:
            levels.append(alias)
    return tuple(levels)


def order_levels(levels: object) -> list[str]:
    """按严重程度排序并去重。"""
    found = set(levels or ())
    return [level for level in LEVEL_ORDER if level in found]


class HitCollector:
    """按行滚动收集命中，并把窗口重叠/相邻的命中合并成连续片段。

    片段要等到「后面不可能再有命中与它重叠」才产出：读到最后一条命中之后
    `after + before` 行（`before` 行是留给下一条命中前文窗口的余量，
    否则相隔几行的两条命中会被拆成两段并重复前文）。文件停更时由调用方
    `flush()` 收尾，文件末尾的报错不会被永远挂起。

    续行永远不算命中，但会作为前后文进入片段；`suppress(line, is_record_start)`
    返回 True 的行既不算命中也不进入片段（用于屏蔽本插件自己的日志）。
    """

    def __init__(
        self,
        levels: object,
        *,
        before: int = 5,
        after: int = 5,
        exclude_keywords: object = (),
        source: str = "",
        suppress=None,
    ):
        self.levels = set(normalize_levels(levels))
        self.before = max(0, int(before))
        self.after = max(0, int(after))
        self.exclude_keywords = [
            str(kw) for kw in (exclude_keywords or []) if str(kw).strip()
        ]
        self.source = source
        self._suppress = suppress

        self._history: deque[str] = deque(maxlen=self.before)
        self._position = 0
        self._lines: list[str] = []
        self._hit_indices: list[int] = []
        self._levels: list[str] = []
        self._start = 0
        self._last_hit = -1

    def feed(self, line: str) -> list[LogBlock]:
        """喂入一行日志，返回本次收尾的片段。"""
        done: list[LogBlock] = []
        position = self._position
        self._position += 1

        record_start = is_record_start(line)
        blocked = bool(self._suppress) and bool(self._suppress(line, record_start))
        level = None if blocked else parse_level(line)
        matched = bool(level) and level in self.levels and not self._excluded(line)

        if blocked:
            # 自身日志不进片段，也不进前文历史，避免污染后续命中
            return done

        if self._lines:
            self._lines.append(line)
            if matched:
                self._accept_hit(level, position, len(self._lines) - 1)
            if position >= self._last_hit + self.after + self.before:
                done.append(self._take_block(unfinished=False))
        elif matched:
            self._lines = list(self._history) + [line]
            self._start = position - len(self._history)
            self._accept_hit(level, position, len(self._lines) - 1)
            if position >= self._last_hit + self.after + self.before:
                done.append(self._take_block(unfinished=False))

        self._history.append(line)
        return done

    def flush(self) -> list[LogBlock]:
        """文件停止增长时收尾：还没凑齐后文的片段也发出去。"""
        if not self._lines:
            return []
        return [self._take_block(unfinished=True)]

    def _accept_hit(self, level: str, position: int, index: int) -> None:
        self._hit_indices.append(index)
        self._levels.append(level)
        self._last_hit = position

    def _take_block(self, *, unfinished: bool) -> LogBlock:
        lines = self._lines
        want = self._last_hit + self.after - self._start + 1
        visible = lines[: max(1, min(len(lines), want))]
        missing = max(0, want - len(visible)) if unfinished else 0
        block = LogBlock(
            source=self.source,
            lines=list(visible),
            hit_indices=list(self._hit_indices),
            levels=list(self._levels),
            start_line=self._start,
            truncated_after=bool(unfinished and missing),
            missing_after=missing,
        )
        self._lines = []
        self._hit_indices = []
        self._levels = []
        self._last_hit = -1
        return block

    def _excluded(self, line: str) -> bool:
        return any(kw in line for kw in self.exclude_keywords)


def block_lines(block: LogBlock) -> list[tuple[str, str | None]]:
    """片段展开为 (行文本, 命中等级或 None)。"""
    marked = dict(zip(block.hit_indices, block.levels))
    return [
        (strip_ansi(raw).rstrip(), marked.get(index))
        for index, raw in enumerate(block.lines)
    ]


def levels_in(lines: list[tuple[str, str | None]]) -> list[str]:
    """一组行里出现过的命中等级（去重、按严重程度排序）。"""
    return order_levels(level for _, level in lines if level)


def render_lines(lines: list[tuple[str, str | None]]) -> str:
    """渲染一组行为正文，命中行以 `>>` 标出。"""
    return "\n".join((">> " if level else "   ") + text for text, level in lines)


def excerpt_chunks(
    blocks: list[LogBlock],
    *,
    max_lines: int = 0,
    chunk_lines: int = 100,
) -> tuple[list[list[tuple[str, str | None]]], int]:
    """把片段摊平成带命中标记的行序列，并按节点大小切片。

    `max_lines` 是本轮展开上限（<=0 表示不限），超出的行被丢弃并在返回值里报数；
    `chunk_lines` 是单个转发节点的行数上限，防止单节点过大导致发送失败。
    空片段不产生空切片（避免发出空节点）。

    Returns:
        (切片列表, 被丢弃行数)。
    """
    flat: list[tuple[str, str | None]] = []
    for block in blocks:
        if not block.lines:
            continue
        if flat:
            flat.append(("", None))  # 片段之间空一行
        flat.extend(block_lines(block))

    limit = len(flat) if max_lines is None or max_lines <= 0 else int(max_lines)
    dropped = max(0, len(flat) - limit)
    flat = flat[:limit]

    size = max(1, int(chunk_lines))
    chunks: list[list[tuple[str, str | None]]] = []
    for index in range(0, len(flat), size):
        chunk = flat[index : index + size]
        if render_lines(chunk).strip():
            chunks.append(chunk)
    return chunks, dropped


def align_line_start(path: Path, size: int) -> int:
    """把偏移对齐到行边界，避免从半行开始读。

    Args:
        path: 日志文件路径。
        size: 期望的起始字节偏移（通常是文件大小）。

    Returns:
        不大于 size 的行首偏移；扫描窗口内找不到换行时返回 size。
    """
    try:
        start = max(0, size - _ALIGN_SCAN_BYTES)
        with path.open("rb") as handle:
            handle.seek(start)
            data = handle.read(size - start)
    except OSError:
        return size
    index = data.rfind(b"\n")
    return start + index + 1 if index >= 0 else size


def _skip_oversize_tail(path: Path, offset: int) -> tuple[int, bool]:
    """跳过单行超长行剩余的字节，返回 (新偏移, 是否已找到行尾)。

    单轮最多扫描 _MAX_SKIP_BYTES：巨行后面的正常日志不会被拖太多轮。
    """
    scanned = 0
    cursor = max(0, int(offset))
    while scanned < _MAX_SKIP_BYTES:
        try:
            with path.open("rb") as handle:
                handle.seek(cursor)
                data = handle.read(_MAX_READ_BYTES)
        except OSError:
            return cursor, False
        if not data:
            # 巨行还没写完（没有行尾）：保持跳过状态，等下一轮再找换行
            return cursor, False
        index = data.find(b"\n")
        if index >= 0:
            return cursor + index + 1, True
        scanned += len(data)
        cursor += len(data)
    return cursor, False


def _boundary_offset(path: Path, offset: int) -> tuple[int, int]:
    """确保偏移落在行首：不在行首就跳到下一个换行之后。

    状态里只有 device/inode/offset，没有行内容校验；若外部把文件原地改写成更大
    体积，offset 可能落在某一行中间，直接读会产出「无头行」。这里用「offset-1 处
    是否是换行」做一次廉价校验，必要时对齐，返回 (新偏移, 跳过字节数)。
    """
    if offset <= 0:
        return 0, 0
    try:
        with path.open("rb") as handle:
            handle.seek(offset - 1)
            previous = handle.read(1)
    except OSError:
        return offset, 0
    if previous in (b"\n", b""):
        return offset, 0
    new_offset, _ = _skip_oversize_tail(path, offset)
    return new_offset, max(0, new_offset - offset)


def new_lines(
    path: Path,
    state: dict | None = None,
    *,
    skip_existing: bool = False,
) -> tuple[list[str], dict]:
    """读取日志文件自上次位置以来的完整新增行。

    Args:
        path: 日志文件路径。
        state: 上次的进度（含 device/inode/offset/skip_to_eol）；None 表示首次见到该文件。
        skip_existing: 首次见到该文件时是否从文件末尾开始（避免启动重放历史）。

    Returns:
        (完整新增行列表, 新进度)。返回值可直接 JSON 持久化（main.py 用原子写落盘），
        未写完的半行不消费，留待下次读取；文件被轮转/截断时自动重新定位。
    """
    try:
        stat = path.stat()
    except OSError:
        return [], dict(state or {})

    ident = (
        int(getattr(stat, "st_dev", 0) or 0),
        int(getattr(stat, "st_ino", 0) or 0),
    )
    if state is None:
        offset = align_line_start(path, stat.st_size) if skip_existing else 0
        current = {
            "device": ident[0],
            "inode": ident[1],
            "offset": offset,
            "skip_to_eol": False,
        }
    else:
        current = {
            "device": int(state.get("device", 0) or 0),
            "inode": int(state.get("inode", 0) or 0),
            "offset": max(0, int(state.get("offset", 0) or 0)),
            "skip_to_eol": bool(state.get("skip_to_eol", False)),
        }
        if (current["device"], current["inode"]) != ident:
            # 文件被轮转/重建：旧内容此前已读，新文件从头读，并记住新的身份，
            # 否则下一轮又会判定身份不符、无限重放整个文件
            current["device"], current["inode"] = ident
            current["offset"] = 0
            current["skip_to_eol"] = False
        elif stat.st_size < current["offset"]:
            # 文件被截断（loguru 清空或外部 truncate）
            current["offset"] = 0
            current["skip_to_eol"] = False

    if current["skip_to_eol"]:
        offset, found = _skip_oversize_tail(path, current["offset"])
        current["offset"] = offset
        current["skip_to_eol"] = not found
        if not found:
            return [], current

    # 偏移对齐：状态被外部改写/原位重写时 offset 可能落在行中间
    aligned, skipped = _boundary_offset(path, current["offset"])
    if skipped:
        current["offset"] = aligned

    offset = current["offset"]
    if stat.st_size <= offset:
        return [], current

    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(_MAX_READ_BYTES)
    except OSError:
        return [], current

    if not data:
        return [], current

    chunks = data.split(b"\n")
    tail = chunks.pop()  # 无换行结尾的半行：不消费，下次重读
    if not chunks and len(data) >= _MAX_READ_BYTES:
        # 单行就超过读取上限：按截断行消费，并标记跳过该行剩余字节，
        # 否则会永远卡在同一位置、或把巨行的尾巴当成新日志行
        current["offset"] = offset + len(data)
        current["skip_to_eol"] = True
        text = data.decode("utf-8", errors="replace").rstrip("\r") + _OVERSIZE_NOTE
        return [text], current

    current["offset"] = offset + len(data) - len(tail)
    lines = [chunk.decode("utf-8", errors="replace").rstrip("\r") for chunk in chunks]
    return lines, current
