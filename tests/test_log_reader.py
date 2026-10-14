"""log_reader 的纯逻辑测试：等级解析、片段合并、摘录切片、增量读取五种边界。

测试不导入 astrbot（离线可跑）。运行：python -m pytest tests -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import log_reader  # noqa: E402


def _line(level: str, message: str, stamp: str = "2026-10-13 03:15:44.276") -> str:
    return f"[{stamp}] [Core] [{level}] [v4.28.0] [x.py:1]: {message}"


# ---------- 等级解析 ----------


def test_parse_level_accepts_astrbot_short_names():
    assert log_reader.parse_level(_line("ERRO", "boom")) == "ERROR"
    assert log_reader.parse_level(_line("CRIT", "boom")) == "CRITICAL"
    assert log_reader.parse_level(_line("WARN", "boom")) == "WARNING"


def test_parse_level_accepts_standard_logging_format():
    assert log_reader.parse_level("ERROR:2026-10-13 03:15:44 something failed") == "ERROR"
    assert log_reader.parse_level("[2026-10-13 03:15:44,276] ERROR root: boom") == "ERROR"


def test_parse_level_ignores_ansi_and_body_tokens():
    colored = "\x1b[31m" + _line("ERRO", "boom") + "\x1b[0m"
    assert log_reader.parse_level(colored) == "ERROR"
    # 等级标记只可能在头部区域：正文里的 ERROR 不算
    body = _line("INFO", "user typed [ERROR] in chat " + "x" * 200)
    assert log_reader.parse_level(body) == "INFO"
    assert log_reader.parse_level("   just some text with ERROR inside") is None


def test_parse_level_rejects_continuation_lines():
    assert log_reader.is_record_start(_line("ERRO", "boom")) is True
    assert log_reader.is_record_start('  File "/root/x.py", line 10, in run') is False
    assert log_reader.is_record_start("ValueError: ERROR while doing the thing") is False
    # 续行里的 ERROR 是正文，不能构成命中
    assert log_reader.parse_level("ValueError: ERROR while doing the thing") is None


def test_parse_timestamp_and_normalize_levels():
    assert log_reader.parse_timestamp(_line("INFO", "hi")) == "2026-10-13 03:15:44.276"
    assert log_reader.parse_timestamp(_line("INFO", "hi", stamp="2026-10-13 03:15:44,276")) == (
        "2026-10-13 03:15:44.276"
    )
    assert log_reader.normalize_levels(["erro", "WARN", "bogus", "ERROR"]) == (
        "ERROR",
        "WARNING",
    )
    assert log_reader.order_levels(["ERROR", "CRITICAL", "DEBUG"]) == ["DEBUG", "ERROR", "CRITICAL"]


# ---------- 片段合并 ----------


def test_hit_collector_merges_overlapping_windows():
    collector = log_reader.HitCollector(["ERROR"], before=2, after=2, source="a.log")
    lines = [
        "p1",
        _line("ERRO", "first"),
        "p2",
        "p3",
        _line("ERRO", "second"),
        "p4",
        "p5",
        "p6",
        "p7",
    ]
    blocks = []
    for line in lines:
        blocks.extend(collector.feed(line))
    blocks.extend(collector.flush())
    assert len(blocks) == 1, "相邻命中必须合并成一段，不能重复前文"
    assert blocks[0].hit_count == 2
    assert blocks[0].lines[0] == "p1"
    assert "p5" in blocks[0].lines


def test_hit_collector_flush_marks_truncated_tail():
    collector = log_reader.HitCollector(["ERROR"], before=0, after=5)
    collector.feed(_line("ERRO", "at eof"))
    blocks = collector.flush()
    assert len(blocks) == 1
    assert blocks[0].truncated_after is True
    assert collector.flush() == [], "flush 必须幂等，第二次没有残留"


def test_hit_collector_suppress_callback_blocks_self_logs_entirely():


    def suppress(line: str, is_record_start: bool) -> bool:
        return "log_watcher" in line

    collector = log_reader.HitCollector(["ERROR"], before=2, after=0, suppress=suppress)
    collector.feed("context before")
    collector.feed("[2026-10-13 03:15:44.276] [log_watcher] [ERRO] [x.py:1]: boom")
    collector.feed('  File "/root/x.py", line 1')
    assert collector.flush() == [], "自身日志与其续行不得进入片段"


def test_hit_collector_exclude_keywords_keep_context():
    collector = log_reader.HitCollector(["ERROR"], before=1, after=0, exclude_keywords=["noisy"])
    collector.feed("before line")
    collector.feed(_line("ERRO", "noisy failure"))
    assert collector.flush() == [], "被排除的行不算命中"
    collector.feed(_line("ERRO", "real failure"))
    blocks = collector.flush()
    assert len(blocks) == 1
    assert "real failure" in blocks[0].lines[-1]


# ---------- 摘录切片 ----------


def test_excerpt_chunks_drops_empty_and_counts_dropped_lines():
    block = log_reader.LogBlock(
        source="a.log",
        lines=[_line("ERRO", f"boom {index}") for index in range(5)],
        hit_indices=[0, 1, 2, 3, 4],
        levels=["ERROR"] * 5,
    )
    chunks, dropped = log_reader.excerpt_chunks([block], max_lines=0, chunk_lines=2)
    assert [len(chunk) for chunk in chunks] == [2, 2, 1]
    assert dropped == 0
    chunks, dropped = log_reader.excerpt_chunks([block], max_lines=3, chunk_lines=10)
    assert dropped == 2
    assert len(chunks) == 1
    # 空片段不产生空切片（避免发出空节点）
    empty = log_reader.LogBlock(source="a.log", lines=[], hit_indices=[], levels=[])
    chunks, dropped = log_reader.excerpt_chunks([empty], max_lines=0, chunk_lines=10)
    assert chunks == []
    assert dropped == 0


def test_render_lines_marks_hits_and_strips_ansi():
    lines = [("ctx", None), ("\x1b[31mhit\x1b[0m", "ERROR")]
    rendered = log_reader.render_lines(log_reader.block_lines(
        log_reader.LogBlock(source="a", lines=["ctx", "\x1b[31mhit\x1b[0m"], hit_indices=[1], levels=["ERROR"])
    ))
    assert rendered == "   ctx\n>> hit"
    assert log_reader.levels_in([(text, level) for text, level in lines]) == ["ERROR"]


# ---------- 增量读取 ----------


def _state_for(path: Path, **overrides) -> dict:
    stat = path.stat()
    state = {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "offset": 0,
        "skip_to_eol": False,
    }
    state.update(overrides)
    return state


def test_new_lines_first_run_skips_history_and_does_not_replay(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("old-1\nold-2\n", encoding="utf-8")

    lines, state = log_reader.new_lines(path, None, skip_existing=True)
    assert lines == [], "首启 skip_existing 不应重放历史"
    assert state["offset"] == path.stat().st_size
    # 半行（无换行结尾）留给下次：定位不能吞掉它
    with path.open("a", encoding="utf-8") as handle:
        handle.write("partial")
    lines, state = log_reader.new_lines(path, state, skip_existing=True)
    assert lines == []
    with path.open("a", encoding="utf-8") as handle:
        handle.write("-done\nnew\n")
    lines, state = log_reader.new_lines(path, state, skip_existing=True)
    assert lines == ["partial-done", "new"]
    lines, state = log_reader.new_lines(path, state, skip_existing=True)
    assert lines == [], "同一进度不得重放"


def test_new_lines_first_run_from_head_when_not_skipping(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("old-1\nold-2\n", encoding="utf-8")
    lines, state = log_reader.new_lines(path, None, skip_existing=False)
    assert lines == ["old-1", "old-2"]
    assert state["offset"] == path.stat().st_size
    lines, _ = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == []


def test_new_lines_half_line_consumed_exactly_once(tmp_path):
    path = tmp_path / "a.log"
    path.write_bytes(b"")
    lines, state = log_reader.new_lines(path, None, skip_existing=False)
    assert lines == []
    with path.open("ab") as handle:
        handle.write(b"half")
    lines, state = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == []
    with path.open("ab") as handle:
        handle.write(b"\r\nnext\n")
    lines, state = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == ["half", "next"], "CRLF 半行补全后必须只出现一次且不带 \\r"


def test_new_lines_reads_from_head_when_inode_changes(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("old\n", encoding="utf-8")
    _, state = log_reader.new_lines(path, None, skip_existing=False)
    rotated = tmp_path / "a.log.new"
    rotated.write_text("rotated-1\nrotated-2\n", encoding="utf-8")
    rotated.replace(path)
    stale = dict(state, inode=state["inode"] + 12345)
    lines, new_state = log_reader.new_lines(path, stale, skip_existing=False)
    assert lines == ["rotated-1", "rotated-2"], "inode 变化后必须从新文件头开始读"
    assert new_state["inode"] == path.stat().st_ino


def test_new_lines_reads_from_head_after_truncate(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("aaaaaaaa\nbbbbbbbb\n", encoding="utf-8")
    _, state = log_reader.new_lines(path, None, skip_existing=False)
    path.write_text("c\n", encoding="utf-8")  # 截断重写
    lines, new_state = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == ["c"]
    assert new_state["offset"] == 2


def test_new_lines_oversize_single_line_does_not_stall_or_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(log_reader, "_MAX_READ_BYTES", 64)
    path = tmp_path / "a.log"
    giant = "G" * 200
    path.write_text(giant, encoding="utf-8")
    lines, state = log_reader.new_lines(path, None, skip_existing=False)
    assert len(lines) == 1
    assert lines[0].endswith(log_reader._OVERSIZE_NOTE)
    assert state["skip_to_eol"] is True
    # 巨行剩余字节 + 换行 + 下一条真实日志
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\nreal-after-giant\n")
    lines, state = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == ["real-after-giant"], "超长行剩余部分不得被当成新日志行"
    assert state["skip_to_eol"] is False
    lines, _ = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == []


def test_new_lines_ignores_missing_file(tmp_path):
    lines, state = log_reader.new_lines(tmp_path / "nope.log", {"offset": 3})
    assert lines == []
    assert state == {"offset": 3}


def test_new_lines_realigns_when_offset_lands_mid_line(tmp_path):
    """状态被外部改写（同 inode 原位放大）时，偏移落在行中间不得产出无头行。"""
    path = tmp_path / "a.log"
    path.write_text("alphaXXXX\nbeta\n", encoding="utf-8")
    stat = path.stat()
    stale = {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "offset": 6,  # 老内容 "alpha\n" 之后的位置，在新内容里落在行中间
        "skip_to_eol": False,
    }
    lines, state = log_reader.new_lines(path, stale, skip_existing=False)
    assert lines == ["beta"], "不得把行中间的残留当成无头日志行"
    assert state["offset"] == path.stat().st_size
    lines, _ = log_reader.new_lines(path, state, skip_existing=False)
    assert lines == []


def test_block_reports_missing_after_lines_on_flush():
    collector = log_reader.HitCollector(["ERROR"], before=0, after=3)
    collector.feed(_line("ERRO", "at eof"))
    blocks = collector.flush()
    assert blocks[0].truncated_after is True
    assert blocks[0].missing_after == 3
    collector = log_reader.HitCollector(["ERROR"], before=0, after=1)
    collector.feed(_line("ERRO", "boom"))
    done = collector.feed("tail line")
    assert done[0].truncated_after is False
    assert done[0].missing_after == 0


def test_align_line_start_returns_line_boundary(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("one\ntwo\nthree", encoding="utf-8")
    size = path.stat().st_size
    aligned = log_reader.align_line_start(path, size)
    assert path.read_bytes()[aligned:] == b"three"


if __name__ == "__main__":  # pragma: no cover - 便于手工单跑
    raise SystemExit(pytest.main([__file__, "-q"]))
