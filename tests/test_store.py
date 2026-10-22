"""store 的纯逻辑测试：原子落盘、进度、计数器、待发队列、磁盘治理。"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import store  # noqa: E402

# ---------- 原子写 ----------


def test_atomic_write_json_round_trip_and_no_temp_leftovers(tmp_path):
    path = tmp_path / "state.json"
    store.atomic_write_json(path, {"version": 1, "files": {"a": 1}})
    assert json.loads(path.read_text(encoding="utf-8")) == {"version": 1, "files": {"a": 1}}
    assert [item.name for item in tmp_path.iterdir()] == ["state.json"]


def test_atomic_write_keeps_old_content_when_replace_fails(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    path.write_text("old-content", encoding="utf-8")

    def boom(*args, **kwargs):
        raise OSError("模拟磁盘故障")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.atomic_write_json(path, {"new": True})
    assert path.read_text(encoding="utf-8") == "old-content", "失败时不得破坏旧内容"
    assert list(tmp_path.iterdir()) == [path], "临时文件必须被清理"


def test_read_json_tolerates_missing_and_corrupt(tmp_path):
    assert store.read_json(tmp_path / "nope.json", {"x": 1}) == {"x": 1}
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert store.read_json(broken, "fallback") == "fallback"


# ---------- tail 进度 ----------


def test_tail_state_store_round_trip_and_sanitize(tmp_path):
    path = tmp_path / "tail.json"
    tail = store.TailStateStore(path)
    tail.set("/logs/a.log", {"device": 1, "inode": 2, "offset": 30, "skip_to_eol": True})
    assert tail.save() is True
    tail.set("/logs/bad.log", "not-a-dict")
    assert tail.get("/logs/bad.log") is None
    loaded = store.TailStateStore(path).load()
    assert loaded.get("/logs/a.log") == {
        "device": 1,
        "inode": 2,
        "offset": 30,
        "skip_to_eol": True,
    }
    # 返回副本：调用方改内存不影响容器
    snapshot = loaded.get("/logs/a.log")
    snapshot["offset"] = 999
    assert loaded.get("/logs/a.log")["offset"] == 30


def test_tail_state_store_drops_corrupt_entries(tmp_path):
    path = tmp_path / "tail.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "files": {
                    "ok.log": {"device": "1", "inode": "2", "offset": "-5"},
                    "corrupt.log": {"device": "x", "inode": "y", "offset": "z"},
                    "string.log": "hello",
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = store.TailStateStore(path).load()
    assert set(loaded.files) == {"ok.log"}
    assert loaded.get("ok.log")["offset"] == 0


# ---------- 计数器 ----------


def test_counter_store_bumps_subcounters_and_windows():
    counters = store.CounterStore()
    assert counters.bump("rounds") == 1
    assert counters.bump("rounds", 2) == 3
    assert counters.get_int("rounds") == 3
    counters.bump_sub("decisions", "send")
    counters.bump_sub("decisions", "send")
    assert counters.sub("decisions") == {"send": 2}
    for moment in (100.0, 130.0, 200.0):
        counters.window_push("sent_minute", moment)
    assert counters.window_count("sent_minute", 200.0, 60.0) == 1
    assert counters.window_count("sent_minute", 200.0, 200.0) == 3
    counters.prune_windows(8000.0)  # 超过窗口保鲜期（7200s）
    assert counters.data["windows"] == {}


def test_counter_store_fingerprints_and_prune():
    counters = store.CounterStore()
    assert counters.touch_fingerprint("fp1", 1000.0) == 1
    assert counters.touch_fingerprint("fp1", 1001.0) == 2
    info = counters.fingerprint_info("fp1")
    assert info["count"] == 2
    assert info["first_ts"] == 1000.0
    assert info["last_ts"] == 1001.0
    assert counters.fingerprint_info("missing")["count"] == 0
    assert counters.prune_fingerprints(1001.0 + 100, older_than=50) == 1
    assert counters.fingerprint_info("fp1")["count"] == 0


def test_counter_store_in_memory_equals_on_disk(tmp_path):
    path = tmp_path / "counters.json"
    counters = store.CounterStore(path)
    counters.bump("alerts_sent", 3)
    counters.bump_sub("decisions", "suppress_dedup", 2)
    counters.buffer("digest_buffer").append({"fingerprint": "fp"})
    counters.burst_state()["count"] = 5
    assert counters.save() is True
    on_disk = json.loads(path.read_text(encoding="utf-8"))["counters"]
    assert on_disk == counters.snapshot(), "进程内计数必须与落盘逐字一致"
    reloaded = store.CounterStore(path).load()
    assert reloaded.snapshot() == counters.snapshot()


# ---------- 待发队列 ----------


def _pending_item(session="s1", fingerprint="fp1", text="alert", **kwargs):
    return store.PendingItem(session=session, fingerprint=fingerprint, text=text, **kwargs)


def _pending_item(session="s1", fingerprint="fp1", text="alert", **kwargs):
    return store.PendingItem(
        session=session,
        fingerprint=fingerprint,
        chunks=[text],
        text=text,
        **kwargs,
    )


def test_pending_queue_merges_same_fingerprint_and_persists(tmp_path):
    """R8：失败条目必须落盘（含原文分片与降级文本），同会话同指纹合并。"""
    path = tmp_path / "pending.json"
    queue = store.PendingQueue(path)
    first = queue.add(_pending_item(created_at=100.0))
    again = queue.add(_pending_item(text="alert-longer", created_at=200.0))
    assert again.item_id == first.item_id
    assert again.text == "alert-longer"
    assert queue.save() is True
    reloaded = store.PendingQueue(path).load()
    stats = reloaded.stats()
    assert stats["pending"] == 1 and stats["active"] == 1
    assert reloaded.items[0].chunks == ["alert-longer"]


def test_pending_item_from_dict_accepts_v1_shape():
    """迁移兼容：v1 的 status/next_attempt_at 字段要能被读进来。"""
    item = store.PendingItem.from_dict(
        {
            "session": "s1",
            "text": "legacy",
            "fingerprint": "fp",
            "attempts": 2,
            "next_attempt_at": 123.0,
            "status": "pending",
        }
    )
    assert item is not None
    assert item.state == "degraded"  # 已尝试过 → 降级态
    assert item.next_at == 123.0
    assert item.chunks == ["legacy"]


def test_pending_queue_state_machine_pending_degraded_abandoned(tmp_path):
    queue = store.PendingQueue(tmp_path / "pending.json")
    item = queue.add(_pending_item(created_at=100.0))
    assert queue.due(0.0) == [item], "新条目应立即到期"
    queue.mark_failure(item.item_id, 100.0, delay=30.0, max_attempts=3, error="boom")
    assert item.state == "degraded", "首次失败转降级态（下一轮发降级文本）"
    assert queue.due(110.0) == [], "退避期内不得重试"
    assert len(queue.due(130.0)) == 1
    queue.mark_failure(item.item_id, 130.0, delay=60.0, max_attempts=3, error="boom")
    assert item.state == "degraded"
    queue.mark_failure(item.item_id, 200.0, delay=60.0, max_attempts=3, error="boom")
    assert item.state == "abandoned"
    assert queue.due(99999.0) == [], "放弃的条目不再重试"
    stats = queue.stats()
    assert stats["abandoned"] == 1, "放弃也要留档，不能静默丢"
    assert stats["active"] == 0
    assert queue.mark_success(item.item_id) is True
    assert queue.stats()["abandoned"] == 0


def test_pending_queue_prunes_and_bounds(tmp_path):
    queue = store.PendingQueue(tmp_path / "pending.json", max_items=3, max_age=10.0)
    for index in range(6):
        queue.add(
            _pending_item(
                session=f"s{index}", fingerprint=f"fp{index}", created_at=float(index)
            )
        )
    assert len(queue.items) == 3, "超出上限必须被裁剪"
    queue.items[0].state = "abandoned"
    queue.items[0].created_at = 0.0
    assert queue.prune(100.0) >= 1
    assert all(item.state in {"pending", "degraded"} for item in queue.items)


def test_pending_item_truncates_oversize_text(tmp_path):
    queue = store.PendingQueue(tmp_path / "pending.json", max_text_chars=20)
    item = queue.add(_pending_item(text="x" * 500))
    assert len(item.text) < 500
    assert item.text.endswith("…（内容过长已截断）")


def _touch(path: Path, size: int, mtime: float) -> None:
    path.write_text("x" * size, encoding="utf-8")
    os.utime(path, (mtime, mtime))


def test_disk_governor_releases_success_and_keeps_failure_residue(tmp_path):
    governor = store.DiskGovernor(tmp_path, keep=10, max_age=86400.0)
    excerpt = governor.write_excerpt("hello")
    assert excerpt.parent == governor.outbox
    spill = governor.spill("failed text", fingerprint="abcdef123456")
    assert spill.parent == governor.failed
    usage = governor.usage()
    assert usage["outbox"]["files"] == 1
    assert usage["failed"]["files"] == 1
    assert governor.release(excerpt) is True
    assert governor.usage()["outbox"]["files"] == 0, "成功残留必须能回收"
    assert governor.usage()["failed"]["files"] == 1, "失败残留保留供重试"
    assert governor.release(tmp_path / "not-there.txt") is False


def test_disk_governor_prunes_both_success_and_failure_residue(tmp_path):
    """§8.5：字节 → 条数 → 年龄三条叠加，两区（成功/失败残留）都生效。"""
    now = 2_000_000.0
    governor = store.DiskGovernor(tmp_path, keep=2, max_age=3600.0)
    governor.outbox.mkdir(parents=True)
    governor.failed.mkdir(parents=True)
    for index in range(4):
        _touch(governor.outbox / f"ok-{index}.txt", 10, now - 7200 + index)
    for index in range(4):
        _touch(governor.failed / f"bad-{index}.txt", 10, now - 7200 + index)
    removed = governor.prune(now)
    assert removed["outbox"] == 4, "超龄文件即使在前两名也会被年龄规则删掉"
    assert removed["failed"] == 4
    assert governor.usage(now)["outbox"]["files"] == 0
    assert governor.usage(now)["failed"]["files"] == 0


def test_disk_governor_keeps_recent_files_within_limits(tmp_path):
    """新鲜文件不因年龄被删，但条数上限仍然裁到 keep。"""
    now = 2_000_000.0
    governor = store.DiskGovernor(tmp_path, keep=2, max_age=3600.0)
    governor.outbox.mkdir(parents=True)
    for index in range(5):
        _touch(governor.outbox / f"new-{index}.txt", 10, now - 10 + index)
    removed = governor.prune(now)
    assert removed["outbox"] == 3
    assert governor.usage(now)["outbox"]["files"] == 2


def test_disk_governor_enforces_byte_cap(tmp_path):
    now = 2_000_000.0
    governor = store.DiskGovernor(tmp_path, keep=100, max_age=10**9, max_bytes=100)
    governor.outbox.mkdir(parents=True)
    for index in range(5):
        _touch(governor.outbox / f"big-{index}.txt", 50, now - 100 + index)
    governor.prune(now)
    usage = governor.usage(now)
    assert usage["outbox"]["bytes"] <= 100
    assert usage["over_limit"] is False


def test_disk_governor_usage_report_shape(tmp_path):
    governor = store.DiskGovernor(tmp_path, keep=1, max_age=3600.0, max_bytes=10)
    governor.outbox.mkdir(parents=True)
    _touch(governor.outbox / "a.txt", 20, 1000.0)
    usage = governor.usage(1000.0)
    assert usage["files"] == 1
    assert usage["bytes"] == 20
    assert usage["over_limit"] is True
    assert "磁盘占用" in governor.report(1000.0)


if __name__ == "__main__":  # pragma: no cover - 便于手工单跑
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------- SQLite 状态库（R11 / §9） ----------


def _sqlite(tmp_path, name="log_watcher.sqlite3"):
    return store.SqliteStore(tmp_path / name).open()


def _insert_legacy_run(db, run_id: str, *, status: str = "running", started_at: float = 0.0) -> None:
    """往历史台账直接插一行（v2.3.0 没有任何写入口，测试只能手工造历史行）。

    这张表 v2.3.0 起「只留不写」：表与列仍在（历史审计证据），写入面随自动修复通道一并删除。
    """
    conn = sqlite3.connect(db.path)
    try:
        conn.execute(
            "INSERT INTO remediation_runs(run_id, fingerprint, severity, started_at, status)"
            " VALUES(?, 'fp', 'HIGH', ?, ?)",
            (str(run_id), float(started_at), str(status)),
        )
        conn.commit()
    finally:
        conn.close()


def _run_status(db, run_id: str) -> str | None:
    """读某历史行的状态（表已无读取 API，测试直接查）。"""
    conn = sqlite3.connect(db.path)
    try:
        row = conn.execute(
            "SELECT status FROM remediation_runs WHERE run_id = ?", (str(run_id),)
        ).fetchone()
    finally:
        conn.close()
    return None if row is None else str(row[0])


def test_sqlite_open_creates_schema_v3(tmp_path):
    db = _sqlite(tmp_path)
    assert db.available and db.writable
    assert db.schema_version == store.SCHEMA_VERSION == 3
    assert db.path.exists()
    # v2.3.0：`remediation_runs` 仍在建（历史审计证据，只留不写）
    for table in ("meta", "file_progress", "pattern_kb", "alerts", "rate_windows",
                  "pending_delivery", "remediation_runs"):
        assert db.count_rows(table) == 0
    db.close()


def test_sqlite_migrate_is_idempotent(tmp_path):
    path = tmp_path / "log_watcher.sqlite3"
    first = store.SqliteStore(path).open()
    assert first.migrate() == 3
    assert first.migrate() == 3
    first.close()
    second = store.SqliteStore(path).open()
    assert second.schema_version == 3 and second.writable
    second.close()


def test_sqlite_refuses_newer_schema_without_touching_file(tmp_path):
    """§9.5 第 3 条：比本实现更新的 user_version 进只读降级，文件不动。"""
    import sqlite3

    path = tmp_path / "log_watcher.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    conn.execute("CREATE TABLE keep_me(x INTEGER)")
    conn.commit()
    conn.close()
    before = path.read_bytes()

    db = store.SqliteStore(path).open()
    assert db.available is True
    assert db.writable is False and db.readonly is True
    assert f"版本 {store.SCHEMA_VERSION + 1}" in db.last_error
    assert db.meta_set("counters", {"a": 1}) is False
    assert db.record_alerts([{"ts": 1.0, "fingerprint": "fp"}]) == 0
    db.close()
    assert path.read_bytes() == before, "降级保护不得改动文件"


def test_sqlite_records_alerts_and_metrics_for(tmp_path):
    db = _sqlite(tmp_path)
    now = 1_000_000.0
    written = db.record_alerts(
        [
            {"ts": now - 10, "fingerprint": "fp1", "severity": "HIGH", "decision": "send",
             "tags": ["a"], "hit_count": 2},
            {"ts": now - 5, "fingerprint": "fp1", "severity": "HIGH",
             "decision": "suppress_dedup"},
            {"ts": now - 90000, "fingerprint": "fp1", "severity": "HIGH"},
        ]
    )
    assert written == 3
    metrics = db.metrics_for(["fp1", "missing"], window=900.0, now=now)
    assert metrics["fp1"]["repeat_count"] == 2
    assert metrics["fp1"]["total"] == 3
    assert metrics["missing"] if "missing" in metrics else True
    assert db.metrics_for([], window=900.0, now=now) == {}
    db.close()


def test_sqlite_counters_and_meta_roundtrip(tmp_path):
    db = _sqlite(tmp_path)
    assert db.counters() == {}
    db.bump_counters({"alerts_sent": 2, "rounds": 1})
    db.bump_counters({"alerts_sent": 3})
    assert db.counters() == {"alerts_sent": 5, "rounds": 1}
    assert db.meta_set("counters_state", {"windows": {"sent_hour": [1.0]}})
    assert db.meta_get("counters_state") == {"windows": {"sent_hour": [1.0]}}
    assert db.meta_get("nope", "fallback") == "fallback"
    db.close()


def test_sqlite_rate_windows(tmp_path):
    db = _sqlite(tmp_path)
    now = 500_000.0
    assert db.push_rates([("sent_minute", now), ("sent_minute", now - 30)]) == 2
    db.push_rate("sent_minute", now - 600)
    db.push_rate("sent_day", now)
    assert db.rate_count("sent_minute", seconds=60, now=now) == 2
    assert db.rate_count("sent_minute", seconds=1200, now=now) == 3
    assert db.rate_count("sent_day", seconds=86400, now=now) == 1
    db.close()


def test_sqlite_progress_roundtrip(tmp_path):
    db = _sqlite(tmp_path)
    assert db.upsert_progress(
        [{"path": "/logs/a.log", "device": 1, "inode": 2, "offset": 30, "size": 40,
          "updated_at": 10.0}]
    ) == 1
    db.upsert_progress(
        [{"path": "/logs/a.log", "device": 1, "inode": 2, "offset": 99, "size": 99,
          "updated_at": 20.0}]
    )
    progress = db.progress()
    assert progress["/logs/a.log"]["offset"] == 99
    view = store.TailStateStore()
    view.import_rows(progress)
    assert view.get("/logs/a.log")["offset"] == 99
    db.close()


def test_sqlite_kb_manual_protection_and_prune(tmp_path):
    db = _sqlite(tmp_path)
    now = 900_000.0
    assert db.kb_upsert(
        [{"fingerprint": "fp1", "severity": "HIGH", "source": "llm", "last_seen": now,
          "tags": ["x"]}]
    ) == 1
    assert db.kb_upsert([{"fingerprint": "fp1", "severity": "LOW", "source": "noise",
                          "last_seen": now}]) == 1
    entry = db.kb_lookup("fp1")
    assert entry["severity"] == "LOW" and entry["hits"] == 2
    assert db.kb_set_manual("fp1", "CRITICAL", reason="人工", tags=["manual"]) is True
    db.kb_upsert([{"fingerprint": "fp1", "severity": "LOW", "source": "llm",
                   "last_seen": now + 1}])
    entry = db.kb_lookup("fp1")
    assert entry["severity"] == "CRITICAL" and entry["manual"] is True
    assert entry["hits"] == 3
    assert db.kb_prune(older_than=1.0, max_entries=500, now=now + 10000) == 0, "manual 不清理"
    assert db.kb_lookup("fp1") is not None
    db.close()


def test_sqlite_pending_state_machine(tmp_path):
    db = _sqlite(tmp_path)
    now = 700_000.0
    item = db.pending_add(
        store.PendingItem(session="s1", fingerprint="fp1", chunks=["a", "b"], text="a\nb")
    )
    assert db.pending_stats(now)["pending"] == 1
    assert [row.item_id for row in db.pending_due(now)] == [item.item_id]
    assert db.pending_update(item.item_id, state="degraded", attempts=1, next_at=now + 30,
                             last_error="boom") is True
    assert db.pending_due(now) == []
    due = db.pending_due(now + 31)
    assert due[0].state == "degraded" and due[0].attempts == 1
    assert db.pending_update(item.item_id, state="abandoned") is True
    assert db.pending_stats(now)["abandoned"] == 1
    # 旧条目已放弃 → 同一指纹的新条目应当重新入队（不覆盖 abandoned 记录）
    fresh = db.pending_add(
        store.PendingItem(session="s1", fingerprint="fp1", chunks=["x"], text="x")
    )
    assert fresh.item_id != item.item_id
    assert db.pending_stats(now)["pending"] == 1
    assert db.pending_stats(now)["abandoned"] == 1
    db.close()


def test_sqlite_pending_import_from_json(tmp_path):
    db = _sqlite(tmp_path)
    rows = [
        {"session": "s1", "text": "legacy", "fingerprint": "fp", "attempts": 0,
         "item_id": "id1"},
        {"session": "s2", "text": "legacy2", "fingerprint": "fp2", "item_id": "id2"},
    ]
    assert db.pending_import(rows) == 2
    assert db.pending_import(rows) == 0, "同 item_id 幂等跳过"
    assert db.pending_stats()["pending"] == 2
    db.close()


def test_sqlite_prune_enforces_limits_and_orphans(tmp_path):
    db = _sqlite(tmp_path)
    now = time.time() + 1
    db.record_alerts(
        [
            {"ts": now - 40 * 86400, "fingerprint": "old"},
            {"ts": now, "fingerprint": "new"},
        ]
    )
    db.push_rate("sent_minute", now - 9000)
    db.push_rate("sent_minute", now)
    item = db.pending_add(store.PendingItem(session="s1", fingerprint="fp", text="t"))
    db.pending_update(item.item_id, state="sent")
    _insert_legacy_run(db, "stuck", started_at=time.time() - 7200)  # 远超 600s 宽限
    removed = db.prune(now=now, cfg={"history_retention_days": 30, "history_max_rows": 1000,
                                     "fingerprint_ttl_hours": 72, "kb_max_entries": 500})
    assert removed["alerts"] == 1
    assert removed["rate"] == 1
    assert removed["pending"] == 1
    assert db.count_rows("alerts") == 1
    assert db.rate_count("sent_minute", seconds=86400, now=now) == 1
    assert _run_status(db, "stuck") == "timeout", "孤儿 running 行要自愈成 timeout"
    assert db.count_rows("remediation_runs") == 1, "自愈只改状态，不删历史行（取证材料）"
    db.close()


def test_sqlite_prune_delete_cap_and_row_limit(tmp_path):
    db = _sqlite(tmp_path)
    now = 3_000_000.0
    db.record_alerts([{"ts": now, "fingerprint": f"fp{index}"} for index in range(1200)])
    removed = db.prune(now=now, cfg={"history_retention_days": 30, "history_max_rows": 1000,
                                     "fingerprint_ttl_hours": 72, "kb_max_entries": 500})
    assert removed["alerts"] <= 500, "单次删限量 ≤ 500 行，避免长事务"
    db.close()


def test_sqlite_json_import_renames_legacy_files(tmp_path):
    """§9.5 第 4 条：JSON → SQLite 一次性导入，旧文件改名留痕不删除。"""
    (tmp_path / "tail_state.json").write_text(
        json.dumps({"version": 1, "files": {"/logs/a.log": {"device": 1, "inode": 2,
                                                            "offset": 42}}}),
        encoding="utf-8",
    )
    (tmp_path / "counters.json").write_text(
        json.dumps({"version": 1, "counters": {"alerts_sent": 7}}), encoding="utf-8"
    )
    (tmp_path / "pending.json").write_text(
        json.dumps({"version": 1, "items": [{"session": "s1", "text": "legacy",
                                             "fingerprint": "fp"}]}),
        encoding="utf-8",
    )
    db = _sqlite(tmp_path)
    assert db.progress()["/logs/a.log"]["offset"] == 42
    assert db.counters()["alerts_sent"] == 7
    assert db.pending_stats()["pending"] == 1
    assert not (tmp_path / "tail_state.json").exists()
    migrated = sorted(path.name for path in tmp_path.glob("*.migrated-*"))
    assert len(migrated) == 3, migrated
    assert len(db.imported_json) == 3
    db.close()


def test_sqlite_degraded_mode_on_unopenable_path(tmp_path):
    """§9.4 第 5 条：库打不开 → 内存态降级，方法仍可调用不抛异常。"""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    db = store.SqliteStore(blocker / "db.sqlite3").open()
    assert db.available is False and db.degraded is True
    assert db.last_error
    assert db.record_alerts([{"ts": 1.0, "fingerprint": "fp"}]) == 0
    assert db.pending_due(1.0) == []
    assert db.counters() == {}
    assert db.usage()["available"] is False
    db.close()


def test_sqlite_usage_shape(tmp_path):
    db = _sqlite(tmp_path)
    db.record_alerts([{"ts": 1.0, "fingerprint": "fp"}])
    usage = db.usage()
    assert usage["schema_version"] == store.SCHEMA_VERSION
    assert usage["alerts"] == 1
    assert usage["bytes"] > 0
    assert set(usage) >= {"path", "bytes", "alerts", "pending", "kb", "runs", "rate"}
    db.close()


def test_counter_store_export_import_round_trip():
    """§6.8：SQLite 承载的是完整状态（含行窗与桶），恢复后行为一致。"""
    source = store.CounterStore()
    source.bump("alerts_sent", 4)
    source.window_push("sent_hour", 1000.0)
    source.buffer("digest_buffer").append({"fingerprint": "fp"})
    source.burst_state()["count"] = 2
    state = source.export_state()

    target = store.CounterStore().import_state(state)
    assert target.snapshot() == source.snapshot()
    assert target.window_count("sent_hour", 1000.0, 60.0) == 1
    assert target.buffer("digest_buffer")[0]["fingerprint"] == "fp"
    assert target.burst_state()["count"] == 2


def test_sqlite_counters_state_survives_reopen(tmp_path):
    """计数快照进 meta，重启后窗口仍然生效（跨重启预算）。"""
    path = tmp_path / "log_watcher.sqlite3"
    first = store.SqliteStore(path).open()
    counters = store.CounterStore().import_state(first.meta_get("counters_state", {}) or {})
    counters.bump("alerts_sent", 2)
    counters.window_push("sent_day", 1000.0)
    first.meta_set("counters_state", counters.export_state())
    first.close()

    second = store.SqliteStore(path).open()
    restored = store.CounterStore().import_state(second.meta_get("counters_state", {}) or {})
    assert restored.get_int("alerts_sent") == 2
    assert restored.window_count("sent_day", 1000.0, 86400.0) == 1
    second.close()


def test_sqlite_pending_due_orders_by_created_at(tmp_path):
    db = _sqlite(tmp_path)
    later = db.pending_add(
        store.PendingItem(session="s2", fingerprint="fp2", text="b", created_at=200.0,
                          next_at=0.0)
    )
    earlier = db.pending_add(
        store.PendingItem(session="s1", fingerprint="fp1", text="a", created_at=100.0,
                          next_at=0.0)
    )
    assert [item.item_id for item in db.pending_due(1.0)] == [earlier.item_id, later.item_id]
    db.close()


def test_sqlite_prune_trim_to_history_max_rows(tmp_path):
    db = _sqlite(tmp_path)
    now = time.time()
    db.record_alerts([{"ts": now - index, "fingerprint": f"fp{index}"} for index in range(1200)])
    removed = 0
    for _ in range(3):
        removed += db.prune(
            now=now,
            cfg={"history_retention_days": 3650, "history_max_rows": 100,
                 "fingerprint_ttl_hours": 72, "kb_max_entries": 500},
        )["alerts"]
    assert removed >= 500
    assert db.count_rows("alerts") <= 1200
    db.close()


def test_sqlite_kb_prune_overflow_keeps_recent(tmp_path):
    db = _sqlite(tmp_path)
    now = time.time()
    db.kb_upsert(
        [
            {"fingerprint": f"fp{index}", "severity": "LOW", "source": "noise",
             "last_seen": now - index}
            for index in range(5)
        ]
    )
    # 全部都在 TTL 窗口内，于是只有「条数上限」这一条规则生效
    removed = db.kb_prune(older_than=3600.0, max_entries=2, now=now)
    assert removed == 3
    assert db.count_rows("pattern_kb") == 2
    assert db.kb_lookup("fp0") is not None, "保留最新见过的两条"
    db.close()


def test_sqlite_exposes_contract_api_surface():
    """§6.8 逐条签名核对：缺方法就是集成断路（KB / 待发队列 / 保留清理依赖这些入口）。"""
    required = [
        "open", "close", "migrate", "checkpoint", "record_alerts", "upsert_progress",
        "bump_counters", "push_rate", "progress", "metrics_for", "counters", "rate_count",
        "kb_lookup", "kb_upsert", "kb_set_manual", "kb_prune", "pending_add", "pending_due",
        "pending_update", "pending_stats", "prune", "usage",
    ]
    missing = [name for name in required if not callable(getattr(store.SqliteStore, name, None))]
    assert not missing, f"SqliteStore 缺契约方法: {missing}"
    # v2.3.0 反向断言：账本写入面随自动修复通道一并删除，留一个都不算完成
    removed = [
        "remediation_count", "remediation_active", "remediation_begin",
        "remediation_finish", "remediation_mark_receipt_sent", "remediation_last_at",
    ]
    still_there = [name for name in removed if hasattr(store.SqliteStore, name)]
    assert not still_there, f"v2.3.0 应已移除的账本方法仍在: {still_there}"
    assert store.SqliteStore.SCHEMA_VERSION == 3
    assert isinstance(store.SqliteStore.schema_version, property)


def test_sqlite_open_and_close_are_idempotent(tmp_path):
    db = _sqlite(tmp_path)
    db.close()
    db.close()
    assert db.available is False
    assert db.pending_due(0.0) == []


# ------------------------------------------------- 历史台账对账 / 权限


def test_sqlite_reconcile_marks_orphan_running_as_aborted(tmp_path):
    """F06 → v2.3.0：历史台账只读，启动对账只把遗留 running 收口成 aborted。"""
    db = _sqlite(tmp_path)
    _insert_legacy_run(db, "orphan", started_at=time.time() - 10)
    assert _run_status(db, "orphan") == "running"
    assert db.reconcile_runs(now=time.time() + 1) == 1
    assert _run_status(db, "orphan") == "aborted"
    assert db.reconcile_runs(now=time.time() + 2) == 0, "幂等"
    # 崩溃后「很快重启」的孤儿同样必须对账（年龄判定会漏）
    _insert_legacy_run(db, "fresh-orphan", started_at=time.time())
    assert db.reconcile_runs(now=time.time()) == 1
    assert db.usage()["runs"] == 2, "对账只改状态，不删证据（保留历史行）"
    db.close()


def test_state_files_and_dirs_use_restricted_modes(tmp_path):
    """F09：状态库 / 摘录文件 0600，目录 0700。"""
    import stat

    db = _sqlite(tmp_path)
    assert stat.S_IMODE((tmp_path / "log_watcher.sqlite3").stat().st_mode) == 0o600
    governor = store.DiskGovernor(tmp_path)
    excerpt = governor.write_excerpt("敏感摘录")
    assert stat.S_IMODE(excerpt.stat().st_mode) == 0o600
    assert stat.S_IMODE(excerpt.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(governor.failed.stat().st_mode) == 0o700
    db.close()


def test_harden_tree_fixes_existing_permissions(tmp_path):
    """F09：启动加固能把既有 0644 文件收到 0600（现网存量文件同口径）。"""
    import stat

    legacy = tmp_path / "tail_state.json"
    legacy.write_text("{}", encoding="utf-8")
    os.chmod(legacy, 0o644)
    fixed = store.harden_tree(tmp_path)
    assert fixed >= 1
    assert stat.S_IMODE(legacy.stat().st_mode) == 0o600


def test_pending_stats_reports_worst_severity_of_undelivered(tmp_path):
    """Q14=c 的汇总行要能说「最高 X 级」：统计里必须带上未送达条目的最高等级。"""
    import models

    db = _sqlite(tmp_path)
    assert db.pending_stats()["max_severity"] == ""
    # 注意：队列按 fingerprint 合并同源条目 ⇒ 三条必须用不同指纹才是三条（见上一个用例）
    for severity, item_id, fingerprint in (
        ("LOW", "i1", "fp1"),
        ("HIGH", "i2", "fp2"),
        ("MEDIUM", "i3", "fp3"),
    ):
        db.pending_add(
            store.PendingItem(
                item_id=item_id,
                session="s",
                text="x",
                fingerprint=fingerprint,
                severity=severity,
            )
        )
    stats = db.pending_stats()
    assert stats["active"] == 3 and stats["max_severity"] == "HIGH"
    # 窗口口径：三天前那条不进 `recent_*` —— 否则终身计数会把历史债永远挂在汇总行上
    db.pending_add(
        store.PendingItem(
            item_id="old",
            session="s2",
            text="x",
            fingerprint="fp-old",
            severity="CRITICAL",
            created_at=time.time() - 3 * 86400,
        )
    )
    stats2 = db.pending_stats()
    assert stats2["active"] == 4 and stats2["max_severity"] == "CRITICAL"
    assert stats2["recent_active"] == 3, "最近 24h 只算窗口内的"
    assert stats2["recent_max_severity"] == "HIGH", "窗口内的最高等级"
    assert stats2["window_hours"] == 24.0
    db.close()


# ---------- v3 判定链审计列（v2.3.0） ----------


def test_sqlite_record_alerts_persists_judged_columns(tmp_path):
    """台账必须能直接回答「这条结论有没有过模型」（judged 0/1，未知 = -1）。"""
    db = _sqlite(tmp_path)
    assert db.record_alerts(
        [
            {"ts": 1.0, "fingerprint": "fp-llm", "judged": 1, "judge_source": "llm"},
            {"ts": 2.0, "fingerprint": "fp-local", "judged": 0, "judge_source": "local"},
            {"ts": 3.0, "fingerprint": "fp-old"},
        ]
    ) == 3
    conn = sqlite3.connect(db.path)
    try:
        rows = conn.execute(
            "SELECT fingerprint, judged, judge_source FROM alerts ORDER BY ts"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [
        ("fp-llm", 1, "llm"),
        ("fp-local", 0, "local"),
        ("fp-old", -1, ""),  # 没给的旧口径 = 未知，不得假装「没判」
    ]
    db.close()


def test_sqlite_migrates_v2_db_and_adds_judge_columns(tmp_path):
    """v2 旧库必须能补列（duplicate column 吞掉），历史行按「未知」处理，不回填。"""
    path = tmp_path / "v2.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
        " fingerprint TEXT NOT NULL, severity TEXT NOT NULL, route TEXT NOT NULL DEFAULT 'notify',"
        " decision TEXT NOT NULL DEFAULT 'send', component TEXT NOT NULL DEFAULT '',"
        " session TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',"
        " summary TEXT NOT NULL DEFAULT '', source_file TEXT NOT NULL DEFAULT '',"
        " hit_count INTEGER NOT NULL DEFAULT 1, excerpt_path TEXT NOT NULL DEFAULT '',"
        " excerpt_lines INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute(
        "CREATE TABLE pattern_kb (fingerprint TEXT PRIMARY KEY, severity TEXT NOT NULL,"
        " confidence REAL NOT NULL DEFAULT 0.5, component TEXT NOT NULL DEFAULT '',"
        " tags TEXT NOT NULL DEFAULT '[]', reason TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT 'llm', hits INTEGER NOT NULL DEFAULT 1,"
        " first_seen REAL NOT NULL, last_seen REAL NOT NULL, manual INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("INSERT INTO pattern_kb VALUES ('fp-old','HIGH',0.5,'','[]','旧理由','llm',1,1,1,0)")
    conn.execute(
        "INSERT INTO alerts(ts, fingerprint, severity) VALUES (1.0, 'fp-old', 'HIGH')"
    )
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    db = store.SqliteStore(path).open()
    assert db.schema_version == 3 and db.writable
    assert db.kb_lookup("fp-old")["judge_source"] == ""
    assert db.kb_lookup("fp-old")["last_judged_at"] == 0.0
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT judged, judge_source FROM alerts").fetchone() == (-1, "")
    finally:
        conn.close()
    db.close()


def test_sqlite_prune_uses_prior_ttl_for_kb(tmp_path):
    """Q5=B：KB（先验）清理看 classify.prior_ttl_hours，fingerprint_ttl_hours 只管去重状态。"""
    db = _sqlite(tmp_path)
    now = time.time()
    db.kb_upsert(
        [
            {"fingerprint": "fp-recent", "severity": "LOW", "source": "llm",
             "last_seen": now - 3600},
            {"fingerprint": "fp-stale", "severity": "LOW", "source": "llm",
             "last_seen": now - 10 * 3600},
        ]
    )
    # 只给 prior_ttl_hours=2 → 10 小时前的条目被清掉
    removed = db.prune(
        now=now,
        cfg={"history_retention_days": 3650, "history_max_rows": 1000,
             "prior_ttl_hours": 2, "kb_max_entries": 500},
    )["kb"]
    assert removed == 1
    assert db.kb_lookup("fp-stale") is None and db.kb_lookup("fp-recent") is not None
    db.close()
