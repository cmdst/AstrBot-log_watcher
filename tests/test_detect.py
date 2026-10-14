"""detect 的纯逻辑测试：自身日志屏蔽、命中收集、指纹、通知闸门与计数落盘一致性。"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import detect  # noqa: E402
import models  # noqa: E402
import store  # noqa: E402


def _line(level: str, message: str, tag: str = "Core", stamp: str = "2026-10-13 03:15:44.276") -> str:
    return f"[{stamp}] [{tag}] [{level}] [v4.28.0] [x.py:1]: {message}"


# ---------- 自身日志屏蔽 ----------


@pytest.mark.parametrize(
    "line",
    [
        # 真实日志里的形态（data/logs/astrbot.log:313）
        "[2026-10-13 02:59:22.934] [log_watcher] [INFO] [log_watcher.main:244]: 命中 1 条日志",
        # 多 Bot 前缀形态
        "[2026-10-13 02:59:22.934] [platform:weixin_personal_demo] [log_watcher] [ERRO] [x.py:1]: boom",
        # 子 logger / uuid 变体
        "[2026-10-13 02:59:22.934] [log_watcher.classify] [ERRO] [x.py:1]: boom",
        "[2026-10-13 02:59:22.934] [log_watcher:8f3a2b1c] [ERRO] [x.py:1]: boom",
        "[2026-10-13 02:59:22.934] [log_watcher-1a2b3c4d] [ERRO] [x.py:1]: boom",
        "2026-10-13 02:59:22 ERROR astrbot.plugin.log_watcher: boom",
        "ERROR:log_watcher.foo:8f3a2b1c: boom",
    ],
)
def test_self_log_filter_matches_all_real_variants(line):
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify(line, True) is True


def test_self_log_filter_ignores_unrelated_lines():
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify(_line("ERRO", "unrelated failure", tag="Core"), True) is False
    assert log_filter.classify(_line("ERRO", "other plugin", tag="astrbot_plugin_splitter"), True) is False


def test_self_log_filter_suppresses_stack_continuations():
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify(_line("ERRO", "boom", tag="log_watcher"), True) is True
    # 续行不带 tag：必须继承所属记录的身份，否则堆栈里的 ERROR 字样会变成命中
    assert log_filter.classify('  File "/root/AstrBot/data/plugins/log_watcher/main.py", line 10', False) is True
    assert log_filter.classify("    raise RuntimeError('ERROR inside traceback')", False) is True
    # 新记录不是自身日志时，后续续行必须立刻恢复为「不屏蔽」
    assert log_filter.classify(_line("ERRO", "unrelated", tag="Core"), True) is False
    assert log_filter.classify("    ValueError: ERROR inside body", False) is False


def test_self_log_filter_detects_traceback_by_plugin_path():
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify('  File "/root/AstrBot/data/plugins/log_watcher/main.py", line 3', False) is True
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify("  at /srv/plugins/log_watcher/deliver.py:12", False) is True
    log_filter = detect.SelfLogFilter()
    assert log_filter.classify('  File "/srv/plugins/other/main.py", line 3', False) is False


def test_self_log_filter_suppresses_delivery_echo_from_adapter():
    """适配器替我们记的发送失败 WARN 也必须屏蔽，否则 levels 含 WARNING 会自反馈放大。"""
    target = "weixin_personal_demo:FriendMessage:<openid>@im.wechat"
    log_filter = detect.SelfLogFilter(echo_ids=[target, target.split(":")[-1]])
    echo = (
        "[2026-10-13 07:59:11.261] [Core] [WARN] [v4.28.2] [weixin_oc.weixin_oc_adapter:915]: "
        "weixin_oc(weixin_personal_demo): sendmessage failed for "
        "<openid>@im.wechat: ret=-2, errcode=0, errmsg=prepare failed"
    )
    assert log_filter.classify(echo, True) is True
    assert log_filter.classify("    raise RuntimeError('prepare failed')", False) is True
    # 同一个平台上别的用户失败：只当线索，不当自身回声
    log_filter = detect.SelfLogFilter(echo_ids=[target])
    other = (
        "[2026-10-13 07:59:11.261] [Core] [WARN] [v4.28.2] [weixin_oc.weixin_oc_adapter:915]: "
        "weixin_oc(weixin_personal_demo): sendmessage failed for another_user@im.wechat: "
        "ret=-2, errmsg=prepare failed"
    )
    assert log_filter.classify(other, True) is False
    # 没有失败特征词的普通适配器日志不受影响
    plain = (
        "[2026-10-13 02:49:37.354] [Core] [INFO] [weixin_oc.weixin_oc_adapter:202]: "
        "weixin_oc adapter weixin_personal_demo loaded with token from config."
    )
    assert log_filter.classify(plain, True) is False


def test_detector_never_hits_on_own_logs():
    detector = detect.Detector(["ERROR", "CRITICAL"], before=1, after=1, source="astrbot.log")
    lines = [
        _line("INFO", "startup", tag="Core"),
        "[2026-10-13 03:00:00.000] [log_watcher] [ERRO] [x.py:1]: 发送失败",
        '  File "/root/AstrBot/data/plugins/log_watcher/main.py", line 10, in _send',
        "RuntimeError: failed to send 1 message segment(s)",
        "[2026-10-13 03:00:01.000] [log_watcher] [CRIT] [v4.28.0] [x.py:1]: 自触发候选",
        _line("ERRO", "real failure"),
    ]
    blocks = []
    for line in lines:
        blocks.extend(detector.feed(line))
    blocks.extend(detector.flush())
    assert len(blocks) == 1, "插件自身日志（含续行）不得产生任何片段"
    assert blocks[0].hit_count == 1
    assert "real failure" in "\n".join(blocks[0].lines)
    assert detector.suppressed_records == 2


def test_detector_ignores_body_level_tokens_in_continuation():
    detector = detect.Detector(["ERROR"], before=2, after=1, source="astrbot.log")
    detector.feed(_line("INFO", "解析用户输入"))
    detector.feed("      ERROR 只是正文里的字样")
    blocks = detector.flush()
    assert blocks == [], "续行里的 ERROR 是正文，不得构成命中"


# ---------- 指纹 ----------


def _block(message: str, stamp: str = "2026-10-13 03:15:44.276", level: str = "ERRO"):
    line = f"[{stamp}] [Core] [{level}] [v4.28.0] [x.py:1]: {message}"
    return models.LogBlock(source="astrbot.log", lines=[line], hit_indices=[0], levels=["ERROR"])


def test_fingerprint_is_unified_and_stable():
    """R2：指纹只有一个实现（classify），detect 必须委托，且同一故障跨时间/会话同指纹。"""
    import classify

    first = detect.fingerprint(_block("failed to connect to the database"))
    second = detect.fingerprint(
        _block("failed to connect to the database", stamp="2026-10-13 09:00:00.000")
    )
    assert first == second
    other = detect.fingerprint(_block("database is locked"))
    assert first != other
    assert len(first) == 16
    for message in ("boom", "database is locked", "No space left on device"):
        block = _block(message)
        assert detect.fingerprint(block) == classify.fingerprint(block)
        assert detect.block_fingerprint(block) == classify.fingerprint(block)
        assert detect.normalize_for_fingerprint(block.lines[0]) == (
            classify.normalize_for_fingerprint(block.lines[0])
        )


def test_normalize_for_fingerprint_delegates_to_classify():
    """R2：归一化也只有一个实现，时间戳/路径至少要被掩码。"""
    text = "[2026-10-13 03:15:44.276] [Core] [ERRO] [/root/AstrBot/data/x.py:12]: boom"
    normalized = detect.normalize_for_fingerprint(text)
    assert "<TS>" in normalized or "<ts>" in normalized
    assert "/root/AstrBot" not in normalized
    import classify

    assert normalized == classify.normalize_for_fingerprint(text)


# ---------- 本地保守分级 ----------


def test_fallback_verdict_matches_classify_block():
    """R2/R12：兜底路径与 classify_block 必须给出同一结论（旧实现有 4 处分歧，已消除）。

    分歧样本（warden 在 t20 报告 + review-1.md 记录）：MCP 中文串不匹配→HIGH、
    平台发送失败→MEDIUM、asyncio 噪声→LOW、provider 重试→LOW。委派给 classify 后
    由构造保证一致，因此这里断言"逐样本等值"而不是钉死某一侧的具体等级。
    """
    import classify

    samples = [
        "No space left on device",
        "Future exception was never retrieved",
        "MCP 服务 github 初始化失败",
        "平台段型不支持导致的发送失败",
        "provider 返回空内容，重试中",
        "写入状态失败: database is locked",
        "totally unknown failure",
    ]
    for message in samples:
        block = _block(message)
        fallback = detect.fallback_verdict(block)
        expected = classify.classify_block(block)
        assert fallback.severity is expected.severity, message
        assert fallback.route == expected.route, message
        assert fallback.fingerprint == expected.fingerprint, message
        assert fallback.route is models.ROUTE_BY_SEVERITY[fallback.severity], message

    critical = detect.fallback_verdict(_block("No space left on device"))
    assert critical.severity is models.Severity.CRITICAL
    assert critical.route is models.Route.EMERGENCY


def test_fallback_verdict_rules_come_from_classify():
    """R12：detect 不再自带一套规则表，规则条目与 classify 的合并结果一致。"""
    import classify

    merged = (
        tuple(getattr(classify, "LOCAL_RULES", ()) or ())
        or tuple(classify.FAILURE_RULES)
        + tuple(classify.NOISE_RULES)
        + tuple(classify.TRANSIENT_RULES)
    )
    assert detect.local_rules() == merged
    assert detect.local_rules(), "规则表不能为空，否则降级路径失去判定依据"


# ---------- 通知闸门 ----------


def _silence_around(moment: float, span: int = 30) -> tuple[tuple[int, int], ...]:
    local = time.localtime(moment)
    start = local.tm_hour * 60 + local.tm_min
    return ((start, (start + span) % (24 * 60)),)


def _alert(fingerprint: str = "fp1", severity=models.Severity.MEDIUM, summary: str = "s"):
    return detect.AlertItem(fingerprint=fingerprint, severity=severity, summary=summary)


def test_detect_reuses_models_types_only():
    """R1/R12：detect 不得自带第二版 Rule/ThreatVerdict 等契约类型。"""
    assert detect.Rule is models.Rule
    assert detect.ThreatVerdict is models.ThreatVerdict
    assert not hasattr(detect, "LOCAL_RULES"), "规则表唯一数据源在 classify"


def test_gate_dedup_precedes_budget():
    """§11.2 第 7 条：同时命中去重与预算时，必须先出 SUPPRESS_DEDUP。"""
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(
            dedupe_window=900.0, max_per_round=10, max_per_minute=10, max_per_hour=1
        ),
    )
    gate.begin_round()
    assert gate.decide(_alert("fp1"), 1000.0) is models.NotifyDecision.SEND
    gate.begin_round()  # 轮内计数归零，但「同指纹 + 小时预算」仍然同时命中
    assert gate.decide(_alert("fp1"), 1010.0) is models.NotifyDecision.SUPPRESS_DEDUP
    assert counters.get_int("suppressed_dedup") == 1
    assert counters.get_int("suppressed_budget") == 0


def test_gate_dedupes_same_fingerprint_within_window():
    counters = store.CounterStore()
    gate = detect.NotifyGate(counters, detect.GateConfig(dedupe_window=900.0))
    assert gate.decide(_alert(), 1000.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert(), 1100.0) is models.NotifyDecision.SUPPRESS_DEDUP
    assert gate.decide(_alert(), 1899.0) is models.NotifyDecision.SUPPRESS_DEDUP
    # 去重是滑动窗口：被抑制的命中同样刷新时间戳，因此「距上次命中满一个窗口」
    # 的那一次才重新放行；中间任何一次复发都会把窗口继续往后推
    assert gate.decide(_alert(), 1899.0 + 900.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert(), 2800.0) is models.NotifyDecision.SUPPRESS_DEDUP
    assert counters.get_int("alerts_sent") == 2
    assert counters.get_int("suppressed_dedup") == 3
    assert counters.fingerprint_info("fp1")["count"] == 5


def test_gate_enforces_round_budget():
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters, detect.GateConfig(dedupe_window=0.0, max_per_round=1, max_per_hour=100)
    )
    gate.begin_round()
    assert gate.decide(_alert("fp0"), 100.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp1"), 101.0) is models.NotifyDecision.SUPPRESS_BUDGET
    assert counters.sub("budget_hits") == {"round": 1}
    gate.begin_round()
    assert gate.decide(_alert("fp2"), 102.0) is models.NotifyDecision.SEND


def test_gate_enforces_minute_budget():
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(dedupe_window=0.0, max_per_round=10, max_per_minute=2, max_per_hour=100),
    )
    gate.begin_round()
    assert gate.decide(_alert("fp0"), 100.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp1"), 101.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp2"), 102.0) is models.NotifyDecision.SUPPRESS_BUDGET
    assert counters.sub("budget_hits") == {"minute": 1}
    # 一分钟之后放行
    assert gate.decide(_alert("fp3"), 200.0) is models.NotifyDecision.SEND


def test_gate_enforces_hour_budget():
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(dedupe_window=0.0, max_per_round=10, max_per_minute=10, max_per_hour=2),
    )
    gate.begin_round()
    assert gate.decide(_alert("fp0"), 100.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp1"), 500.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp2"), 900.0) is models.NotifyDecision.SUPPRESS_BUDGET
    assert counters.sub("budget_hits") == {"hour": 1}


def test_gate_enforces_day_budget():
    """§4.4：日预算跨轮次/跨重启生效（窗口由状态承载），超限记 budget_hits.day。"""
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(
            dedupe_window=0.0,
            max_per_round=10,
            max_per_minute=100,
            max_per_hour=100,
            max_per_day=2,
        ),
    )
    gate.begin_round()
    assert gate.decide(_alert("d0"), 100.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("d1"), 200.0) is models.NotifyDecision.SEND
    gate.begin_round()
    assert gate.decide(_alert("d2"), 300.0) is models.NotifyDecision.SUPPRESS_BUDGET
    assert counters.sub("budget_hits") == {"day": 1}
    assert counters.window_count("sent_day", 300.0, 86400.0) == 2


def test_gate_buffers_low_severity_for_digest():
    counters = store.CounterStore()
    config = detect.GateConfig(digest_interval=100.0, digest_max_items=10)
    gate = detect.NotifyGate(counters, config)
    assert gate.decide(_alert("low1", models.Severity.LOW), 500.0) is models.NotifyDecision.DIGEST_BUFFER
    assert gate.decide(_alert("low2", models.Severity.LOW), 510.0) is models.NotifyDecision.DIGEST_BUFFER
    assert gate.decide(_alert("ignored", models.Severity.IGNORE), 520.0) is models.NotifyDecision.STORE_ONLY
    assert counters.get_int("digest_buffered") == 2
    assert counters.get_int("ignored") == 1
    assert gate.flush_digest(560.0) is None, "未到聚合间隔不得发送"
    payload = gate.flush_digest(620.0)
    assert payload is not None
    assert payload["count"] == 2
    assert payload["fingerprints"] == ["low1", "low2"]
    assert counters.get_int("digest_flushed") == 1
    assert counters.buffer("digest_buffer") == []
    assert gate.flush_digest(2000.0) is None


def test_gate_flushes_digest_early_when_buffer_full():
    counters = store.CounterStore()
    gate = detect.NotifyGate(counters, detect.GateConfig(digest_interval=9999.0, digest_max_items=3))
    for index in range(3):
        gate.decide(_alert(f"low{index}", models.Severity.LOW), 100.0 + index)
    payload = gate.flush_digest(103.0)
    assert payload is not None and payload["count"] == 3


def test_gate_applies_silence_window_but_lets_critical_through():
    counters = store.CounterStore()
    moment = time.mktime((2026, 10, 13, 3, 15, 0, 0, 0, -1))
    config = detect.GateConfig(
        silence_ranges=_silence_around(moment),
        silence_min_severity=models.Severity.HIGH,
    )
    gate = detect.NotifyGate(counters, config)
    assert gate.decide(_alert("m1", models.Severity.MEDIUM), moment) is models.NotifyDecision.SUPPRESS_SILENCE
    assert gate.decide(_alert("c1", models.Severity.CRITICAL), moment) is models.NotifyDecision.SEND
    assert counters.get_int("suppressed_silence") == 1
    assert counters.get_int("alerts_sent") == 1


def test_parse_silence_and_in_silence_wraps_midnight():
    ranges = detect.parse_silence(["23:00-07:00", "bogus", "25:00-26:00"])
    assert ranges == ((23 * 60, 7 * 60),)
    midnight = time.mktime((2026, 10, 13, 1, 0, 0, 0, 0, -1))
    noon = time.mktime((2026, 10, 13, 12, 0, 0, 0, 0, -1))
    assert detect.in_silence(midnight, ranges) is True
    assert detect.in_silence(noon, ranges) is False
    assert detect.in_silence(noon, ()) is False


def test_gate_coalesces_burst_and_flushes_after_window():
    counters = store.CounterStore()
    config = detect.GateConfig(
        dedupe_window=0.0,
        max_per_minute=100,
        max_per_hour=100,
        burst_window=60.0,
        burst_threshold=3,
        burst_min_severity=models.Severity.MEDIUM,
    )
    gate = detect.NotifyGate(counters, config)
    decisions = [gate.decide(_alert(f"f{index}"), 1000.0 + index) for index in range(5)]
    assert decisions[:3] == [models.NotifyDecision.SEND] * 3
    assert decisions[3:] == [models.NotifyDecision.BURST_COALESCED] * 2
    assert gate.flush_burst(1050.0) is None, "窗口未结束不得吐桶"
    payload = gate.flush_burst(1070.0)
    assert payload is not None and payload["count"] == 2
    assert counters.get_int("burst_coalesced") == 2
    assert counters.burst_state()["items"] == []
    assert gate.decide(_alert("f9"), 1071.0) is models.NotifyDecision.SEND


def test_gate_counters_survive_reload_and_keep_suppressing(tmp_path):
    path = tmp_path / "counters.json"
    counters = store.CounterStore(path)
    gate = detect.NotifyGate(counters, detect.GateConfig(dedupe_window=900.0))
    assert gate.decide(_alert("fp1"), 1000.0) is models.NotifyDecision.SEND
    assert gate.decide(_alert("fp1"), 1010.0) is models.NotifyDecision.SUPPRESS_DEDUP
    assert counters.save() is True

    reloaded = store.CounterStore(path).load()
    assert reloaded.snapshot() == counters.snapshot(), "进程内计数必须与落盘一致"
    gate2 = detect.NotifyGate(reloaded, detect.GateConfig(dedupe_window=900.0))
    assert gate2.decide(_alert("fp1"), 1020.0) is models.NotifyDecision.SUPPRESS_DEDUP
    assert reloaded.get_int("suppressed_dedup") == 2


if __name__ == "__main__":  # pragma: no cover - 便于手工单跑
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_gate_low_severity_not_coalesced_by_burst():
    """突发合并只作用于 ≥ burst_min_severity 的等级（LOW 走摘要）。"""
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(dedupe_window=0.0, max_per_minute=100, max_per_hour=100,
                          burst_window=60.0, burst_threshold=1,
                          burst_min_severity=models.Severity.MEDIUM),
    )
    assert gate.decide(_alert("low", models.Severity.LOW), 1000.0) is (
        models.NotifyDecision.DIGEST_BUFFER
    )
    assert counters.get_int("burst_coalesced") == 0
    assert counters.get_int("digest_buffered") == 1


def test_gate_prunes_fingerprint_state_by_ttl():
    """指纹状态不能无限增长（§4.2 fingerprint_ttl_hours）。"""
    counters = store.CounterStore()
    counters.touch_fingerprint("old", 1000.0)
    counters.touch_fingerprint("new", 9000.0)
    assert counters.prune_fingerprints(9000.0, older_than=3600.0) == 1
    assert counters.fingerprint_info("old")["count"] == 0
    assert counters.fingerprint_info("new")["count"] == 1


def test_self_log_filter_can_be_disabled_by_empty_names():
    """配置成空 self_log_names 时不应崩溃（默认仍有 log_watcher）。"""
    log_filter = detect.SelfLogFilter(names=[])
    assert log_filter.names == ["log_watcher"]
    assert log_filter.classify("[2026-10-13 03:00:00.000] [log_watcher] [ERRO] [x]: b", True)


def test_gate_notify_min_severity_compresses_to_digest():
    """F15：notify_min_severity 生效 —— 低于下限的即时告警压成摘要，不即时发。"""
    counters = store.CounterStore()
    gate = detect.NotifyGate(
        counters,
        detect.GateConfig(
            dedupe_window=0.0, notify_min_severity=models.Severity.HIGH
        ),
    )
    assert gate.decide(_alert("m1", models.Severity.MEDIUM), 100.0) is (
        models.NotifyDecision.DIGEST_BUFFER
    )
    assert gate.decide(_alert("h1", models.Severity.HIGH), 101.0) is models.NotifyDecision.SEND
    assert counters.get_int("digest_buffered") == 1
    assert counters.get_int("alerts_sent") == 1
    assert detect.GateConfig.from_mapping({"notify_min_severity": "CRITICAL"}).notify_min_severity is (
        models.Severity.CRITICAL
    )


def test_echo_detection_survives_longer_prefixes():
    """F17：回声判定窗口必须容纳更长的平台前缀（真实行 221 字符，id 在 [141,179)）。"""
    target = "<openid>@im.wechat"
    ids = [f"weixin_personal_demo:FriendMessage:{target}", target]
    short = (
        "[2026-10-13 07:59:11.261] [Core] [WARN] [v4.28.2] [weixin_oc.weixin_oc_adapter:915]: "
        f"sendmessage failed for {target}: errmsg=prepare failed"
    )
    long = (
        "[2026-10-13 07:59:11.261] [Core] [WARN] [v4.28.2] [weixin_oc.weixin_oc_adapter:915]: "
        + "x" * 140
        + f" sendmessage failed for {target}: errmsg=prepare failed"
    )
    for line in (short, long):
        assert len(line) <= detect._ECHO_HEADER_LIMIT
        assert detect.is_self_feedback_line(line, ids) is True
        assert detect.SelfLogFilter(echo_ids=ids).classify(line, True) is True
    assert len(long) > detect._SELF_HEADER_LIMIT, "长前缀用例必须超过旧的 200 字符窗口"
