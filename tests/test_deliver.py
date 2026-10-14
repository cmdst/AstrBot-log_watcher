"""deliver 的纯逻辑测试：通道能力、段型选择、分片、退避重试、降级路径。"""

from __future__ import annotations

import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import deliver  # noqa: E402
import models  # noqa: E402

REAL_WEIXIN_SESSION = "weixin_personal_demo:FriendMessage:<openid>@im.wechat"
REAL_FAILURE = "failed to send 1 message segment(s)"


def _block(message: str = "boom", hits: int = 1):
    lines = []
    indices = []
    levels = []
    for index in range(hits):
        lines.append(f"[2026-10-13 03:15:44.{index:03d}] [Core] [ERRO] [v4.28.0] [x.py:{index}]: {message}")
        indices.append(index)
        levels.append("ERROR")
    return models.LogBlock(source="astrbot.log", lines=lines, hit_indices=indices, levels=levels)


def _verdict(severity: models.Severity = models.Severity.HIGH, route=None) -> models.ThreatVerdict:
    return models.ThreatVerdict(
        severity=severity,
        confidence=0.8,
        tags=["delivery"],
        fingerprint="deadbeefdeadbeef",
        evidence=REAL_FAILURE,
        reason="测试判定",
        route=route or models.ROUTE_BY_SEVERITY[severity],
    )


# ---------- 通道能力 ----------


def test_caps_for_weixin_instance_id_is_conservative():
    caps = deliver.caps_for(deliver.session_platform(REAL_WEIXIN_SESSION))
    assert caps.platform == "weixin_oc"
    assert caps.plain is True
    assert caps.forward is False, "weixin_oc 对 Node/Nodes 只是静默忽略，必须当作不支持"
    assert caps.file is False, "weixin_oc 的 File 段会 raise，必须当作不支持"
    assert deliver.caps_for("weixin_oc").file is False


def test_caps_for_known_and_unknown_platforms():
    assert deliver.caps_for("aiocqhttp").forward is True
    assert deliver.caps_for("aiocqhttp:group:1").forward is True
    assert deliver.caps_for("webchat").plain is True
    unknown = deliver.caps_for("some_new_platform")
    assert unknown.platform == "unknown"
    assert unknown.forward is False and unknown.file is False
    assert deliver.caps_for("").platform == "unknown"


def test_caps_for_overrides():
    caps = deliver.caps_for("aiocqhttp", {"aiocqhttp": {"forward": False, "max_chars": 500}})
    assert caps.forward is False
    assert caps.max_chars == 500
    wildcard = deliver.caps_for("whatever", {"*": {"max_chars": 123}})
    assert wildcard.max_chars == 123
    assert deliver.caps_for("aiocqhttp").forward is True, "override 不得污染内置表"


# ---------- 段型选择 ----------


def test_weixin_plan_never_uses_forward_or_attachment():
    for mode in ("forward", "file", "auto", "text"):
        plan = deliver.build_send_plan(
            _verdict(),
            deliver.DeliverConfig(send_mode=mode),
            REAL_WEIXIN_SESSION,
            block=_block(),
            excerpt="x" * 4000,
        )
        assert plan.kind == "text", f"mode={mode} 时 weixin_oc 只能发纯文本"
        assert plan.chunks, "计划不能为空"
        assert max(len(chunk) for chunk in plan.chunks) <= deliver.caps_for("weixin_oc").max_chars


def test_weixin_forward_request_is_reported_as_degradation():
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(send_mode="forward"),
        REAL_WEIXIN_SESSION,
        block=_block(),
    )
    assert any("合并转发" in note for note in plan.degradation)
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(send_mode="file"),
        REAL_WEIXIN_SESSION,
        block=_block(),
    )
    assert any("附件" in note for note in plan.degradation)


def test_capable_channel_uses_forward_when_asked():
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(send_mode="forward"),
        "aiocqhttp:group:10001",
        block=_block(),
        excerpt="y" * 3000,
    )
    assert plan.kind == "forward"
    assert len(plan.chunks) >= 2


def test_plan_skips_ignore_and_digest_routes():
    ignored = deliver.build_send_plan(
        _verdict(models.Severity.IGNORE, models.Route.STORE), None, "aiocqhttp:group:1"
    )
    assert ignored.kind == "skip" and ignored.chunks == []
    digest = deliver.build_send_plan(
        _verdict(models.Severity.LOW, models.Route.DIGEST), None, "aiocqhttp:group:1"
    )
    assert digest.kind == "skip"
    direct = deliver.build_send_plan(
        _verdict(models.Severity.LOW, models.Route.DIGEST),
        deliver.DeliverConfig(allow_digest_direct=True),
        "aiocqhttp:group:1",
        block=_block(),
    )
    assert direct.kind == "text" and direct.chunks


def test_plan_chunking_preserves_content_and_respects_cap():
    body_block = _block("failure", hits=3)
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(max_chars_per_message=200, include_excerpt=True),
        REAL_WEIXIN_SESSION,
        block=body_block,
        excerpt="\n".join(f"line-{index}" for index in range(40)),
    )
    assert len(plan.chunks) > 2
    assert all(len(chunk) <= 200 for chunk in plan.chunks)
    rebuilt = "\n".join(deliver.strip_plan_markers(chunk) for chunk in plan.chunks)
    assert "line-0" in rebuilt and "line-39" in rebuilt
    assert len(plan.chunks) == len({index for index, _ in enumerate(plan.chunks)})


def test_plan_without_sessions_still_builds_text():
    plan = deliver.build_send_plan(_verdict(), None, "", block=_block())
    assert plan.kind == "text"
    assert plan.session == ""


def test_empty_content_yields_skip_not_empty_node():
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(include_excerpt=False),
        "weixin_oc:FriendMessage:u",
        block=None,
    )
    assert plan.chunks and plan.kind == "text"
    caps = models.ChannelCaps(
        platform="broken", plain=False, forward=False, file=False, image=False, max_chars=100
    )
    plan = deliver.build_send_plan(_verdict(), None, "broken:group:1", block=_block(), caps=caps)
    assert plan.kind == "skip"


def test_weixin_hard_rule_survives_evil_overrides():
    """§11.3 ②：即使 channel_overrides 打开 file/forward，weixin_oc 也不得产出那些段型。"""
    overrides = {"weixin_oc": {"file": True, "image": True, "forward": True}}
    caps = deliver.caps_for("weixin_personal_demo", overrides)
    assert (caps.file, caps.image, caps.forward) == (False, False, False)
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(send_mode="forward", prefer_forward=True),
        REAL_WEIXIN_SESSION,
        block=_block(),
        excerpt="x" * 3000,
        caps=caps,
    )
    assert plan.kind == "text"
    assert all("node" not in chunk.lower() and "attachment" not in chunk.lower()
               for chunk in plan.chunks)


def test_split_text_edges():
    assert deliver.split_text("", 10) == []
    assert deliver.split_text("  \n ", 10) == []
    assert deliver.split_text("a" * 25, 10) == ["a" * 10, "a" * 10, "a" * 5]
    text = "\n".join(f"row {index}" for index in range(50))
    pieces = deliver.split_text(text, 40)
    assert all(len(piece) <= 40 for piece in pieces)
    assert "\n".join(pieces) == text


def test_split_with_markers_adds_no_marker_for_single_chunk():
    assert deliver.split_with_markers("short", 100) == ["short"]
    pieces = deliver.split_with_markers("z" * 50, 20)
    assert len(pieces) > 1
    assert all(len(piece) <= 20 for piece in pieces)
    total = len(pieces)
    assert pieces[0].endswith(f"（1/{total}）")
    assert pieces[-1].endswith(f"（{total}/{total}）")
    assert "".join(
        deliver.strip_plan_markers(piece).replace("\n", "") for piece in pieces
    ) == "z" * 50


# ---------- 降级与退避 ----------


def test_degrade_keeps_minimal_text_and_notes():
    plan = deliver.build_send_plan(
        _verdict(),
        deliver.DeliverConfig(max_chars_per_message=500),
        REAL_WEIXIN_SESSION,
        block=_block(),
        excerpt="z" * 2000,
    )
    degraded = deliver.degrade(plan)
    assert degraded.kind == "text"
    assert len(degraded.chunks) == 1
    assert len(degraded.chunks[0]) <= 320 + 40
    assert any("降级" in note for note in degraded.degradation)
    empty = deliver.degrade(models.SendPlan(session="s", kind="text", chunks=[]))
    assert empty.kind == "skip"


def test_retry_delays_grow_and_stay_capped_and_deterministic():
    policy = deliver.RetryPolicy(max_attempts=5, base_delay=10.0, factor=4.0, max_delay=100.0)
    delays = [deliver.next_delay(attempt, policy) for attempt in range(1, 6)]
    assert delays == [deliver.next_delay(attempt, policy) for attempt in range(1, 6)]
    assert delays[0] < delays[1] < delays[2]
    assert max(delays) <= policy.max_delay
    exact = deliver.RetryPolicy(base_delay=10.0, factor=2.0, jitter=0.0, max_delay=100.0)
    assert [deliver.next_delay(attempt, exact) for attempt in range(1, 5)] == [
        10.0,
        20.0,
        40.0,
        80.0,
    ]
    seeded = [deliver.next_delay(attempt, policy, rng=random.Random(7)) for attempt in range(1, 4)]
    again = [deliver.next_delay(attempt, policy, rng=random.Random(7)) for attempt in range(1, 4)]
    assert seeded == again


def test_should_retry_boundaries():
    policy = deliver.RetryPolicy(max_attempts=3)
    assert deliver.should_retry(0, policy) is True
    assert deliver.should_retry(2, policy) is True
    assert deliver.should_retry(3, policy) is False


# ---------- 渲染 ----------


def test_render_alert_card_contains_key_fields():
    card = deliver.render_alert_card(_block(REAL_FAILURE, hits=2), _verdict())
    assert "HIGH" in card
    assert "deadbeefdeadbeef" in card
    assert REAL_FAILURE in card
    assert "2026-10-13 03:15:44.000" in card
    assert deliver.render_alert_card(models.LogBlock(source="x"), _verdict())


def test_render_alert_card_reports_truncated_tail_quantitatively():
    block = _block("boom")
    block.truncated_after = True
    block.missing_after = 4
    card = deliver.render_alert_card(block, _verdict())
    assert "末尾片段后文未凑齐" in card
    assert "缺 4 行" in card
    block.missing_after = 0
    assert "缺" not in deliver.render_alert_card(block, _verdict())


def test_render_digest_and_burst():
    digest = deliver.render_digest(
        {
            "count": 3,
            "items": [
                {"fingerprint": "fp1", "summary": "a"},
                {"fingerprint": "fp1", "summary": "a"},
                {"fingerprint": "fp2", "summary": "b"},
            ],
        }
    )
    assert "LOW" in digest
    assert "×2 fp1" in digest
    burst = deliver.render_burst({"count": 12, "items": [{"fingerprint": "fp9"}] * 12})
    assert "12 条" in burst


# ---------- 结构约束：不再存在 File 段构造点 ----------


def test_no_file_segment_construction_in_runtime_modules():
    root = Path(__file__).resolve().parent.parent
    for name in ("main.py", "deliver.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert "File(" not in source, f"{name} 不得再构造 File 段"
        assert not re.search(r"message_components\s+import[^\n]*\bFile\b", source), (
            f"{name} 不得导入 File 段"
        )
    main_source = (root / "main.py").read_text(encoding="utf-8")
    assert "from astrbot.api.message_components import Node, Nodes, Plain" in main_source


if __name__ == "__main__":  # pragma: no cover - 便于手工单跑
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_split_text_keeps_multibyte_characters():
    text = "\n".join(f"第{index}行：中文告警内容" for index in range(40))
    pieces = deliver.split_text(text, 30)
    assert all(len(piece) <= 30 for piece in pieces)
    assert "\n".join(pieces) == text


def test_retry_delay_is_capped_at_max():
    policy = deliver.RetryPolicy(base_delay=100.0, factor=10.0, jitter=0.0, max_delay=150.0)
    assert deliver.next_delay(1, policy) == 100.0
    assert deliver.next_delay(2, policy) == 150.0
    assert deliver.next_delay(9, policy) == 150.0


def test_plan_forwards_only_when_caps_allow_and_mode_asks():
    block = _block()
    caps = deliver.caps_for("aiocqhttp")
    auto = deliver.build_send_plan(
        _verdict(), deliver.DeliverConfig(send_mode="auto"), "aiocqhttp:group:1",
        block=block, caps=caps,
    )
    assert auto.kind == "text", "auto 不主动升级为转发"
    forced = deliver.build_send_plan(
        _verdict(), deliver.DeliverConfig(send_mode="forward"), "aiocqhttp:group:1",
        block=block, caps=caps,
    )
    assert forced.kind == "forward"
