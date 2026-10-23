"""deliver 的纯逻辑测试：通道能力、段型选择、分片、退避重试、降级路径。"""

from __future__ import annotations

import asyncio
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


# ---------- 结构约束：File 段只允许在一个地方构造 ----------


def test_file_segment_is_constructed_only_in_the_attachment_branch():
    """v2.3.0：不再“所有通道都禁发文件”，改成“只有主出口的附件分支才构造 File 段”。

    旧用例断言 main.py / deliver.py 里出现 `File(` 就红 —— 那是 weixin 时代的一刀切；
    现在报告形态必须发文件，所以收窄成三条可核对的约束：
    ① `File(` 在 main.py 里**只有 1 处**，且落在 `_send_plan` 的附件分支内；
    ② deliver.py 一行都不许有（投递层只描述附件，不构造段）；
    ③ 不支持文件的通道（weixin / qq_official）永远拿不到 attachments（见报告形态用例）。
    """
    root = Path(__file__).resolve().parent.parent
    main_source = (root / "main.py").read_text(encoding="utf-8")
    assert "from astrbot.api.message_components import File, Node, Nodes, Plain" in main_source
    assert main_source.count("File(") == 1, "main.py 只允许在附件分支构造一次 File 段"
    send_plan = main_source.split("    async def _send_plan(", 1)[1].split("\n    async def ", 1)[0]
    assert "File(" in send_plan, "File 段必须落在 _send_plan 里（唯一发送者）"
    assert "item.path" in send_plan, "附件必须用绝对路径（File(file=…)）"
    deliver_source = (root / "deliver.py").read_text(encoding="utf-8")
    assert "File(" not in deliver_source, "deliver.py 不得构造 File 段"
    assert not re.search(r"message_components\s+import[^\n]*\bFile\b", deliver_source)


# ---------- v2.3.0 告警形态：1 条诊断文本 + 1 个原始日志文件 ----------

REPORT_PATH = "/app/data/plugin_data/log_watcher/outbox/reports/alert-20261023-060112-HIGH-deadbeef.log"


def _spec(**overrides) -> deliver.ReportSpec:
    base = dict(
        path=REPORT_PATH,
        name="alert-20261023-060112-HIGH-deadbeef.log",
        mode="excerpt",
        size=38912,
        lines=211,
        truncated=False,
        keep_days=7,
    )
    base.update(overrides)
    return deliver.ReportSpec(**base)


def _llm_verdict(
    severity: models.Severity = models.Severity.HIGH, **overrides
) -> models.ThreatVerdict:
    verdict = _verdict(severity)
    verdict.judged = True
    verdict.judge_source = "llm"
    verdict.reason = "数据库连接被占满：写入状态失败（sqlite3.OperationalError）"
    for key, value in overrides.items():
        setattr(verdict, key, value)
    return verdict


def test_aiocqhttp_private_plan_is_one_full_text_plus_one_file():
    """验收 1：aiocqhttp 私聊 = 1 条诊断文本（不切段、无 1/N）+ 1 个文件段。"""
    plan = deliver.build_send_plan(
        _llm_verdict(),
        deliver.DeliverConfig(),
        "aiocqhttp:FriendMessage:2060958352",
        block=_block(hits=2),
        report=_spec(),
        allow_attachment=True,
        repeat_count=2,
    )
    assert plan.kind == "text"
    assert len(plan.chunks) == 1, "首段必须单条发完，不允许再裂成 2~3 段"
    cap = min(deliver.caps_for("aiocqhttp").max_chars, deliver.DeliverConfig().head_max_chars)
    assert len(plan.chunks[0]) <= cap
    assert not re.search(r"（\d+/\d+）", plan.chunks[0]), "主路径不得出现分片标记"
    assert len(plan.attachments) == 1
    attachment = plan.attachments[0]
    assert attachment.path == REPORT_PATH and attachment.name.endswith(".log")
    assert attachment.size == 38912
    body = plan.chunks[0]
    for token in (
        "【AstrBot 日志告警｜HIGH】",
        "第 3 次命中",
        "可能原因：",
        "是否建议修复：",
        "修复建议：",
        "—— 人工处置清单（静态表，非模型生成）——",
        "—— 原始日志 ——",
        "alert-20261023-060112-HIGH-deadbeef.log",
        "本轮命中段",
    ):
        assert token in body, f"首段缺 {token}"


def test_no_model_diagnosis_first_line_is_explicit():
    """验收 2：无模型诊断时首行明示「本地规则判定，未取得模型诊断」，且不得伪装成模型结论。"""
    verdict = _verdict()
    verdict.source = "degraded"
    verdict.judged = False
    verdict.judge_source = "degraded"
    verdict.tags = ["degraded:llm-budget"]
    verdict.reason = "本地规则：database is locked"
    diagnosis = deliver.render_diagnosis(verdict)
    assert diagnosis.splitlines()[0].startswith(deliver.NO_MODEL_LOCAL)
    assert "degraded:llm-budget" in diagnosis, "要用 T3 定的 degraded:* 枚举，不自造字符串"
    assert "模型判定" not in diagnosis
    plan = deliver.build_send_plan(
        verdict,
        deliver.DeliverConfig(),
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        report=_spec(),
    )
    assert deliver.NO_MODEL_LOCAL in plan.chunks[0]


def test_manual_override_is_not_rendered_as_model_diagnosis():
    verdict = _verdict()
    verdict.source = "manual"
    verdict.judged = False
    verdict.judge_source = "manual"
    verdict.tags = ["manual-override"]
    diagnosis = deliver.render_diagnosis(verdict)
    assert diagnosis.splitlines()[0] == deliver.NO_MODEL_MANUAL
    assert "（模型判定｜" not in diagnosis, "人工覆写不得渲染成模型诊断"


def test_diagnosis_structure_is_fixed_for_every_source():
    """验收 2：三种来源都必须是「可能原因 / 是否建议修复 / 修复建议」三段。"""
    degraded = _verdict()
    degraded.source = "degraded"
    degraded.judge_source = "degraded"
    degraded.tags = ["degraded:llm-timeout"]
    for verdict in (_llm_verdict(), degraded, _verdict()):
        diagnosis = deliver.render_diagnosis(verdict)
        for token in ("可能原因：", "是否建议修复：", "修复建议："):
            assert token in diagnosis, f"{verdict.source} 缺固定段 {token}"


def test_group_outlet_gets_text_and_path_but_no_file():
    """验收 4（Q4=A）：文件只发主出口；群出口只发文本 + 本机路径。"""
    plan = deliver.build_send_plan(
        _llm_verdict(),
        deliver.DeliverConfig(),
        "aiocqhttp:GroupMessage:744868236",
        block=_block(),
        report=_spec(),
        allow_attachment=False,
    )
    assert plan.attachments == [], "群出口不得发文件（群文件上传未实测）"
    assert len(plan.chunks) == 1 and not re.search(r"（\d+/\d+）", plan.chunks[0])
    assert "完整日志见 " + REPORT_PATH in plan.chunks[0]
    assert any("备用出口只发文本；群只有做主出口时才会尝试发文件" in note for note in plan.degradation)


def test_channels_without_file_capability_never_get_attachments():
    """验收 6：weixin/qq_official 零附件，单条文本 + 明确本机路径。"""
    for session in (
        "weixin_personal_demo:FriendMessage:x@im.wechat",
        "qq_official:FriendMessage:1",
    ):
        plan = deliver.build_send_plan(
            _llm_verdict(),
            deliver.DeliverConfig(),
            session,
            block=_block(hits=2),
            report=_spec(),
            allow_attachment=True,
        )
        assert plan.attachments == [], f"{session} 不得出现 attachments"
        assert len(plan.chunks) == 1, "无文件能力的通道也必须单条发完"
        cap = deliver.caps_for(deliver.session_platform(session)).max_chars
        assert len(plan.chunks[0]) <= cap
        assert "完整日志见 " + REPORT_PATH in plan.chunks[0]
        assert any("不支持文件段" in note for note in plan.degradation)


def test_report_modes_are_stated_in_first_line_and_section():
    """验收 3（Q3=A）：excerpt / file 两种口径都要在首行或段落里说清。"""
    excerpt = deliver.build_send_plan(
        _llm_verdict(), None, "aiocqhttp:FriendMessage:1", block=_block(), report=_spec()
    )
    assert "本轮命中段" in excerpt.chunks[0]
    raw = deliver.build_send_plan(
        _llm_verdict(),
        None,
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        report=_spec(mode="file"),
    )
    assert "整份日志（raw_mode=file）" in raw.chunks[0]
    assert "整份日志（raw_mode=file）" in deliver.render_report_section(_spec(mode="file"), attached=True)


def test_head_long_diagnosis_is_compressed_not_split():
    """首段超长时压缩诊断，绝不切段（这正是用户抱怨的割裂感来源）。"""
    verdict = _llm_verdict(reason="证据" * 500)
    plan = deliver.build_send_plan(
        verdict,
        deliver.DeliverConfig(head_max_chars=600),
        "aiocqhttp:FriendMessage:1",
        block=_block(hits=3),
        report=_spec(),
    )
    assert len(plan.chunks) == 1
    assert len(plan.chunks[0]) <= 600
    assert not re.search(r"（\d+/\d+）", plan.chunks[0])
    assert "可能原因：" in plan.chunks[0]


def test_degrade_drops_attachments_but_keeps_report_hint():
    plan = deliver.build_send_plan(
        _llm_verdict(), None, "aiocqhttp:FriendMessage:1", block=_block(), report=_spec()
    )
    degraded = deliver.degrade(plan)
    assert degraded.attachments == [], "降级文本自身不带附件（重试由待发队列决定）"
    assert any("报告文件已保留" in note for note in degraded.degradation)


def test_report_disabled_falls_back_to_inline_excerpt():
    """报告关闭（或写文件失败）时回到旧的内联摘录形态：零附件，绝不静默什么都不发。"""
    plan = deliver.build_send_plan(
        _llm_verdict(),
        deliver.DeliverConfig(include_excerpt=True),
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        excerpt="line-1\nline-2",
        report=None,
    )
    assert plan.attachments == []
    assert "—— 摘录 ——" in plan.chunks[0]
    assert "line-1" in plan.chunks[0]


def test_partial_delivery_counts_as_delivered_and_stops_chain():
    """验收 7：附件失败（文本成功）= partial，但**算送达**，不整条重试、不再走备用出口。"""
    async def scenario():
        async def send(session, plan):
            return models.DeliveryOutcome(
                session=session, ok=True, partial=True, file_ok=False, error="附件发送失败"
            )

        return await deliver.deliver_over_outlets(
            ["main", "backup"], _plan_for, send, attempts=2
        )

    ok, outcomes, planned = asyncio.run(scenario())
    assert ok is True
    assert len(outcomes) == 1, "附件失败不触发整条重试"
    assert outcomes[0].partial is True and outcomes[0].file_ok is False


def test_main_report_pipeline_is_observable():
    """验收 7：main 侧的三处可观测点（写失败/附件未送达/计数）必须在源码里，不许吞异常。"""
    source = (Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8")
    assert "写告警报告失败（改发文本并给出本机路径）" in source
    assert "报告文件未送达（首段文本已发）" in source
    assert 'self.counters.bump("delivery_partial")' in source
    assert "报告超上限已截断" in source
    # 报告正文首行必须写明口径（Q3=A：两种模式都要能一眼看出来）
    assert "整份日志（report.raw_mode=file）" in source
    assert "本轮命中段（含前后文，逐字；report.raw_mode=excerpt）" in source
    # 文件名规则只在 store.ReportStore.report_name 一处（main 不自己拼）
    assert "alert-" in (Path(__file__).resolve().parent.parent / "store.py").read_text(
        encoding="utf-8"
    )


def test_attachment_roundtrip_shape():
    attachment = models.Attachment(path=REPORT_PATH, name="a.log", size=12)
    restored = models.Attachment.from_dict(attachment.to_dict())
    assert restored is not None and restored.path == REPORT_PATH and restored.size == 12
    assert models.Attachment.from_dict({"name": "no-path"}) is None
    plan = models.SendPlan(session="s", chunks=[], attachments=[attachment])
    assert plan.empty is False, "只有附件也算有效计划"


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


def test_outlet_order_keeps_priority_and_dedupes():
    """出口列表**即优先级**（第 1 个是主出口）：保序、去空白、去重。"""
    assert deliver.outlet_order(["main", " backup ", "", "main", None, "third"]) == [
        "main",
        "backup",
        "third",
    ]
    assert deliver.outlet_order([]) == [] and deliver.outlet_order(None) == []


def _plan_for(session: str):
    return deliver.SendPlan(session=session, kind="text", chunks=["x"])


def test_deliver_over_outlets_stops_at_first_success():
    """主出口成功就不再碰备用出口 —— 不再「两处都收到」。"""
    sent: list[str] = []

    async def scenario():
        async def send(session, plan):
            sent.append(session)
            return models.DeliveryOutcome(session=session, ok=True, attempts=1)

        return await deliver.deliver_over_outlets(
            ["main", "backup"], _plan_for, send, attempts=2
        )

    ok, outcomes, planned = asyncio.run(scenario())
    assert ok is True and sent == ["main"], "备用出口不得被使用"
    assert [session for session, _ in planned] == ["main"]


def test_deliver_over_outlets_switches_after_attempts_exhausted():
    """Q7 定案：单出口默认重试一次（attempts=2），用尽后切下一个出口；备用成功即算送达。"""
    calls: list[str] = []
    sleeps: list[float] = []
    events: list[str] = []

    async def scenario():
        async def send(session, plan):
            calls.append(session)
            return models.DeliveryOutcome(
                session=session, ok=(session == "backup"), attempts=1, error="prepare failed"
            )

        async def sleep(seconds):
            sleeps.append(seconds)

        return await deliver.deliver_over_outlets(
            ["main", "backup"],
            _plan_for,
            send,
            attempts=2,
            delay=lambda attempt: 5.0,
            sleep=sleep,
            on_event=lambda kind, payload: events.append(kind),
        )

    ok, outcomes, planned = asyncio.run(scenario())
    assert ok is True
    assert calls == ["main", "main", "backup"], "主出口两次都失败后才切备用（不再 4 连重试）"
    assert sleeps == [5.0], "同一出口失败一次后等 5s 再试"
    assert events == ["retry", "switch", "backup_used"]
    assert len(outcomes) == 3 and [s for s, _ in planned] == ["main", "backup"]


def test_deliver_over_outlets_reports_total_failure_once():
    """所有出口都失败：返回 False 并给一次 give_up（调用方据此**只入队一次**）。"""
    events: list[str] = []

    async def scenario():
        async def send(session, plan):
            return models.DeliveryOutcome(session=session, ok=False, attempts=1, error="dead")

        return await deliver.deliver_over_outlets(
            ["main", "backup"], _plan_for, send, attempts=1,
            on_event=lambda kind, payload: events.append(kind),
        )

    ok, outcomes, planned = asyncio.run(scenario())
    assert ok is False and len(outcomes) == 2 and len(planned) == 2
    assert events == ["switch", "switch", "give_up"]


def test_deliver_over_outlets_survives_empty_plan_and_plan_error():
    """计划为空或构造抛异常只跳过该出口，后面的出口照用（不能把整条链路带走）。"""
    calls: list[str] = []

    async def scenario():
        def build(session):
            if session == "boom":
                raise RuntimeError("builder failed")
            if session == "silent":
                return deliver.SendPlan(session=session, kind="skip", reason="IGNORE 仅入库")
            return _plan_for(session)

        async def send(session, plan):
            calls.append(session)
            return models.DeliveryOutcome(session=session, ok=True, attempts=1)

        return await deliver.deliver_over_outlets(
            ["boom", "silent", "main"], build, send, attempts=1
        )

    ok, outcomes, planned = asyncio.run(scenario())
    assert ok is True and calls == ["main"] and [s for s, _ in planned] == ["main"]


def test_has_redundant_outlets_needs_two_entries():
    """Q8=b 定案的闸门条件：出口 <2 条就算不合格（main 据此停摆）。"""
    assert deliver.has_redundant_outlets(["a", "b"]) is True
    assert deliver.has_redundant_outlets(["a", "a"]) is False, "同一条写两遍不算冗余"
    assert deliver.has_redundant_outlets(["a", "  "]) is False
    assert deliver.has_redundant_outlets([]) is False
    assert deliver.has_redundant_outlets(None) is False
    assert deliver.has_redundant_outlets(["a"], minimum=1) is True


def test_mask_session_hides_identifier_but_keeps_shape():
    """会话标识不进日志：启动横幅与投递报错都走 mask_session。"""
    assert deliver.mask_session("哈尼娅:FriendMessage:2060958352") == "哈尼娅:FriendMessage:（ID 已隐）"
    assert deliver.mask_session("哈尼娅:GroupMessage:744868236") == "哈尼娅:GroupMessage:（ID 已隐）"
    # 解析不出三段的原样返回（宁可留着，也别把调试信息弄丢）
    assert deliver.mask_session("weixin_oc:FriendMessage:") == "weixin_oc:FriendMessage:"
    assert deliver.mask_session("no-colon") == "no-colon"
    assert deliver.mask_session("") == ""
    assert deliver.mask_session(None) == ""


# ---------- v2.3.0 修复轮：门控纯函数与文档一致性守卫 ----------

_PLUGIN_DIR = Path(__file__).resolve().parent.parent


def test_attachment_allowed_only_for_first_outlet():
    """F1：只有 outlets[0] 为 True（旧写法在测试里零判别力）。"""
    assert deliver.attachment_allowed("a", ["a", "b"]) is True
    assert deliver.attachment_allowed("b", ["a", "b"]) is False, "备用出口不得发文件"
    assert deliver.attachment_allowed("", ["a"]) is False
    assert deliver.attachment_allowed("a", ["a"], deliver.caps_for("aiocqhttp")) is True


def test_attachment_allowed_false_for_empty_outlets():
    """F1：空出口列表 = 没有主出口。"""
    assert deliver.attachment_allowed("a", []) is False
    assert deliver.attachment_allowed("a", None) is False


def test_attachment_allowed_false_when_primary_lacks_file_caps():
    """F1：主出口通道不支持文件（weixin_oc）时必须为 False。"""
    caps = deliver.caps_for("weixin_oc")
    assert caps.file is False
    assert deliver.attachment_allowed("weixin:x", ["weixin:x"], caps) is False


def test_main_uses_the_pure_attachment_gate():
    """F1 变异防线：main 的 allow_attachment 必须是 attachment_allowed(...) 调用。

    把 main.py 改成 ``allow_attachment=True`` 或 ``session != primary_outlet`` 时这条会红。
    """
    import ast

    source = (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "build_send_plan":
            for keyword in node.keywords:
                if keyword.arg == "allow_attachment":
                    values.append(keyword.value)
    assert values, "main.py 里没找到 build_send_plan(allow_attachment=…)"
    for value in values:
        assert isinstance(value, ast.Call), "allow_attachment 必须是函数调用，不能是常量/比较式"
        assert isinstance(value.func, ast.Attribute)
        assert value.func.attr == "attachment_allowed"


def test_report_form_ignores_forward_request_but_says_so():
    """F4：报告形态恒为单条文本；send_mode=forward / prefer_forward 只影响旧内联路径。"""
    cfg = deliver.DeliverConfig(send_mode="forward", prefer_forward=True)
    plan = deliver.build_send_plan(
        _llm_verdict(),
        cfg,
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        report=_spec(),
    )
    assert plan.kind == "text"
    assert len(plan.chunks) == 1 and len(plan.attachments) == 1
    assert any("报告形态恒为单条文本" in note for note in plan.degradation)
    # 旧内联路径仍尊重 forward（不能顺手把旧行为改掉）
    inline = deliver.build_send_plan(
        _llm_verdict(),
        cfg,
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        excerpt="line",
        report=None,
    )
    assert inline.kind == "forward"


def test_attached_report_also_gives_local_path():
    """F5：附件形态也要给本机留存路径（群做主出口/File 段静默失败时的兜底）。"""
    section = deliver.render_report_section(_spec(), attached=True)
    assert "（本机留存：" + REPORT_PATH + "）" in section
    plan = deliver.build_send_plan(
        _llm_verdict(),
        deliver.DeliverConfig(),
        "aiocqhttp:FriendMessage:1",
        block=_block(),
        report=_spec(),
    )
    assert "（本机留存：" + REPORT_PATH + "）" in plan.chunks[0]


def test_report_path_is_stamped_for_every_fingerprint_in_report():
    """F7：report 是轮级工件，本轮写进报告的指纹行都要有 report_path（源码级守卫）。"""
    source = (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")
    body = source.split("def _stamp_report_path(", 1)[1].split("\n    async def ", 1)[0]
    assert "fingerprints" in body.split("\n", 1)[0] or "fingerprints" in body[:120]
    assert "in wanted" in body, "盖章必须按指纹集合判断，不能只比单个 verdict"
    call = source.split("self._stamp_report_path(", 1)[1][:260]
    assert "{item[1].fingerprint for item in sendable" in call, "盖章集合必须来自本轮 sendable"


def test_retry_attachment_wording_is_explicit():
    """F10 选①：重试携带附件时，文案必须写「重试会再发一次附件」。"""
    source = (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")
    body = source.split("def _enqueue_failure(", 1)[1].split("\n    async def ", 1)[0]
    assert "重试会再发一次附件" in body
    assert "plan.attachments" in body, "只有带附件时才追加这句"


def test_v230_dropped_keys_have_single_source_guard_and_fixture_runs(capsys):
    """F8：22 键在测试与迁移工具之间必须有交叉断言；fixture 干跑可复现。"""
    sys.path.insert(0, str(_PLUGIN_DIR / "tools"))
    import migrate_config_v3 as migrate
    import test_config_map

    assert set(migrate.REMOVED_V230_FLAT) == set(test_config_map.DROPPED_IN_V230)
    assert len(migrate.REMOVED_V230_FLAT) == 22
    fixture = _PLUGIN_DIR / "tools" / "fixtures" / "log_watcher_config_v2.2.0.sample.json"
    assert fixture.is_file(), "仓库自带的 v2.2.0 fixture 丢了"
    code = migrate.run(["--dry-run", "--config", str(fixture)])
    out = capsys.readouterr().out
    assert code == migrate.EXIT_OK
    assert "将删除  ：22 / 22" in out
    assert "将补默认值：9" in out
    assert "FIXTURE-" not in out, "迁移工具不得打印配置值"
