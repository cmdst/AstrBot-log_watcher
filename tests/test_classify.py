"""classify.py 的行为级测试：字段契约、本地判定、指纹、安全闸、提示词与解析。

末尾「提示词资产与评测集」段（T4 交付物）额外覆盖：
``prompts/classify_system.md``、``prompts/remediate_task.md`` 与
``tests/classify_cases.json``（10 条用例，含注入用例）的加载、预算与围栏断言。

全部离线：不导入 astrbot、不访问网络、不依赖真实日志文件、不 spawn 任何进程。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import fields
from pathlib import Path

import pytest

_PLUGIN_DIR = Path(__file__).resolve().parents[1]
_TESTS_DIR = Path(__file__).resolve().parent
for _path in (_PLUGIN_DIR, _TESTS_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import classify  # noqa: E402
import engine  # noqa: E402
import models  # noqa: E402
from classify import (  # noqa: E402
    LLMOutputError,
    apply_safety_guards,
    build_classification_prompt,
    classify_block,
    component_of,
    degraded_verdict,
    fingerprint,
    parse_llm_verdict,
    route_for_severity,
    severity_max,
)
from log_reader import LogBlock, parse_level  # noqa: E402
from models import (  # noqa: E402
    ROUTE_BY_SEVERITY,
    SEVERITY_ORDER,
    Route,
    Severity,
    ThreatVerdict,
)

# ============================================================ 共用样例（真实/构造）
# 样例给 test_classify.py 与 test_engine.py 共用；来源（真实样例为 astrbot.log 原文拷贝，
# 只替换时间戳/会话 id；构造样例按同一格式仿真）逐条写在各自 docstring 里。
# 命中行用 log_reader.parse_level 推导，与生产链路的收集方式一致。


def make_block(
    lines: list[str],
    *,
    source: str = "astrbot.log",
    levels: tuple[str, ...] = ("ERROR", "CRITICAL"),
    hit_indices: list[int] | None = None,
    truncated_after: bool = False,
) -> LogBlock:
    """按生产口径组装片段：命中行 = 等级在 ``levels`` 里的行。

    Args:
        lines: 原始日志行。
        source: 来源文件/标签。
        levels: 视为命中的等级集合。
        hit_indices: 显式指定命中行（默认按 ``levels`` 推导）。
        truncated_after: 片段是否因文件停更被提前收尾。

    Returns:
        组装好的 :class:`~log_reader.LogBlock`。
    """
    hits = (
        list(hit_indices)
        if hit_indices is not None
        else [i for i, line in enumerate(lines) if parse_level(line) in levels]
    )
    hit_levels = [parse_level(lines[i]) or "ERROR" for i in hits]
    return LogBlock(
        source=source,
        lines=list(lines),
        hit_indices=hits,
        levels=hit_levels,
        truncated_after=truncated_after,
    )


# ---------------------------------------------------------------- 已知良性噪声


def asyncio_future_block(
    *, stamp: str = "2026-10-13 07:59:09.747", inner: str = "EmbeddingProviderError"
) -> LogBlock:
    """asyncio『Future exception was never retrieved』（真实样例：astrbot.log 9643~9650 原文）。

    这是 log_watcher 命中量最大的一族：独立复核
    ``grep -c "Future exception was never retrieved" data/logs/astrbot.log`` = 176，
    占 findings-recon.md 统计的 198 条命中的 88.9%，且 176/176 的内层异常都是
    ``EmbeddingProviderError('Framework embedding call failed: Request timed out.')``（良性噪声）。
    因此这一族必须整族短路、零 LLM 调用。
    """
    return make_block(
        [
            f"[{stamp}] [Core] [ERRO] [asyncio.base_events:1833]: Future exception was never retrieved",
            f"future: <Future finished exception={inner}('Framework embedding call failed: Request timed out.')>",
            f"data.plugins.astrbot_plugin_self_learning.services.embedding.base.{inner}: Framework embedding call failed: Request timed out.",
        ]
    )


def mcp_init_block(*, stamp: str = "2026-10-13 02:49:37.234") -> LogBlock:
    """可选 MCP 服务初始化失败、只让工具降级（构造样例：真实日志 02:49 只有 INFO 连接日志，
    ERRO 形态按 findings-recon.md 的 MCP 初始化失败描述仿真）。"""
    return make_block(
        [
            f"[{stamp}] [Core] [ERRO] [provider.func_tool_manager:590]: MCP 服务 github 初始化失败: TimeoutError('handshake timeout')",
            "[2026-10-13 02:49:37.235] [Core] [INFO] [provider.func_tool_manager:600]: 已跳过不可用的 MCP 服务 github",
        ]
    )


def send_failed_block(*, stamp: str = "2026-10-13 07:59:11.780") -> LogBlock:
    """平台段型不支持导致的发送失败（真实样例：astrbot.log 9672 行原文，
    weixin_oc 拒收 File 段，会话 id 已脱敏）。"""
    return make_block(
        [
            f"[{stamp}] [log_watcher] [ERRO] [v4.28.2] [log_watcher.main:253]: 发送日志提醒到 "
            "weixin_personal_demo:FriendMessage:<openid>@im.wechat 失败: "
            "RuntimeError: weixin_oc(weixin_personal_demo) failed to send 1 message segment(s)",
        ]
    )


def agent_tool_path_miss_block(*, stamp: str = "2026-10-14 21:00:09.759") -> LogBlock:
    """agent 把工作区文件猜成绝对路径导致的 ENOENT（真实样例：astrbot.log 27153 行原文，
    个人账本文件名替换为中性名 ``example_ledger.md``）。

    语义属调用方自伤：Core 只把错误回灌模型，模型可自行改路径重试，服务侧无副作用；
    文件真实位置在会话工作区 ``data/workspaces/<umo>/``，而不是它猜的 ``data/`` 根下。
    同一形态在 40 小时内出现 2 次（astrbot.log 10393 / 27153），修复前被判 MEDIUM 并推送。
    """
    return make_block(
        [
            f"[{stamp}] [Core] [INFO] [runners.tool_loop_agent_runner:1183]: 使用工具："
            "astrbot_file_read_tool，参数：{'limit': 50, 'path': '/root/AstrBot/data/example_ledger.md'}",
            f"[{stamp}] [Core] [ERRO] [v4.28.2] [computer_tools.fs:399]: Error reading file: "
            "[Errno 2] No such file or directory: '/root/AstrBot/data/example_ledger.md'",
        ]
    )


# ---------------------------------------------------------------- 真故障


def plugin_load_traceback_block(*, stamp: str = "2026-10-13 09:01:02.001") -> LogBlock:
    """插件加载失败 + 未捕获异常栈（构造样例，格式取自真实 Traceback 段）。"""
    return make_block(
        [
            f"[{stamp}] [Core] [ERRO] [v4.28.2] [core.star.star_manager:412]: 插件 astrbot_plugin_x 加载失败: Unhandled exception",
            "Traceback (most recent call last):",
            '  File "/root/AstrBot/data/plugins/astrbot_plugin_x/main.py", line 12, in <module>',
            "    import missing_dep",
            "ModuleNotFoundError: No module named 'missing_dep'",
        ]
    )


def db_locked_block(*, stamp: str = "2026-10-13 09:15:44.512") -> LogBlock:
    """SQLite 状态库不可用、去重/冷却会失效（构造样例）。"""
    return make_block(
        [
            f"[{stamp}] [Core] [ERRO] [v4.28.2] [core.pipeline.scheduler:88]: 写入状态失败: "
            "sqlite3.OperationalError: database is locked",
        ]
    )


def provider_retry_block(*, stamp: str = "2026-10-13 07:20:52.444") -> LogBlock:
    """上游 503 + 重试（真实样例：astrbot.log 07:20:49~07:20:52 的 WARN 原文）。"""
    return make_block(
        [
            "[2026-10-13 07:20:49.094] [Core] [WARN] [v4.28.2] [sources.request_retry:68]: [OpenAI] Request failed with retryable error; retrying (3/3)",
            f"[{stamp}] [Core] [WARN] [v4.28.2] [runners.tool_loop_agent_runner:627]: Chat Model "
            "cpa_Gemini/gemini-3.7-flash-high request error: Error code: 503 - auth_unavailable",
        ],
        levels=("WARNING",),
    )


def critical_exit_block(*, stamp: str = "2026-10-13 09:30:00.000") -> LogBlock:
    """CRIT 等级：主循环异常退出（构造样例，真实日志里暂无 CRIT 行）。"""
    return make_block(
        [
            f"[{stamp}] [Core] [CRIT] [v4.28.2] [core.lifecycle:77]: AstrBot 主循环异常退出，进程即将终止",
        ]
    )


def warning_only_block(*, stamp: str = "2026-10-13 10:00:00.000") -> LogBlock:
    """无法归类的 WARN（构造样例，等级只有 WARNING）。"""
    return make_block(
        [
            f"[{stamp}] [astrbot_plugin_y] [WARN] [v4.28.2] [astrbot_plugin_y.main:20]: 配置项 foo 已废弃，将回落到默认值",
        ],
        levels=("WARNING",),
    )


#: 良性噪声：判定后不得进入「需要紧急修复」的等级
BENIGN_NOISE_SAMPLES: dict[str, object] = {
    "asyncio_future": asyncio_future_block,
    "mcp_init_failed": mcp_init_block,
    "platform_send_failed": send_failed_block,
    "agent_tool_path_miss": agent_tool_path_miss_block,
}

#: 真故障：判定后不得被 IGNORE 放行
TRUE_FAILURE_SAMPLES: dict[str, object] = {
    "plugin_load_traceback": plugin_load_traceback_block,
    "database_locked": db_locked_block,
    "provider_retry": provider_retry_block,
    "critical_exit": critical_exit_block,
}

#: 全部样例（供 LLM 提示词与列宽测试复用）
ALL_SAMPLES: dict[str, object] = {
    **BENIGN_NOISE_SAMPLES,
    **TRUE_FAILURE_SAMPLES,
    "warning_only": warning_only_block,
}


# models.py 的数据类契约：ThreatVerdict(severity, confidence, tags, component,
# fingerprint, is_new_pattern, evidence, reason, route, source) —— 字段与顺序逐字一致
CONTRACT_FIELDS = (
    "severity",
    "confidence",
    "tags",
    "component",
    "fingerprint",
    "is_new_pattern",
    "evidence",
    "reason",
    "route",
    "source",
)
REPAIR_ROUTES = (Route.REMEDIATE, Route.EMERGENCY)
ROUTE_ORDER = tuple(item.value for item in Route)


def _llm_text(severity: str, **overrides: object) -> str:
    """造一段 LLM 输出 JSON。"""
    payload: dict[str, object] = {
        "severity": severity,
        "confidence": 0.9,
        "tags": ["llm-tag"],
        "reason": "模型给出的理由",
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


# ------------------------------------------------------------------ 字段契约


def test_verdict_field_order_matches_architecture_contract() -> None:
    assert tuple(item.name for item in fields(ThreatVerdict)) == CONTRACT_FIELDS
    verdict = classify_block(db_locked_block())
    assert tuple(verdict.to_dict().keys()) == CONTRACT_FIELDS


def test_classify_and_engine_reuse_the_single_models_contract() -> None:
    """跨模块同一性：classify/engine 不得再定义一份同名枚举/数据类。"""
    assert classify.Severity is models.Severity
    assert classify.Route is models.Route
    assert classify.ThreatVerdict is models.ThreatVerdict
    assert engine.Severity is models.Severity
    assert engine.ThreatVerdict is models.ThreatVerdict
    assert classify.ROUTE_BY_SEVERITY is models.ROUTE_BY_SEVERITY
    verdict = classify_block(db_locked_block())
    assert isinstance(verdict, models.ThreatVerdict)
    assert isinstance(verdict.severity, models.Severity)
    assert isinstance(verdict.route, models.Route)
    # 反向证明：本地判定出来的枚举能被 main/deliver 的 isinstance 认出来
    assert verdict.severity is models.Severity.HIGH
    assert verdict.source == "local"


def test_severity_and_route_enum_values_are_exact() -> None:
    assert tuple(item.value for item in SEVERITY_ORDER) == (
        "IGNORE",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )
    assert ROUTE_ORDER == (
        "store",
        "digest",
        "notify",
        "remediate",
        "emergency",
    )
    assert ROUTE_BY_SEVERITY == {
        Severity.IGNORE: Route.STORE,
        Severity.LOW: Route.DIGEST,
        Severity.MEDIUM: Route.NOTIFY,
        Severity.HIGH: Route.REMEDIATE,
        Severity.CRITICAL: Route.EMERGENCY,
    }
    # 非法等级一律保守落到 MEDIUM，绝不静默成 IGNORE
    assert Severity.parse("LOUD") is Severity.MEDIUM
    assert Severity.parse("high") is Severity.HIGH
    assert severity_max(Severity.LOW, Severity.HIGH, Severity.IGNORE) is Severity.HIGH
    # 分级 → 去向由 models.ROUTE_BY_SEVERITY 决定，本模块只做可覆写的包装
    for level, expected in ROUTE_BY_SEVERITY.items():
        assert route_for_severity(level) is expected


def test_verdict_round_trips_through_json() -> None:
    verdict = classify_block(plugin_load_traceback_block())
    payload = json.loads(json.dumps(verdict.to_dict(), ensure_ascii=False))
    assert payload["severity"] == "HIGH"
    assert payload["route"] == "remediate"
    restored = ThreatVerdict.from_dict(payload)
    assert restored.severity is Severity.HIGH
    assert restored.route is Route.REMEDIATE
    assert restored.fingerprint == verdict.fingerprint
    assert restored.source == "local"


# ------------------------------------------------------------------ 指纹


def test_fingerprint_stable_across_time_session_and_line_number() -> None:
    first = make_block(
        [
            "[2026-10-13 09:15:44.512] [Core] [ERRO] [v4.28.2] [core.pipeline.scheduler:88]: 写入状态失败: "
            "sqlite3.OperationalError: database is locked (session=9000000000)"
        ]
    )
    second = make_block(
        [
            "[2026-10-14 18:02:07.001] [Core] [ERRO] [v4.28.2] [core.pipeline.scheduler:412]: 写入状态失败: "
            "sqlite3.OperationalError: database is locked (session=2060958352)"
        ]
    )
    assert fingerprint(first) == fingerprint(second)
    assert classify_block(first).fingerprint == classify_block(second).fingerprint


def test_fingerprint_separates_different_causes() -> None:
    locked = fingerprint(db_locked_block())
    traceback = fingerprint(plugin_load_traceback_block())
    assert locked != traceback
    # asyncio 包装行相同、内层异常不同的两段必须分开，否则知识库会串味
    embedding = fingerprint(asyncio_future_block(inner="EmbeddingProviderError"))
    value_error = fingerprint(asyncio_future_block(inner="ValueError"))
    assert embedding != value_error


def test_fingerprint_keeps_plugin_identity() -> None:
    def block_for(plugin: str) -> object:
        return make_block(
            [
                f"[2026-10-13 13:00:00.000] [Core] [ERRO] [v4.28.2] [core.star.star_manager:412]: "
                f"插件 data/plugins/{plugin}/main.py 执行出错: Unhandled exception"
            ]
        )

    first = fingerprint(block_for("astrbot_plugin_self_learning"))
    second = fingerprint(block_for("astrbot_plugin_livingmemory"))
    assert first != second, "长下划线标识符被误掩码，不同插件的故障会撞成同一指纹"


# ------------------------------------------------- 良性噪声 / 真故障（本地模式）


@pytest.mark.parametrize("name", sorted(BENIGN_NOISE_SAMPLES))
def test_benign_noise_never_reaches_repair_levels(name: str) -> None:
    block = BENIGN_NOISE_SAMPLES[name]()  # type: ignore[operator]
    verdict = classify_block(block)
    assert verdict.severity in (Severity.IGNORE, Severity.LOW), (
        f"{name} 被判成了 {verdict.severity}"
    )
    assert verdict.route not in REPAIR_ROUTES
    assert verdict.tags[0].startswith("noise:")


def test_agent_tool_path_miss_stays_quiet() -> None:
    """agent 自伤的 ENOENT 必须停在 LOW+DIGEST：不推送、零 LLM、不进修复候选。"""
    block = agent_tool_path_miss_block()
    verdict = classify_block(block)

    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST
    assert "noise:agent-tool-path-miss" in verdict.tags
    assert classify.is_benign_noise(block) is True


@pytest.mark.parametrize("name", sorted(TRUE_FAILURE_SAMPLES))
def test_true_failures_are_not_ignored(name: str) -> None:
    block = TRUE_FAILURE_SAMPLES[name]()  # type: ignore[operator]
    verdict = classify_block(block)
    assert verdict.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL), (
        f"{name} 被判成了 {verdict.severity}"
    )
    assert verdict.route not in (Route.STORE, Route.DIGEST)
    assert verdict.evidence.strip()
    assert verdict.reason.strip()


def test_critical_level_line_forces_critical() -> None:
    verdict = classify_block(critical_exit_block())
    assert verdict.severity is Severity.CRITICAL
    assert verdict.route is Route.EMERGENCY
    assert "level:CRITICAL" in verdict.tags
    assert "level:CRITICAL" in verdict.reason


def _unmatched_error_block() -> LogBlock:
    """一行谁都不认识的 ERROR（2026-10-16 生产实测：一天 95 条这样的块直推微信）。"""
    return make_block(
        [
            "[2026-10-13 11:00:00.000] [Core] [ERRO] [v4.28.2] [core.unknown.module:42]: "
            "出现了没有任何规则覆盖的怪异错误状态码 4711",
        ]
    )


def test_unmatched_error_line_is_not_ignored() -> None:
    """未被任何规则解释的 ERROR：仍然被看见（留摘录、带标签），但只进摘要，不即时推送。

    **2026-10-17 的策略变更（运营方决定）**：此前这一族直接判 MEDIUM，而 MEDIUM 的最小
    含义是「立刻推一条微信」；生产实测 24 h 内 95 条推送里 95 条都属于这一族。
    恢复旧行为是一条配置：``unmatched_severity = "MEDIUM"``（见下方可逆性用例）。
    """
    verdict = classify_block(_unmatched_error_block())
    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST
    assert "local-mode:unmatched-error" in verdict.tags
    assert verdict.evidence.strip()
    assert verdict.reason.strip()


def test_unmatched_severity_is_reversible_and_typo_safe() -> None:
    """可逆性 + 笔误安全：MEDIUM 回到旧行为；非法值回落 LOW（笔误不得把安静变成打扰）。"""
    block = _unmatched_error_block()
    restored = classify_block(block, cfg={"unmatched_severity": "MEDIUM"})
    assert restored.severity is Severity.MEDIUM
    assert restored.route is Route.NOTIFY
    assert classify_block(block, cfg={"unmatched_severity": "LWO"}).severity is Severity.LOW


def test_noise_line_with_unmatched_error_goes_to_digest() -> None:
    """一致性：噪声规则只解释了一部分命中行时，同样只进摘要（否则这里留一条刷屏缝）。"""
    lines = [
        asyncio_future_block().lines[0],  # 已知噪声行
        "[2026-10-13 11:00:01.000] [Core] [ERRO] [v4.28.2] [core.unknown.module:43]: "
        "另一个没人认识的错误 4712",
    ]
    verdict = classify_block(make_block(lines))
    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST
    assert "local-mode:unmatched-error" in verdict.tags


def test_transient_retry_keeps_contract_baseline() -> None:
    """验收基线（TRANS-01-provider-retry）：可恢复抖动的默认等级仍是 MEDIUM + notify。

    这条基线来自 architecture §4.1 与用例 notes「压成 LOW = 漏报」，本次改动**不得**带跑它。
    """
    verdict = classify_block(provider_retry_block())
    assert verdict.severity is Severity.MEDIUM
    assert verdict.route is Route.NOTIFY


def test_transient_severity_tunable_to_digest() -> None:
    """运营方旋钮：``transient_severity = "LOW"`` ⇒ 抖动只进摘要，provider 抖动不再刷聊天。"""
    verdict = classify_block(provider_retry_block(), cfg={"transient_severity": "LOW"})
    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST


def test_warning_only_block_stays_low() -> None:
    verdict = classify_block(warning_only_block())
    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST


def test_noise_line_does_not_mask_a_real_failure_in_same_block() -> None:
    block = make_block(
        [
            "[2026-10-13 07:59:09.747] [Core] [ERRO] [asyncio.base_events:1833]: Future exception was never retrieved",
            "future: <Future finished exception=EmbeddingProviderError('Framework embedding call failed: Request timed out.')>",
            "[2026-10-13 07:59:09.900] [Core] [ERRO] [v4.28.2] [core.pipeline.scheduler:88]: "
            "写入状态失败: sqlite3.OperationalError: database is locked",
        ]
    )
    verdict = classify_block(block)
    assert verdict.severity is Severity.HIGH
    assert verdict.route is Route.REMEDIATE
    assert "failure:database-error" in verdict.tags
    assert "noise:asyncio-future-never-retrieved" in verdict.tags

    llm_says_critical = parse_llm_verdict(_llm_text("CRITICAL"), block)
    assert apply_safety_guards(llm_says_critical, block).severity is Severity.CRITICAL
    llm_says_ignore = parse_llm_verdict(_llm_text("IGNORE"), block)
    assert apply_safety_guards(llm_says_ignore, block).severity is Severity.HIGH


# --------------------------------------------------------- reason / tags 可追溯


def test_reason_and_tags_are_traceable() -> None:
    block = asyncio_future_block()
    verdict = classify_block(block)
    assert verdict.tags and verdict.tags[0] == "noise:asyncio-future-never-retrieved"
    assert "noise:asyncio-future-never-retrieved" in verdict.reason
    assert verdict.fingerprint[:12] in verdict.reason
    assert ">> " in verdict.evidence
    assert "Future exception was never retrieved" in verdict.evidence
    assert verdict.component == "asyncio.base_events"


def test_component_extracted_from_module_line_tag() -> None:
    assert component_of(send_failed_block()) == "log_watcher.main"
    assert (
        component_of(
            make_block(
                ["[2026-10-13 11:00:00.000] [Core] [ERRO] [v4.28.2] [core.x:1]: 崩了"]
            )
        )
        == "core.x"
    )


def test_repeat_count_marks_pattern_known() -> None:
    block = db_locked_block()
    fresh = classify_block(block)
    repeated = classify_block(block, {"repeat_count": 3})
    assert fresh.is_new_pattern is True
    assert repeated.is_new_pattern is False
    assert "repeat:3" in repeated.tags


def test_route_map_override_from_cfg() -> None:
    """下阶段（deliver/main）可以用配置覆写等级→去向，不必改分级层。"""
    verdict = classify_block(db_locked_block(), cfg={"route_map": {"HIGH": "notify"}})
    assert verdict.severity is Severity.HIGH
    assert verdict.route is Route.NOTIFY
    assert classify_block(db_locked_block()).route is Route.REMEDIATE


# ------------------------------------------------------------------ 安全闸


def test_noise_guard_clamps_llm_escalation() -> None:
    block = asyncio_future_block()
    parsed = parse_llm_verdict(_llm_text("CRITICAL", reason="看起来像崩溃"), block)
    assert parsed.severity is Severity.CRITICAL
    guarded = apply_safety_guards(parsed, block)
    assert guarded.severity in (Severity.IGNORE, Severity.LOW)
    assert "guard:noise-clamp" in guarded.tags
    assert "安全闸" in guarded.reason
    assert guarded.route not in REPAIR_ROUTES
    # 原始 LLM 理由必须保留，便于事后复盘
    assert "看起来像崩溃" in guarded.reason


def test_failure_floor_blocks_silent_pass() -> None:
    block = plugin_load_traceback_block()
    local = classify_block(block)
    parsed = parse_llm_verdict(_llm_text("IGNORE", reason="只是插件问题"), block)
    guarded = apply_safety_guards(parsed, block)
    assert guarded.severity is local.severity
    assert guarded.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "guard:failure-floor" in guarded.tags
    assert guarded.route not in (Route.STORE, Route.DIGEST)


def test_guards_pass_consistent_verdict_through() -> None:
    block = provider_retry_block()
    parsed = parse_llm_verdict(_llm_text("MEDIUM"), block)
    assert apply_safety_guards(parsed, block) is parsed


def test_degraded_verdict_is_conservative_even_if_config_says_ignore() -> None:
    block = send_failed_block()
    verdict = degraded_verdict(
        block, cfg={"fallback_severity": "IGNORE"}, error="timeout"
    )
    assert verdict.severity is Severity.MEDIUM
    assert verdict.route is Route.NOTIFY
    assert "llm-degraded" in verdict.tags
    assert "timeout" in verdict.reason


def test_degraded_verdict_honors_schema_default_severity_name() -> None:
    """main.py 的配置键叫 default_severity，同样要当作降级地板。"""
    verdict = degraded_verdict(
        db_locked_block(), cfg={"default_severity": "LOW"}, error="非法输出"
    )
    assert verdict.severity is Severity.HIGH  # 本地硬故障优先，地板只抬不压
    assert verdict.route is Route.REMEDIATE
    assert verdict.source == "degraded"


# ------------------------------------------------------------ LLM 输出解析


def test_parse_llm_verdict_accepts_plain_and_fenced_json() -> None:
    block = provider_retry_block()
    plain = parse_llm_verdict(_llm_text("MEDIUM"), block)
    fenced = parse_llm_verdict(f"```json\n{_llm_text('HIGH')}\n```", block)
    assert plain.severity is Severity.MEDIUM and plain.route is Route.NOTIFY
    assert fenced.severity is Severity.HIGH and fenced.route is Route.REMEDIATE
    assert "llm" in plain.tags
    assert plain.fingerprint == classify_block(block).fingerprint


def test_parse_llm_verdict_keeps_engine_owned_fields() -> None:
    block = provider_retry_block()
    local = classify_block(block)
    verdict = parse_llm_verdict(
        _llm_text(
            "LOW",
            fingerprint="deadbeefdeadbeef",
            route="ALERT_REPAIR_NOW",
            component="",
        ),
        block,
    )
    assert verdict.fingerprint == local.fingerprint
    assert verdict.route is Route.DIGEST  # 由等级推导，不采纳模型自述
    assert verdict.component == local.component


def test_parse_llm_verdict_clamps_confidence_and_tags() -> None:
    block = provider_retry_block()
    verdict = parse_llm_verdict(
        _llm_text("MEDIUM", confidence=7.5, tags="单个标签"), block
    )
    assert verdict.confidence == 1.0
    assert "单个标签" in verdict.tags


@pytest.mark.parametrize(
    "text",
    [
        "这段日志我看没问题，不用处理。",
        "",
        '{"severity": "SEVERE", "confidence": 0.9, "reason": "等级名不在枚举内"}',
        '{"confidence": 0.9, "reason": "缺 severity"}',
        '{"severity": "HIGH", "confidence": "很高", "reason": "置信度非法"}',
        '{"severity": "HIGH", "confidence": null, "reason": "置信度为 null"}',
        '{"severity": "HIGH", "tags": 3, "reason": "tags 非法"}',
    ],
)
def test_parse_llm_verdict_rejects_invalid_output(text: str) -> None:
    with pytest.raises(LLMOutputError):
        parse_llm_verdict(text, provider_retry_block())


def test_parse_llm_verdict_tolerates_prefixes() -> None:
    verdict = parse_llm_verdict(
        f"好的，结论如下：\n{_llm_text('HIGH')}\n以上。", provider_retry_block()
    )
    assert verdict.severity is Severity.HIGH


# ------------------------------------------------------------------ 提示词


def test_prompt_declares_untrusted_data_and_schema() -> None:
    block = db_locked_block()
    prompt = build_classification_prompt(block)
    assert "不可信数据" in prompt
    assert ">> " in prompt
    assert block.hit_count == prompt.count(">> ")
    for field in ("severity", "confidence", "tags", "component", "reason"):
        assert field in prompt
    assert classify_block(block).fingerprint in prompt


def test_prompt_truncates_context_but_keeps_hit_lines() -> None:
    lines = [
        f"[2026-10-13 12:00:00.{index:03d}] [Core] [INFO] [core.x:1]: 上下文行 {index}"
        for index in range(200)
    ]
    lines[150] = (
        "[2026-10-13 12:00:00.150] [Core] [ERRO] [v4.28.2] [core.x:1]: 命中-关键错误"
    )
    block = make_block(lines)
    prompt = build_classification_prompt(block, cfg={"llm_max_block_lines": 10})
    assert "命中-关键错误" in prompt
    body = prompt.split("【日志片段】", 1)[1].split("【输出要求】", 1)[0]
    rendered = [
        line
        for line in body.splitlines()
        if line.startswith(">> ") or line.startswith("   ")
    ]
    assert len(rendered) <= 10
    assert "上下文行 199" not in prompt or len(rendered) <= 10


def test_prompt_uses_custom_system_text_when_configured() -> None:
    from classify import prompt_system_text

    assert prompt_system_text({}) != ""
    assert (
        prompt_system_text({"classify_system_prompt": "自定义提示词"}) == "自定义提示词"
    )


# ================================================== 提示词资产与评测集（T4 交付物）
# 资产与用例由 T4 产出，路径按 architecture.md §2.1/§5.3：
#   prompts/classify_system.md / prompts/remediate_task.md / tests/classify_cases.json
# 本段只读文件、不联网、不 spawn 任何进程。

_CASES_PATH = _TESTS_DIR / "classify_cases.json"
_SYSTEM_PROMPT_PATH = _PLUGIN_DIR / "prompts" / "classify_system.md"
_REMEDIATE_TEMPLATE_PATH = _PLUGIN_DIR / "prompts" / "remediate_task.md"

#: 系统提示词预算（architecture 侧口径：只放角色/JSON/五级/原则/不确定策略）
_SYSTEM_PROMPT_MAX_CHARS = 2200

#: remediate_task.md 的占位符白名单（与 prompt-remediation.md §2 的映射表逐字一致）
_TEMPLATE_PLACEHOLDERS = {
    "fingerprint", "severity", "route", "source", "component", "tags",
    "repeat_count", "is_new_pattern", "source_file", "start_line", "hit_count",
    "block_lines", "truncated_after", "missing_after", "first_seen", "now",
    "gate_reason", "previous_runs", "reason", "evidence", "stats",
}


def _load_cases() -> list[dict]:
    """读取评测集（缺文件时直接失败：资产是交付物的一部分）。"""
    assert _CASES_PATH.is_file(), f"评测集缺失：{_CASES_PATH}"
    payload = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload.get("cases"), list) and payload["cases"], "cases 为空"
    return payload["cases"]


def _case_block(case: dict) -> LogBlock:
    """按用例还原一个 LogBlock（与生产链路的字段口径一致）。"""
    return LogBlock(
        source=f"{case['id']}.log",
        lines=list(case["lines"]),
        hit_indices=list(case["hit_line_indexes"]),
        levels=list(case["levels"]),
    )


def _bare_tags(tags: list[str]) -> list[str]:
    """去掉 ``kind:`` 前缀（本地规则短名的形状见 models.Rule.kind）。"""
    return [
        tag.split(":", 1)[1] if tag.startswith(("failure:", "noise:", "transient:")) else tag
        for tag in tags
    ]


def test_cases_file_matches_models_enums_and_shape() -> None:
    cases = _load_cases()
    assert len(cases) >= 5, "任务书要求 ≥5 条评测用例"
    seen: set[str] = set()
    for case in cases:
        assert case["id"] not in seen, f"重复 id：{case['id']}"
        seen.add(case["id"])
        assert case["expected_severity"] in [item.value for item in SEVERITY_ORDER]
        lo, hi = case["expected_severity_range"]
        assert SEVERITY_ORDER.index(Severity(lo)) <= SEVERITY_ORDER.index(Severity(hi))
        assert case["expected_route"] == ROUTE_BY_SEVERITY[Severity(case["expected_severity"])].value
        assert case["hit_line_indexes"] and max(case["hit_line_indexes"]) < len(case["lines"])
        # 置信度不在这里断言：用例只约束等级/标签，confidence 分档由提示词规范约束模型行为
        assert isinstance(case["required_tags"], list) and case["required_tags"]
        assert isinstance(case["forbidden_tags"], list)


@pytest.mark.parametrize("case", _load_cases(), ids=lambda case: case["id"])
def test_case_local_baseline_and_forbidden_tags(case: dict) -> None:
    """本地路径必须落在用例声明的基线/区间语义里，且不得产出禁用标签。"""
    verdict = classify_block(_case_block(case))
    bare = _bare_tags(verdict.tags)
    assert not [tag for tag in case["forbidden_tags"] if tag in bare], verdict.tags
    # 本地基线：带 local_baseline_gap 的用例是已记录的实现缺口（见用例 notes），
    # 期望值来自 architecture.md，不得因为实现没做到就下调期望值。
    if not case.get("local_baseline_gap"):
        assert verdict.severity.value == case["expected_severity"], (
            f"{case['id']}：本地 {verdict.severity.value} != 期望 {case['expected_severity']}"
        )


def test_engine_config_forwards_the_severity_knobs() -> None:
    """main 的白名单必须转发两个等级旋钮 —— 这条只能量**源码**，原因在下面。

    为什么会有这条古怪的用例：2026-10-17 加的两个旋钮只写进了 ``_conf_schema.json`` 与
    ``classify.py``，**漏在 ``main._engine_config()`` 这个显式白名单里** ⇒ 生产链路上被静默
    丢弃：引擎路径（``engine._classify`` → ``classify_block(block, metrics, cfg)``）与 detect
    兜底路径都拿不到，运营方把 ``transient_severity`` 设成 LOW 不生效，派单承诺的
    「``unmatched_severity=MEDIUM`` 一步回滚」同样失效。``main.py`` 顶部 import astrbot ⇒
    库内没有夹具能实例化它，所以这里退一步钉「源码事实」；端到端判据仍靠真跑（ops 那份复核）。
    """
    source = (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")
    body = source.split("def _engine_config(self)", 1)[1].split("\n    def ", 1)[0]
    for key in ("unmatched_severity", "transient_severity"):
        assert f'"{key}"' in body, (
            f"_engine_config 白名单漏了 {key}：生产链路上这个旋钮会被静默丢弃"
        )
    fallback = source.split("def _classify(self", 1)[1].split("\n    def ", 1)[0]
    assert "fallback_verdict(block, cfg=" in fallback, (
        "兜底路径也必须把 cfg 传进去，否则降级时旋钮同样失效"
    )


def test_prompt_assets_exist_and_are_utf8() -> None:
    assert _SYSTEM_PROMPT_PATH.is_file(), f"系统提示词缺失：{_SYSTEM_PROMPT_PATH}"
    assert _REMEDIATE_TEMPLATE_PATH.is_file(), f"修复模板缺失：{_REMEDIATE_TEMPLATE_PATH}"
    system = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    template = _REMEDIATE_TEMPLATE_PATH.read_text(encoding="utf-8")
    for token in ("不可信数据", "severity", "confidence", "tags", "component", "reason"):
        assert token in system, f"系统提示词缺 {token}"
    for level in (item.value for item in SEVERITY_ORDER):
        assert level in system, f"系统提示词缺等级语义 {level}"
    for token in ("不可信数据", "log_excerpt", "只读", "重启", "推送", "root_cause", "changed_files"):
        assert token in template, f"修复模板缺 {token}"


def test_system_prompt_file_is_loaded_within_budget() -> None:
    """三级回落必须真的读到文件，而不是永远用内置常量（architecture §5.3）。"""
    from classify import prompt_system_text

    system = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip()
    loaded = prompt_system_text({})
    assert loaded.strip() == system, "prompt_system_text 未加载 prompts/classify_system.md"
    assert len(loaded) <= _SYSTEM_PROMPT_MAX_CHARS, f"系统提示词超预算：{len(loaded)} 字符"


def test_remediation_template_placeholders_are_documented() -> None:
    """模板占位符必须全部落在 prompt-remediation.md §2 的映射表里（禁止自创）。

    占位符是 ``string.Template`` 的 ``$name`` 形式（不用 ``str.format``）：
    模板正文里有 JSON 代码块（``{"root_cause":...}``），花括号必须保持原样。
    """
    from string import Template

    template = _REMEDIATE_TEMPLATE_PATH.read_text(encoding="utf-8")
    found = set(Template(template).get_identifiers())
    assert found, "模板没有任何占位符"
    assert found <= _TEMPLATE_PLACEHOLDERS, f"未登记占位符：{sorted(found - _TEMPLATE_PLACEHOLDERS)}"
    # JSON 代码块里的花括号不得被当成占位符（防有人改回 str.format）
    assert '{"root_cause"' in template
    assert not set(re.findall(r"\{([a-z_]+)\}", template)), "模板混入了 {name} 形式的占位符"


def test_case_excerpts_match_local_evidence() -> None:
    """用例第 1 行必须出现在本地证据摘录里（用例与判定链路不脱节）。"""
    for case in _load_cases():
        verdict = classify_block(_case_block(case))
        token = case["lines"][case["hit_line_indexes"][0]].split("]:")[-1].strip()[:40]
        assert token[:20] in verdict.evidence, f"{case['id']}：证据里缺 {token[:20]!r}"


def test_log_excerpt_fence_wraps_untrusted_text() -> None:
    """注入防护（architecture §11.2 第 15 条 + §5.3）：正文必须在 <log_excerpt> 围栏内。"""
    case = next(item for item in _load_cases() if item["id"].startswith("INJ-"))
    prompt = build_classification_prompt(_case_block(case))
    start = prompt.find("<log_excerpt>")
    end = prompt.find("</log_excerpt>", start + 1)
    assert start != -1 and end > start, "用户提示词缺少 <log_excerpt> 围栏"
    fenced = prompt[start:end]
    outside = prompt[:start] + prompt[end:]
    for line in case["lines"]:
        assert line in fenced, f"正文未进围栏：{line[:40]!r}"
        assert line not in outside, f"正文泄漏到围栏外：{line[:40]!r}"


def test_remediation_template_renders_with_safe_substitute() -> None:
    """模板必须能被 ``safe_substitute`` 渲染：无未替换占位符、证据落在围栏内。

    这里只验模板本身（渲染器由 remediate.build_remediation_task 实现）；
    ``safe_substitute`` 是推荐的实现方式：日志正文里出现 ``$`` 也不会被当成占位符。
    """
    from string import Template

    case = next(item for item in _load_cases() if item["id"] == "FAIL-02-db-locked")
    block = _case_block(case)
    verdict = classify_block(block)
    template = Template(_REMEDIATE_TEMPLATE_PATH.read_text(encoding="utf-8"))
    rendered = template.safe_substitute(
        {
            **(dict.fromkeys(_TEMPLATE_PLACEHOLDERS, "-")),
            "fingerprint": verdict.fingerprint,
            "severity": verdict.severity.value,
            "route": verdict.route.value,
            "source": verdict.source,
            "component": verdict.component,
            "reason": verdict.reason,
            "evidence": verdict.evidence,
        }
    )
    assert not Template(rendered).get_identifiers(), "渲染后仍有占位符"
    start = rendered.find("<log_excerpt>")
    end = rendered.find("</log_excerpt>", start + 1)
    assert start != -1 and end > start, "渲染结果缺少 <log_excerpt> 围栏"
    assert verdict.evidence in rendered[start:end], "证据未落在围栏内"
    assert verdict.fingerprint in rendered
    assert "不可信数据" in rendered[:start], "围栏前缺少不可信数据声明"


# ------------------------------------------------- t17 修复回归（F14 路由安全地板）


def test_route_map_cannot_silence_high_or_critical() -> None:
    """F14：route_map 不得把 HIGH/CRITICAL 静默降级成 store/digest（漏报）。"""
    from classify import route_for_severity

    assert route_for_severity("CRITICAL", {"CRITICAL": "store"}) is not Route.STORE
    assert route_for_severity("HIGH", {"HIGH": "store"}) is not Route.STORE
    assert route_for_severity("HIGH", {"HIGH": "digest"}) is not Route.DIGEST
    assert route_for_severity("CRITICAL", {"CRITICAL": "store"}) is Route.EMERGENCY
    assert route_for_severity("CRITICAL", {"CRITICAL": "ignore"}) is Route.EMERGENCY
    # 低等级仍允许覆写（地板只护 HIGH/CRITICAL），合法高等级覆写也允许
    assert route_for_severity("MEDIUM", {"MEDIUM": "digest"}) is Route.DIGEST
    assert route_for_severity("HIGH", {"HIGH": "emergency"}) is Route.EMERGENCY
