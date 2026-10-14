"""engine.py 的行为级测试：LLM 调用契约、超时/异常/非法输出降级、知识库短路与人工覆写。

全部离线：用假 provider 替身（duck-typed ``Context``）覆盖网络路径，不导入 astrbot。
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PLUGIN_DIR = Path(__file__).resolve().parents[1]
_TESTS_DIR = Path(__file__).resolve().parent
for _path in (_PLUGIN_DIR, _TESTS_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

# 共用样例定义在 test_classify.py（任务声明的 inScope 文件），避免多出一个未声明文件
import engine  # noqa: E402
import test_classify as samples  # noqa: E402
from classify import Route, Severity, classify_block, severity_rank  # noqa: E402
from engine import FingerprintKnowledgeBase, ThreatEngine  # noqa: E402
from log_reader import LogBlock  # noqa: E402
from models import RemediationGate, ThreatVerdict  # noqa: E402

REPAIR_ROUTES = (Route.REMEDIATE, Route.EMERGENCY)
BASE_CFG = {
    "classify_mode": "llm",
    "llm_provider_id": "test-provider",
    "llm_timeout": 5,
    "kb_enabled": True,
}


def _llm_text(severity: str, **overrides: object) -> str:
    payload: dict[str, object] = {
        "severity": severity,
        "confidence": 0.8,
        "tags": ["llm-tag"],
        "reason": "模型理由",
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


class FakeContext:
    """``Context.llm_generate`` 的替身：只接受关键字参数，记录每次调用的入参。"""

    def __init__(
        self,
        *,
        text: str = "",
        exc: BaseException | None = None,
        delay: float = 0.0,
        raw: object | None = None,
    ):
        self.text = text
        self.exc = exc
        self.delay = delay
        self.raw = raw
        self.calls: list[dict[str, object]] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def llm_generate(
        self, *, chat_provider_id, prompt=None, system_prompt=None, **kwargs
    ):  # noqa: ANN001, ANN003
        self.calls.append(
            {
                "chat_provider_id": chat_provider_id,
                "prompt": prompt,
                "system_prompt": system_prompt,
            }
        )
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc is not None:
            raise self.exc
        if self.raw is not None:
            return self.raw
        return SimpleNamespace(completion_text=self.text)


class BrokenKnowledgeBase:
    """读写都抛异常的知识库：验证知识库故障不会打穿判定层。"""

    def get(self, fingerprint: str):  # noqa: ANN201
        raise RuntimeError("kb get down")

    def put(self, entry) -> bool:  # noqa: ANN001
        raise RuntimeError("kb put down")


# --------------------------------------------------------------- LLM 调用契约


def test_llm_call_uses_llm_generate_with_explicit_provider_id() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))

    assert context.call_count == 1
    call = context.calls[0]
    assert call["chat_provider_id"] == "test-provider"
    assert isinstance(call["prompt"], str) and "不可信数据" in call["prompt"]
    assert isinstance(call["system_prompt"], str) and "JSON" in call["system_prompt"]
    assert verdict.severity is Severity.MEDIUM
    assert verdict.route is Route.NOTIFY
    assert verdict.is_new_pattern is True
    assert "llm" in verdict.tags
    assert engine.stats()["llm_calls"] == 1


def test_llm_response_without_completion_text_attribute_is_tolerated() -> None:
    context = FakeContext(raw=_llm_text("HIGH"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.db_locked_block()))
    assert verdict.severity is Severity.HIGH


# ------------------------------------------------------------------- 降级路径


def test_llm_timeout_degrades_conservatively() -> None:
    context = FakeContext(text=_llm_text("IGNORE"), delay=0.4)
    engine = ThreatEngine(context, cfg={**BASE_CFG, "llm_timeout": 0.05})
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))

    assert verdict.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    assert verdict.route not in (Route.STORE, Route.DIGEST)
    assert "llm-timeout" in verdict.tags
    assert engine.stats()["degraded"] == 1


def test_llm_invalid_output_degrades_conservatively() -> None:
    context = FakeContext(text="这段日志看起来没问题，不用处理。")
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))

    assert verdict.severity is Severity.MEDIUM
    assert "llm-invalid-output" in verdict.tags
    assert verdict.route not in (Route.STORE, Route.DIGEST)
    assert "输出非法" in verdict.reason


def test_invalid_output_degradation_never_below_medium() -> None:
    context = FakeContext(
        text='{"severity":"NOPE","confidence":0.1,"reason":"非法等级"}'
    )
    engine = ThreatEngine(context, cfg={**BASE_CFG, "fallback_severity": "IGNORE"})
    verdict = asyncio.run(engine.classify(samples.warning_only_block()))
    assert verdict.severity is Severity.MEDIUM
    assert verdict.route is Route.NOTIFY


def test_llm_exception_is_isolated_and_engine_keeps_working() -> None:
    context = FakeContext(exc=RuntimeError("provider exploded"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    first = asyncio.run(engine.classify(samples.db_locked_block()))

    assert first.severity is Severity.HIGH  # 本地硬故障 + 保守降级
    assert "llm-error" in first.tags
    assert "provider exploded" in first.reason

    context.exc = None
    context.text = _llm_text("MEDIUM")
    second = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert second.severity is Severity.MEDIUM
    assert context.call_count == 2


def test_degraded_result_is_not_cached() -> None:
    context = FakeContext(text=_llm_text("IGNORE"), delay=0.4)
    engine = ThreatEngine(context, cfg={**BASE_CFG, "llm_timeout": 0.05})
    block = samples.provider_retry_block()
    degraded = asyncio.run(engine.classify(block))
    assert "llm-timeout" in degraded.tags

    context.delay = 0.0
    context.text = _llm_text("HIGH")
    recovered = asyncio.run(engine.classify(block))
    assert context.call_count == 2, (
        "降级结果被写进了知识库，provider 恢复后不会再问 LLM"
    )
    assert recovered.severity is Severity.HIGH
    assert "kb-hit:llm" not in recovered.tags


# ------------------------------------------------------- 知识库短路 / 人工覆写


def test_kb_short_circuit_avoids_second_llm_call() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    first = asyncio.run(
        engine.classify(samples.provider_retry_block(stamp="2026-10-13 07:20:52.444"))
    )
    second = asyncio.run(
        engine.classify(samples.provider_retry_block(stamp="2026-10-13 09:59:00.000"))
    )

    assert context.call_count == 1, "重复指纹不应重复调用 LLM"
    assert engine.stats()["llm_calls"] == 1
    assert engine.stats()["kb_hits"] == 1
    assert first.is_new_pattern is True
    assert second.is_new_pattern is False
    assert second.severity is first.severity
    assert "kb-hit:llm" in second.tags
    assert "知识库命中" in second.reason
    assert second.evidence.strip(), "命中知识库也要带本次片段的实时摘录"


def test_manual_override_has_highest_priority_and_skips_llm() -> None:
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    fingerprint = classify_block(samples.asyncio_future_block()).fingerprint

    assert (
        engine.set_manual(fingerprint, "HIGH", reason="运维已确认该噪声需要跟踪")
        is True
    )
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))

    assert context.call_count == 0
    assert verdict.severity is Severity.HIGH
    assert verdict.route is Route.REMEDIATE
    assert "manual-override" in verdict.tags
    assert "人工覆写" in verdict.reason
    assert engine.stats()["manual_hits"] == 1


def test_manual_entry_is_never_overwritten_by_automatic_results() -> None:
    kb = FingerprintKnowledgeBase()
    assert kb.set_manual("fp-1", "HIGH", reason="人工") is True
    assert (
        kb.put({"fingerprint": "fp-1", "severity": "IGNORE", "source": "llm"}) is False
    )
    entry = kb.get("fp-1")
    assert (
        entry is not None
        and entry["severity"] == "HIGH"
        and entry["source"] == "manual"
    )

    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG), kb=kb)
    engine.set_manual("fp-1", "HIGH", reason="人工")
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))
    assert verdict.fingerprint != "fp-1"  # 该片段不是人工那条，走正常判定
    assert kb.get("fp-1")["severity"] == "HIGH"


def test_kb_disabled_lets_llm_be_called_again() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "kb_enabled": False})
    asyncio.run(engine.classify(samples.provider_retry_block()))
    asyncio.run(engine.classify(samples.provider_retry_block()))
    assert context.call_count == 2


def test_knowledge_base_failure_is_isolated() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG), kb=BrokenKnowledgeBase())
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert verdict.severity is Severity.MEDIUM
    assert context.call_count == 1


# --------------------------------------------------------------- 模式与短路


def test_noise_shortcut_skips_llm_for_known_noise() -> None:
    context = FakeContext(text=_llm_text("CRITICAL"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))

    assert context.call_count == 0
    assert verdict.severity in (Severity.IGNORE, Severity.LOW)
    assert verdict.route not in REPAIR_ROUTES
    assert "noise-shortcut" in verdict.tags
    assert engine.stats()["noise_shortcut"] == 1


def test_real_noise_family_needs_zero_llm_calls() -> None:
    """captain 指定断言：真实噪声族（198 命中里 176 条、88.9%）必须完全零 LLM 调用。

    用的是 **真实日志行**（``data/logs/astrbot.log`` 9643~9650 原文：
    ``[Core] [ERRO] [asyncio.base_events:1833]: Future exception was never retrieved``
    加内层 ``EmbeddingProviderError('Framework embedding call failed: Request timed out.')``），
    只用时间戳模拟这一族反复出现的形态；独立复核命令：
    ``grep -c "Future exception was never retrieved" data/logs/astrbot.log`` = 176。
    """
    context = FakeContext(text=_llm_text("CRITICAL"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdicts = [
        asyncio.run(
            engine.classify(
                samples.asyncio_future_block(stamp=f"2026-10-13 19:{minute:02d}:09.747")
            )
        )
        for minute in range(6)
    ]

    assert context.call_count == 0, "真实噪声族仍然调用了 LLM"
    assert len({item.fingerprint for item in verdicts}) == 1, (
        "同一噪声族应折叠成同一指纹"
    )
    assert all(item.severity in (Severity.IGNORE, Severity.LOW) for item in verdicts)
    assert all(item.route not in REPAIR_ROUTES for item in verdicts)
    assert verdicts[0].source == "local", "首条由本地噪声规则给出"
    assert all(item.source == "kb" for item in verdicts[1:]), "其余由知识库短路给出"
    stats = engine.stats()
    assert stats["noise_shortcut"] == 1, "首个指纹走噪声短路"
    assert stats["kb_hits"] == 5, "后续同指纹应命中知识库而不是再判定一次"
    assert stats["llm_calls"] == 0


def test_noise_shortcut_can_be_disabled_for_llm_review() -> None:
    context = FakeContext(text=_llm_text("LOW"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "noise_shortcut": False})
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))
    assert context.call_count == 1
    assert verdict.severity is Severity.LOW


def test_local_mode_never_calls_llm() -> None:
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "classify_mode": "local"})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert verdict.route in (Route.REMEDIATE, Route.EMERGENCY)


def test_missing_provider_falls_back_to_local_without_llm() -> None:
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg={"classify_mode": "llm", "llm_provider_id": ""})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert "llm-unconfigured" in verdict.tags
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)


def test_schema_style_config_keys_are_honored() -> None:
    """main.py 用的是 classify_provider_id / classify_mode=auto / classify_timeout_seconds。"""
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(
        context,
        cfg={
            "classify_mode": "auto",
            "classify_provider_id": "schema-provider",
            "classify_timeout_seconds": 7,
        },
    )
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert context.call_count == 1, "schema 键名不同导致 LLM 判定被静默跳过"
    assert context.calls[0]["chat_provider_id"] == "schema-provider"
    assert engine._timeout() == 7.0
    assert verdict.severity is Severity.MEDIUM


def test_auto_mode_without_provider_stays_local_and_says_so() -> None:
    context = FakeContext(text=_llm_text("HIGH"))
    engine = ThreatEngine(context, cfg={"classify_mode": "auto"})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert "llm-unconfigured" in verdict.tags
    assert "本地模式" in verdict.reason
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)


def test_schema_default_severity_is_a_degradation_floor() -> None:
    context = FakeContext(text="我看不出来")
    engine = ThreatEngine(
        context,
        cfg={
            "classify_mode": "auto",
            "classify_provider_id": "schema-provider",
            "default_severity": "IGNORE",
        },
    )
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert verdict.severity is Severity.MEDIUM, "降级地板被配置压到 IGNORE 就等于放行"
    assert verdict.route not in (Route.STORE, Route.DIGEST)


def test_context_is_optional() -> None:
    engine = ThreatEngine(None, cfg={"classify_mode": "llm", "llm_provider_id": "x"})
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert verdict.severity is Severity.MEDIUM


# ------------------------------------------------------------------- 安全闸


def test_engine_clamps_llm_escalation_on_benign_noise() -> None:
    context = FakeContext(text=_llm_text("CRITICAL", reason="看上去像进程崩溃"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "noise_shortcut": False})
    verdict = asyncio.run(engine.classify(samples.mcp_init_block()))

    assert verdict.severity in (Severity.IGNORE, Severity.LOW)
    assert verdict.route not in REPAIR_ROUTES
    assert "guard:noise-clamp" in verdict.tags
    assert engine.stats()["guarded"] == 1


def test_engine_blocks_llm_silent_pass_on_hard_failure() -> None:
    context = FakeContext(text=_llm_text("IGNORE", reason="大概不重要"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))

    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert verdict.route not in (Route.STORE, Route.DIGEST)
    assert "guard:failure-floor" in verdict.tags
    # 被闸门修正过的结论同样要落库，后续同指纹直接复用
    assert engine.kb.get(verdict.fingerprint) is not None


def test_guarded_verdict_is_cached_for_repeat_fingerprints() -> None:
    context = FakeContext(text=_llm_text("IGNORE", reason="大概不重要"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    asyncio.run(
        engine.classify(
            samples.plugin_load_traceback_block(stamp="2026-10-13 09:01:02.001")
        )
    )
    second = asyncio.run(
        engine.classify(
            samples.plugin_load_traceback_block(stamp="2026-10-13 10:01:02.001")
        )
    )
    assert context.call_count == 1
    assert second.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "kb-hit:llm" in second.tags


# ------------------------------------------------------------------- 健壮性


def test_empty_block_is_handled() -> None:
    block = LogBlock(source="", lines=[], hit_indices=[], levels=[])
    verdict = classify_block(block)
    assert verdict.severity is Severity.LOW
    engine = ThreatEngine(None, cfg={"classify_mode": "local"})
    assert asyncio.run(engine.classify(block)).severity is Severity.LOW


def test_engine_never_raises_even_on_corrupt_input() -> None:
    engine = ThreatEngine(FakeContext(text=_llm_text("HIGH")), cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(object()))  # type: ignore[arg-type]
    assert verdict.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    assert "classify-error" in verdict.tags
    assert "保守降级" in verdict.reason
    assert engine.stats()["degraded"] == 1


def test_provider_id_prefers_llm_provider_id_key() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(
        context, cfg={**BASE_CFG, "chat_provider_id": "legacy-provider"}
    )
    asyncio.run(engine.classify(samples.provider_retry_block()))
    assert context.calls[0]["chat_provider_id"] == "test-provider"


def test_engine_stats_are_a_snapshot() -> None:
    engine = ThreatEngine(None, cfg={"classify_mode": "local"})
    snapshot = engine.stats()
    asyncio.run(engine.classify(samples.provider_retry_block()))
    assert snapshot["local"] == 0
    assert engine.stats()["local"] == 1


@pytest.mark.parametrize("mode", ["flat", "package"])
def test_modules_import_without_astrbot(mode: str) -> None:
    if mode == "flat":
        code = (
            "import sys; import classify, engine;"
            " leaked = sorted(m for m in sys.modules if m.startswith('astrbot'));"
            " assert not leaked, leaked; print('offline-ok')"
        )
        cwd = _PLUGIN_DIR
    else:
        code = (
            "import sys; import log_watcher.classify, log_watcher.engine;"
            " leaked = sorted(m for m in sys.modules if m.startswith('astrbot'));"
            " assert not leaked, leaked; print('pkg-ok')"
        )
        cwd = _PLUGIN_DIR.parent
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert ("offline-ok" in proc.stdout) or ("pkg-ok" in proc.stdout)


# ------------------------------------------------- t17 修复回归（F04/F07/F15/V1）


def _error_block(message: str = "database is locked", stamp: str = "2026-10-13 09:15:44.512"):
    line = f"[{stamp}] [Core] [ERRO] [v4.28.2] [core.pipeline.scheduler:88]: {message}"
    return LogBlock(source="astrbot.log", lines=[line], hit_indices=[0], levels=["ERROR"])


class _BudgetContext:
    """假 provider：记录每次调用，返回合法 JSON（F04 预算测试用）。"""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def llm_generate(self, *, chat_provider_id, prompt, system_prompt):  # noqa: ANN001
        self.calls.append(chat_provider_id)
        return SimpleNamespace(
            completion_text=(
                '{"severity":"HIGH","confidence":0.9,"tags":["llm"],'
                '"component":"core","reason":"假 provider"}'
            )
        )


def test_llm_budget_caps_calls_per_round() -> None:
    """F04：先过闸再调 LLM —— 40 个新指纹块最多只花 llm_max_calls_per_round 次。"""
    context = _BudgetContext()
    engine = ThreatEngine(
        context,
        cfg={
            "classify_mode": "llm",
            "llm_provider_id": "fake-provider",
            "llm_max_calls_per_round": 2,
            "noise_shortcut": False,
            "kb_enabled": False,
        },
    )
    engine.begin_round()

    async def scenario() -> list[ThreatVerdict]:
        return [
            await engine.classify(_error_block(f"unique failure {index}"))
            for index in range(40)
        ]

    verdicts = asyncio.run(scenario())
    assert len(context.calls) == 2, f"LLM 调用必须被轮预算截断，实际 {len(context.calls)}"
    assert engine.stats()["llm_budget_skipped"] == 38
    assert sum(1 for item in verdicts if "llm-budget" in item.tags) == 38
    assert all(item.source == "local" for item in verdicts[2:])

    engine.begin_round()
    asyncio.run(engine.classify(_error_block("another unique failure")))
    assert len(context.calls) == 3, "新一轮应恢复预算"


def test_llm_budget_hour_window_is_enforced() -> None:
    """F04：小时窗口同样生效（轮预算放宽也不能无限调）。"""
    context = _BudgetContext()
    engine = ThreatEngine(
        context,
        cfg={
            "classify_mode": "llm",
            "llm_provider_id": "fake-provider",
            "llm_max_calls_per_round": 100,
            "llm_max_calls_per_hour": 1,
            "noise_shortcut": False,
            "kb_enabled": False,
        },
    )
    engine.begin_round()
    asyncio.run(engine.classify(_error_block("first unique")))
    verdict = asyncio.run(engine.classify(_error_block("second unique")))
    assert len(context.calls) == 1
    assert "llm-budget:hour" in verdict.tags


def test_should_remediate_delegates_to_ledger() -> None:
    """F07：engine.should_remediate 一行委派到账本；没有账本时 fail-closed。"""
    calls: list[tuple] = []

    class FakeLedger:
        def can_start(self, verdict, *, now, metrics=None):  # noqa: ANN001
            calls.append((verdict.fingerprint, now, metrics))
            return RemediationGate(False, "cooldown")

    verdict = ThreatVerdict(
        severity=Severity.HIGH, fingerprint="fp1", confidence=0.9, route=Route.REMEDIATE
    )
    gate = engine.should_remediate(
        verdict, {"repeat_count": 3}, {}, ledger=FakeLedger(), now=123.0
    )
    assert (gate.allowed, gate.reason) == (False, "cooldown")
    assert calls == [("fp1", 123.0, {"repeat_count": 3})]
    assert engine.should_remediate(verdict, {}, {}).reason == "off"


def test_classify_enable_false_skips_kb_and_llm() -> None:
    """F15：分级总开关关闭 ⇒ 直接按等级触发（不查 KB、不调 LLM）。"""
    context = _BudgetContext()
    engine = ThreatEngine(
        context, cfg={"classify_mode": "llm", "llm_provider_id": "fake", "classify_enable": False}
    )
    verdict = asyncio.run(engine.classify(_error_block("unique for disabled classify")))
    assert not context.calls
    assert "classify-disabled" in verdict.tags
    assert engine.stats()["llm_calls"] == 0


def test_new_pattern_escalate_raises_low_and_medium_only() -> None:
    """F15/§4.3：new_pattern_escalate=true 时只给 LOW/MEDIUM 的新指纹升一级。"""
    engine = ThreatEngine(None, cfg={"classify_mode": "local", "new_pattern_escalate": True})
    low_block = LogBlock(
        source="astrbot.log",
        lines=[
            "[2026-10-13 09:15:44.512] [Core] [WARN] [v4.28.2] [p.py:1]: unknown benign-ish notice"
        ],
        hit_indices=[0],
        levels=["WARNING"],
    )
    verdict = asyncio.run(engine.classify(low_block, {"repeat_count": 0}))
    assert verdict.is_new_pattern is True
    assert "escalated" in verdict.tags
    assert severity_rank(verdict.severity) >= severity_rank(Severity.MEDIUM)

    engine_off = ThreatEngine(None, cfg={"classify_mode": "local"})
    plain = asyncio.run(engine_off.classify(low_block, {"repeat_count": 0}))
    assert "escalated" not in plain.tags


def test_sqlite_knowledge_base_persists_and_survives_restart(tmp_path: Path) -> None:
    """V1：跑一轮后 pattern_kb 行数 > 0；重启（重开库 + 新引擎）后 kb_lookup 命中。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "kb.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db, max_entries=100)
    engine_local = ThreatEngine(
        None, cfg={"classify_mode": "local", "kb_enabled": True}, kb=kb
    )
    block = _error_block("database is locked")
    verdict = asyncio.run(engine_local.classify(block, {"repeat_count": 0}))
    assert verdict.fingerprint
    assert kb.pending >= 1, "判定后应有待落库条目"
    assert kb.flush() >= 1
    assert db.count_rows("pattern_kb") > 0, "断言 1：跑一轮后 pattern_kb 行数必须 > 0"
    fingerprint = verdict.fingerprint
    db.close()

    db2 = store_mod.SqliteStore(tmp_path / "kb.sqlite3").open()
    assert db2.kb_lookup(fingerprint) is not None, "断言 2：重启后 kb_lookup 必须命中"
    kb2 = engine.SqliteKnowledgeBase(db2)
    assert kb2.prime([fingerprint]) == 1
    engine2 = ThreatEngine(None, cfg={"classify_mode": "local"}, kb=kb2)
    cached = asyncio.run(engine2.classify(block, {"repeat_count": 3}))
    assert cached.source in {"kb", "manual"}
    assert "kb-hit" in " ".join(cached.tags) or "manual-override" in cached.tags
    db2.close()


def test_sqlite_knowledge_base_manual_entry_is_not_overwritten(tmp_path: Path) -> None:
    """V1：人工覆写条目不得被非 manual 结果覆盖（落库前后都成立）。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "kb2.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db)
    assert kb.set_manual("fp-manual", Severity.IGNORE, reason="人工忽略") is True
    assert kb.put({"fingerprint": "fp-manual", "severity": "CRITICAL", "source": "llm"}) is False
    assert kb.flush() == 0
    row = db.kb_lookup("fp-manual")
    assert row is not None and row["manual"] is True and row["severity"] == "IGNORE"
    kb2 = engine.SqliteKnowledgeBase(db)
    kb2.prime(["fp-manual"])
    assert kb2.get("fp-manual")["source"] == "manual"
    assert kb2.put({"fingerprint": "fp-manual", "severity": "HIGH", "source": "kb"}) is False
    db.close()
