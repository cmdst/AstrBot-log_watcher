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

import tempfile

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
from models import ThreatVerdict  # noqa: E402

#: 「被抬到最高一级」的去向集合：v2.3.0 起 HIGH 不再进修复候选（→ NOTIFY），唯一还会被
#: 抬到顶的是 CRITICAL 的 ``EMERGENCY``；``Route.REMEDIATE`` 只作为历史值保留。
ESCALATED_ROUTES = (Route.EMERGENCY,)
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
    """降级结论不写库：provider 恢复后必须重新判定（而不是捡回降级时的本地结论）。"""
    context = FakeContext(text=_llm_text("IGNORE"), delay=0.4)
    engine = ThreatEngine(context, cfg={**BASE_CFG, "llm_timeout": 0.05})
    block = samples.provider_retry_block()
    degraded = asyncio.run(engine.classify(block))
    assert "llm-timeout" in degraded.tags
    assert "degraded:llm-timeout" in degraded.tags
    assert degraded.judged is False and degraded.judge_source == "degraded"
    assert engine.kb.get(degraded.fingerprint) is None, "降级结论被写进了知识库"

    context.delay = 0.0
    context.text = _llm_text("HIGH")
    recovered = asyncio.run(engine.classify(block))
    assert context.call_count == 2, (
        "降级结果被写进了知识库，provider 恢复后不会再问 LLM"
    )
    # Q11=b（2026-10-18 定案）：provider_retry 是**纯粹的可恢复抖动** ⇒ 模型给 HIGH 也要被封顶
    # 到 MEDIUM（不许进自动修复）。本用例关心的是缓存语义（call_count / tags），等级按新策略钉死。
    assert recovered.severity is Severity.MEDIUM
    assert "transient-escalation-capped" in recovered.tags
    assert "kb-hit:llm" not in recovered.tags
    assert recovered.judged is True
    assert engine.stats()["prior_injected"] == 0, "降级没有留下先验，第二次不该注入历史"


# ---------------------------------------------- 知识库：先验，不是判决出口（v2.3.0）


def test_kb_prior_still_calls_llm() -> None:
    """C1：知识库命中只作先验 —— 同一指纹第二次必须重新问模型，旧结论不得回传。

    这是 v2.3.0 的靶心：旧实现（engine.py:688-693）命中 KB 就直接 return，
    跳过「模型调用 + 安全闸 + 预算记账」整段，把历史结论当成现在的结论。
    """
    context = FakeContext(text=_llm_text("MEDIUM", reason="第一次模型理由"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    first = asyncio.run(
        engine.classify(samples.provider_retry_block(stamp="2026-10-13 07:20:52.444"))
    )
    context.text = _llm_text("LOW", reason="第二次模型理由")
    second = asyncio.run(
        engine.classify(samples.provider_retry_block(stamp="2026-10-13 09:59:00.000"))
    )

    assert context.call_count == 2, "重复指纹必须重新判定（TTL 复用被禁止）"
    assert engine.stats()["llm_calls"] == 2
    assert engine.stats()["kb_hits"] == 1, "第二次应读到历史先验"
    assert engine.stats()["prior_injected"] == 1
    assert first.severity is Severity.MEDIUM and second.severity is Severity.LOW
    assert "第一次模型理由" not in second.reason, "KB 里的旧 reason 不得作为本次结论"
    assert "第二次模型理由" in second.reason
    assert second.judged is True and second.judge_source == "llm"
    assert "prior-overturned" in second.tags, "模型推翻了历史先验，应留可审计标签"
    assert "kb-hit:llm" not in second.tags
    prompt = str(context.calls[1]["prompt"])
    assert "历史判定（先验" in prompt and "第一次模型理由" in prompt, (
        "历史结论必须以先验形式进提示词，而不是直接当结论"
    )
    assert second.evidence.strip(), "命中先验也要带本次片段的实时摘录"
    assert first.evidence != second.evidence, "两段证据来自各自片段"


def test_kb_prior_confirmed_when_model_agrees() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    asyncio.run(engine.classify(samples.provider_retry_block(stamp="2026-10-13 07:00:00.000")))
    second = asyncio.run(
        engine.classify(samples.provider_retry_block(stamp="2026-10-13 08:00:00.000"))
    )
    assert context.call_count == 2
    assert "prior-confirmed" in second.tags


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
    assert verdict.route is Route.NOTIFY  # v2.3.0：HIGH 只通知人工
    assert "manual-override" in verdict.tags
    assert "人工覆写" in verdict.reason
    assert engine.stats()["manual_hits"] == 1
    # 人工覆写是「唯一豁免」，但它也不是模型判定
    assert verdict.judged is False and verdict.judge_source == "manual"
    assert verdict.source == "manual"


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


def test_kb_disabled_still_judges_but_skips_prior() -> None:
    """``kb_enabled`` 只决定「读不读先验」，**不再**决定「判不判」。"""
    prompts: dict[bool, list[str]] = {}
    for enabled in (True, False):
        context = FakeContext(text=_llm_text("MEDIUM"))
        engine = ThreatEngine(context, cfg={**BASE_CFG, "kb_enabled": enabled})
        asyncio.run(
            engine.classify(samples.provider_retry_block(stamp="2026-10-13 07:00:00.000"))
        )
        asyncio.run(
            engine.classify(samples.provider_retry_block(stamp="2026-10-13 08:00:00.000"))
        )
        assert context.call_count == 2, f"kb_enabled={enabled} 时跨轮跳过了模型判定"
        prompts[enabled] = [str(call["prompt"]) for call in context.calls]
    assert "上次 MEDIUM" in prompts[True][1], "开启知识库时第二次应注入先验"
    assert "上次 MEDIUM" not in prompts[False][1], "关闭知识库时不得注入先验"
    assert "无（知识库里没有该指纹）" in prompts[False][1]


def test_knowledge_base_failure_is_isolated() -> None:
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG), kb=BrokenKnowledgeBase())
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert verdict.severity is Severity.MEDIUM
    assert context.call_count == 1
    assert verdict.judged is True, "知识库坏了不妨碍模型判定生效"


# --------------------------------------------------------------- 模式与短路


def test_noise_shortcut_is_off_by_default_so_noise_is_judged() -> None:
    """C2：默认配置下良性噪声也要过模型；模型抬到 CRITICAL 时由安全闸压回。"""
    context = FakeContext(text=_llm_text("CRITICAL", reason="看上去像崩溃"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))  # 不给 noise_shortcut ⇒ 默认 false
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))

    assert context.call_count == 1, "默认必须每条都过 LLM"
    assert verdict.judged is True and verdict.judge_source == "llm"
    assert verdict.severity in (Severity.IGNORE, Severity.LOW)
    assert verdict.route not in ESCALATED_ROUTES
    assert "noise-shortcut" not in verdict.tags
    assert "guard:noise-clamp" in verdict.tags
    assert engine.stats()["noise_shortcut"] == 0


def test_noise_shortcut_skips_llm_only_when_explicitly_enabled() -> None:
    """True 是显式逃生阀：零 token，但结论必须标 judged=false，不得伪装成模型判定。"""
    context = FakeContext(text=_llm_text("CRITICAL"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "noise_shortcut": True})
    verdict = asyncio.run(engine.classify(samples.asyncio_future_block()))

    assert context.call_count == 0
    assert verdict.severity in (Severity.IGNORE, Severity.LOW)
    assert verdict.route not in ESCALATED_ROUTES
    assert "noise-shortcut" in verdict.tags
    assert verdict.judged is False and verdict.judge_source == "local"
    assert engine.stats()["noise_shortcut"] == 1
    assert engine.stats()["llm_skipped"] == 1


def test_real_noise_family_is_rejudged_every_round() -> None:
    """真实噪声族（198 命中里 176 条、88.9%）不再靠零成本短路：跨轮必须重新判定。

    用的是 **真实日志行**（``data/logs/astrbot.log`` 9643~9650 原文：
    ``[Core] [ERRO] [asyncio.base_events:1833]: Future exception was never retrieved``
    加内层 ``EmbeddingProviderError('Framework embedding call failed: Request timed out.')``），
    只用时间戳模拟这一族反复出现的形态；独立复核命令：
    ``grep -c "Future exception was never retrieved" data/logs/astrbot.log`` = 176。

    旧契约（v2.2.0）断言「0 次 LLM + 后续走知识库短路」；v2.3.0 按新契约改写为
    「每轮都判一次、同一轮内才允许批内复用」—— 用例保留、语义按新事实重写。
    """
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdicts = []
    for minute in range(3):
        engine.begin_round()  # 每一轮扫描
        verdicts.append(
            asyncio.run(
                engine.classify(
                    samples.asyncio_future_block(stamp=f"2026-10-13 19:{minute:02d}:09.747")
                )
            )
        )

    assert context.call_count == 3, "跨轮的同一噪声族必须重新判定"
    assert len({item.fingerprint for item in verdicts}) == 1, "同一噪声族应折叠成同一指纹"
    assert all(item.severity in (Severity.IGNORE, Severity.LOW) for item in verdicts)
    assert all(item.route not in ESCALATED_ROUTES for item in verdicts)
    assert all(item.judged is True and item.judge_source == "llm" for item in verdicts)
    stats = engine.stats()
    assert stats["noise_shortcut"] == 0
    assert stats["llm_calls"] == 3
    assert stats["kb_hits"] == 2, "第 2、3 轮读到历史先验（只作参考）"


def test_agent_tool_path_miss_is_judged_but_never_escalates() -> None:
    """agent 工具 ENOENT 属调用方自伤：模型可以看，但安全闸不许把它抬成告警。

    旧契约是「噪声短路，零 LLM 调用」；v2.3.0 改成「照判，但噪声闸压回 LOW」——
    结论仍是 DIGEST，不会刷聊天。
    """
    context = FakeContext(text=_llm_text("CRITICAL"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    verdict = asyncio.run(engine.classify(samples.agent_tool_path_miss_block()))

    assert context.call_count == 1
    assert verdict.severity is Severity.LOW
    assert verdict.route is Route.DIGEST
    assert "guard:noise-clamp" in verdict.tags
    assert verdict.judged is True


def test_local_mode_never_calls_llm() -> None:
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "classify_mode": "local"})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert verdict.route in (Route.NOTIFY, Route.EMERGENCY)
    # 显式 local 是用户选择，但结论仍不是模型判定
    assert verdict.judged is False and verdict.judge_source == "local"
    assert "local-judged" in verdict.tags


def test_missing_provider_is_degraded_and_never_writes_kb() -> None:
    """C4（真缺陷）：需要 LLM 却没配 provider ⇒ 降级且**不写库**。

    旧实现把本地结论以 ``source=local`` 写进 pattern_kb，等 provider 配好后又被
    知识库短路吃掉 ⇒ 错误被永久固化。v2.3.0 起这条路径不得落库。
    """
    context = FakeContext(text=_llm_text("IGNORE"))
    engine = ThreatEngine(context, cfg={"classify_mode": "llm", "llm_provider_id": ""})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert "llm-unconfigured" in verdict.tags
    assert "degraded:llm-unconfigured" in verdict.tags
    assert verdict.source == "degraded"
    assert verdict.judged is False and verdict.judge_source == "degraded"
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert engine.kb.get(verdict.fingerprint) is None, "C4：未配 provider 的结论不得写库"


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


def test_auto_mode_without_provider_degrades_instead_of_silently_judging() -> None:
    context = FakeContext(text=_llm_text("HIGH"))
    engine = ThreatEngine(context, cfg={"classify_mode": "auto"})
    verdict = asyncio.run(engine.classify(samples.plugin_load_traceback_block()))
    assert context.call_count == 0
    assert "llm-unconfigured" in verdict.tags
    assert "需要 LLM" in verdict.reason
    assert verdict.source == "degraded" and verdict.judged is False
    assert verdict.severity in (Severity.HIGH, Severity.CRITICAL)
    assert engine.kb.get(verdict.fingerprint) is None, "C4：不得把未判结论固化进知识库"


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
    """没有 Context 就等于「LLM 不可用」：降级、不写库、不冒充已判。"""
    engine = ThreatEngine(None, cfg={"classify_mode": "llm", "llm_provider_id": "x"})
    verdict = asyncio.run(engine.classify(samples.provider_retry_block()))
    assert verdict.severity is Severity.MEDIUM
    assert verdict.source == "degraded" and verdict.judged is False
    assert "degraded:llm-unconfigured" in verdict.tags
    assert engine.kb.get(verdict.fingerprint) is None


# ------------------------------------------------------------------- 安全闸


def test_engine_clamps_llm_escalation_on_benign_noise() -> None:
    context = FakeContext(text=_llm_text("CRITICAL", reason="看上去像进程崩溃"))
    engine = ThreatEngine(context, cfg={**BASE_CFG, "noise_shortcut": False})
    verdict = asyncio.run(engine.classify(samples.mcp_init_block()))

    assert verdict.severity in (Severity.IGNORE, Severity.LOW)
    assert verdict.route not in ESCALATED_ROUTES
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


def test_guarded_verdict_is_rejudged_next_round_with_prior() -> None:
    """被安全闸修正过的结论也只作先验：下一轮必须重新问模型（旧契约是「直接复用」）。"""
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
    assert context.call_count == 2, "被闸门修正的结论不得当成缓存跳过模型"
    assert second.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "guard:failure-floor" in second.tags
    assert "kb-hit:llm" not in second.tags
    assert "prior-overturned" in second.tags  # 先验是 HIGH，本轮模型说 IGNORE
    # 被闸门修正过的结论同样落库（只作先验/统计）
    assert engine.kb.get(second.fingerprint) is not None
    assert engine.kb.get(second.fingerprint)["judge_source"] == "llm"
    assert engine.kb.get(second.fingerprint)["last_judged_at"] > 0


# ------------------------------------------------- 批内复用 / 跨轮重判（v2.3.0）


def test_batch_memo_judges_once_per_fingerprint() -> None:
    """同一轮里同一指纹只判一次（同一次观察），三段各用自己片段的证据。"""
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    engine.begin_round()
    blocks = [
        samples.provider_retry_block(stamp=f"2026-10-13 11:0{index}:00.000")
        for index in range(3)
    ]
    verdicts = [asyncio.run(engine.classify(block)) for block in blocks]

    assert context.call_count == 1, "同一批同指纹只该付一次 token"
    assert engine.stats()["batch_memo_hits"] == 2
    assert engine.stats()["llm_forced"] == 1
    assert "batch-reused" in verdicts[1].tags and "batch-reused" in verdicts[2].tags
    assert all(item.judged is True for item in verdicts), "复用的是本轮的模型结论"
    evidences = [item.evidence for item in verdicts]
    assert len(set(evidences)) == 3, "每段证据必须来自自己的片段"


def test_next_round_rejudges_same_fingerprint() -> None:
    """跨轮必须重判：批内复用的备忘录由 begin_round 清空（不用 TTL 复用省钱）。"""
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    block = samples.provider_retry_block(stamp="2026-10-13 12:00:00.000")
    for _ in range(2):
        engine.begin_round()
        asyncio.run(engine.classify(block))
    assert context.call_count == 2
    assert engine.stats()["batch_memo_hits"] == 0


def test_without_begin_round_every_call_is_judged() -> None:
    """调用方没开轮（例如单测直调）时按「每次都是新一轮」处理，绝不隐式缓存。"""
    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    block = samples.provider_retry_block()
    asyncio.run(engine.classify(block))
    asyncio.run(engine.classify(block))
    assert context.call_count == 2


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
    assert "degraded:engine-error" in verdict.tags
    assert "保守降级" in verdict.reason
    assert verdict.judged is False and verdict.judge_source == "degraded"
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


def _run_pkg_import_probe(code: str, package: str) -> "subprocess.CompletedProcess[str]":
    """在「父目录里有个名叫 <package> 的目录」的临时舞台里跑包子进程。

    为什么需要舞台：包导入形态要求**父目录里那个目录名**就是合法包名。库的 clone 目录叫
    ``AstrBot-log_watcher``（带连字符，不是合法标识符）⇒ 直接从库目录跑**必然**假失败
    （`ModuleNotFoundError: No module named 'log_watcher'`；2026-10-19 fix 复跑 v2.1.0 时撞到，
    这条红在库目录下每次都会出现）。这里在临时目录里造一个**字面叫 ``log_watcher`` 的符号链接**
    指向真实插件目录，再以它为 cwd —— 断言照旧，且与仓库目录名无关。
    """
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / package
        try:
            staged.symlink_to(_PLUGIN_DIR, target_is_directory=True)
        except (OSError, NotImplementedError):  # pragma: no cover - 极少数文件系统
            pytest.skip(f"本机不允许建符号链接，跳过包导入形态（{package}）")
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp,
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.mark.parametrize("mode", ["flat", "package"])
def test_modules_import_without_astrbot(mode: str) -> None:
    if mode == "flat":
        code = (
            "import sys; import classify, engine;"
            " leaked = sorted(m for m in sys.modules if m.startswith('astrbot'));"
            " assert not leaked, leaked; print('offline-ok')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(_PLUGIN_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
    else:
        code = (
            "import sys; import log_watcher.classify, log_watcher.engine;"
            " leaked = sorted(m for m in sys.modules if m.startswith('astrbot'));"
            " assert not leaked, leaked; print('pkg-ok')"
        )
        proc = _run_pkg_import_probe(code, "log_watcher")
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


def test_llm_budget_defers_instead_of_settling_locally() -> None:
    """F04（v2.3.0 语义）：预算只管「本轮判几段」，超出的**排队 + 降级**，不许本地定案。"""
    context = _BudgetContext()
    engine = ThreatEngine(
        context,
        cfg={
            "classify_mode": "llm",
            "llm_provider_id": "fake-provider",
            "llm_max_calls_per_round": 1,
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
    assert len(context.calls) == 1, f"LLM 调用必须被轮预算截断，实际 {len(context.calls)}"
    assert engine.stats()["llm_budget_skipped"] == 39
    deferred = verdicts[1:]
    assert all(item.source == "degraded" for item in deferred), "预算用尽不得退回本地定案"
    assert all(item.judged is False for item in deferred)
    assert sum(1 for item in deferred if "degraded:llm-budget" in item.tags) == 39
    assert all("judged-deferred" in item.tags for item in deferred)
    assert engine.deferred_judgements == 39, "没判成的指纹必须进待判队列"

    # 下一轮：上一轮排队的指纹优先判定（预算只延迟、不取消）
    engine.begin_round()
    deferred_fp = classify_block(_error_block("unique failure 1")).fingerprint
    assert deferred_fp in engine._priority
    promoted = asyncio.run(engine.classify(_error_block("unique failure 1")))
    assert promoted.judged is True and promoted.judge_source == "llm"
    assert len(context.calls) == 2
    # 轮预算已被上面这次用掉：本轮的新指纹继续排队
    fresh = asyncio.run(engine.classify(_error_block("brand new unique failure")))
    assert "degraded:llm-budget" in fresh.tags
    assert fresh.judged is False


def test_llm_budget_hour_window_defers_and_labels() -> None:
    """F04：小时窗口同样生效（轮预算放宽也不能无限调），超出同样排队 + 降级。"""
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
    assert "degraded:llm-budget" in verdict.tags
    assert verdict.judged is False
    # 小时窗仍是满的：下一轮把它提升为优先也判不了，只能继续排队（不取消）
    engine.begin_round()
    again = asyncio.run(engine.classify(_error_block("second unique")))
    assert again.judged is False and "degraded:llm-budget" in again.tags
    assert len(context.calls) == 1


def test_degraded_tag_family_is_complete() -> None:
    """degraded:* 标签族齐全（超时 / 异常 / 非法输出 / 安全闸 / 预算 / 未配 provider）。"""
    block = samples.provider_retry_block()
    families: set[str] = set()

    families |= set(
        asyncio.run(
            ThreatEngine(FakeContext(exc=RuntimeError("boom")), cfg=dict(BASE_CFG)).classify(block)
        ).tags
    )
    families |= set(
        asyncio.run(
            ThreatEngine(FakeContext(text="不是 JSON"), cfg=dict(BASE_CFG)).classify(block)
        ).tags
    )
    families |= set(
        asyncio.run(
            ThreatEngine(FakeContext(text=_llm_text("IGNORE"), delay=0.3),
                         cfg={**BASE_CFG, "llm_timeout": 0.05}).classify(block)
        ).tags
    )
    families |= set(
        asyncio.run(
            ThreatEngine(FakeContext(text=_llm_text("IGNORE")), cfg={"classify_mode": "auto"}).classify(block)
        ).tags
    )
    budget_engine = ThreatEngine(
        _BudgetContext(),
        cfg={
            "classify_mode": "llm",
            "llm_provider_id": "fake",
            "llm_max_calls_per_round": 1,
            "noise_shortcut": False,
            "kb_enabled": False,
        },
    )
    budget_engine.begin_round()
    asyncio.run(budget_engine.classify(_error_block("first budget block")))
    families |= set(
        asyncio.run(budget_engine.classify(_error_block("deferred budget block"))).tags
    )

    for expected in (
        "degraded:llm-error",
        "degraded:llm-invalid-output",
        "degraded:llm-timeout",
        "degraded:llm-unconfigured",
        "degraded:llm-budget",
    ):
        assert expected in families, f"降级标签族缺 {expected}"

    # 安全闸异常：临时替换撞进 engine 命名空间的 apply_safety_guards，验证 guard-error 分支
    engine_guard = ThreatEngine(FakeContext(text=_llm_text("IGNORE")), cfg=dict(BASE_CFG))

    def boom(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError("guard down")

    patched = engine.apply_safety_guards
    engine.apply_safety_guards = boom
    try:
        tags = asyncio.run(engine_guard.classify(block)).tags
    finally:
        engine.apply_safety_guards = patched
    assert "degraded:guard-error" in tags


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


def test_sqlite_knowledge_base_persists_as_prior_after_restart(tmp_path: Path) -> None:
    """V1（按 v2.3.0 契约改写）：跑一轮后 pattern_kb 非空；重启后仍能读到**先验**，
    但知识库不再产出结论（旧断言「重启后仍短路」已失效）。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "kb.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db, max_entries=100)
    engine_local = ThreatEngine(
        None, cfg={"classify_mode": "local", "kb_enabled": True}, kb=kb
    )
    block = _error_block("database is locked")
    verdict = asyncio.run(engine_local.classify(block, {"repeat_count": 0}))
    assert verdict.fingerprint
    assert verdict.judged is False and verdict.judge_source == "local"
    assert kb.pending >= 1, "判定后应有待落库条目"
    assert kb.flush() >= 1
    assert db.count_rows("pattern_kb") > 0, "断言 1：跑一轮后 pattern_kb 行数必须 > 0"
    fingerprint = verdict.fingerprint
    db.close()

    db2 = store_mod.SqliteStore(tmp_path / "kb.sqlite3").open()
    row = db2.kb_lookup(fingerprint)
    assert row is not None, "断言 2：重启后 kb_lookup 必须命中（先验还在）"
    assert row["judge_source"] == "local"
    assert row["last_judged_at"] == 0.0, "本地结论不是真判，不得伪造判定时间"
    kb2 = engine.SqliteKnowledgeBase(db2)
    assert kb2.prime([fingerprint]) == 1
    engine2 = ThreatEngine(None, cfg={"classify_mode": "local"}, kb=kb2)
    cached = asyncio.run(engine2.classify(block, {"repeat_count": 3}))
    assert cached.source == "local", "知识库只作先验，不得再产出 kb 结论"
    assert cached.judged is False
    assert "kb-hit" not in " ".join(cached.tags)
    assert engine2._kb_lookup(fingerprint) is not None, "重启后先验仍能读到"
    db2.close()


def test_sqlite_kb_records_judge_audit_columns(tmp_path: Path) -> None:
    """真判过的条目要留下 last_judged_at / judge_source（台账与报告据此区分）。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "kb3.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db)
    kb.put(
        {
            "fingerprint": "fp-llm",
            "severity": "HIGH",
            "source": "llm",
            "last_judged_at": 1234.5,
            "judge_source": "llm",
        }
    )
    assert kb.flush() == 1
    row = db.kb_lookup("fp-llm")
    assert row is not None
    assert row["judge_source"] == "llm" and row["last_judged_at"] == 1234.5
    # 后续本地写库不得把「真判过」的事实抹掉（审计列只增不减）
    db.kb_upsert(
        [{"fingerprint": "fp-llm", "severity": "LOW", "source": "local", "last_seen": 2000.0}]
    )
    row = db.kb_lookup("fp-llm")
    assert row["last_judged_at"] == 1234.5, "本地写库把真判时间清零了"
    db.close()


def test_prior_ttl_expires_old_entries(tmp_path: Path) -> None:
    """``classify.prior_ttl_hours``：过期的自动先验不再注入（人工覆写永不过期）。"""
    import time as time_mod

    now = time_mod.time()
    kb = FingerprintKnowledgeBase()
    kb.put(
        {
            "fingerprint": "fp-old",
            "severity": "HIGH",
            "reason": "陈年旧结论",
            "source": "llm",
            "updated_at": now - 100 * 3600,
            "last_judged_at": now - 100 * 3600,
            "judge_source": "llm",
        }
    )
    engine_ttl = ThreatEngine(None, cfg={"classify_mode": "local", "prior_ttl_hours": 72}, kb=kb)
    assert engine_ttl._kb_lookup("fp-old") is None, "超过 prior_ttl_hours 的先验应失效"
    engine_long = ThreatEngine(
        None, cfg={"classify_mode": "local", "prior_ttl_hours": 720}, kb=kb
    )
    assert engine_long._kb_lookup("fp-old") is not None
    kb.set_manual("fp-manual", "HIGH", reason="人工")
    assert engine_ttl._kb_lookup("fp-manual") is not None, "人工覆写不受先验 TTL 影响"


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


def test_repeat_window_never_skips_judging() -> None:
    """``classify.repeat_window_seconds`` 只影响 repeat_count 统计，不参与「判不判」。"""
    for window in (1, 86400):
        context = FakeContext(text=_llm_text("MEDIUM"))
        engine = ThreatEngine(context, cfg={**BASE_CFG, "repeat_window_seconds": window})
        for _ in range(2):
            engine.begin_round()
            asyncio.run(
                engine.classify(samples.provider_retry_block(), {"repeat_count": 9})
            )
        assert context.call_count == 2, f"repeat_window={window} 时跳过了模型判定"


def test_judging_never_consults_notification_dedupe_window() -> None:
    """铁律：通知去重只能影响「发不发」，不得进入判定层（按 AST 量代码，注释不算）。"""
    import ast

    tree = ast.parse(Path(engine.__file__).read_text(encoding="utf-8"))
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    identifiers |= {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    for forbidden in ("dedupe_window", "rate_windows", "suppress_dedup"):
        assert forbidden not in identifiers, f"判定层引用了通知去重概念：{forbidden}"


def test_notification_dedupe_does_not_skip_judging() -> None:
    """B7：同一指纹 10 分钟内连打三轮 —— 判还是每轮都判，只是通知被收敛成 1 条。

    这条把「判定去重」与「通知去重」两件事钉在同一个场景里：判定侧跨轮必须重判
    （call_count=3 / judged=True ×3），通知侧由既有 rate_windows 规则抑制（1 SEND + 2 抑制）。
    """
    import detect
    import store as store_mod

    context = FakeContext(text=_llm_text("MEDIUM"))
    engine = ThreatEngine(context, cfg=dict(BASE_CFG))
    counters = store_mod.CounterStore()
    gate = detect.NotifyGate(counters, detect.GateConfig(dedupe_window=900.0))
    block = samples.provider_retry_block(stamp="2026-10-13 13:00:00.000")
    decisions = []
    verdicts = []
    for step in range(3):
        engine.begin_round()
        gate.begin_round()
        verdict = asyncio.run(engine.classify(block))
        verdicts.append(verdict)
        decisions.append(
            gate.decide(
                detect.AlertItem(
                    fingerprint=verdict.fingerprint,
                    severity=verdict.severity,
                    summary="x",
                    ts=1000.0 + step * 60,
                ),
                1000.0 + step * 60,
            )
        )

    assert context.call_count == 3, "通知去重期间也必须每轮重新判定"
    assert all(item.judged is True for item in verdicts)
    assert decisions == [
        detect.NotifyDecision.SEND,
        detect.NotifyDecision.SUPPRESS_DEDUP,
        detect.NotifyDecision.SUPPRESS_DEDUP,
    ]


def test_unconfigured_provider_never_reaches_pattern_kb(tmp_path: Path) -> None:
    """C4（落库版）：需要 LLM 却未配 provider 时，**一行** pattern_kb 都不许写。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "c4.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db)
    engine_unconfigured = ThreatEngine(
        FakeContext(text=_llm_text("HIGH")), cfg={"classify_mode": "auto"}, kb=kb
    )
    verdict = asyncio.run(engine_unconfigured.classify(samples.plugin_load_traceback_block()))
    assert kb.flush() == 0
    assert db.count_rows("pattern_kb") == 0
    assert db.kb_lookup(verdict.fingerprint) is None
    db.close()


def test_llm_verdict_persists_judge_audit_columns(tmp_path: Path) -> None:
    """真实的模型判定要落 last_judged_at / judge_source=llm（审计链闭环）。"""
    import store as store_mod

    db = store_mod.SqliteStore(tmp_path / "audit.sqlite3").open()
    kb = engine.SqliteKnowledgeBase(db)
    engine_llm = ThreatEngine(FakeContext(text=_llm_text("HIGH")), cfg=dict(BASE_CFG), kb=kb)
    verdict = asyncio.run(engine_llm.classify(samples.db_locked_block()))
    assert verdict.judged is True and verdict.judge_source == "llm"
    assert kb.flush() == 1
    row = db.kb_lookup(verdict.fingerprint)
    assert row is not None
    assert row["judge_source"] == "llm"
    assert row["last_judged_at"] > 0
    db.close()
