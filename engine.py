"""威胁分级引擎：本地判定、指纹知识库与 LLM 判定的编排（纯逻辑，不导入 astrbot）。

判定顺序（短路优先，避免对同一指纹重复付 LLM 的钱）：

1. 人工覆写：知识库里 ``source == "manual"`` 的指纹直接返回，优先级最高，
   不会被任何自动结果覆盖，也不经过安全闸；
2. 知识库短路：命中已缓存指纹（LLM 判定或本地噪声规则）直接复用，不再调用 LLM；
3. 已知噪声短路（``noise_shortcut``，默认开）：本地规则认定为良性噪声时直接给结论，
   最吵的一类噪声不消耗 token；
4. LLM 判定：``classify_mode == "llm"`` 且配置了 provider id 时调用
   ``Context.llm_generate``（显式传 ``chat_provider_id``），带超时；
   输出经 :func:`classify.apply_safety_guards` 修正后写入知识库；
5. 本地兜底：``classify_mode == "local"``、未配置 provider、LLM 超时/异常/输出非法时，
   一律退到 :func:`classify.classify_block`，降级等级取 ``max(本地等级, fallback_severity)``
   （默认 MEDIUM），保证「不静默放行」。

降级结果与本地兜底结果都不写知识库：provider 抖动或临时没配好，不该把某个指纹永久钉死。
异常隔离：LLM 与知识库的任何异常都在本层吞掉并转成结构化结论，不影响调用方主循环。
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Protocol

try:
    from .classify import (
        DEFAULT_SYSTEM_PROMPT,
        LLMOutputError,
        apply_safety_guards,
        build_classification_prompt,
        cfg_first,
        cfg_get,
        clamp_transient_escalation,
        classify_block,
        degraded_verdict,
        is_benign_noise,
        parse_llm_verdict,
        prompt_system_text,
        route_for_severity,
        severity_max,
    )
    from .log_reader import LogBlock
    from .models import Severity, ThreatVerdict
except ImportError:  # 平铺导入（tests 直接 import engine）
    from classify import (
        DEFAULT_SYSTEM_PROMPT,
        LLMOutputError,
        apply_safety_guards,
        build_classification_prompt,
        cfg_first,
        cfg_get,
        clamp_transient_escalation,
        classify_block,
        degraded_verdict,
        is_benign_noise,
        parse_llm_verdict,
        prompt_system_text,
        route_for_severity,
        severity_max,
    )
    from log_reader import LogBlock
    from models import Severity, ThreatVerdict

_log = logging.getLogger("log_watcher.engine")

DEFAULT_LLM_MAX_CALLS_ROUND = 5
"""每轮 LLM 调用上限（F04；0 = 不限）。"""

DEFAULT_LLM_MAX_CALLS_HOUR = 60
"""每小时 LLM 调用上限（F04；0 = 不限）。"""

def _bool_cfg(cfg: Mapping | object | None, key: str, default: bool) -> bool:
    """读布尔配置（字符串 "false"/"0" 也当假，避免配置面把假值读成真）。"""
    value = cfg_get(cfg, key, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _int_cfg(
    cfg: Mapping | object | None, key: str, default: int, minimum: int, maximum: int
) -> int:
    """读整数配置并夹紧到 [minimum, maximum]（非法值回落默认）。"""
    try:
        value = int(cfg_get(cfg, key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


LOCAL_SOURCE = "local"
"""本地规则判定结果的 KB source（§5.1 第 4 行：本地结论也要落库）。"""

MANUAL_SOURCE = "manual"
LLM_SOURCE = "llm"
NOISE_SOURCE = "local-noise"

_DEFAULT_LLM_TIMEOUT = 30.0
_MIN_LLM_TIMEOUT = 0.05
_MAX_LLM_TIMEOUT = 600.0


class KnowledgeBase(Protocol):
    """指纹知识库的最小接口（store.py 的 SQLite 版本照此实现即可）。

    条目形状::

        {"fingerprint": str, "severity": str, "confidence": float, "tags": list[str],
         "component": str, "reason": str, "source": "manual"|"llm"|"local-noise",
         "hits": int, "updated_at": float}
    """

    def get(self, fingerprint: str) -> Mapping[str, Any] | None:
        """取指纹对应的条目，取不到返回 None。"""
        ...

    def put(self, entry: Mapping[str, Any]) -> bool:
        """写入/更新条目；``source == "manual"`` 的既有条目不得被非 manual 条目覆盖。"""
        ...


class FingerprintKnowledgeBase:
    """进程内指纹知识库（引擎默认实现，重启即失；持久化交给 store.py 的 SQLite 版本）。"""

    def __init__(self, *, max_entries: int = 500):
        """初始化。

        Args:
            max_entries: 容量上限，超出时按插入顺序淘汰非 manual 条目（人工覆写永不淘汰）。
        """
        self.max_entries = max(1, int(max_entries))
        self._entries: dict[str, dict[str, Any]] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def has(self, fingerprint: str) -> bool:
        """指纹是否已在库中。"""
        return fingerprint in self._entries

    def get(self, fingerprint: str) -> Mapping[str, Any] | None:
        """取条目（只读快照，调用方改动不会污染库）。"""
        entry = self._entries.get(fingerprint)
        return dict(entry) if entry is not None else None

    def put(self, entry: Mapping[str, Any]) -> bool:
        """写入条目；拒绝覆盖人工覆写条目。

        Args:
            entry: 至少含 ``fingerprint`` 与 ``severity``。

        Returns:
            是否写入成功。
        """
        fingerprint = str(entry.get("fingerprint") or "").strip()
        if not fingerprint:
            return False
        existing = self._entries.get(fingerprint)
        source = str(entry.get("source") or "auto")
        if (
            existing is not None
            and existing.get("source") == MANUAL_SOURCE
            and source != MANUAL_SOURCE
        ):
            _log.warning(
                "指纹 %s 已有人工覆写，拒绝被 %s 结果覆盖", fingerprint[:12], source
            )
            return False
        record = dict(existing or {})
        record.update({key: value for key, value in entry.items() if value is not None})
        record["fingerprint"] = fingerprint
        record["source"] = source
        self._entries[fingerprint] = record
        self._evict()
        return True

    def set_manual(
        self,
        fingerprint: str,
        severity: object,
        *,
        reason: str = "",
        tags: tuple[str, ...] | list[str] = (),
        confidence: float = 1.0,
        component: str = "",
    ) -> bool:
        """写一条人工覆写（``source=manual``），优先级高于任何自动判定。

        Args:
            fingerprint: 目标指纹。
            severity: 人工指定的等级。
            reason: 人工理由（会写进结论，可追溯谁改的）。
            tags: 附加标签。
            confidence: 置信度，人工覆写默认 1.0。
            component: 覆盖组件名。

        Returns:
            是否写入成功。
        """
        return self.put(
            {
                "fingerprint": str(fingerprint).strip(),
                "severity": Severity.parse(severity).value,
                "confidence": min(1.0, max(0.0, float(confidence))),
                "tags": [str(tag) for tag in tags],
                "component": str(component or ""),
                "reason": str(reason or "人工覆写"),
                "source": MANUAL_SOURCE,
                "hits": 1,
                "updated_at": time.time(),
            }
        )

    def _evict(self) -> None:
        """超容量时淘汰最早的非 manual 条目。"""
        while len(self._entries) > self.max_entries:
            victim = next(
                (
                    fp
                    for fp, entry in self._entries.items()
                    if entry.get("source") != MANUAL_SOURCE
                ),
                None,
            )
            if victim is None:
                return
            del self._entries[victim]


class SqliteKnowledgeBase:
    """持久化指纹知识库（V1/R11）：读走内存缓存，写进 :meth:`flush` 批量落库。

    与 ``store.SqliteStore`` 的接线（§6.6）：

    - **读**：只读内存缓存。事件循环里禁止直接 sqlite（§9.4 第 3 条），所以
      ``get()`` 不触库；main 每轮在 ``asyncio.to_thread`` 里调 :meth:`prime`
      把本轮要用到的指纹批量装进缓存。
    - **写**：``put()`` 只更新缓存与待落库集合，``flush()`` 在 ``to_thread`` 里
      调 ``store.kb_upsert()`` 一次性落库（main 每轮调一次）。
    - **人工覆写**：``manual`` 条目永不被非 manual 结果覆盖（``put`` 直接拒绝）。
    """

    def __init__(
        self,
        store: Any,
        *,
        max_entries: int = 500,
        cache_size: int = 2048,
    ):
        """初始化。

        Args:
            store: :class:`store.SqliteStore`（或同接口替身，需有 ``kb_lookup`` /
                ``kb_upsert`` / ``kb_set_manual``）。
            max_entries: 落库时的知识库条数上限（交给 ``store.prune`` 用）。
            cache_size: 进程内缓存条数上限（LRU）。
        """
        self.store = store
        self.max_entries = max(1, int(max_entries))
        self.cache_size = max(16, int(cache_size))
        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty: dict[str, dict[str, Any]] = {}

    def __len__(self) -> int:
        return len(self._cache)

    @property
    def pending(self) -> int:
        """尚未落库的条目数（观测用）。"""
        return len(self._dirty)

    @staticmethod
    def _row_to_entry(row: Mapping[str, Any]) -> dict[str, Any]:
        """把存储层行规整成 KB 条目（字段名与 FingerprintKnowledgeBase 对齐）。"""
        return {
            "fingerprint": str(row.get("fingerprint") or ""),
            "severity": str(row.get("severity") or "MEDIUM"),
            "confidence": float(row.get("confidence") or 0.0),
            "tags": list(row.get("tags") or []),
            "component": str(row.get("component") or ""),
            "reason": str(row.get("reason") or ""),
            "source": MANUAL_SOURCE if row.get("manual") else str(row.get("source") or "llm"),
            "hits": int(row.get("hits") or 0),
            "updated_at": float(row.get("last_seen") or 0.0),
        }

    def prime(self, fingerprints: Any) -> int:
        """把一批指纹从库装进缓存（必须在 ``asyncio.to_thread`` 里调用）。

        Args:
            fingerprints: 指纹序列。

        Returns:
            本次加载的条数（已缓存/待落库的不重复加载）。
        """
        loaded = 0
        for fingerprint in fingerprints or ():
            key = str(fingerprint or "").strip()
            if not key or key in self._cache or key in self._dirty:
                continue
            try:
                row = self.store.kb_lookup(key)
            except Exception as exc:  # 库坏不得影响判定（当作未命中）
                _log.warning("知识库批量载入失败：%s: %s", type(exc).__name__, exc)
                break
            if row:
                self._cache[key] = self._row_to_entry(row)
                loaded += 1
        self._evict()
        return loaded

    def has(self, fingerprint: str) -> bool:
        """指纹是否已知（只看缓存，不触库）。"""
        return self.get(fingerprint) is not None

    def get(self, fingerprint: str) -> Mapping[str, Any] | None:
        """取条目（只读快照；缓存未命中返回 None，不查库）。"""
        key = str(fingerprint or "").strip()
        entry = self._dirty.get(key) or self._cache.get(key)
        return dict(entry) if entry is not None else None

    def put(self, entry: Mapping[str, Any]) -> bool:
        """写入条目（进缓存 + 待落库）；拒绝覆盖人工覆写条目。"""
        fingerprint = str(entry.get("fingerprint") or "").strip()
        if not fingerprint:
            return False
        existing = self._dirty.get(fingerprint) or self._cache.get(fingerprint)
        source = str(entry.get("source") or "auto")
        if (
            existing is not None
            and existing.get("source") == MANUAL_SOURCE
            and source != MANUAL_SOURCE
        ):
            _log.warning(
                "指纹 %s 已有人工覆写，拒绝被 %s 结果覆盖", fingerprint[:12], source
            )
            return False
        record = dict(existing or {})
        record.update({key: value for key, value in entry.items() if value is not None})
        record["fingerprint"] = fingerprint
        record["source"] = source
        self._cache[fingerprint] = record
        self._dirty[fingerprint] = record
        self._evict()
        return True

    def set_manual(
        self,
        fingerprint: str,
        severity: object,
        *,
        reason: str = "",
        tags: tuple[str, ...] | list[str] = (),
        confidence: float = 1.0,
    ) -> bool:
        """人工指定等级（写库 + 缓存；后续自动判定不得覆盖）。"""
        key = str(fingerprint or "").strip()
        if not key:
            return False
        try:
            ok = bool(
                self.store.kb_set_manual(
                    key,
                    getattr(severity, "value", severity),
                    reason=reason,
                    tags=list(tags),
                    confidence=confidence,
                )
            )
        except Exception as exc:
            _log.warning("写入人工覆写失败：%s: %s", type(exc).__name__, exc)
            return False
        if ok:
            self._cache[key] = {
                "fingerprint": key,
                "severity": str(getattr(severity, "value", severity)),
                "confidence": float(confidence),
                "tags": list(tags),
                "component": "",
                "reason": reason,
                "source": MANUAL_SOURCE,
                "hits": int((self._cache.get(key) or {}).get("hits", 0) or 0) + 1,
                "updated_at": time.time(),
            }
            self._dirty.pop(key, None)  # 已直接落库，不必再 flush
        return ok

    def flush(self) -> int:
        """把待落库条目批量写库（幂等，必须在 ``to_thread`` 里调用）。

        Returns:
            本次落库条数（失败返回 0，不抛异常）。
        """
        if not self._dirty:
            return 0
        entries = list(self._dirty.values())
        try:
            written = int(self.store.kb_upsert(entries) or 0)
        except Exception as exc:
            _log.warning("知识库落库失败（保留待下次 flush）：%s: %s", type(exc).__name__, exc)
            return 0
        self._dirty.clear()
        return written

    def _evict(self) -> None:
        """缓存超限时按插入顺序淘汰非 manual 条目（人工覆写永不淘汰）。"""
        while len(self._cache) > self.cache_size:
            victim = next(
                (key for key, item in self._cache.items() if item.get("source") != MANUAL_SOURCE),
                None,
            )
            if victim is None:
                return
            del self._cache[victim]


class ThreatEngine:
    """分级引擎：把片段变成 :class:`~classify.ThreatVerdict`。"""

    def __init__(
        self,
        context: object | None = None,
        *,
        cfg: Mapping | object | None = None,
        kb: KnowledgeBase | None = None,
        system_prompt: str | None = None,
    ):
        """初始化。

        Args:
            context: AstrBot ``Context``（只需提供 ``llm_generate``），可为 None（纯本地）。
            cfg: 插件配置，支持 ``classify_mode`` / ``llm_provider_id`` /
                ``llm_timeout`` / ``fallback_severity`` / ``kb_enabled`` /
                ``kb_max_entries`` / ``noise_shortcut`` / ``llm_max_block_lines`` /
                ``classify_system_prompt`` / ``route_map``。
            kb: 知识库实现，缺省用进程内 :class:`FingerprintKnowledgeBase`。
            system_prompt: 分级系统提示词，缺省用 ``classify.DEFAULT_SYSTEM_PROMPT``。
        """
        self._context = context
        self._cfg = cfg if cfg is not None else {}
        self._system_prompt = (
            system_prompt or prompt_system_text(self._cfg) or DEFAULT_SYSTEM_PROMPT
        )
        try:
            max_entries = int(cfg_get(self._cfg, "kb_max_entries", 500))
        except (TypeError, ValueError):
            max_entries = 500
        self._kb: KnowledgeBase = (
            kb if kb is not None else FingerprintKnowledgeBase(max_entries=max_entries)
        )
        self._kb_active = (
            bool(cfg_get(self._cfg, "kb_enabled", True)) and self._kb is not None
        )
        self._stats = {
            "llm_calls": 0,
            "kb_hits": 0,
            "manual_hits": 0,
            "noise_shortcut": 0,
            "local": 0,
            "degraded": 0,
            "guarded": 0,
            "llm_budget_skipped": 0,
        }
        # F04：LLM 调用预算（按轮 + 按小时），超限的块走本地规则并打 llm-budget 标签
        self._round_llm_calls = 0
        self._llm_call_times: list[float] = []

    def begin_round(self) -> None:
        """每轮扫描开始前调用：重置「每轮 LLM 调用数」（F04 的轮内预算）。"""
        self._round_llm_calls = 0

    @property
    def llm_calls(self) -> int:
        """累计 LLM 调用次数（观测用）。"""
        return int(self._stats["llm_calls"])

    def _llm_budget_allows(self, *, now: float | None = None) -> tuple[bool, str]:
        """LLM 预算闸（F04）：**调用前**判定，超限的块走本地规则。

        Returns:
            ``(是否允许调用, 拒绝原因)``；原因 ∈ {``round``, ``hour``}。
        """
        per_round = _int_cfg(self._cfg, "llm_max_calls_per_round", DEFAULT_LLM_MAX_CALLS_ROUND, 0, 1000)
        per_hour = _int_cfg(self._cfg, "llm_max_calls_per_hour", DEFAULT_LLM_MAX_CALLS_HOUR, 0, 100000)
        moment = time.time() if now is None else float(now)
        self._llm_call_times = [
            item for item in self._llm_call_times if moment - item < 3600.0
        ]
        if per_round > 0 and self._round_llm_calls >= per_round:
            return False, "round"
        if per_hour > 0 and len(self._llm_call_times) >= per_hour:
            return False, "hour"
        return True, ""

    def _note_llm_call(self, *, now: float | None = None) -> None:
        """记一次 LLM 调用（预算计数）。

        ``stats["llm_calls"]`` 由 :meth:`_call_llm` 自增（既有口径，测试钉住），
        这里只维护预算用的轮内计数与小时窗口，避免重复计数。
        """
        moment = time.time() if now is None else float(now)
        self._round_llm_calls += 1
        self._llm_call_times.append(moment)

    def _apply_new_pattern_escalation(
        self, verdict: ThreatVerdict, metrics: Mapping | None
    ) -> ThreatVerdict:
        """F15/§4.3：``new_pattern_escalate=true`` 时给新指纹（LOW/MEDIUM）升一级。

        升权发生在**引擎**（路由裁决层），不改 ``classify_block`` 的纯函数语义；
        ``HIGH/CRITICAL/IGNORE`` 不变；事实写进 tags 与 reason。
        """
        if not _bool_cfg(self._cfg, "new_pattern_escalate", False):
            return verdict
        if not verdict.is_new_pattern:
            return verdict
        if verdict.severity not in (Severity.LOW, Severity.MEDIUM):
            return verdict
        boosted = (
            Severity.MEDIUM if verdict.severity is Severity.LOW else Severity.HIGH
        )
        tags = list(verdict.tags)
        for tag in ("new-pattern", "escalated"):
            if tag not in tags:
                tags.append(tag)
        _log.info(
            "新指纹升权（new_pattern_escalate）：%s -> %s（指纹 %s）",
            verdict.severity.value,
            boosted.value,
            verdict.fingerprint[:12],
        )
        return replace(
            verdict,
            severity=boosted,
            tags=tags,
            reason=verdict.reason
            + f"；新指纹升权（{verdict.severity.value}→{boosted.value}，new_pattern_escalate=true）",
            route=route_for_severity(boosted, cfg_get(self._cfg, "route_map", None)),
        )

    @property
    def kb(self) -> KnowledgeBase:
        """当前知识库（接线时替换成 store.py 的 SQLite 实现）。"""
        return self._kb

    def stats(self) -> dict[str, int]:
        """返回计数器快照（观测用：LLM 调用次数、短路命中、降级次数等）。"""
        return dict(self._stats)

    def set_manual(
        self,
        fingerprint: str,
        severity: object,
        *,
        reason: str = "",
        tags: tuple[str, ...] | list[str] = (),
        confidence: float = 1.0,
    ) -> bool:
        """写一条人工覆写；未实现该能力的外部知识库会返回 False。

        Args:
            fingerprint: 目标指纹。
            severity: 人工指定的等级。
            reason: 人工理由。
            tags: 附加标签。
            confidence: 置信度。

        Returns:
            是否写入成功。
        """
        setter = getattr(self._kb, "set_manual", None)
        if not callable(setter):
            return False
        try:
            return bool(
                setter(
                    fingerprint,
                    severity,
                    reason=reason,
                    tags=tags,
                    confidence=confidence,
                )
            )
        except Exception as exc:  # 知识库故障不影响主循环
            _log.warning("人工覆写写入失败：%s: %s", type(exc).__name__, exc)
            return False

    async def classify(
        self, block: LogBlock, metrics: Mapping | None = None
    ) -> ThreatVerdict:
        """判定一个日志片段的威胁等级（本方法不抛异常）。

        Args:
            block: 日志片段。
            metrics: 可选上下文统计，见 :func:`classify.classify_block`。

        Returns:
            结构化结论；LLM 不可用或判定层意外异常时返回保守降级结论。
        """
        try:
            verdict = await self._classify(block, metrics)
            # 收口（Q11=b 定案）：纯抖动族不许被抬到 HIGH/CRITICAL 从而触发自动修复。
            # 放在这里是因为这是公开入口唯一的成功 return，KB/噪声/LLM/降级各分支都汇到它。
            return clamp_transient_escalation(
                self._apply_new_pattern_escalation(verdict, metrics), self._cfg
            )
        except Exception as exc:  # 最后一道保险：看门狗不能因为判定层 bug 死掉
            self._stats["degraded"] += 1
            _log.warning("判定层异常，保守降级：%s: %s", type(exc).__name__, exc)
            floor = severity_max(
                Severity.parse(
                    cfg_first(
                        self._cfg,
                        "fallback_severity",
                        "default_severity",
                        default="MEDIUM",
                    )
                ),
                Severity.MEDIUM,
            )
            return ThreatVerdict(
                severity=floor,
                confidence=0.0,
                tags=["classify-error", "local-mode"],
                component="unknown",
                fingerprint="",
                is_new_pattern=False,
                evidence="",
                reason=(
                    f"判定层异常（{type(exc).__name__}: {exc}），保守降级为 {floor.value}；"
                    "该指纹不写知识库，避免污染后续判定"
                ),
                route=route_for_severity(floor, cfg_get(self._cfg, "route_map", None)),
                source="degraded",
            )

    async def _classify(
        self, block: LogBlock, metrics: Mapping | None = None
    ) -> ThreatVerdict:
        """判定主流程：知识库短路 → 噪声短路 → LLM → 安全闸 → 落库。"""
        cfg = self._cfg
        local = classify_block(block, metrics, cfg)

        if not _bool_cfg(cfg, "classify_enable", True):
            # F15：分级总开关关闭 ⇒ 直接按等级触发（不查 KB、不调 LLM）；
            # §5.1 第 4 行：本地结论**要写知识库**（source=local），否则 V1 的
            # 「跑一轮后 pattern_kb 行数 > 0」在关闭分级时永远不成立
            self._stats["local"] += 1
            verdict = replace(
                local,
                tags=[*local.tags, "classify-disabled"],
                reason=local.reason + "；classify_enable=false，跳过知识库与 LLM 判定",
            )
            self._remember(verdict, source=LOCAL_SOURCE)
            return verdict

        entry = self._kb_lookup(local.fingerprint)
        if entry is not None:
            manual = str(entry.get("source") or "") == MANUAL_SOURCE
            self._stats["manual_hits" if manual else "kb_hits"] += 1
            self._touch(entry)
            return self._verdict_from_entry(entry, local)

        mode = self._mode()
        provider_id = self._provider_id()
        if not self._llm_wanted(mode) or not provider_id or self._context is None:
            self._stats["local"] += 1
            verdict = local
            if self._llm_wanted(mode):
                verdict = replace(
                    local,
                    tags=[*local.tags, "llm-unconfigured"],
                    reason=local.reason
                    + f"；模式 {mode} 需要 LLM，但未配置可用的 provider/context，退到本地模式",
                )
            # §5.1 第 4 行：本地模式结论同样写知识库（V1：跑一轮后 pattern_kb 必须非空）
            self._remember(verdict, source=LOCAL_SOURCE)
            return verdict

        if bool(cfg_get(cfg, "noise_shortcut", True)) and is_benign_noise(block):
            self._stats["noise_shortcut"] += 1
            verdict = replace(
                local,
                tags=[*local.tags, "noise-shortcut"],
                reason=local.reason + "；命中已知良性噪声规则，短路返回（不调用 LLM）",
            )
            self._remember(verdict, source=NOISE_SOURCE)
            return verdict

        allowed, budget_reason = self._llm_budget_allows()
        if not allowed:
            # F04：预算用尽 ⇒ 本块走本地规则（先过闸再调 LLM，绝不「先花 token 再判」）
            self._stats["llm_budget_skipped"] += 1
            self._stats["local"] += 1
            _log.warning(
                "LLM 预算用尽（%s），本块走本地规则；指纹 %s",
                budget_reason,
                local.fingerprint[:12],
            )
            return replace(
                local,
                tags=[*local.tags, "llm-budget", f"llm-budget:{budget_reason}"],
                reason=local.reason + f"；LLM 预算用尽（{budget_reason}），本块未调用 LLM",
            )

        timeout = self._timeout()
        try:
            prompt = build_classification_prompt(block, metrics, cfg, local=local)
            self._note_llm_call()
            text = await asyncio.wait_for(
                self._call_llm(provider_id, prompt), timeout=timeout
            )
        except asyncio.TimeoutError:
            self._stats["degraded"] += 1
            _log.warning(
                "LLM 判定超时（>%gs），保守降级；指纹 %s",
                timeout,
                local.fingerprint[:12],
            )
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"调用超过 {timeout:g}s 未返回",
                tag="llm-timeout",
                local=local,
            )
        except Exception as exc:  # 网络/协议/provider 内部错误一律隔离
            self._stats["degraded"] += 1
            _log.warning("LLM 判定异常，保守降级：%s: %s", type(exc).__name__, exc)
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"{type(exc).__name__}: {exc}",
                tag="llm-error",
                local=local,
            )

        try:
            verdict = parse_llm_verdict(text, block, metrics, cfg, local=local)
        except LLMOutputError as exc:
            self._stats["degraded"] += 1
            _log.warning("LLM 输出非法，保守降级：%s", exc)
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"输出非法：{exc}",
                tag="llm-invalid-output",
                local=local,
            )
        except Exception as exc:  # 解析层的意外同样不得打穿主循环
            self._stats["degraded"] += 1
            _log.warning("LLM 输出解析异常，保守降级：%s: %s", type(exc).__name__, exc)
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"{type(exc).__name__}: {exc}",
                tag="llm-invalid-output",
                local=local,
            )

        try:
            guarded = apply_safety_guards(verdict, block, metrics, cfg, local=local)
        except Exception as exc:  # 安全闸本身出问题也不能把不安全的结论放出去
            self._stats["degraded"] += 1
            _log.warning("安全闸执行异常，保守降级：%s: %s", type(exc).__name__, exc)
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"安全闸执行异常 {type(exc).__name__}: {exc}",
                tag="guard-error",
                local=local,
            )
        if guarded is not verdict:
            self._stats["guarded"] += 1
            _log.warning(
                "安全闸修正了 LLM 判定：%s -> %s",
                verdict.severity.value,
                guarded.severity.value,
            )
        self._remember(guarded, source=LLM_SOURCE)
        return guarded

    async def _call_llm(self, provider_id: str, prompt: str) -> str:
        """调用 ``Context.llm_generate``（显式传 ``chat_provider_id``）并取回纯文本。

        Args:
            provider_id: 聊天 provider id，必须由配置显式指定。
            prompt: 用户提示词。

        Returns:
            模型输出的纯文本。
        """
        self._stats["llm_calls"] += 1
        response = await self._context.llm_generate(  # type: ignore[attr-defined]
            chat_provider_id=provider_id,
            prompt=prompt,
            system_prompt=self._system_prompt,
        )
        text = getattr(response, "completion_text", None)
        return text if isinstance(text, str) else str(response)

    def _mode(self) -> str:
        """取分级模式（``classify_mode`` / ``mode``，默认 auto）。"""
        raw = cfg_first(self._cfg, "classify_mode", "mode", default="auto")
        return str(raw).strip().lower() or "auto"

    @staticmethod
    def _llm_wanted(mode: str) -> bool:
        """模式是否需要 LLM：llm=必须，auto=有 provider 就调用，local 及未知值都不调用。"""
        return mode in ("llm", "auto")

    def _provider_id(self) -> str:
        """取配置里的 provider id。

        兼容插件 schema 的 ``classify_provider_id``、内部短名 ``provider_id`` 与
        SDK 术语 ``llm_provider_id`` / ``chat_provider_id``——键名不一致会让 LLM 判定
        被静默跳过，属本项目最忌讳的失效面。
        """
        raw = cfg_first(
            self._cfg,
            "llm_provider_id",
            "chat_provider_id",
            "provider_id",
            "classify_provider_id",
            default="",
        )
        return str(raw).strip()

    def _timeout(self) -> float:
        """取 LLM 超时秒数（默认 30s，夹在 [0.05, 600] 内）。"""
        try:
            value = float(
                cfg_first(
                    self._cfg,
                    "llm_timeout",
                    "timeout",
                    "classify_timeout_seconds",
                    default=_DEFAULT_LLM_TIMEOUT,
                )
            )
        except (TypeError, ValueError):
            value = _DEFAULT_LLM_TIMEOUT
        return min(_MAX_LLM_TIMEOUT, max(_MIN_LLM_TIMEOUT, value))

    def _kb_lookup(self, fingerprint: str) -> Mapping[str, Any] | None:
        """读知识库（异常隔离：知识库坏了也不影响判定）。"""
        if not self._kb_active or not fingerprint:
            return None
        try:
            return self._kb.get(fingerprint)
        except Exception as exc:
            _log.warning(
                "指纹知识库读取失败（忽略并继续）：%s: %s", type(exc).__name__, exc
            )
            return None

    def _remember(self, verdict: ThreatVerdict, *, source: str) -> None:
        """把结论写回知识库（异常隔离）。"""
        if not self._kb_active:
            return
        try:
            self._kb.put(
                {
                    "fingerprint": verdict.fingerprint,
                    "severity": verdict.severity.value,
                    "confidence": verdict.confidence,
                    "tags": list(verdict.tags),
                    "component": verdict.component,
                    "reason": verdict.reason,
                    "source": source,
                    "hits": 1,
                    "updated_at": time.time(),
                }
            )
        except Exception as exc:
            _log.warning(
                "指纹知识库写入失败（忽略并继续）：%s: %s", type(exc).__name__, exc
            )

    def _touch(self, entry: Mapping[str, Any]) -> None:
        """命中次数 +1（保留原 source，人工覆写不会被降级成自动结果）。"""
        if not self._kb_active:
            return
        try:
            updated = dict(entry)
            updated["hits"] = int(entry.get("hits", 0) or 0) + 1
            updated["updated_at"] = time.time()
            self._kb.put(updated)
        except Exception as exc:
            _log.warning(
                "指纹命中计数失败（忽略并继续）：%s: %s", type(exc).__name__, exc
            )

    def _verdict_from_entry(
        self, entry: Mapping[str, Any], local: ThreatVerdict
    ) -> ThreatVerdict:
        """把知识库条目还原成结论（``evidence`` 用本次片段的实时摘录）。"""
        source = str(entry.get("source") or "kb")
        manual = source == MANUAL_SOURCE
        severity = Severity.parse(entry.get("severity"), local.severity)
        try:
            confidence = min(1.0, max(0.0, float(entry.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        raw_tags = entry.get("tags") or []
        tags = [
            str(tag)
            for tag in (raw_tags if isinstance(raw_tags, (list, tuple)) else [raw_tags])
        ]
        tags.append("manual-override" if manual else f"kb-hit:{source}")
        entry_source = MANUAL_SOURCE if manual else "kb"
        try:
            hits = int(entry.get("hits", 0) or 0)
        except (TypeError, ValueError):
            hits = 0
        return ThreatVerdict(
            severity=severity,
            confidence=confidence,
            tags=tags,
            component=str(entry.get("component") or local.component),
            fingerprint=local.fingerprint,
            is_new_pattern=False,
            evidence=local.evidence,
            reason=(
                f"知识库命中（{'人工覆写' if manual else source}，已命中 {hits} 次）："
                f"{entry.get('reason') or '无历史理由'}；指纹 {local.fingerprint[:12]}"
            ),
            route=route_for_severity(severity, cfg_get(self._cfg, "route_map", None)),
            source=entry_source,
        )
