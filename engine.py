"""威胁分级引擎：本地判定、指纹知识库与 LLM 判定的编排（纯逻辑，不导入 astrbot）。

判定顺序（v2.3.0：**每条错误都必须经模型重新下结论**，知识库只当先验）：

1. 人工覆写：知识库里 ``source == "manual"`` 的指纹直接返回（唯一豁免），
   优先级最高，不会被任何自动结果覆盖，也不经过安全闸；
2. 批内复用（``begin_round()`` 之后、同一轮之内）：同一指纹在本轮已经真判过一次时
   复用那条结论，但 ``evidence`` 用本次片段重建 —— 同一批的同一指纹是**同一次观察**，
   这是唯一允许的判定去重；
3. 知识库先验：命中历史条目**不再 return**，只把条目作为「历史判定（仅供参考，可推翻）」
   注入提示词（``build_classification_prompt(prior=...)``）。历史结论不参与判决；
4. 显式 ``local`` 模式：本地规则给结论（``judged=False``），只作观测/先验写库；
5. 需要 LLM 但没有 provider/context：显式降级（``degraded:llm-unconfigured``），
   **不写库** —— 否则「没配 provider」的本地结论会被永久固化成历史先验；
6. 已知噪声短路只在 ``noise_shortcut=true``（默认 **false**）时生效，
   且结论标 ``judged=False``（不得伪装成模型判定）；
7. LLM 判定：``classify_mode`` 允许且 provider 可用时调用 ``Context.llm_generate``，
   输出经 :func:`classify.apply_safety_guards` 修正后写入知识库（``judged=True``）；
8. 预算用尽：**只延迟、不取消** —— 该指纹进待判队列，下一轮优先判定；本轮返回
   ``source="degraded"`` + ``degraded:llm-budget``（绝不静默用本地结论定案）；
9. 降级：LLM 超时/异常/输出非法/安全闸异常/未配置 provider 时返回 ``source="degraded"``，
   ``judged=False``，``judge_source="degraded"``，标签带 ``degraded:*`` 前缀。

知识库（``pattern_kb``）仍然保留：记录命中次数/最近出现，供统计、先验注入与去重使用；
它**不再是判决来源**。人工覆写与本地结论的写入语义不变；
降级结果、预算排队结果一律不写库（provider 抖动不该把某个指纹永久钉死）。
异常隔离：LLM 与知识库的任何异常都在本层吞掉并转成结构化结论，不影响调用方主循环。
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
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

_JUDGE_QUEUE_MAX = 500
"""待判队列长度上限（内存态；超出丢最旧，防止日志风暴把内存拖垮）。"""

DEFAULT_PRIOR_TTL_HOURS = 72
"""历史先验的保留期（``classify.prior_ttl_hours``；人工覆写永不过期）。"""

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

    v2.3.0：本接口**只**用于「记录 / 统计 / 先验 / 人工覆写」，
    :meth:`get` 的返回值**不得**直接变成判决结论。

    条目形状::

        {"fingerprint": str, "severity": str, "confidence": float, "tags": list[str],
         "component": str, "reason": str, "source": "manual"|"llm"|"local"|"local-noise",
         "hits": int, "updated_at": float,
         "last_judged_at": float, "judge_source": "llm"|"degraded"|"local"|"manual"|""}
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
            # 审计两列（v2.3.0 schema v3）：何时真判过、依据是什么
            "last_judged_at": float(row.get("last_judged_at") or 0.0),
            "judge_source": str(row.get("judge_source") or ""),
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
                ``kb_max_entries`` / ``prior_ttl_hours`` / ``noise_shortcut`` /
                ``llm_max_block_lines`` / ``llm_max_calls_per_round`` /
                ``llm_max_calls_per_hour`` / ``classify_system_prompt`` / ``route_map``。
                ``repeat_window_seconds`` 只由 main 的统计窗口消费（判定层不因它跳过模型）。
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
            #: 历史先验命中次数（知识库里有条目；只观测，**不再**是判决出口）
            "kb_hits": 0,
            #: 真正把历史条目注进提示词的次数
            "prior_injected": 0,
            "manual_hits": 0,
            "noise_shortcut": 0,
            "local": 0,
            "degraded": 0,
            "guarded": 0,
            "llm_budget_skipped": 0,
            #: 进入 LLM 路径（含随后超时/异常/非法输出而降级）的段数
            "llm_forced": 0,
            #: 完全没有尝试模型的段数（显式 local / 未配 provider / 噪声短路 / 预算排队 / 批内复用）
            "llm_skipped": 0,
            #: 同一轮内同指纹复用（唯一允许的判定去重；跨轮必重判）
            "batch_memo_hits": 0,
            #: 跨轮复用次数的留位（默认 0：v2.3.0 不提供跨轮复用开关）
            "judge_reused": 0,
        }
        # F04：LLM 调用预算（按轮 + 按小时）。预算用尽**只延迟判定**（进待判队列），
        # 不再把「没判」伪装成「已判」的本地结论。
        self._round_llm_calls = 0
        self._llm_call_times: list[float] = []
        #: 当前是否处于一轮扫描里（由 :meth:`begin_round` 开启）。只有一轮之内才允许
        #: 批内复用；调用方没开轮（例如单测直接 classify）时按「每次都是新一轮」处理。
        self._round_active = False
        #: 本轮已真判过的指纹 -> (结论, 时间)。跨轮由 begin_round 清空 ⇒ 跨轮必重判。
        self._round_memo: dict[str, tuple[ThreatVerdict, float]] = {}
        #: 因预算/小时窗没判成的指纹（FIFO，去重，有界），下一轮优先判定
        self._judge_queue: deque[str] = deque()
        #: 本轮享有「预算优先权」的指纹（上一轮排队的产物）
        self._priority: set[str] = set()
        self._round_snapshot: dict[str, int] = {}

    def begin_round(self) -> None:
        """每轮扫描开始前调用：清空批内复用 + 提升上一轮的待判队列。

        - 清空 ``_round_memo``：**同批同指纹只判一次，跨轮必重判**（TTL 复用被明确禁止）；
        - 把上一轮因预算排队下来的指纹提升为本轮优先判定（预算只延迟、不取消）。
        """
        self._round_llm_calls = 0
        self._round_active = True
        self._round_memo.clear()
        self._round_snapshot = dict(self._stats)
        self._promote_priority()

    def round_stats(self) -> dict[str, int]:
        """本轮增量计数器（供 main 每轮写一行审计 INFO：判了多少、复用多少、降级多少）。"""
        return {
            key: int(value) - int(self._round_snapshot.get(key, 0))
            for key, value in self._stats.items()
        }

    @property
    def deferred_judgements(self) -> int:
        """待判队列长度（预算排队中、下一轮优先判定的指纹数）。"""
        return len(self._judge_queue) + len(self._priority)

    def _promote_priority(self) -> None:
        """把待判队列提升为本轮优先集合（每次最多提升一轮预算的量，避免排队放大成本）。"""
        capacity = _int_cfg(
            self._cfg, "llm_max_calls_per_round", DEFAULT_LLM_MAX_CALLS_ROUND, 0, 1000
        )
        if capacity <= 0:
            capacity = DEFAULT_LLM_MAX_CALLS_ROUND
        self._priority = set()
        while self._judge_queue and len(self._priority) < capacity:
            self._priority.add(self._judge_queue.popleft())

    def _defer_judgement(self, fingerprint: str) -> None:
        """把「本轮没判成」的指纹放进待判队列（有界、去重；0 长度指纹不入队）。"""
        key = str(fingerprint or "").strip()
        if not key or key in self._judge_queue or key in self._priority:
            return
        if len(self._judge_queue) >= _JUDGE_QUEUE_MAX:
            self._judge_queue.popleft()
            _log.warning("待判队列已满（%d），丢弃最旧的一条排队指纹", _JUDGE_QUEUE_MAX)
        self._judge_queue.append(key)

    def _memo_get(self, fingerprint: str) -> ThreatVerdict | None:
        """取本轮早先那次真判的结论（只在轮内有效；跨轮由 begin_round 清空）。"""
        if not self._round_active or not fingerprint:
            return None
        item = self._round_memo.get(fingerprint)
        return item[0] if item is not None else None

    def _memo_put(self, fingerprint: str, verdict: ThreatVerdict, now: float) -> None:
        """记录本轮该指纹的结论（只记录真判成功的结论）。"""
        if not self._round_active or not fingerprint or not verdict.judged:
            return
        self._round_memo[fingerprint] = (verdict, now)

    @property
    def llm_calls(self) -> int:
        """累计 LLM 调用次数（观测用）。"""
        return int(self._stats["llm_calls"])

    def _llm_budget_allows(
        self, *, now: float | None = None, priority: bool = False
    ) -> tuple[bool, str]:
        """LLM 预算闸（F04）：**调用前**判定；超限的块进待判队列，不再本地定案。

        Args:
            now: 计时基准（测试注入）。
            priority: 该指纹是否享有本轮优先权（上一轮排队的产物）。优先指纹不受
                **轮**预算限制（它的额度本来就该在本轮兑现），但仍受**小时**预算约束。

        Returns:
            ``(是否允许调用, 拒绝原因)``；原因 ∈ {``round``, ``hour``}。
        """
        per_round = _int_cfg(self._cfg, "llm_max_calls_per_round", DEFAULT_LLM_MAX_CALLS_ROUND, 0, 1000)
        per_hour = _int_cfg(self._cfg, "llm_max_calls_per_hour", DEFAULT_LLM_MAX_CALLS_HOUR, 0, 100000)
        moment = time.time() if now is None else float(now)
        self._llm_call_times = [
            item for item in self._llm_call_times if moment - item < 3600.0
        ]
        if per_hour > 0 and len(self._llm_call_times) >= per_hour:
            return False, "hour"
        if not priority and per_round > 0 and self._round_llm_calls >= per_round:
            return False, "round"
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
                tags=["classify-error", "local-mode", "degraded:engine-error"],
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
                judged=False,
                judge_source="degraded",
            )

    async def _classify(
        self, block: LogBlock, metrics: Mapping | None = None
    ) -> ThreatVerdict:
        """判定主流程：人工覆写 → 批内复用 → 先验注入 → LLM → 安全闸 → 落库。

        v2.3.0 的铁律（逐行可查）：

        - **知识库命中不是出口**：命中只把条目作为 ``prior`` 注进提示词，结论必须由模型
          （或显式降级）给出；原来的 ``return _verdict_from_entry(...)`` 已删除；
        - **批内复用只在轮内**（``begin_round`` 清空），跨轮必重判；
        - **通知去重不影响判定**：``repeat_count`` / ``budget.dedupe_window_seconds`` 只决定
          「发不发」，本函数从不因为「最近通知过」而跳过模型调用；
        - **降级不写库、不冒充已判**：``source="degraded"`` + ``judged=False``。
        """
        cfg = self._cfg
        now = time.time()
        local = classify_block(block, metrics, cfg)
        fingerprint = local.fingerprint
        # 本轮是否享有「预算优先权」（上一轮排队的产物）。取完立刻用掉：无论后面走哪条
        # 分支，这条排队记录都算在本轮兑现，不会永远挂在 _priority 里。
        is_priority = fingerprint in self._priority
        self._priority.discard(fingerprint)

        if not _bool_cfg(cfg, "classify_enable", True):
            # F15：分级总开关关闭 ⇒ 直接按等级触发（不查 KB、不调 LLM）。
            # 本地结论仍写库（只作统计与先验；V1 的「跑一轮后 pattern_kb 非空」仍成立）。
            self._stats["local"] += 1
            self._stats["llm_skipped"] += 1
            verdict = replace(
                local,
                tags=[*local.tags, "classify-disabled", "judged-skipped"],
                reason=local.reason + "；classify_enable=false，跳过知识库与 LLM 判定",
                judged=False,
                judge_source="local",
            )
            self._remember(verdict, source=LOCAL_SOURCE)
            return verdict

        # ① 人工覆写是唯一豁免：它是人的决定，不是「历史自动结论」。
        prior = self._kb_lookup(fingerprint)
        if prior is not None and str(prior.get("source") or "") == MANUAL_SOURCE:
            self._stats["manual_hits"] += 1
            self._stats["llm_skipped"] += 1
            self._touch(prior)
            return replace(
                self._verdict_from_entry(prior, local),
                judged=False,
                judge_source="manual",
            )

        # ② 批内复用：同一轮里同一指纹只判一次（同一次观察）；跨轮由 begin_round 清空。
        memo = self._memo_get(fingerprint)
        if memo is not None:
            self._stats["batch_memo_hits"] += 1
            self._stats["llm_skipped"] += 1
            tags = list(memo.tags)
            if "batch-reused" not in tags:
                tags.append("batch-reused")
            return replace(
                memo,
                component=memo.component or local.component,
                fingerprint=fingerprint,
                evidence=local.evidence,
                tags=tags,
            )

        if prior is not None:
            # ③ 知识库命中：只当观测与先验，绝不当判决出口。
            self._stats["kb_hits"] += 1

        mode = self._mode()
        provider_id = self._provider_id()
        provider_is_default = False
        if not provider_id:
            # v2.3.1：留空 = 回落到 AstrBot 当前的对话模型（与 media_analysis 同口径）。
            # 每轮现取、不缓存 —— 运营方在 WebUI 换默认模型后，下一轮就跟着换。
            provider_id = self._default_provider_id()
            provider_is_default = bool(provider_id)

        if not self._llm_wanted(mode):
            # 显式 local 模式：用户选择不调模型。结论是本地判定（judged=False）。
            self._stats["local"] += 1
            self._stats["llm_skipped"] += 1
            verdict = replace(
                local,
                tags=[*local.tags, "local-judged", "judged-skipped"],
                reason=local.reason + f"；classify_mode={mode}（显式本地模式，未调用模型）",
                judged=False,
                judge_source="local",
            )
            self._remember(verdict, source=LOCAL_SOURCE)
            return verdict

        if not provider_id or self._context is None:
            # C4（真缺陷）：需要 LLM 但没有 provider/context ⇒ 显式降级，**不写库**。
            # 否则这条本地结论会被永久固化成历史先验，等 provider 配好也不会被重判。
            self._stats["degraded"] += 1
            self._stats["llm_skipped"] += 1
            missing = (
                "未配置 provider_id，且取不到 AstrBot 当前的对话模型"
                if self._context is not None
                else "没有可用的 Context"
            )
            _log.warning(
                "模式 %s 需要 LLM，但%s；本块降级且不写知识库（指纹 %s）",
                mode,
                missing,
                fingerprint[:12],
            )
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=f"模式 {mode} 需要 LLM，但{missing}",
                tag="llm-unconfigured",
                local=local,
            )

        if _bool_cfg(cfg, "noise_shortcut", False) and is_benign_noise(block):
            # C2：零成本短路必须由运营方显式打开（默认 false），且不得伪装成模型判定。
            self._stats["noise_shortcut"] += 1
            self._stats["llm_skipped"] += 1
            verdict = replace(
                local,
                tags=[*local.tags, "noise-shortcut", "judged-skipped"],
                reason=local.reason
                + "；命中已知良性噪声规则，短路返回（noise_shortcut=true，未调用模型）",
                judged=False,
                judge_source="local",
            )
            self._remember(verdict, source=NOISE_SOURCE)
            return verdict

        self._stats["llm_forced"] += 1
        allowed, budget_reason = self._llm_budget_allows(priority=is_priority)
        if not allowed:
            # F04（v2.3.0 语义）：预算只延迟判定，不取消判定 —— 排队 + 显式降级，
            # 绝不用本地结论「看起来像已判」地定案。
            self._stats["llm_budget_skipped"] += 1
            self._stats["degraded"] += 1
            self._stats["llm_skipped"] += 1
            self._defer_judgement(fingerprint)
            _log.warning(
                "LLM 预算用尽（%s），本块已排队到下一轮优先判定；指纹 %s（待判队列 %d）",
                budget_reason,
                fingerprint[:12],
                self.deferred_judgements,
            )
            return degraded_verdict(
                block,
                metrics,
                cfg,
                error=(
                    f"LLM 预算用尽（{budget_reason}），本块已排队到下一轮优先判定"
                    "（预算只延迟判定，不取消判定）"
                ),
                tag="llm-budget",
                local=local,
                extra_tags=[f"llm-budget:{budget_reason}", "judged-deferred"],
            )
        timeout = self._timeout()
        try:
            prompt = build_classification_prompt(
                block, metrics, cfg, local=local, prior=prior
            )
            if prior is not None:
                self._stats["prior_injected"] += 1
            self._note_llm_call(now=now)
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
            verdict = parse_llm_verdict(text, block, metrics, cfg, local=local, prior=prior)
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
        if provider_is_default:
            # 让台账与报告能看出「这次用的不是运营方手选的模型」，换默认模型时便于回溯。
            guarded = replace(
                guarded, tags=[*guarded.tags, "provider:default-fallback"]
            )
        if guarded is not verdict:
            self._stats["guarded"] += 1
            _log.warning(
                "安全闸修正了 LLM 判定：%s -> %s",
                verdict.severity.value,
                guarded.severity.value,
            )
        self._remember(guarded, source=LLM_SOURCE)
        self._memo_put(guarded.fingerprint, guarded, now)
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

    def _default_provider_id(self) -> str:
        """回落：取 AstrBot 当前对话 provider 的 id（``classify.provider_id`` 留空时用）。

        与 ``astrbot_plugin_media_analysis`` 同口径：只问核心「现在用哪个对话模型」，
        不猜、不缓存、不写配置 —— 运营方在 WebUI 换默认模型后，下一轮自动跟随。

        Returns:
            provider id；取不到（无 context / 未设置 / 类型不符 / 无 id）时返回空串，
            由调用方按「未配置」显式降级。
        """
        if self._context is None:
            return ""
        getter = getattr(self._context, "get_using_provider", None)
        if not callable(getter):
            return ""
        try:
            provider = getter()
        except Exception as exc:  # 核心对类型不符会抛 ValueError；一律按取不到处理
            _log.warning(
                "读取 AstrBot 当前对话模型失败，按未配置处理：%s: %s",
                type(exc).__name__,
                exc,
            )
            return ""
        config = getattr(provider, "provider_config", None)
        if isinstance(config, dict):
            value = config.get("id")
            if isinstance(value, str):
                return value.strip()
        return ""

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
        """读知识库先验（异常隔离：知识库坏了也不影响判定）。

        v2.3.0：返回值**只用于两件事** —— 人工覆写豁免、历史先验注入提示词；
        它不再是判决出口。超过 ``classify.prior_ttl_hours`` 的自动条目不再当先验
        （人工覆写永不过期）。
        """
        if not self._kb_active or not fingerprint:
            return None
        try:
            entry = self._kb.get(fingerprint)
        except Exception as exc:
            _log.warning(
                "指纹知识库读取失败（忽略并继续）：%s: %s", type(exc).__name__, exc
            )
            return None
        if entry is None:
            return None
        if str(entry.get("source") or "") == MANUAL_SOURCE:
            return entry
        try:
            seen = float(entry.get("updated_at") or 0.0)
        except (TypeError, ValueError):
            seen = 0.0
        ttl = _int_cfg(self._cfg, "prior_ttl_hours", DEFAULT_PRIOR_TTL_HOURS, 1, 720) * 3600
        if seen > 0 and time.time() - seen > ttl:
            return None  # 先验过期：不作提示，也不作判决（判决本来就不看它）
        return entry

    def _remember(self, verdict: ThreatVerdict, *, source: str) -> None:
        """把结论写回知识库（异常隔离；只作统计/先验，不再是判决来源）。"""
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
                    # 审计两列（v2.3.0）：真判时间与依据；非模型结论不写判时间
                    "last_judged_at": time.time() if verdict.judged else 0.0,
                    "judge_source": verdict.judge_source or source,
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
        """把**人工覆写**条目还原成结论（``evidence`` 用本次片段的实时摘录）。

        v2.3.0：自动条目（``source=llm`` / ``local`` / ``local-noise``）**不再**走本函数
        —— 它们只作先验。非 manual 条目传进来时直接返回本地结论，避免「历史自动结论
        被当成判决」的老病灶从别的调用点绕回来。
        """
        if str(entry.get("source") or "") != MANUAL_SOURCE:
            return local
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
        tags.append("manual-override")
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
                f"人工覆写（已命中 {hits} 次）："
                f"{entry.get('reason') or '无人工理由'}；指纹 {local.fingerprint[:12]}"
            ),
            route=route_for_severity(severity, cfg_get(self._cfg, "route_map", None)),
            source=MANUAL_SOURCE,
            judged=False,
            judge_source="manual",
        )
