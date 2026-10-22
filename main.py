"""log_watcher：定期扫描 AstrBot 日志目录，命中指定等级时按通道能力主动告警。

运行时入口在本文件，纯逻辑在同目录的 log_reader / detect / deliver / classify /
engine / models / store（这些模块不导入 astrbot，可离线单测）。本文件只做四件事：

1. 编排：定时扫描 → 增量读取 → 检测 → 分级（engine.ThreatEngine，R3）→ 闸门 → 投递 → 落盘；
2. 唯一发送者：所有消息都经 `_send_plan()` 发出，段型按通道能力挑（weixin_oc 只发纯文本，
   绝不发附件段，避免 `failed to send N message segment(s)` 把整条告警一起带走）；
3. 不丢告警：投递失败进 PendingQueue（SQLite 优先，库坏了退内存态）退避重试，重试发降级文本，
   耗尽后留档 `abandoned` 并计数，且在下一条成功消息里回执「历史未送达 N 条」（R8）；
4. 状态与纪律：SQLite 每轮单事务批量落库（`asyncio.to_thread`），读走内存缓存（R11/§9.4）。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Node, Nodes, Plain
from astrbot.api.star import Context, Star, StarTools

from . import config_map, deliver, detect, store
from .log_reader import block_lines, new_lines, normalize_levels, render_lines
from .models import (
    DeliveryOutcome,
    LogBlock,
    Route,
    SendPlan,
    Severity,
    ThreatVerdict,
)

PLUGIN_NAME = "log_watcher"
_STATE_DB = "log_watcher.sqlite3"
_FORWARD_NAME = "AstrBot 日志"
_FORWARD_UIN = "10001"
# 单条合并转发最多带多少个节点：节点过多协议端容易组装失败，超了就退回文本分片
_MAX_FORWARD_NODES = 20

_MIN_POLL_SECONDS = 5
_MAX_POLL_SECONDS = 24 * 3600
_MAX_CONTEXT_LINES = 200
_MAX_LINES_PER_POLL = 5000
_MAX_CHARS_PER_MESSAGE = 8000
_MAX_EXCERPT_CHARS = 20000
_MISSING_NOTICE_INTERVAL = 600.0
_DISK_REPORT_MIN_INTERVAL = 3600.0
_CHECKPOINT_INTERVAL = 24 * 3600.0


def _as_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _degraded_text(text: str, limit: int = 320) -> str:
    """重试时的降级文本：只保留摘要头，尽量提高送达概率。"""
    head = str(text or "").strip()
    if len(head) <= limit:
        return head
    return head[:limit].rstrip() + "\n…（降级重试：完整摘录见日志目录）"


class LogWatcherPlugin(Star):
    """日志目录监听 + 按通道能力告警（文本/合并转发，失败退避重试）。"""

    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        self.config = config or {}
        # 配置访问层：v2.2.0 起配置按组分块（见 _conf_schema.json），以点号路径读取；
        # 嵌套缺失时回退旧扁平键（命中会打一条 WARNING 提示迁移），再回退默认值。
        # 键名映射的唯一事实源是 config_map.KEY_MAP（加键时必须同步 schema / KEY_MAP / 这里）。
        self.cfg = config_map.ConfigView(self.config)

        try:
            self.data_dir = Path(StarTools.get_data_dir(PLUGIN_NAME))
        except Exception as exc:
            self.data_dir = Path(os.getcwd()) / "data" / "plugin_data" / PLUGIN_NAME
            logger.warning(f"StarTools.get_data_dir 不可用，回退到 {self.data_dir}: {exc}")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 状态：SQLite 优先（R11），打不开则内存态降级（§9.4 第 5 条）
        self.sqlite: store.SqliteStore | None = None
        self.tail = store.TailStateStore(self.data_dir / "tail_state.json")
        self.counters = store.CounterStore()
        self.pending = store.PendingQueue(self.data_dir / "pending.json")
        self.disk = store.DiskGovernor(
            self.data_dir,
            keep=_as_int(self.cfg.get("state.keep_excerpt_files", 50), 50, 1, 1000),
            max_age=float(
                _as_int(self.cfg.get("state.outbox_max_age_hours", 24), 24, 1, 720) * 3600
            ),
            max_bytes=_as_int(
                self.cfg.get("state.outbox_max_bytes", 32 * 1024 * 1024),
                32 * 1024 * 1024,
                1024 * 1024,
                1024 * 1024 * 1024,
            ),
        )
        self.gate = detect.NotifyGate(self.counters, self._gate_config())
        self.retry_policy = deliver.RetryPolicy(
            max_attempts=_as_int(self.cfg.get("delivery.max_attempts", 4), 4, 1, 20),
            base_delay=float(
                _as_int(self.cfg.get("delivery.base_delay_seconds", 5), 5, 1, 600)
            ),
        )

        self.engine = None
        self._classify_fn = None

        self._task: asyncio.Task | None = None
        self._detectors: dict[str, detect.Detector] = {}
        self._detector_signature: tuple | None = None
        self._round_excerpt: Path | None = None
        self._round_excerpt_text = ""
        self._round_alerts: list[dict] = []
        self._round_progress: list[dict] = []
        self._round_rates: list[tuple[str, float]] = []
        self._round_deltas: dict[str, int] = {}
        self._fingerprint_stats: dict[str, dict] = {}
        self._pending_stats: dict = {}
        #: 出口策略不合格时的停摆原因（空串＝正常）；见 _check_outlet_policy（Q8=b / Q15=b）
        self._config_blocked = ""
        self._missing_notice_at = 0.0
        self._disk_report_at = 0.0
        self._checkpoint_at = 0.0
        self._no_session_notice = False
        self._no_level_notice = False
        self._store_error_notified = False
        self._store_error = ""
        #: C5：engine 失效兜底只打一次 ERROR（避免每轮刷屏），但每次都要打标签
        self._engine_unavailable_logged = False

    # ---------- 生命周期 ----------

    async def initialize(self) -> None:
        self.sqlite = await asyncio.to_thread(self._open_store)
        await self._startup_maintenance()
        await self._hydrate_state()
        self.engine = self._build_engine()
        self.gate = detect.NotifyGate(self.counters, self._gate_config())
        backlog = self._pending_stats_value()
        caps = {session: self._caps_for(session).platform for session in self._sessions()}
        state = "SQLite" if self._store_ready() else "内存态（状态库不可用）"
        if self._store_ready() and not self._store_writable():
            state = "只读（状态库拒绝写入）"
        kb = getattr(self.engine, "kb", None)
        kb_state = type(kb).__name__ if kb is not None else "无"
        if self.sqlite is not None and self.sqlite.last_error:
            logger.error(f"{self._plat()}状态库异常：{self.sqlite.last_error}")
        self._check_outlet_policy()
        logger.info(
            f"{self._plat()}日志监听启动：目录 {self._log_dir()}，匹配 {self._pattern()}，"
            f"等级 {list(self._levels()) or '未配置'}，形态 {self._send_mode()}，"
            f"间隔 {self._interval()}s，会话 {len(self._sessions())} 条"
            f"（{'/'.join(sorted({str(item) for item in caps.values()})) or '未配置'}）；"
            f"状态 {state}，分级 {self._classify_mode()}"
            f"（provider {'已配置' if self._classify_provider_id() else '未配置'}），"
            f"知识库 {kb_state}；{self.disk.report()}"
        )
        if backlog.get("active") or backlog.get("abandoned"):
            logger.info(
                f"{self._plat()}待重试投递 {backlog.get('active', 0)} 条、已放弃 "
                f"{backlog.get('abandoned', 0)} 条（上次运行遗留）"
            )
        self._task = asyncio.create_task(self._loop())

    async def _startup_maintenance(self) -> None:
        """启动维护：孤儿 run 对账（F06）+ 既有落盘权限加固（F09）。"""
        if self.sqlite is not None and self.sqlite.available:
            try:
                reconciled = await asyncio.to_thread(
                    self.sqlite.reconcile_runs, grace_seconds=0.0
                )
            except Exception as exc:
                reconciled = 0
                logger.warning(f"{self._plat()}孤儿 run 对账失败（忽略并继续）: {exc!r}")
            if reconciled:
                logger.warning(
                    f"{self._plat()}启动对账：{reconciled} 条遗留的 running 历史记录标记为"
                    " aborted（v2.3.0 起不再写入该表，只做一次性对账）"
                )
        try:
            hardened = await asyncio.to_thread(store.harden_tree, self.data_dir)
        except Exception as exc:
            hardened = 0
            logger.warning(f"{self._plat()}落盘权限加固失败（忽略并继续）: {exc!r}")
        if hardened:
            logger.info(f"{self._plat()}已把 {hardened} 个数据文件/目录权限收窄到 0600/0700")

    async def terminate(self) -> None:
        task, self._task = self._task, None
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        await self._commit_round(time.time(), final=True)
        if self.sqlite is not None and self.sqlite.available:
            await asyncio.to_thread(self.sqlite.checkpoint, truncate=True)
            await asyncio.to_thread(self.sqlite.close)
        logger.info(f"{self._plat()}日志监听已停止；{self.disk.report()}")

    async def _loop(self) -> None:
        if self._config_blocked:
            # 停摆：不扫描、不投递（原因已在 initialize 里 ERROR ＋ 写进 CONFIG-INVALID.txt）
            logger.warning(f"{self._plat()}插件处于停摆状态，扫描线程不启动")
            return
        while True:
            try:
                await self._scan_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"{self._plat()}扫描日志失败: {type(exc).__name__}: {exc}")
            await asyncio.sleep(self._interval())

    def _check_outlet_policy(self) -> None:
        """Q8=b ＋ Q15=b：出口不足两条 ⇒ **加载但停摆**（不静默假装在工作）。

        为什么不是 raise：核心 loader 对**实例化**阶段的异常只保证"不再往下走"，插件失败在日志里
        不一定醒目；而"停摆 ＋ 在状态目录写一份 CONFIG-INVALID.txt"是运营方能在**自己会看的地方**
        留下的确定痕迹。配置合格后重启即恢复（合格时会把旧痕迹删掉，免得误导下一个人）。
        """
        self._config_blocked = ""
        sessions = self._sessions()
        marker = self.data_dir / "CONFIG-INVALID.txt"
        if deliver.has_redundant_outlets(sessions):
            if marker.exists():
                try:
                    marker.unlink()
                except OSError as exc:
                    logger.warning(f"{self._plat()}清理旧 CONFIG-INVALID.txt 失败: {exc!r}")
            return
        self._config_blocked = (
            f"notify.target_sessions 只有 {len(deliver.outlet_order(sessions))} 条出口，"
            "策略要求至少 2 条（主出口 ＋ 备用出口）"
        )
        try:
            marker.write_text(
                "# log_watcher 配置不合格：插件已停摆\n\n"
                f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"原因：{self._config_blocked}\n"
                "怎么恢复：把插件配置里的 `notify.target_sessions` 填成**至少两条**"
                "（第 1 条是主出口、第 2 条是备用出口：主出口失败时才投备用出口），保存后重启 AstrBot。\n"
                "为什么这么定：2026-10-18 运营方定案 —— 只有一个出口时，「通道坏了」与「一切正常」"
                "长得一模一样（历史上 81 条告警就这样躺在 abandoned 里，其中 9 条是 HIGH）。\n",
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning(f"{self._plat()}写 CONFIG-INVALID.txt 失败（仍然停摆）: {exc!r}")
        logger.error(
            f"{self._plat()}{self._config_blocked} ⇒ **插件停摆**：不扫描、不投递；"
            f"填够两条并重启即恢复（详见 {marker}）"
        )

    def _open_store(self) -> store.SqliteStore | None:
        """打开状态库；失败返回 None 并进入内存态降级。"""
        configured = str(self.cfg.get("state.db_path") or "").strip()
        path = (
            Path(os.path.expanduser(configured))
            if configured
            else self.data_dir / _STATE_DB
        )
        try:
            return store.SqliteStore(path).open()
        except Exception as exc:  # 兜底：store 内部已尽量不抛，这里再保一层
            logger.error(f"{self._plat()}打开状态库失败，改用内存态: {exc!r}")
            return None

    async def _hydrate_state(self) -> None:
        """从状态库恢复进度/计数/待发（读一次，进程内走缓存）。"""
        if not self._store_ready():
            # 内存态降级：读旧 JSON（若存在），保证重启后至少不漏掉待发
            self.tail.load()
            self.counters.load()
            self.pending.load()
            return
        progress = await asyncio.to_thread(self.sqlite.progress)
        self.tail.import_rows(progress)
        state = await asyncio.to_thread(self.sqlite.meta_get, "counters_state", None)
        if isinstance(state, Mapping) and state:
            self.counters.import_state(state)
        else:
            legacy = await asyncio.to_thread(self.sqlite.counters)
            if legacy:
                self.counters.import_state(legacy)

    def _store_ready(self) -> bool:
        """状态库是否可用（连接是否建立）。"""
        return bool(self.sqlite is not None and self.sqlite.available)

    def _store_writable(self) -> bool:
        """状态库是否**可写**（F08）。

        只读库（版本过高降级 / 权限只读 / 磁盘满）下 ``SqliteStore._write`` 会静默返回
        默认值，去重/预算/速率这些持久状态全部退化成空操作 —— 所以可写性是行为前提。
        """
        return bool(self.sqlite is not None and self.sqlite.writable)

    def _notice_store_error(self) -> None:
        """状态库错误变化时打一条 error（F08：不允许只在启动时打印一次）。"""
        if self.sqlite is None:
            return
        current = self.sqlite.last_error
        if current and current != self._store_error:
            self._store_error = current
            logger.error(f"{self._plat()}状态库错误：{current}")

    def _build_engine(self):
        """构造 ThreatEngine（R3）：优先接 SQLite 知识库，失败退回进程内 KB。"""
        try:
            from .engine import ThreatEngine
        except Exception as exc:
            logger.warning(f"{self._plat()}engine 模块不可用，分级退回本地规则: {exc!r}")
            return None
        kb = None
        if self._store_ready():
            try:
                from .engine import SqliteKnowledgeBase

                kb = SqliteKnowledgeBase(
                    self.sqlite,
                    max_entries=_as_int(
                        self.cfg.get("classify.kb_max_entries", 500), 500, 50, 100000
                    ),
                )
            except Exception as exc:
                logger.warning(f"{self._plat()}SQLite 知识库不可用，改用进程内 KB: {exc!r}")
        try:
            return ThreatEngine(self.context, cfg=self._engine_config(), kb=kb)
        except Exception as exc:
            logger.warning(f"{self._plat()}ThreatEngine 构造失败，分级退回本地规则: {exc!r}")
            return None

    # ---------- 扫描 ----------

    async def _scan_once(self) -> None:
        now = time.time()
        levels = self._levels()
        if not levels:
            if not self._no_level_notice:
                self._no_level_notice = True
                logger.warning(f"{self._plat()}未配置 scan.levels，日志扫描不会产生提醒")
            return
        self._no_level_notice = False
        self.counters.bump("rounds")
        self._bump_delta("rounds")
        self.gate.begin_round()
        begin_round = getattr(self.engine, "begin_round", None)
        if callable(begin_round):
            begin_round()  # F04：重置「每轮 LLM 调用数」
        self._notice_store_error()
        self._round_alerts.clear()
        self._round_progress.clear()
        self._round_rates.clear()
        self._round_excerpt = None
        self._round_excerpt_text = ""

        files = self._list_files()
        if not files:
            self._notice_missing_files()

        blocks: list[LogBlock] = []
        for path in files:
            key = str(path)
            detector = self._detector_for(key, levels)
            lines, state = new_lines(
                path, self.tail.get(key), skip_existing=self._skip_existing()
            )
            if state:
                # stat 失败时不写入空 state，否则下次会当成新文件重放
                self.tail.set(key, state)
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                self._round_progress.append(
                    {**state, "path": key, "size": size, "updated_at": now}
                )
            if not lines:
                blocks.extend(detector.flush())
                continue
            self.counters.bump("lines_read", len(lines))
            self._bump_delta("lines_read", len(lines))
            for line in lines:
                blocks.extend(detector.feed(line))

        if not files:
            # 文件全部消失时也要收尾，否则等后文的片段会被永久搁置
            for detector in self._detectors.values():
                blocks.extend(detector.flush())

        if blocks:
            await self._handle_blocks(blocks, now)
        await self._flush_aggregates(now)
        await self._retry_pending(now)
        self.counters.prune_fingerprints(now, self._fingerprint_ttl())
        self.counters.prune_windows(now)
        await self._commit_round(now)
        self._maybe_report_disk(now)

    def _detector_for(self, key: str, levels: tuple[str, ...]) -> detect.Detector:
        signature = (
            levels,
            self._before(),
            self._after(),
            tuple(self._exclude_keywords()),
            tuple(self._self_log_names()),
            tuple(self._self_echo_ids()),
        )
        if signature != self._detector_signature:
            self._detectors.clear()
            self._detector_signature = signature
        detector = self._detectors.get(key)
        if detector is None:
            detector = detect.Detector(
                levels,
                before=self._before(),
                after=self._after(),
                exclude_keywords=self._exclude_keywords(),
                source=key,
                self_names=self._self_log_names(),
                self_echo_ids=self._self_echo_ids(),
            )
            self._detectors[key] = detector
        return detector

    # ---------- 分级 → 闸门 → 告警留痕 ----------

    async def _handle_blocks(self, blocks: list[LogBlock], now: float) -> None:
        sessions = self._sessions()
        fingerprints = [detect.fingerprint(block) for block in blocks]
        hits = sum(block.hit_count for block in blocks)
        self.counters.bump("hits", hits)
        self._bump_delta("hits", hits)
        await self._refresh_fingerprint_stats(fingerprints, now)
        await self._refresh_pending_stats(now)
        await self._prime_knowledge_base(fingerprints)
        metrics = self._metrics(blocks, now, fingerprints=fingerprints)
        excerpt = self._render_excerpt(blocks)
        excerpt_lines = len(excerpt.splitlines()) if excerpt else 0
        excerpt_path = str(self._round_excerpt) if self._round_excerpt else ""

        sendable: list[tuple[LogBlock, ThreatVerdict]] = []
        for block, fallback_fp in zip(blocks, fingerprints):
            verdict = await self._classify(block, metrics)
            if not verdict.fingerprint:
                verdict.fingerprint = fallback_fp
            if verdict.source == "degraded":
                # 判定层降级必须留痕：engine 用的是 stdlib logger，不在 AstrBot 日志管道里，
                # 不在这里补一条就没有任何文件级痕迹（B14）。
                logger.warning(f"{self._plat()}判定降级：{verdict.reason}")
            decision = self.gate.decide(
                detect.AlertItem(
                    fingerprint=verdict.fingerprint,
                    severity=verdict.severity,
                    summary=self._summary_of(block),
                    session=sessions[0] if sessions else "",
                    ts=now,
                    tags=list(verdict.tags),
                ),
                now,
            )
            self.counters.bump_sub("decisions", decision.value)
            self._bump_delta(f"decisions.{decision.value}")
            self._record_alert(block, verdict, decision, now, excerpt_path, excerpt_lines)
            if decision is detect.NotifyDecision.SEND:
                sendable.append((block, verdict))
            elif decision is detect.NotifyDecision.DIGEST_BUFFER:
                logger.debug(f"{self._plat()}LOW 命中进入摘要聚合（{verdict.fingerprint}）")

        self._log_judge_summary(len(blocks))

        if sendable:
            if sessions:
                await self._deliver_round(sendable, excerpt, now)
            elif not self._no_session_notice:
                self._no_session_notice = True
                logger.warning(
                    f"{self._plat()}命中 {sum(b.hit_count for b, _ in sendable)} 条日志，"
                    "但未配置 notify.target_sessions，提醒被丢弃"
                )

    def _log_judge_summary(self, blocks: int) -> None:
        """每轮一行审计 INFO：判了几段、复用几段、降级几段、还有多少排队（§5.2）。

        这是「每条错误必过 LLM」与成本的唯一审计线：``llm_forced`` 是进入模型路径的段数，
        ``llm_calls`` 是实际发起的模型调用，``llm_skipped`` 是完全没尝试模型的段数。
        """
        summary = getattr(self.engine, "round_stats", None)
        if not callable(summary) or not blocks:
            return
        try:
            stats = summary()
        except Exception as exc:  # 汇总失败不得影响主循环
            logger.debug(f"{self._plat()}判定汇总失败（忽略）：{exc!r}")
            return
        logger.info(
            f"{self._plat()}本轮判定汇总：段 {blocks}，判定路径 {stats.get('llm_forced', 0)}"
            f"（模型调用 {stats.get('llm_calls', 0)}），批内复用 {stats.get('batch_memo_hits', 0)}，"
            f"降级 {stats.get('degraded', 0)}，未判 {stats.get('llm_skipped', 0)}，"
            f"待判队列 {getattr(self.engine, 'deferred_judgements', 0)}"
        )

    async def _classify(self, block: LogBlock, metrics: Mapping) -> ThreatVerdict:
        """分级：优先 engine.ThreatEngine.classify（R3，含 LLM 与降级链），失败回本地规则。

        C5（v2.3.0）：engine 构造失败 / 返回非 ``ThreatVerdict`` / 抛异常时的本地兜底
        **必须打标签** —— ``source="degraded"``、``degraded:engine-unavailable``、
        ``judged=False``，并打一次 ERROR。否则「每条错误必过 LLM」在 engine 起不来时
        会静默失效，而台账/报告看不出这条结论根本没问过模型。
        """
        if self.engine is not None:
            try:
                verdict = await self.engine.classify(block, metrics)
                if isinstance(verdict, ThreatVerdict):
                    return verdict
                return self._degraded_fallback(
                    block,
                    ThreatVerdict.from_dict(verdict),
                    reason="分级引擎返回了非 ThreatVerdict 的结论",
                )
            except Exception as exc:
                return self._degraded_fallback(
                    block,
                    None,
                    reason=f"分级引擎异常 {type(exc).__name__}: {exc}",
                )
        hook = self._classify_hook()
        if hook is not None:
            try:
                result = hook(block, metrics, self._engine_config())
                if isinstance(result, ThreatVerdict):
                    # classify 模块直接给了结论：它没有经过模型，同样按降级留痕
                    return self._degraded_fallback(block, result, reason="分级引擎不可用，走 classify 兜底")
                return self._degraded_fallback(
                    block,
                    ThreatVerdict.from_dict(result),
                    reason="classify 兜底返回了非 ThreatVerdict 的结论",
                )
            except Exception as exc:
                return self._degraded_fallback(
                    block,
                    None,
                    reason=f"classify 兜底异常 {type(exc).__name__}: {exc}",
                )
        return self._degraded_fallback(block, None, reason="分级引擎不可用且 classify 兜底缺失")

    def _degraded_fallback(
        self, block: LogBlock, verdict: ThreatVerdict | None, *, reason: str
    ) -> ThreatVerdict:
        """把「没有模型参与」的兜底结论统一成显式降级形态（C5）。"""
        base = verdict or detect.fallback_verdict(block, cfg=self._engine_config())
        if not base.fingerprint:
            base = replace(base, fingerprint=detect.fingerprint(block))
        tags = [*base.tags, "degraded:engine-unavailable", "judged-skipped"]
        if "engine-unavailable" not in tags:
            tags.append("engine-unavailable")
        if not self._engine_unavailable_logged:
            self._engine_unavailable_logged = True
            logger.error(
                f"{self._plat()}分级引擎不可用，已退到本地规则兜底（本次降级结论标 "
                f"degraded:engine-unavailable，不冒充模型判定）：{reason}"
            )
        else:
            logger.debug(f"{self._plat()}分级引擎仍不可用，继续本地兜底：{reason}")
        return ThreatVerdict(
            severity=base.severity,
            confidence=base.confidence,
            tags=tags,
            component=base.component,
            fingerprint=base.fingerprint,
            is_new_pattern=base.is_new_pattern,
            evidence=base.evidence,
            reason=f"{base.reason}；{reason}（本次未经模型判定）",
            route=base.route,
            source="degraded",
            judged=False,
            judge_source="degraded",
        )

    def _classify_hook(self):
        """classify.classify_block 的兜底入口（engine 不可用时才走）。"""
        if self._classify_fn is not None:
            return self._classify_fn
        try:
            from .classify import classify_block

            self._classify_fn = classify_block
        except Exception:
            self._classify_fn = None
        return self._classify_fn

    async def _refresh_fingerprint_stats(self, fingerprints: list[str], now: float) -> None:
        """每轮最多一次 `metrics_for` 聚合查询（§9.4 第 2 条）。

        v2.3.0（Q5=B）：``repeat_count`` 的统计窗口用 ``classify.repeat_window_seconds``；
        通知去重窗口仍是 ``budget.dedupe_window_seconds``。两者分开，**都不影响判不判**。
        """
        if not self._store_ready() or not fingerprints:
            self._fingerprint_stats = {}
            return
        window = self._repeat_window()
        self._fingerprint_stats = await asyncio.to_thread(
            self.sqlite.metrics_for, sorted(set(fingerprints)), window=window, now=now
        )

    async def _prime_knowledge_base(self, fingerprints: list[str]) -> None:
        """每轮把要判定的指纹批量装进 KB 缓存（V1/§9.4：事件循环里不查库）。"""
        kb = getattr(self.engine, "kb", None)
        prime = getattr(kb, "prime", None)
        if not callable(prime) or not fingerprints:
            return
        try:
            loaded = await asyncio.to_thread(prime, sorted(set(fingerprints)))
        except Exception as exc:
            logger.warning(f"{self._plat()}知识库预热失败（忽略并继续）: {exc!r}")
            return
        if loaded:
            logger.debug(f"{self._plat()}知识库预热 {loaded} 条指纹")

    async def _refresh_pending_stats(self, now: float) -> None:
        if self._store_ready():
            self._pending_stats = await asyncio.to_thread(self.sqlite.pending_stats, now)
        else:
            self._pending_stats = self.pending.stats(now)

    def _metrics(
        self, blocks: list[LogBlock], now: float, *, fingerprints: list[str] | None = None
    ) -> dict:
        """分级上下文（§6.1；G3：repeat_count 来自状态库，LLM 无权改）。"""
        if fingerprints is None:
            fingerprints = [detect.fingerprint(block) for block in blocks]
        repeat = 0
        seen: dict[str, int] = {}
        for fingerprint in fingerprints:
            repeat += int(
                self._fingerprint_stats.get(fingerprint, {}).get("repeat_count", 0)
            )
            seen[fingerprint] = seen.get(fingerprint, 0) + 1
            repeat += seen[fingerprint] - 1  # 同一批内同指纹累加
        pending = self._pending_stats or {}
        return {
            "blocks": len(blocks),
            "hits": sum(block.hit_count for block in blocks),
            "lines": sum(len(block.lines) for block in blocks),
            "levels": sorted({level for block in blocks for level in block.levels}),
            "repeat_count": repeat,
            "fingerprints": list(fingerprints),
            "counters": {
                "sent_hour": self.counters.window_count("sent_hour", now, 3600.0),
                "sent_day": self.counters.window_count("sent_day", now, 86400.0),
                "pending": int(pending.get("active", 0)),
                "abandoned": int(pending.get("abandoned", 0)),
            },
            "self_feedback": self._self_feedback_in(blocks),
        }

    def _self_feedback_in(self, blocks: list[LogBlock]) -> bool:
        """本轮命中片段里是否出现「本插件自己发送失败」的回声（F07）。"""
        echo_ids = self._self_echo_ids()
        if not echo_ids:
            return False
        for block in blocks:
            for line in block.lines:
                if detect.is_self_feedback_line(line, echo_ids):
                    return True
        return False

    def _summary_of(self, block: LogBlock) -> str:
        if block.hit_indices and block.hit_indices[0] < len(block.lines):
            return detect.normalize_for_fingerprint(block.lines[block.hit_indices[0]])[:300]
        return ""

    def _record_alert(
        self,
        block: LogBlock,
        verdict: ThreatVerdict,
        decision: detect.NotifyDecision,
        now: float,
        excerpt_path: str,
        excerpt_lines: int,
    ) -> None:
        """R6：每一条被抑制/聚合/放行的命中都留痕（计数器 + 入库）。"""
        self._round_alerts.append(
            {
                "ts": now,
                "fingerprint": verdict.fingerprint,
                "severity": verdict.severity.value,
                "route": verdict.route.value,
                "decision": decision.value,
                "component": verdict.component,
                "session": (self._sessions() or [""])[0],
                "tags": list(verdict.tags),
                "summary": self._summary_of(block),
                "source_file": block.source,
                "hit_count": block.hit_count,
                "excerpt_path": excerpt_path,
                "excerpt_lines": excerpt_lines,
                # v2.3.0 审计列：台账直接回答「这条结论有没有过模型」，
                # 不再靠 tags 里混写的 llm / local:* 反推（AGENTS.md §4 的误读教训）。
                "judged": 1 if verdict.judged else 0,
                "judge_source": verdict.judge_source or "",
            }
        )

    # ---------- 投递 ----------

    def _render_excerpt(self, blocks: list[LogBlock]) -> str:
        text = "\n\n".join(render_lines(block_lines(block)) for block in blocks)
        limit = self._max_lines_per_poll()
        lines = text.split("\n")
        if len(lines) > limit:
            text = "\n".join(lines[:limit]) + f"\n…（本轮另有 {len(lines) - limit} 行未展开）"
        if len(text) > _MAX_EXCERPT_CHARS:
            text = text[: _MAX_EXCERPT_CHARS] + "\n…（摘录过长已截断）"
        self._round_excerpt_text = text
        if self._excerpt_mode() == "off":
            self._round_excerpt = None
            return text
        try:
            self._round_excerpt = self.disk.write_excerpt(text)
        except OSError as exc:
            self._round_excerpt = None
            logger.warning(f"{self._plat()}写摘录存档失败（不影响发送）: {exc!r}")
        return text

    async def _deliver_round(
        self, sendable: list[tuple[LogBlock, ThreatVerdict]], excerpt: str, now: float
    ) -> None:
        verdict = max(
            (item[1] for item in sendable),
            key=lambda item: detect.severity_rank(item.severity),
        )
        block = next(item[0] for item in sendable if item[1] is verdict)
        hits = sum(block.hit_count for block, _ in sendable)
        backlog = self._pending_stats or {}
        note = ""
        # Q14=c：在下一条成功消息的尾部把账报清楚。口径是**最近一个窗口**（默认 24h），不是终身 ——
        # 终身计数会把 2026-10-14~18 那 81 条历史债永远挂在每条消息尾部（实测：终身 81 / 24h 内 6）。
        if backlog.get("recent_active") or backlog.get("recent_abandoned"):
            counts = []
            if backlog.get("recent_active"):
                counts.append(f"待重试 {backlog.get('recent_active', 0)} 条")
            if backlog.get("recent_abandoned"):
                counts.append(f"已放弃 {backlog.get('recent_abandoned', 0)} 条")
            extra = []
            worst = str(backlog.get("recent_max_severity") or "")
            age = float(backlog.get("recent_oldest_age") or 0.0)
            if worst:
                extra.append(f"最高 {worst} 级")
            if age:
                extra.append(f"最早 {age / 3600:.1f} 小时前")
            tail = f"（{'，'.join(extra)}）" if extra else ""
            note = (
                f"最近 {backlog.get('window_hours', 24):g} 小时未送达："
                f"{'、'.join(counts)}{tail}（见 plugin_data/{PLUGIN_NAME}）"
            )
        all_ok, outcomes, planned = await self._deliver_outlets(
            lambda session: deliver.build_send_plan(
                verdict,
                self._deliver_config(),
                session,
                block=block,
                excerpt=excerpt,
                caps=self._caps_for(session),
                extra_note=note,
            ),
            "日志提醒",
        )
        ok_sessions = {item.session for item in outcomes if item.ok}
        for session, plan in planned:
            # 降级提示无论成败都要可见：失败轮次的操作者更需要知道发的是降级形态
            for hint in plan.degradation:
                if session in ok_sessions:
                    logger.info(f"{self._plat(session)}投递提示：{hint}")
                else:
                    logger.warning(f"{self._plat(session)}投递提示（本轮失败）：{hint}")
        if not outcomes:
            # 所有出口这轮都不发（计划为空）：不算失败，也不清摘录存档
            all_ok = True
        elif all_ok:
            self.counters.bump("delivery_ok")
            self._bump_delta("delivery_ok")
        else:
            self.counters.bump("delivery_failed")
            self._bump_delta("delivery_failed")
            session, plan = planned[0]
            await self._enqueue_failure(session, plan, verdict, outcomes[-1], now)
        logger.info(
            f"{self._plat()}命中 {hits} 条日志（{len(sendable)} 段），"
            f"出口 {len(self._sessions())} 个（尝试 {len(outcomes)} 次），"
            f"成功：{'是' if all_ok else '否'}"
        )
        if all_ok and self._round_excerpt is not None and self._excerpt_mode() != "file":
            # ledger_only：成功即回收（成功残留不留垃圾）；file 模式保留给人工取证
            self.disk.release(self._round_excerpt)
            self._round_excerpt = None

    async def _send_plan(self, session: str, plan: SendPlan) -> DeliveryOutcome:
        """按计划投递：文本分片逐条发，转发形态组装一条 Nodes；返回结果不抛异常。"""
        outcome = DeliveryOutcome(session=session, attempts=1)
        chunks = [chunk for chunk in plan.chunks if str(chunk).strip()]
        if not chunks:
            outcome.error = "没有非空片段，放弃发送（避免空节点）"
            return outcome
        try:
            if plan.kind == "forward" and len(chunks) <= _MAX_FORWARD_NODES:
                chain = MessageChain(
                    chain=[
                        Nodes(
                            nodes=[
                                Node(
                                    uin=_FORWARD_UIN,
                                    name=_FORWARD_NAME,
                                    content=[Plain(chunk)],
                                )
                                for chunk in chunks
                            ]
                        )
                    ]
                )
                if not await self.context.send_message(session, chain):
                    outcome.error = f"找不到会话 {deliver.mask_session(session)} 对应的平台"
                    return outcome
            else:
                if plan.kind == "forward":
                    logger.warning(
                        f"{self._plat(session)}合并转发节点数 {len(chunks)} 超限，"
                        "退回文本分片发送"
                    )
                for chunk in chunks:
                    sent = await self.context.send_message(
                        session, MessageChain(chain=[Plain(chunk)])
                    )
                    if not sent:
                        outcome.error = f"找不到会话 {deliver.mask_session(session)} 对应的平台"
                        return outcome
        except Exception as exc:
            outcome.error = f"{type(exc).__name__}: {exc}"
            return outcome
        outcome.ok = True
        return outcome

    async def _deliver_outlets(self, build_plan, label: str):
        """按出口顺序投递（2026-10-18 定案）：主出口成功即停，失败才走备用出口；
        每个出口最多 ``delivery.max_attempts`` 次尝试（默认 2 = 初投 + 1 次重试）。

        与旧行为的差别（为什么改）：从前是「每个目标都发一遍、各自失败各自进重试队列」——
        两个出口都通时你会**两处都收到**（重复打扰），出口死掉时又各自堆 ``abandoned``。
        现在**列表即优先级**，第一个成功就停。

        Args:
            build_plan: ``(session) -> SendPlan``。
            label: 日志里的业务名（如「日志提醒」）。

        Returns:
            :func:`deliver.deliver_over_outlets` 的三元组。
        """
        return await deliver.deliver_over_outlets(
            self._sessions(),
            build_plan,
            self._send_plan,
            attempts=self.retry_policy.max_attempts,
            delay=lambda attempt: deliver.next_delay(attempt, self.retry_policy),
            sleep=asyncio.sleep,
            on_event=lambda kind, payload: self._log_delivery_event(kind, payload, label),
        )

    def _log_delivery_event(self, kind: str, payload: dict, label: str) -> None:
        """把出口链的观测点写成一行一事件的日志（便于 grep 归因）。"""
        plat = self._plat(str(payload.get("session", "")))
        if kind == "retry":
            logger.warning(
                f"{plat}{label}第 {payload.get('attempt')}/{payload.get('budget')} 次失败，"
                f"{float(payload.get('wait') or 0):.0f}s 后在同一出口重试：{payload.get('error')}"
            )
        elif kind == "switch":
            logger.warning(f"{plat}{label}该出口 {payload.get('budget')} 次均失败，切下一个出口")
        elif kind == "backup_used":
            logger.info(
                f"{plat}{label}主出口未成功，已改用第 {int(payload.get('index', 0)) + 1} 个出口"
            )
        elif kind == "give_up":
            logger.error(f"{self._plat()}{label}所有出口均失败（试过 {payload.get('tried')} 个）")
        elif kind == "plan_error":
            logger.warning(f"{plat}{label}构造投递计划失败，跳过该出口：{payload.get('error')}")
        elif kind == "skipped":
            logger.debug(f"{plat}{label}本轮不进这个出口（计划为空）")

    async def _enqueue_failure(
        self,
        session: str,
        plan: SendPlan,
        verdict: ThreatVerdict,
        outcome: DeliveryOutcome,
        now: float,
    ) -> None:
        """失败轮次：落库进重试队列（并留失败残留），绝不静默丢弃（R8）。"""
        text = "\n\n".join(plan.chunks) or plan.reason
        try:
            self.disk.spill(text, fingerprint=verdict.fingerprint)
        except OSError as exc:
            logger.warning(f"{self._plat(session)}写失败残留文件失败: {exc!r}")
        # 契约语义（§6.8）：chunks 存原文分片，text 存降级文本；首次失败即进入
        # degraded 态（原文已试过一遍，下一轮直接发降级文本，提高送达概率）
        degraded_plan = deliver.degrade(plan)
        head = (
            degraded_plan.chunks[0] if degraded_plan.chunks else _degraded_text(text)
        )[:200].rstrip()
        item = store.PendingItem(
            session=session,
            kind=plan.kind if plan.kind in {"text", "forward"} else "text",
            chunks=list(plan.chunks),
            text=f"{head}\n…（降级重试：完整摘录见日志目录）",
            fingerprint=verdict.fingerprint,
            severity=verdict.severity.value,
            route=verdict.route.value,
            attempts=1,
            state="degraded",
            created_at=now,
            next_at=now + deliver.next_delay(1, self.retry_policy),
            last_error=outcome.error,
        )
        stored = await self._pending_add(item)
        self.counters.bump("delivery_failed")
        self._bump_delta("delivery_failed")
        logger.warning(
            f"{self._plat(session)}投递失败已入重试队列（1/"
            f"{self.retry_policy.max_attempts}，{int(stored.next_at - now)}s 后重试）："
            f"{outcome.error}"
        )

    async def _retry_pending(self, now: float) -> None:
        """重试到期的失败投递：首次重试即发降级文本，耗尽转 abandoned 并留档。"""
        due = await self._pending_due(now)
        for item in due[: self._retry_batch()]:
            self.counters.bump("delivery_retries")
            self._bump_delta("delivery_retries")
            degraded = item.state == "degraded"
            # 契约语义（§6.8）：text = 降级文本，chunks = 原文分片
            text = item.text or _degraded_text("\n\n".join(item.chunks))
            if not degraded:
                text = "\n\n".join(item.chunks) or item.text
            plan = SendPlan(
                session=item.session, kind=item.kind or "text", chunks=[text or "（空内容）"]
            )
            outcome = await self._send_plan(item.session, plan)
            if outcome.ok:
                await self._pending_success(item.item_id)
                self.counters.bump("delivery_ok")
                self._bump_delta("delivery_ok")
                if degraded:
                    self.counters.bump("delivery_degraded")
                    self._bump_delta("delivery_degraded")
                logger.info(
                    f"{self._plat(item.session)}重试成功（第 {item.attempts + 1} 次尝试，"
                    f"降级={'是' if degraded else '否'}）"
                )
                continue
            updated = await self._pending_failure(item, now, outcome.error)
            if updated is not None and updated.state == "abandoned":
                self.counters.bump("delivery_abandoned")
                self._bump_delta("delivery_abandoned")
                logger.error(
                    f"{self._plat(item.session)}重试耗尽，标记放弃（共 {updated.attempts} 次）："
                    f"{outcome.error}"
                )
            else:
                self.counters.bump("delivery_failed")
                self._bump_delta("delivery_failed")
                logger.warning(
                    f"{self._plat(item.session)}重试失败（"
                    f"{getattr(updated, 'attempts', '?')}/{self.retry_policy.max_attempts}）："
                    f"{outcome.error}"
                )

    # ---------- 待发队列（SQLite 优先，内存态降级） ----------

    async def _pending_add(self, item: store.PendingItem) -> store.PendingItem:
        if self._store_ready():
            return await asyncio.to_thread(self.sqlite.pending_add, item)
        return self.pending.add(item)

    async def _pending_due(self, now: float) -> list[store.PendingItem]:
        if self._store_ready():
            return await asyncio.to_thread(self.sqlite.pending_due, now)
        return self.pending.due(now)

    async def _pending_failure(
        self, item: store.PendingItem, now: float, error: str
    ) -> store.PendingItem | None:
        attempts = int(item.attempts) + 1
        delay = deliver.next_delay(attempts, self.retry_policy)
        state = "abandoned" if attempts >= self.retry_policy.max_attempts else "degraded"
        next_at = float("inf") if state == "abandoned" else now + delay
        if self._store_ready():
            await asyncio.to_thread(
                self.sqlite.pending_update,
                item.item_id,
                attempts=attempts,
                state=state,
                next_at=next_at,
                last_error=str(error)[:500],
            )
            item.attempts = attempts
            item.state = state
            item.next_at = next_at
            item.last_error = str(error)[:500]
            return item
        return self.pending.mark_failure(
            item.item_id,
            now,
            delay=delay,
            max_attempts=self.retry_policy.max_attempts,
            error=error,
        )

    async def _pending_success(self, item_id: str) -> None:
        if self._store_ready():
            await asyncio.to_thread(self.sqlite.pending_update, item_id, state="sent")
            return
        self.pending.mark_success(item_id)

    def _pending_stats_value(self) -> dict:
        return dict(self._pending_stats or {})

    async def _commit_round(self, now: float, *, final: bool = False) -> None:
        """每轮一次批量事务（§9.4 第 1 条）；库不可用时退回 JSON 内存态落盘。"""
        alerts = list(self._round_alerts)
        progress = list(self._round_progress)
        rates = list(self._round_rates)
        deltas = dict(self._round_deltas)
        counters_state = self.counters.export_state()
        self._round_alerts.clear()
        self._round_progress.clear()
        self._round_rates.clear()
        self._round_deltas.clear()

        if not self._store_ready():
            if not self._store_error_notified:
                self._store_error_notified = True
                logger.error(
                    f"{self._plat()}状态库不可用，进入内存态降级（告警照发、"
                    "进度与计数用 JSON 兜底）"
                )
            self.tail.save()
            self.counters.save()
            self.pending.save()
            return

        kb_flush = self._kb_flush_hook()

        def run() -> None:
            if alerts:
                self.sqlite.record_alerts(alerts)
            if progress:
                self.sqlite.upsert_progress(progress)
            if rates:
                self.sqlite.push_rates(rates)
            if deltas:
                self.sqlite.bump_counters(deltas)
            self.sqlite.meta_set("counters_state", counters_state)
            self.sqlite.meta_set(
                "digest_last_flush", self.counters.data.get("digest_last_flush", 0.0)
            )
            self.sqlite.prune(now=now, cfg=self._prune_config())
            if kb_flush is not None:
                with contextlib.suppress(Exception):
                    kb_flush()

        await asyncio.to_thread(run)
        if final or now - self._checkpoint_at >= _CHECKPOINT_INTERVAL:
            self._checkpoint_at = now
            await asyncio.to_thread(self.sqlite.checkpoint, truncate=False)

    def _kb_flush_hook(self):
        """知识库落库入口（§9.4 第 2 条：main 每轮在 to_thread 里调用 flush）。"""
        for source in (getattr(self.engine, "kb", None), self.engine):
            flush = getattr(source, "flush", None)
            if callable(flush):
                return flush
        return None

    def _bump_delta(self, name: str, delta: int = 1) -> None:
        """记录本轮的计数增量（每轮一次性 bump 到 SQLite）。"""
        self._round_deltas[name] = self._round_deltas.get(name, 0) + int(delta)

    def _record_rate(self, scope: str, now: float) -> None:
        self.counters.window_push(scope, now)
        self._round_rates.append((scope, float(now)))

    # ---------- 聚合 ----------

    async def _flush_aggregates(self, now: float) -> None:
        digest = self.gate.flush_digest(now)
        if digest is not None:
            text = deliver.render_digest(digest)
            self._record_aggregate(
                "digest_flushed", text, digest.get("fingerprints", []), now
            )
            await self._broadcast(text, now, Severity.LOW, Route.DIGEST)
        burst = self.gate.flush_burst(now)
        if burst is not None:
            text = deliver.render_burst(burst)
            fingerprints = [item.get("fingerprint", "") for item in burst.get("items", [])]
            self._record_aggregate("burst_coalesced", text, fingerprints, now)
            await self._broadcast(text, now, Severity.HIGH, Route.NOTIFY)

    def _record_aggregate(
        self, decision: str, text: str, fingerprints: list, now: float
    ) -> None:
        for fingerprint in fingerprints or [""]:
            self._round_alerts.append(
                {
                    "ts": now,
                    "fingerprint": str(fingerprint),
                    "severity": "LOW" if decision == "digest_flushed" else "HIGH",
                    "route": "digest" if decision == "digest_flushed" else "notify",
                    "decision": decision,
                    "session": (self._sessions() or [""])[0],
                    "summary": text.splitlines()[0][:300],
                }
            )

    async def _broadcast(
        self, text: str, now: float, severity: Severity, route: Route
    ) -> None:
        """把聚合结果发给所有会话（失败同样进重试队列）。"""
        if not self._sessions():
            return
        all_ok, outcomes, planned = await self._deliver_outlets(
            lambda session: SendPlan(session=session, kind="text", chunks=[text]),
            "聚合摘要",
        )
        if all_ok:
            self.counters.bump("delivery_ok")
            self._bump_delta("delivery_ok")
            return
        if planned:
            session, plan = planned[0]
            verdict = ThreatVerdict(
                severity=severity,
                fingerprint=f"{route.value}-{int(now)}",
                route=route,
            )
            await self._enqueue_failure(session, plan, verdict, outcomes[-1], now)

    # ---------- 日志前缀 ----------

    def _plat(self, session: str | None = None) -> str:
        """self_guard.log_with_bot_id 开启时给日志补平台前缀（平台 ID 取自会话前缀）。"""
        if not bool(self.cfg.get("self_guard.log_with_bot_id", False)):
            return ""
        if session and ":" in session:
            return f"[platform:{session.split(':', 1)[0]}] "
        platforms = sorted(
            {item.split(":", 1)[0] for item in self._sessions() if ":" in item}
        )
        return f"[platform:{','.join(platforms)}] " if platforms else ""

    # ---------- 配置映射（R4：插件键 → 模块 cfg） ----------

    def _levels(self) -> tuple[str, ...]:
        return normalize_levels(self.cfg.get("scan.levels"))

    def _send_mode(self) -> str:
        mode = str(self.cfg.get("notify.send_mode") or "auto").strip().lower()
        if mode in {"file", "txt"}:
            # 历史配置：附件形态在部分通道必然失败，统一走文本（K10）
            return "auto(file→text)"
        return mode if mode in {"auto", "text", "forward"} else "auto"

    def _deliver_config(self) -> deliver.DeliverConfig:
        mode = str(self.cfg.get("notify.send_mode") or "auto").strip().lower()
        return deliver.DeliverConfig(
            send_mode=mode or "auto",
            prefer_forward=bool(self.cfg.get("notify.prefer_forward", False)),
            include_excerpt=bool(self.cfg.get("notify.include_excerpt", True)),
            max_excerpt_chars=_as_int(
                self.cfg.get("notify.max_excerpt_chars", 6000), 6000, 200, _MAX_EXCERPT_CHARS
            ),
            max_chars_per_message=_as_int(
                self.cfg.get("notify.max_chars_per_message", 0), 0, 0, _MAX_CHARS_PER_MESSAGE
            ),
        )

    def _gate_config(self) -> detect.GateConfig:
        return detect.GateConfig.from_mapping(
            {
                "dedupe_window": _as_int(
                    self.cfg.get("budget.dedupe_window_seconds", 900), 900, 0, 7 * 86400
                ),
                "max_per_round": _as_int(
                    self.cfg.get("budget.max_alerts_per_round", 5), 5, 0, 100
                ),
                "max_per_minute": _as_int(
                    self.cfg.get("budget.max_alerts_per_minute", 12), 12, 0, 600
                ),
                "max_per_hour": _as_int(
                    self.cfg.get("budget.max_alerts_per_hour", 80), 80, 0, 5000
                ),
                "max_per_day": _as_int(
                    self.cfg.get("budget.max_alerts_per_day", 300), 300, 0, 50000
                ),
                "burst_window": _as_int(
                    self.cfg.get("budget.burst_window_seconds", 60), 60, 1, 3600
                ),
                "burst_threshold": _as_int(
                    self.cfg.get("budget.burst_threshold", 8), 8, 1, 500
                ),
                "burst_min_severity": self.cfg.get("budget.burst_min_severity", "MEDIUM"),
                "digest_interval": _as_int(
                    self.cfg.get("budget.digest_interval_seconds", 1800), 1800, 10, 86400
                ),
                "digest_max_items": _as_int(
                    self.cfg.get("budget.digest_max_items", 50), 50, 1, 1000
                ),
                "silence_ranges": self.cfg.get("budget.silence_ranges", []),
                "silence_min_severity": self.cfg.get("budget.silence_min_severity", "HIGH"),
                "notify_min_severity": self.cfg.get("notify.min_severity", "MEDIUM"),
            }
        )

    def _engine_config(self) -> dict:
        """engine.py 的内部 cfg 键（§6.6，R4：与插件配置键显式转换）。"""
        route_map = self.cfg.get("classify.route_map")
        return {
            "classify_enable": bool(self.cfg.get("classify.enable", True)),
            "classify_mode": self._classify_mode(),
            "llm_provider_id": self._classify_provider_id(),
            "llm_timeout": _as_int(
                self.cfg.get("classify.timeout_seconds", 20), 20, 5, 300
            ),
            "llm_max_block_lines": _as_int(
                self.cfg.get("classify.max_block_lines", 80), 80, 5, 500
            ),
            "classify_system_prompt": str(self.cfg.get("classify.system_prompt") or ""),
            "fallback_severity": str(self.cfg.get("classify.fallback_severity") or "MEDIUM"),
            # 2026-10-18 补漏：这两个旋钮当时只写进了 schema 与 classify，**没进本白名单** ⇒
            # 生产链路上被静默丢弃（引擎路径与 detect 兜底路径都拿不到）：运营方设
            # transient_severity=LOW 不生效，派单承诺的 unmatched_severity=MEDIUM「一步回滚」也失效。
            # 白名单是本函数存在的意义（R4 显式转换），加键时必须同步这里。
            # 回归：tests/test_classify.py::test_engine_config_forwards_the_severity_knobs
            "unmatched_severity": str(self.cfg.get("classify.unmatched_severity") or "LOW"),
            "transient_severity": str(self.cfg.get("classify.transient_severity") or "MEDIUM"),
            "kb_enabled": bool(self.cfg.get("classify.kb_enabled", True)),
            "kb_max_entries": _as_int(
                self.cfg.get("classify.kb_max_entries", 500), 500, 50, 100000
            ),
            # v2.3.0：默认 **False** —— 每条命中都必须过模型（C2）；true 是显式逃生阀，
            # 走它的结论会标 judged=False。schema 默认值必须与这里逐字一致。
            "noise_shortcut": bool(self.cfg.get("classify.noise_shortcut", False)),
            # v2.3.0 新增（Q5=B）：判定先验保留期。engine 用它过滤过期的历史先验。
            "prior_ttl_hours": _as_int(
                self.cfg.get("classify.prior_ttl_hours", 72), 72, 1, 720
            ),
            # ``repeat_window_seconds`` 的消费方是 _refresh_fingerprint_stats（repeat_count
            # 统计窗口）。这里一并转发，保证「schema / KEY_MAP / 本白名单」三处不漏键；
            # 它**不参与**判不判，也**不参与**发不发（通知去重窗口是 budget.dedupe_window）。
            "repeat_window_seconds": self._repeat_window(),
            "route_map": route_map if isinstance(route_map, dict) else {},
            "new_pattern_escalate": bool(self.cfg.get("classify.new_pattern_escalate", False)),
            "notify_min_severity": str(self.cfg.get("notify.min_severity") or "MEDIUM"),
            "llm_max_calls_per_round": _as_int(
                self.cfg.get("classify.max_calls_per_round", 5), 5, 0, 1000
            ),
            "llm_max_calls_per_hour": _as_int(
                self.cfg.get("classify.max_calls_per_hour", 60), 60, 0, 100000
            ),
        }

    def _prune_config(self) -> dict:
        return {
            "history_retention_days": _as_int(
                self.cfg.get("state.history_retention_days", 30), 30, 1, 3650
            ),
            "history_max_rows": _as_int(
                self.cfg.get("state.history_max_rows", 20000), 20000, 1000, 1000000
            ),
            # Q5=B：知识库（先验）保留期归 classify.prior_ttl_hours；
            # state.fingerprint_ttl_hours 收窄为「通知去重状态」保留期（见 _fingerprint_ttl）。
            "prior_ttl_hours": _as_int(
                self.cfg.get("classify.prior_ttl_hours", 72), 72, 1, 720
            ),
            "kb_max_entries": _as_int(
                self.cfg.get("classify.kb_max_entries", 500), 500, 50, 100000
            ),
        }

    def _classify_mode(self) -> str:
        mode = str(self.cfg.get("classify.mode") or "auto").strip().lower()
        return mode if mode in {"auto", "local", "llm"} else "auto"

    def _classify_provider_id(self) -> str:
        return str(self.cfg.get("classify.provider_id") or "").strip()

    def _before(self) -> int:
        return _as_int(self.cfg.get("scan.context_before", 5), 5, 0, _MAX_CONTEXT_LINES)

    def _after(self) -> int:
        return _as_int(self.cfg.get("scan.context_after", 5), 5, 0, _MAX_CONTEXT_LINES)

    def _max_lines_per_poll(self) -> int:
        return _as_int(
            self.cfg.get("scan.max_lines_per_poll", 200), 200, 20, _MAX_LINES_PER_POLL
        )

    def _interval(self) -> int:
        return _as_int(
            self.cfg.get("scan.poll_interval_seconds", 30),
            30,
            _MIN_POLL_SECONDS,
            _MAX_POLL_SECONDS,
        )

    def _retry_batch(self) -> int:
        return _as_int(self.cfg.get("delivery.retry_batch", 5), 5, 1, 50)

    def _fingerprint_ttl(self) -> float:
        """通知去重状态的保留期（Q5=B：``state.fingerprint_ttl_hours`` 语义收窄后的唯一用途）。

        它清理的是 ``counters`` 里的指纹冷却记录（决定「还发不发」），与判定先验
        （``classify.prior_ttl_hours``）无关。**不要**把它接回判定链。
        """
        return float(
            _as_int(self.cfg.get("state.fingerprint_ttl_hours", 72), 72, 1, 24 * 30) * 3600
        )

    def _repeat_window(self) -> float:
        """``repeat_count`` 的统计窗口（秒；v2.3.0 新配置 ``classify.repeat_window_seconds``）。

        只喂判定上下文与观测；判定本身不被它跳过，通知去重也不看它。
        """
        return float(
            _as_int(
                self.cfg.get("classify.repeat_window_seconds", 900), 900, 0, 7 * 86400
            )
        )

    def _excerpt_mode(self) -> str:
        mode = str(self.cfg.get("state.excerpt_mode") or "ledger_only").strip().lower()
        return mode if mode in {"off", "ledger_only", "file"} else "ledger_only"

    def _sessions(self) -> list[str]:
        return _as_list(self.cfg.get("notify.target_sessions"))

    def _self_log_names(self) -> list[str]:
        names = [PLUGIN_NAME, *_as_list(self.cfg.get("self_guard.log_names"))]
        return list(dict.fromkeys(names))

    def _self_echo_ids(self) -> list[str]:
        """本插件目标会话 id：用于屏蔽「自己发送失败被适配器记的 WARN 回声」。

        取自 notify.target_sessions 去掉平台前缀后的会话 id 与完整会话串，另可用
        self_guard.feedback_ids 追加；判定还要求行里出现发送失败特征词，
        所以不会误伤同一平台上其他用户的故障。
        """
        ids: list[str] = []
        for session in self._sessions():
            text = str(session).strip()
            if text:
                ids.append(text)
            if ":" in text:
                tail = text.split(":")[-1].strip()
                if tail:
                    ids.append(tail)
        ids.extend(_as_list(self.cfg.get("self_guard.feedback_ids")))
        return list(dict.fromkeys([item for item in ids if len(item) >= 6]))

    def _exclude_keywords(self) -> list[str]:
        return _as_list(self.cfg.get("scan.exclude_keywords"))

    def _skip_existing(self) -> bool:
        return bool(self.cfg.get("scan.start_from_end", True))

    def _pattern(self) -> str:
        """日志文件名模式（F11：必须是相对模式且不含 ``..``，否则回落 ``*.log``）。

        ``../*.log`` 会读到日志目录之外的文件（内容照样进摘录/对话/磁盘），绝对模式会抛
        ``NotImplementedError`` 让插件静默不扫描 —— 两者都在这里拦掉并 warning。
        """
        raw = str(self.cfg.get("scan.file_pattern") or "*.log").strip() or "*.log"
        candidate = Path(raw)
        if candidate.is_absolute() or ".." in candidate.parts:
            logger.warning(
                f"{self._plat()}scan.file_pattern={raw!r} 不是合法的相对模式（绝对路径或含 ..），"
                "已回落 *.log（F11）"
            )
            return "*.log"
        return raw

    def _channel_overrides(self) -> dict:
        raw = self.cfg.get("delivery.channel_overrides")
        return raw if isinstance(raw, dict) else {}

    def _caps_for(self, session: str):
        """按平台取通道能力：优先用平台实例的 meta().name 兜底。"""
        platform = deliver.session_platform(session)
        instance = self._find_platform(platform)
        if instance is not None:
            try:
                platform = str(instance.meta().name or platform)
            except Exception:
                pass
        return deliver.caps_for(platform, self._channel_overrides())

    def _find_platform(self, platform: str):
        try:
            for instance in self.context.platform_manager.platform_insts:
                with contextlib.suppress(Exception):
                    if instance.meta().id == platform:
                        return instance
        except Exception:
            return None
        return None

    def _log_dir(self) -> Path:
        """日志目录：优先用配置，其次跟随 AstrBot 的 log_file_path，最后回落 data/logs。"""
        configured = str(self.cfg.get("scan.log_dir") or "").strip()
        if configured:
            return Path(os.path.expanduser(configured))
        data_root = self.data_dir.parent.parent
        raw = str(self._global_config().get("log_file_path") or "").strip()
        if raw:
            path = Path(os.path.expanduser(raw))
            if not path.is_absolute():
                path = data_root / raw
            return path.parent
        return data_root / "logs"

    def _global_config(self) -> dict:
        try:
            return self.context.get_config() or {}
        except Exception as exc:
            logger.debug(f"读取 AstrBot 全局配置失败，回退默认日志目录: {exc!r}")
            return {}

    def _list_files(self) -> list[Path]:
        """列出待扫描的日志文件（F11：结果必须落在日志目录内）。"""
        directory = self._log_dir()
        if not directory.is_dir():
            return []
        try:
            candidates = sorted(directory.glob(self._pattern()))
        except (OSError, ValueError, NotImplementedError) as exc:
            logger.warning(f"{self._plat()}扫描日志目录 {directory} 失败: {exc!r}")
            return []
        base = directory.resolve()
        files: list[Path] = []
        skipped = 0
        for path in candidates:
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
            except OSError:
                continue
            if resolved == base or base in resolved.parents:
                files.append(path)
            else:
                skipped += 1
        if skipped:
            logger.warning(
                f"{self._plat()}有 {skipped} 个匹配文件位于日志目录之外，已丢弃（F11 越界防护）"
            )
        return files

    def _notice_missing_files(self) -> None:
        now = time.monotonic()
        if now - self._missing_notice_at < _MISSING_NOTICE_INTERVAL:
            return
        self._missing_notice_at = now
        logger.warning(
            f"{self._plat()}日志目录 {self._log_dir()} 下没有匹配 {self._pattern()} 的文件；"
            "若 AstrBot 未开启文件日志，请先在 WebUI「配置文件 → 系统」打开 log_file_enable"
        )

    # ---------- 磁盘与状态查询 ----------

    def _maybe_report_disk(self, now: float) -> None:
        configured = float(
            _as_int(self.cfg.get("state.disk_report_interval_hours", 24), 24, 1, 168)
        ) * 3600.0
        interval = max(_DISK_REPORT_MIN_INTERVAL, configured)
        if now - self._disk_report_at < interval:
            return
        self._disk_report_at = now
        removed = self.disk.prune(now)
        logger.info(
            f"{self._plat()}{self.disk.report(now)}；本轮清理 "
            f"{removed['outbox'] + removed['failed']} 个文件"
        )

    def disk_report(self) -> dict:
        """当前占用报告（磁盘 + 状态库），供集成方与运行手册使用。"""
        report = self.disk.usage()
        report["db"] = self.sqlite.usage() if self.sqlite is not None else {"available": False}
        return report

    def stats(self) -> dict:
        """运行统计（计数/待发/磁盘/状态库/分级引擎）。"""
        engine_stats = {}
        stats_hook = getattr(self.engine, "stats", None)
        if callable(stats_hook):
            with contextlib.suppress(Exception):
                engine_stats = dict(stats_hook() or {})
        return {
            "counters": self.counters.snapshot(),
            "pending": self._pending_stats,
            "disk": self.disk.usage(),
            "db": self.sqlite.usage() if self.sqlite is not None else {"available": False},
            "engine": engine_stats,
            "tail_files": len(self.tail.files),
        }
