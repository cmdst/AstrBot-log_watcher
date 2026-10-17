"""log_watcher 的检测层：自身日志屏蔽、命中收集、指纹、通知闸门。

纯逻辑模块（不导入 astrbot），可离线单测。这里承担三个容易静默失效的点：
1. 自身日志屏蔽：本插件各级日志（含异常栈续行、`[platform:..]` 前缀、uuid 后缀
   logger 名）绝不构成命中，杜绝「插件报错 → 被自己捕获 → 再报错」的自触发回路；
2. 指纹：同一条故障反复出现要能归并，去掉时间戳/数字/路径/hex 等噪声；
3. 通知闸门：去重窗口、轮次/分钟/小时预算、LOW 摘要聚合、静默时段、突发抑制，
   计数全部走 CounterStore，进程内与落盘一致。
"""

from __future__ import annotations

import contextlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

try:  # 包内导入（main.py 走这条）
    from .log_reader import HitCollector, strip_ansi
    from .models import (
        ROUTE_BY_SEVERITY,
        NotifyDecision,
        Rule,
        Severity,
        ThreatVerdict,
        severity_rank,
    )
    from .store import CounterStore
except ImportError:  # 纯逻辑直连导入（pytest / python -c 走这条）
    from log_reader import HitCollector, strip_ansi
    from models import (  # noqa: F401 —— Rule 是刻意的契约再导出（R12：detect.Rule is models.Rule）
        ROUTE_BY_SEVERITY,
        NotifyDecision,
        Rule,
        Severity,
        ThreatVerdict,
        severity_rank,
    )
    from store import CounterStore

import logging

_log = logging.getLogger("log_watcher.detect")

PLUGIN_NAMES = ("log_watcher",)
_SELF_HEADER_LIMIT = 200
# 回声（适配器替我们记的发送失败行）判定窗口：F17 —— 真实行 221 字符、目标 id 在 [141,179)
_ECHO_HEADER_LIMIT = 512


class SelfLogFilter:
    """判定一行是否属于本插件自己的日志，续行继承所属记录的身份。

    覆盖的形态（都来自真实日志与 AstrBot 的 logger 命名规则）：
    `[log_watcher]`、`[log_watcher.main]`、`[log_watcher:8f3a2b1c]`（uuid 后缀）、
    `[log_watcher-1a2b3c4d]`、`astrbot.plugin.log_watcher`、`[platform:xxx] [log_watcher] …`、
    以及堆栈续行里的 `plugins/log_watcher/*.py` 文件路径。

    另有一类真实的自反馈源（findings-recon.md §2）：本插件的发送失败会被平台适配器
    记成**别的组件**的 WARN，例如
    `[Core] [WARN] [weixin_oc.weixin_oc_adapter:915]: weixin_oc(...): sendmessage failed for
    o9cq…@im.wechat: ret=-2, errmsg=prepare failed`。这类行不含插件名，若 levels 含
    WARNING 就会「自己失败 → 再告警一次」。用 `echo_ids`（本插件的目标会话 id）
    + 发送失败特征词做联合判定，只屏蔽指向自己目标的失败回声，不误伤其他用户的平台故障。
    """

    ECHO_FAILURE_TOKENS = (
        "sendmessage failed",
        "failed to send",
        "no supported segments",
        "prepare failed",
        "outbound message ignored",
    )

    def __init__(
        self,
        names: object = PLUGIN_NAMES,
        extra_keywords: object = (),
        *,
        echo_ids: object = (),
        header_limit: int = _SELF_HEADER_LIMIT,
        echo_limit: int = _ECHO_HEADER_LIMIT,
    ):
        raw_names = [names] if isinstance(names, str) else list(names or ())
        self.names = [str(name) for name in raw_names if str(name).strip()] or list(
            PLUGIN_NAMES
        )
        self.extra_keywords = [
            str(kw) for kw in (extra_keywords or ()) if str(kw).strip()
        ]
        raw_ids = [echo_ids] if isinstance(echo_ids, str) else list(echo_ids or ())
        self.echo_ids = [str(item) for item in raw_ids if str(item).strip()]
        self.header_limit = int(header_limit)
        # F17：回声判定窗口比普通头部更宽 —— 现网真实回声行全长 221 字符，目标 id 落在
        # [141,179)，200 字符窗口只剩 21 字符余量；实例名/前缀再长一点就会漏判（自反馈回路）
        self.echo_limit = max(self.header_limit, int(echo_limit))
        self._patterns: list[re.Pattern] = []
        self._path_patterns: list[re.Pattern] = []
        for name in self.names:
            quoted = re.escape(name)
            self._patterns.append(
                re.compile(rf"\[\s*{quoted}(?:[.:_\-][0-9A-Za-z_.\-]{{0,48}})?\s*\]")
            )
            self._patterns.append(re.compile(rf"astrbot\.plugin\.{quoted}\b"))
            self._patterns.append(re.compile(rf"\b{quoted}\b"))
            self._path_patterns.append(re.compile(rf"plugins[\\/]{quoted}[\\/]"))
            self._path_patterns.append(re.compile(rf"[\\/]{quoted}\.py\b"))
        self._active = False

    def classify(self, line: str, is_record_start: bool) -> bool:
        """返回 True 表示该行（或它所属的记录）是本插件自己的日志。

        Args:
            line: 原始日志行。
            is_record_start: 该行是否是记录头行。

        Returns:
            True = 属于自身日志，调用方应完全屏蔽（不进命中、不进前文）。
        """
        head = strip_ansi(line)[: self.header_limit]
        echo_head = strip_ansi(line)[: self.echo_limit]
        if is_record_start:
            self._active = self._matches(head, echo_head)
            return self._active
        if self._active:
            return True
        if any(pattern.search(head) for pattern in self._patterns):
            self._active = True
            return True
        if self._is_delivery_echo(echo_head):
            self._active = True
            return True
        if any(pattern.search(head) for pattern in self._path_patterns):
            self._active = True
            return True
        return False

    def _matches(self, head: str, echo_head: str | None = None) -> bool:
        """自身日志匹配（``echo_head`` 传入时用更宽的窗口判回声，见 F17）。"""
        if any(keyword in head for keyword in self.extra_keywords):
            return True
        if any(pattern.search(head) for pattern in self._patterns):
            return True
        if self._is_delivery_echo(echo_head if echo_head is not None else head):
            return True
        return False

    def _is_delivery_echo(self, head: str) -> bool:
        """本插件发送失败被平台适配器记下的回声（含目标会话 id + 失败特征词）。"""
        if not self.echo_ids:
            return False
        if not any(token in head for token in self.ECHO_FAILURE_TOKENS):
            return False
        return any(echo_id in head for echo_id in self.echo_ids)


def is_self_feedback_line(line: str, echo_ids: object = ()) -> bool:
    """该行是否是「本插件自己发送失败」的回声（F07：修复闸第 9 步的自反馈分支）。

    判定窗口用 :data:`_ECHO_HEADER_LIMIT`（比普通头部更宽，见 F17）。

    Args:
        line: 原始日志行。
        echo_ids: 目标会话 id 列表（``main._self_echo_ids()``）。

    Returns:
        True 表示这行是本插件失败回声（应抑制通知，并作为修复风暴闸的输入）。
    """
    return SelfLogFilter(echo_ids=echo_ids)._is_delivery_echo(
        strip_ansi(line)[:_ECHO_HEADER_LIMIT]
    )


class Detector:
    """带自身日志屏蔽的命中收集器（main.py 每轮每文件一个实例）。"""

    def __init__(
        self,
        levels: object,
        *,
        before: int = 5,
        after: int = 5,
        exclude_keywords: object = (),
        source: str = "",
        self_names: object = PLUGIN_NAMES,
        self_keywords: object = (),
        self_echo_ids: object = (),
        self_filter: SelfLogFilter | None = None,
    ):
        self.filter = self_filter or SelfLogFilter(
            self_names, self_keywords, echo_ids=self_echo_ids
        )
        self.suppressed_records = 0
        self.collector = HitCollector(
            levels,
            before=before,
            after=after,
            exclude_keywords=exclude_keywords,
            source=source,
            suppress=self._suppress,
        )

    def _suppress(self, line: str, is_record_start: bool) -> bool:
        blocked = self.filter.classify(line, is_record_start)
        if blocked and is_record_start:
            self.suppressed_records += 1
        return blocked

    def feed(self, line: str) -> list:
        """喂入一行，返回本次收尾的片段（续行不计命中）。"""
        return self.collector.feed(line)

    def flush(self) -> list:
        """文件停更时收尾，返回剩余片段。"""
        return self.collector.flush()


# ---------- 指纹 ----------



def _classify_module():
    """取 classify 模块（R2：指纹与规则表的唯一实现都在那里）。

    包内导入优先，失败回落到平铺导入（与 §2.2 硬规则 4 的约定一致）。
    延迟到调用时导入：模块级导入会让 detect → classify 的依赖方向固化，
    而 classify 只需要 models/log_reader，不需要 detect。
    """
    try:
        from . import classify as module
    except ImportError:  # pragma: no cover - 平铺导入（pytest / python -c）
        import classify as module
    return module


def normalize_for_fingerprint(text: str) -> str:
    """把一行日志归一成可比较的形态（R2：委托 classify，唯一实现）。"""
    return _classify_module().normalize_for_fingerprint(text)


def fingerprint(block) -> str:
    """计算日志片段的稳定指纹（R2：委托 classify.fingerprint，禁止第二实现）。"""
    return _classify_module().fingerprint(block)


def block_fingerprint(block, *, max_hits: int = 5) -> str:
    """兼容别名：旧调用方用的名字，同样委托 classify.fingerprint。"""
    return _classify_module().fingerprint(block)


# ---------- 本地保守分级（classify.py 未就绪/LLM 不可用时的降级路径） ----------

_LEVEL_BASE: dict[str, Severity] = {
    "DEBUG": Severity.IGNORE,
    "INFO": Severity.IGNORE,
    "WARNING": Severity.LOW,
    "ERROR": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
_LEVEL_RANK: dict[Severity, int] = {
    severity: index for index, severity in enumerate(Severity)
}


def _rule_matches(rule, haystack: str) -> bool:
    """规则是否命中：兼容「子串 / 正则字符串 / 已编译正则」三种 pattern 形态。"""
    pattern = getattr(rule, "pattern", "")
    if isinstance(pattern, re.Pattern):
        return bool(pattern.search(haystack))
    if not isinstance(pattern, str) or not pattern:
        return False
    if getattr(rule, "is_regex", False):
        with contextlib.suppress(re.error):
            return bool(re.search(pattern, haystack))
        return False
    return pattern in haystack


def local_rules() -> tuple:
    """本地规则表（R12：唯一数据源在 classify，detect 不再各建一版）。

    §6.4 的契约名是 `classify.LOCAL_RULES`；若该模块暂时只有分表
    （`FAILURE_RULES`/`NOISE_RULES`/`TRANSIENT_RULES`），按同一顺序拼起来用，
    仍然只有一个来源，不会产生第二套规则数据。
    """
    module = _classify_module()
    rules = getattr(module, "LOCAL_RULES", None)
    if isinstance(rules, tuple) and rules:
        return rules
    merged: list = []
    for name in ("FAILURE_RULES", "NOISE_RULES", "TRANSIENT_RULES"):
        table = getattr(module, name, None)
        if isinstance(table, (tuple, list)):
            merged.extend(table)
    return tuple(merged)


def fallback_verdict(
    block, *, rules: object = None, cfg: Mapping | object | None = None
) -> ThreatVerdict:
    """本地保守分级（主循环在 engine/classify 不可用时的确定性兜底）。

    R2/R12 单一源：判定语义只有 ``classify`` 一份实现 —— 本函数直接委派
    ``classify.classify_block``，不再自带规则表与优先级。此前 detect 的第二套实现
    与 classify 有 4 处可复现分歧（MCP 中文串不匹配→HIGH、平台发送失败→MEDIUM、
    asyncio 噪声→LOW、provider 重试→LOW），委派后按构造消除。

    Args:
        block: 日志片段。
        rules: **已废弃**（历史参数）。判定规则统一来自 ``classify``；传值只会记一条
            warning，不再用于本地匹配，避免出现第二套规则优先级。
        cfg: 插件配置，透传给 ``classify.classify_block``。**必须传**：白名单之外的键直接
            影响等级落点（``unmatched_severity`` / ``transient_severity`` / ``route_map``），
            不传就等于把运营方的设置静默丢掉（2026-10-18 实测的漏传就是这么来的）。

    Returns:
        :class:`~models.ThreatVerdict`；``classify`` 不可用时退回"只按命中等级"的
        最小结论（fingerprint 留空，由调用方用预计算值补齐）。
    """
    if rules is not None:
        _log.warning("detect.fallback_verdict 的 rules 参数已废弃：判定统一走 classify（R12）")
    module = _classify_module()
    try:
        return module.classify_block(block, cfg=cfg)
    except Exception as exc:  # classify 不可用也不能把主循环打挂
        _log.warning("classify 不可用，退回按等级的最小结论：%s: %s", type(exc).__name__, exc)
    hit_lines = [
        block.lines[index] for index in block.hit_indices if index < len(block.lines)
    ]
    severity = max(
        (_LEVEL_BASE.get(level, Severity.MEDIUM) for level in block.levels),
        key=lambda item: _LEVEL_RANK[item],
        default=Severity.MEDIUM,
    )
    return ThreatVerdict(
        severity=severity,
        confidence=0.2,
        tags=["unclassified", "classify-unavailable"],
        component=(block.source.rsplit("/", 1)[-1] if block.source else ""),
        fingerprint="",
        is_new_pattern=False,
        evidence="\n".join(line.strip() for line in hit_lines[:3])[:400],
        reason="classify 模块不可用，仅按命中等级给出保守结论",
        route=ROUTE_BY_SEVERITY[severity],
        source="degraded",
    )


# ---------- 通知闸门 ----------

@dataclass
class GateConfig:
    """通知预算与抑制参数（配置项由 main.py 从插件配置映射）。"""

    dedupe_window: float = 900.0
    max_per_round: int = 5
    max_per_minute: int = 12
    max_per_hour: int = 80
    max_per_day: int = 300
    burst_window: float = 60.0
    burst_threshold: int = 8
    burst_min_severity: Severity = Severity.MEDIUM
    digest_interval: float = 1800.0
    digest_max_items: int = 50
    silence_ranges: tuple[tuple[int, int], ...] = ()
    silence_min_severity: Severity = Severity.HIGH
    notify_min_severity: Severity = Severity.MEDIUM

    @classmethod
    def from_mapping(cls, raw: object) -> GateConfig:
        """从配置 dict 构造；缺字段/非法值一律回落到默认。"""

        def _num(value, default: float) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        data = raw if isinstance(raw, dict) else {}
        return cls(
            dedupe_window=max(0.0, _num(data.get("dedupe_window"), 900.0)),
            max_per_round=max(0, int(_num(data.get("max_per_round"), 5))),
            max_per_minute=max(0, int(_num(data.get("max_per_minute"), 12))),
            max_per_hour=max(0, int(_num(data.get("max_per_hour"), 80))),
            max_per_day=max(0, int(_num(data.get("max_per_day"), 300))),
            burst_window=max(1.0, _num(data.get("burst_window"), 60.0)),
            burst_threshold=max(1, int(_num(data.get("burst_threshold"), 8))),
            burst_min_severity=Severity.parse(
                data.get("burst_min_severity"), Severity.MEDIUM
            ),
            digest_interval=max(1.0, _num(data.get("digest_interval"), 1800.0)),
            digest_max_items=max(1, int(_num(data.get("digest_max_items"), 50))),
            silence_ranges=parse_silence(data.get("silence_ranges")),
            silence_min_severity=Severity.parse(
                data.get("silence_min_severity"), Severity.HIGH
            ),
            notify_min_severity=Severity.parse(
                data.get("notify_min_severity"), Severity.MEDIUM
            ),
        )


def parse_silence(specs: object) -> tuple[tuple[int, int], ...]:
    """把 `["23:00-07:00"]` 这类静默时段解析成分钟区间，非法项忽略。"""
    raw = [specs] if isinstance(specs, str) else list(specs or ())
    ranges: list[tuple[int, int]] = []
    for spec in raw:
        text = str(spec).strip()
        if "-" not in text:
            continue
        start_text, _, end_text = text.partition("-")
        try:
            start = _minutes_of_day(start_text)
            end = _minutes_of_day(end_text)
        except ValueError:
            continue
        ranges.append((start, end))
    return tuple(ranges)


def _minutes_of_day(text: str) -> int:
    hours, _, minutes = str(text).strip().partition(":")
    value = int(hours) * 60 + int(minutes or 0)
    if not 0 <= value < 24 * 60:
        raise ValueError(f"越界的时刻: {text!r}")
    return value


def in_silence(moment: float, ranges: object) -> bool:
    """判断某个时刻是否落在静默时段（支持跨夜区间，按本机时区）。"""
    pairs = list(ranges or ())
    if not pairs:
        return False
    local = time.localtime(float(moment))
    minute = local.tm_hour * 60 + local.tm_min
    for start, end in pairs:
        if start <= end:
            if start <= minute < end:
                return True
        elif minute >= start or minute < end:
            return True
    return False


@dataclass
class AlertItem:
    """闸门输入：一条待通知的告警（来自分级结果）。"""

    fingerprint: str = ""
    severity: Severity = Severity.MEDIUM
    summary: str = ""
    session: str = ""
    ts: float = 0.0
    tags: list[str] = field(default_factory=list)


class NotifyGate:
    """通知闸门：去重 → 静默 → LOW 聚合 → 预算 → 突发抑制 → 放行。"""

    def __init__(self, counters: CounterStore, config: GateConfig | None = None):
        self.counters = counters
        self.config = config or GateConfig()
        self._round_sent = 0

    def begin_round(self) -> None:
        """每轮扫描开始时调用，重置轮次计数（轮次上限按轮算）。"""
        self._round_sent = 0

    def decide(self, item: AlertItem, now: float) -> NotifyDecision:
        """裁决一条告警的去留，并同步更新计数器。"""
        config = self.config
        severity = Severity.parse(item.severity)
        if severity is Severity.IGNORE:
            self.counters.bump("ignored")
            return NotifyDecision.STORE_ONLY

        info = self.counters.fingerprint_info(item.fingerprint)
        if (
            item.fingerprint
            and info["last_ts"]
            and float(now) - info["last_ts"] < config.dedupe_window
        ):
            # 滑动窗口：被抑制的重复命中同样刷新时间戳，持续复发的同一指纹
            # 在停止复发满一个窗口之前不会反复打扰
            self.counters.bump("suppressed_dedup")
            self.counters.touch_fingerprint(item.fingerprint, now)
            return NotifyDecision.SUPPRESS_DEDUP

        if in_silence(now, config.silence_ranges) and severity_rank(
            severity
        ) < severity_rank(config.silence_min_severity):
            # 静默期也更新时间戳：静默结束后不补发一堆积压告警
            self.counters.bump("suppressed_silence")
            self.counters.touch_fingerprint(item.fingerprint, now)
            return NotifyDecision.SUPPRESS_SILENCE

        if severity is Severity.LOW or severity_rank(severity) < severity_rank(
            config.notify_min_severity
        ):
            # §4.2：LOW 一律聚合；低于 notify_min_severity 的即时告警也压成摘要
            buffer = self.counters.buffer("digest_buffer")
            if not buffer:
                # 聚合间隔从「桶里出现第一条」开始算，避免重启后立刻甩一堆摘要
                self.counters.data["digest_last_flush"] = float(now)
            buffer.append(
                {
                    "fingerprint": item.fingerprint,
                    "severity": severity.value,
                    "summary": item.summary[:400],
                    "session": item.session,
                    "ts": float(now),
                }
            )
            self.counters.bump("digest_buffered")
            self.counters.touch_fingerprint(item.fingerprint, now)
            return NotifyDecision.DIGEST_BUFFER

        reason = ""
        if self._round_sent >= config.max_per_round:
            reason = "round"
        elif (
            self.counters.window_count("sent_minute", now, 60.0)
            >= config.max_per_minute
        ):
            reason = "minute"
        elif (
            self.counters.window_count("sent_hour", now, 3600.0)
            >= config.max_per_hour
        ):
            reason = "hour"
        elif (
            self.counters.window_count("sent_day", now, 86400.0)
            >= config.max_per_day
        ):
            reason = "day"
        if reason:
            self.counters.bump("suppressed_budget")
            self.counters.bump_sub("budget_hits", reason)
            self.counters.touch_fingerprint(item.fingerprint, now)
            return NotifyDecision.SUPPRESS_BUDGET

        if severity_rank(severity) >= severity_rank(config.burst_min_severity) and (
            self.counters.window_count("sent_burst", now, config.burst_window)
            >= config.burst_threshold
        ):
            burst = self.counters.burst_state()
            if not burst["items"]:
                burst["started"] = float(now)
            burst["count"] = int(burst["count"]) + 1
            burst["items"].append(
                {
                    "fingerprint": item.fingerprint,
                    "severity": severity.value,
                    "summary": item.summary[:200],
                }
            )
            self.counters.bump("burst_coalesced")
            self.counters.touch_fingerprint(item.fingerprint, now)
            return NotifyDecision.BURST_COALESCED

        self._round_sent += 1
        self.counters.bump("alerts_sent")
        self.counters.window_push("sent_minute", now)
        self.counters.window_push("sent_hour", now)
        self.counters.window_push("sent_day", now)
        self.counters.window_push("sent_burst", now)
        self.counters.touch_fingerprint(item.fingerprint, now)
        return NotifyDecision.SEND

    def flush_digest(self, now: float) -> dict | None:
        """到点（或缓冲满）时把 LOW 摘要聚合为一条，返回聚合内容。"""
        buffer = self.counters.buffer("digest_buffer")
        if not buffer:
            return None
        last = float(self.counters.data.get("digest_last_flush") or 0.0)
        due = (float(now) - last) >= self.config.digest_interval
        full = len(buffer) >= self.config.digest_max_items
        if not (due or full):
            return None
        items = list(buffer)
        self.counters.data["digest_buffer"] = []
        self.counters.data["digest_last_flush"] = float(now)
        self.counters.bump("digest_flushed")
        return {
            "count": len(items),
            "items": items,
            "fingerprints": sorted({item["fingerprint"] for item in items if item["fingerprint"]}),
            "flushed_at": float(now),
        }

    def flush_burst(self, now: float) -> dict | None:
        """突发窗口结束后把合并桶吐出来（一条合并告警）。"""
        burst = self.counters.burst_state()
        if not burst["items"]:
            return None
        if float(now) - float(burst["started"]) < self.config.burst_window:
            return None
        result = {
            "count": int(burst["count"]),
            "items": list(burst["items"]),
            "started": float(burst["started"]),
        }
        burst["started"] = 0.0
        burst["count"] = 0
        burst["items"] = []
        return result
