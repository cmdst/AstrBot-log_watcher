"""log_watcher 的数据契约：跨模块共享的纯数据结构。

本模块只依赖标准库（不导入 astrbot、不做 IO），便于纯逻辑测试；
字段名与 architecture.md 的 ThreatVerdict / Rule / LogBlock 契约对齐，
classify.py / engine.py / deliver.py / store.py 与 main.py 共用同一形状，避免各自发明字段。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """威胁分级（五级，与提示词资产的枚举值逐字对齐）。"""

    IGNORE = "IGNORE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def parse(cls, value: object, default: Severity = None) -> Severity:
        """把任意输入规整为 Severity，非法值回落到 default（默认 MEDIUM）。

        Args:
            value: 待解析的值，可以是 Severity、字符串或 None。
            default: 非法值时的回落等级。

        Returns:
            规整后的 Severity。
        """
        fallback = default or cls.MEDIUM
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().upper()
        for item in cls:
            if item.value == text:
                return item
        return fallback


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.IGNORE,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def severity_rank(value: object) -> int:
    """返回等级的严重度序号（IGNORE=0 … CRITICAL=4），用于阈值比较。"""
    return SEVERITY_ORDER.index(Severity.parse(value))


class Route(str, Enum):
    """分级后的路由动作（默认语义写死在 ROUTE_BY_SEVERITY）。

    ``REMEDIATE`` 是 **v2.3.0 之前的历史去向**（当时 HIGH 默认进「自动修复候选」）。
    v2.3.0 移除了自动修复能力，默认映射改为 HIGH → ``NOTIFY``；但**枚举成员必须留着**：
    ① 历史台账 ``alerts.route`` 里已有一批该历史值的行，删成员就解析不出来；
    ② 运营方配置的 ``route_map`` 可能仍写着这个旧去向名，删成员会让它静默失效。
    它现在的语义只是「最高级即时告警」——和 ``EMERGENCY`` 一样**只通知人工**。
    """

    STORE = "store"
    DIGEST = "digest"
    NOTIFY = "notify"
    REMEDIATE = "remediate"
    EMERGENCY = "emergency"


ROUTE_BY_SEVERITY: dict[Severity, Route] = {
    Severity.IGNORE: Route.STORE,
    Severity.LOW: Route.DIGEST,
    Severity.MEDIUM: Route.NOTIFY,
    # v2.3.0：HIGH 不再默认进「自动修复候选」，改为普通即时通知（交人工处置）。
    Severity.HIGH: Route.NOTIFY,
    Severity.CRITICAL: Route.EMERGENCY,
}


class NotifyDecision(str, Enum):
    """通知闸门的裁决结果。"""

    STORE_ONLY = "store_only"
    SEND = "send"
    DIGEST_BUFFER = "digest_buffer"
    SUPPRESS_DEDUP = "suppress_dedup"
    SUPPRESS_SILENCE = "suppress_silence"
    SUPPRESS_BUDGET = "suppress_budget"
    BURST_COALESCED = "burst_coalesced"


@dataclass
class LogLine:
    """一条日志行的解析结果。"""

    text: str
    level: str | None = None
    timestamp: str | None = None
    source: str = ""
    line_no: int = 0
    is_record_start: bool = True
    is_self: bool = False
    is_hit: bool = False


@dataclass
class LogBlock:
    """一段连续的日志片段，可包含多条命中。

    前后文窗口重叠或相邻的命中会合并进同一段，避免重复粘贴前文。
    """

    source: str
    lines: list[str] = field(default_factory=list)
    hit_indices: list[int] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    start_line: int = 0
    truncated_after: bool = False
    missing_after: int = 0

    @property
    def hit_count(self) -> int:
        """本段命中的日志条数。"""
        return len(self.hit_indices)


@dataclass
class ThreatVerdict:
    """分级结论：本地模式与 LLM 模式必须给出同一形状。

    ``judged`` / ``judge_source``（v2.3.0 新增）回答「这条结论到底有没有过一次模型判定」，
    与 ``source``（谁写的这条结论）**分开**：报告首段据此分派「LLM 诊断」还是
    「本次未经模型判定」。默认 ``judged=False`` 是 fail-closed —— 没有显式声明过过模型的
    构造点，一律不得被渲染成模型结论（``parse_llm_verdict`` 是唯一把它置 True 的地方）。
    """

    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    component: str = ""
    fingerprint: str = ""
    is_new_pattern: bool = False
    evidence: str = ""
    reason: str = ""
    route: Route = Route.NOTIFY
    source: str = "local"
    #: 本条结论是否真的由模型给出（本地规则 / 噪声短路 / 预算排队 / 降级 / 人工覆写均为 False）。
    judged: bool = False
    #: 结论依据：``llm`` | ``degraded`` | ``local`` | ``manual`` | ``prior``（空串 = 未知）。
    judge_source: str = ""

    def to_dict(self) -> dict:
        """序列化为可 JSON 落盘的 dict。"""
        return {
            "severity": self.severity.value,
            "confidence": float(self.confidence),
            "tags": list(self.tags),
            "component": self.component,
            "fingerprint": self.fingerprint,
            "is_new_pattern": bool(self.is_new_pattern),
            "evidence": self.evidence,
            "reason": self.reason,
            "route": self.route.value,
            "source": self.source,
            "judged": bool(self.judged),
            "judge_source": self.judge_source,
        }

    @classmethod
    def from_dict(cls, raw: object, *, default: ThreatVerdict = None) -> ThreatVerdict:
        """从 dict 还原；非法/缺字段回落到 default 的同名字段。

        Args:
            raw: 待解析的映射。
            default: 缺字段时的基准对象（默认构造一个中性判定）。

        Returns:
            还原后的 ThreatVerdict。
        """
        base = default or cls()
        if not isinstance(raw, dict):
            return base
        route_text = str(raw.get("route") or base.route.value).strip().lower()
        route = base.route
        for item in Route:
            if item.value == route_text:
                route = item
                break
        try:
            confidence = float(raw.get("confidence", base.confidence))
        except (TypeError, ValueError):
            confidence = base.confidence
        tags = raw.get("tags")
        if not isinstance(tags, (list, tuple)):
            tags = base.tags

        severity = Severity.parse(raw.get("severity"), base.severity)
        return cls(
            severity=severity,
            confidence=min(1.0, max(0.0, confidence)),
            tags=[str(tag) for tag in tags],
            component=str(raw.get("component", base.component) or ""),
            fingerprint=str(raw.get("fingerprint", base.fingerprint) or ""),
            is_new_pattern=bool(raw.get("is_new_pattern", base.is_new_pattern)),
            evidence=str(raw.get("evidence", base.evidence) or ""),
            reason=str(raw.get("reason", base.reason) or ""),
            route=route if raw.get("route") else ROUTE_BY_SEVERITY[severity],
            source=str(raw.get("source", base.source) or base.source),
            judged=bool(raw.get("judged", base.judged)),
            judge_source=str(raw.get("judge_source", base.judge_source) or ""),
        )


@dataclass
class Rule:
    """本地规则表的唯一形状（R1/G6：合并 detect 与 classify 的两版 Rule）。

    Attributes:
        name: 规则名（兼容旧 detect 写法）。
        pattern: 正则或子串，永远存 str，编译由使用方缓存。
        severity: 命中后的等级。
        tags: 命中后追加的标签。
        enabled: 是否启用。
        is_regex: False=子串匹配；True=re.search。
        kind: failure | noise | transient，决定同级优先级与标签前缀。
        tag: 规则短名，进入 tags/reason；空则用 name。
        note: 中文说明，直接写进 reason。
        confidence: 命中后的置信度。
    """

    name: str = ""
    pattern: str = ""
    severity: Severity = Severity.MEDIUM
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    is_regex: bool = False
    kind: str = "failure"
    tag: str = ""
    note: str = ""
    confidence: float = 0.5


@dataclass
class ChannelCaps:
    """通道能力：决定本轮能用哪些段型，避免发出通道不支持的段。"""

    platform: str = "unknown"
    plain: bool = True
    forward: bool = False
    file: bool = False
    image: bool = False
    max_chars: int = 1500


@dataclass
class Attachment:
    """一个待发送的文件段（v2.3.0：告警报告 = 首段诊断 + 原始日志文件）。

    为什么不直接存 ``Path``：这形状要进待发重试队列（``pending_delivery.attachments``
    存 JSON），必须可序列化、可跨进程还原；``path`` 用绝对路径，``name`` 是聊天里
    显示的文件名（也是回执里写给人看的那个名字）。
    """

    path: str = ""
    name: str = ""
    kind: str = "file"
    size: int = 0

    def to_dict(self) -> dict:
        """序列化（重试队列用）。"""
        return {
            "path": self.path,
            "name": self.name,
            "kind": self.kind,
            "size": int(self.size),
        }

    @classmethod
    def from_dict(cls, raw: object) -> Attachment | None:
        """从 dict 还原；没有 path 的一律丢弃（空附件不许进计划）。"""
        if not isinstance(raw, dict):
            return None
        path = str(raw.get("path") or "").strip()
        if not path:
            return None
        return cls(
            path=path,
            name=str(raw.get("name") or "").strip() or path.rsplit("/", 1)[-1],
            kind=str(raw.get("kind") or "file"),
            size=int(raw.get("size") or 0),
        )


@dataclass
class SendPlan:
    """一次投递计划：由通道能力决定段型，失败后可降级重发。

    v2.3.0：除文本分片外还可带**文件附件**（``attachments``）。``empty`` 必须同时看
    两者 —— 只有附件没有文本的计划也是有效计划（反过来则沿用旧语义）。
    """

    session: str = ""
    kind: str = "text"
    chunks: list[str] = field(default_factory=list)
    degradation: list[str] = field(default_factory=list)
    reason: str = ""
    #: 附件段（顺序即发送顺序，文本之后）。只有 ``caps.file`` 且允许附件的出口才会非空。
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """没有任何可分发的段（文本与附件都空）时为 True。"""
        return not self.chunks and not self.attachments


@dataclass
class DeliveryOutcome:
    """一次投递的最终结果（R8 三态：ok / degraded / failed 由 ok+degraded 表达）。"""

    session: str = ""
    ok: bool = False
    attempts: int = 0
    degraded: bool = False
    error: str = ""
    #: 附件（文件段）的结果：``None`` = 本计划没有附件；``True/False`` = 发成功/发失败。
    file_ok: bool | None = None
    #: 文本已送达、附件失败 ⇒ ``partial=True``（算送达，但要记一笔；不整条重试）。
    partial: bool = False
