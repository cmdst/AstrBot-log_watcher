"""log_watcher 的投递层（纯逻辑）：通道能力 → 段型选择 → 分片 → 退避重试 → 降级。

设计要点（对应缺陷证据）：
1. 通道能力表决定段型：weixin_oc 只支持纯文本（astrbot/.../weixin_oc_adapter.py 的
   send_by_session 遇到 File 段会 raise `failed to send N message segment(s)`，
   且会把同一条消息里排在 File 之前的 Plain 摘要一起丢掉；遇到 Node/Nodes 这类
   不支持的段只记 debug 并静默不发），所以这里根本不生成该通道发不出的段型；
2. 失败不静默：投递失败由调用方落 PendingQueue 重试（退避由本模块计算），重试耗尽
   后走 degrade() 降级成最小文本，再失败才标记放弃并计数；
3. 历史配置 send_mode=file 不再落到附件形态，映射为通道自适应的文本投递。

v2.3.0 的告警形态（用户诉求）：**1 条完整诊断文本 + 1 个原始日志文件**，不再把正文
按 QQ 长度切成 2~3 段。分派规则：
- 通道 ``caps.file`` 且这个出口允许附件（主出口）⇒ ``chunks`` 只有 1 段（保证单条可发完），
  ``attachments`` 带 1 个 ``.log``；
- 其余通道 / 群出口 ⇒ 仍是单条文本，但必须写清「完整日志见 <本机路径>」，零附件；
- 无模型诊断时首行明示「本地规则判定，未取得模型诊断」，**不得**伪装成模型结论。
分片函数（``split_with_markers``）只留给「不生成报告文件」的旧内联摘录路径与极端兜底。
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

try:  # 包内导入（main.py 走这条）
    from .classify import neutralize_untrusted
    from .log_reader import block_lines, levels_in, parse_timestamp
    from .models import (
        Attachment,
        ChannelCaps,
        Route,
        SendPlan,
        Severity,
        ThreatVerdict,
    )
except ImportError:  # 纯逻辑直连导入（pytest / python -c 走这条）
    from classify import neutralize_untrusted
    from log_reader import block_lines, levels_in, parse_timestamp
    from models import (
        Attachment,
        ChannelCaps,
        Route,
        SendPlan,
        Severity,
        ThreatVerdict,
    )

# 通道能力表：plain/forward/file/image 表示该通道能否可靠发出对应段型。
# max_chars 是单条纯文本消息的安全长度（超过就分片）。
# weixin_oc 的依据（findings-recon.md §1）：适配器源码虽然认识 File/Image/Video，但它们
# 要走 ilink CDN 上传链；本环境实测 70 轮里 59 轮 `prepare failed`（纯文本也一起失败），
# 而 Node/Nodes 在这条通道上只打 debug 就被丢弃（静默不发）。所以附件/转发一律标为不可用，
# 只发纯文本，失败交给退避重试与降级路径兜底。
CHANNEL_CAPS: dict[str, ChannelCaps] = {
    "weixin_oc": ChannelCaps(
        platform="weixin_oc", plain=True, forward=False, file=False, image=False, max_chars=1200
    ),
    "aiocqhttp": ChannelCaps(
        platform="aiocqhttp", plain=True, forward=True, file=True, image=True, max_chars=3000
    ),
    "qq_official": ChannelCaps(
        platform="qq_official", plain=True, forward=False, file=False, image=False, max_chars=900
    ),
    "webchat": ChannelCaps(
        platform="webchat", plain=True, forward=True, file=False, image=True, max_chars=4000
    ),
    "telegram": ChannelCaps(
        platform="telegram", plain=True, forward=False, file=False, image=True, max_chars=3500
    ),
    "discord": ChannelCaps(
        platform="discord", plain=True, forward=False, file=False, image=True, max_chars=1800
    ),
    "slack": ChannelCaps(
        platform="slack", plain=True, forward=False, file=False, image=True, max_chars=3000
    ),
}

# 平台 id 前缀 → 能力表键（weixin_oc 的实例 id 形如 weixin_personal_demo）
PREFIX_RULES: tuple[tuple[str, str], ...] = (
    ("weixin", "weixin_oc"),
    ("wx", "weixin_oc"),
    ("aiocqhttp", "aiocqhttp"),
    ("onebot", "aiocqhttp"),
    ("napcat", "aiocqhttp"),
    ("llonebot", "aiocqhttp"),
    ("qq_official", "qq_official"),
    ("qqofficial", "qq_official"),
    ("webchat", "webchat"),
    ("telegram", "telegram"),
    ("discord", "discord"),
    ("slack", "slack"),
)

DEFAULT_CAPS = ChannelCaps(
    platform="unknown", plain=True, forward=False, file=False, image=False, max_chars=1500
)

_FORWARD_CHUNK_CHARS = 1800
_DEGRADED_CHARS = 320
_CONTINUATION = "（续）"
#: 无模型诊断时诊断段的首行（用户可读的「这句不是模型说的」）。
NO_MODEL_LOCAL = "本地规则判定，未取得模型诊断"
#: 人工覆写（知识库 manual 条目）时诊断段的首行 —— 也绝不是模型结论。
NO_MODEL_MANUAL = "人工覆写（非模型判定）"
#: 诊断段里「可能原因」的单行上限（超长就压进报告文件，别把首段撑破）。
DIAGNOSIS_MAX_CHARS = 400
#: 首段被压到极限时的收尾提示（有报告文件时指向文件）。
_HEAD_CLIP_NOTE = "…（首段已截断，完整内容见报告文件）"

#: HIGH/CRITICAL 的静态人工处置清单 —— **必须是代码里的常量**，不允许模型生成（防幻觉）。
#: 按等级给 3 条最通用、最不会错的动作；具体定位仍然靠报告文件里的原始行。
HANDLING_CHECKLIST: dict[Severity, tuple[str, ...]] = {
    Severity.CRITICAL: (
        "先确认进程是否还活着（systemctl status / ps），必要时重启并保留现场",
        "看磁盘与内存（df -h、free -m）：满了先腾空间，别直接删日志或状态库",
        "把本报告文件与本机日志一起留档，再动配置",
    ),
    Severity.HIGH: (
        "按首段「可能原因」定位组件，先只读复现一次（合成一行日志探针即可）",
        "确认影响面：只有该组件降级，还是整条告警链路失效",
        "改配置前先备份（状态库 + plugin_data），改完按 runbook 的重载步骤生效",
    ),
    Severity.MEDIUM: (
        "先观察是否自愈（多数是可恢复抖动）；同一指纹连续出现再看报告文件",
    ),
}


@dataclass
class DeliverConfig:
    """投递形态配置（main.py 从插件配置映射，历史值在这里做兼容）。"""

    send_mode: str = "auto"
    prefer_forward: bool = False
    include_excerpt: bool = True
    max_excerpt_chars: int = 6000
    max_chars_per_message: int = 0
    node_chars: int = _FORWARD_CHUNK_CHARS
    allow_digest_direct: bool = False
    #: 首段（诊断文本）的硬上限：与通道 max_chars 取小；超长就压缩诊断而不是切段。
    head_max_chars: int = 1200


@dataclass
class RetryPolicy:
    """退避重试策略：attempt 从 1 开始，延迟按 base * factor^(attempt-1) 增长并封顶。"""

    max_attempts: int = 4
    base_delay: float = 5.0
    factor: float = 3.0
    max_delay: float = 900.0
    jitter: float = 0.25
    seed: int = 0xC0FFEE


@dataclass
class SessionTarget:
    """一个投递目标（会话 + 平台名）。"""

    session: str
    platform: str = ""
    caps: ChannelCaps = field(default_factory=lambda: DEFAULT_CAPS)


def session_platform(session: str) -> str:
    """从 unified_msg_origin 取平台 id（`weixin_personal_demo:FriendMessage:xxx`）。"""
    text = str(session or "").strip()
    return text.split(":", 1)[0] if ":" in text else text


def caps_for(platform: str, overrides: object = None) -> ChannelCaps:
    """按平台名取通道能力，支持配置覆盖（overrides: {平台: {字段: 值}}）。

    Args:
        platform: 平台 id（可以是 `weixin_personal_demo` 这类实例 id）。
        overrides: 可选的覆盖表，键为平台 id 或 `*`，值为字段字典。

    Returns:
        该平台的能力表；未知平台用保守默认（只发纯文本）。
    """
    key = str(platform or "").strip().lower()
    caps: ChannelCaps | None = None
    matched: str | None = None
    if key in CHANNEL_CAPS:
        matched, caps = key, _clone(CHANNEL_CAPS[key])
    else:
        for name, target in CHANNEL_CAPS.items():
            if name in key:
                matched, caps = name, _clone(target)
                break
        if caps is None:
            for prefix, target in PREFIX_RULES:
                if key.startswith(prefix) or prefix in key:
                    matched, caps = target, _clone(CHANNEL_CAPS[target])
                    break
    if caps is None:
        caps = _clone(DEFAULT_CAPS)
    table = overrides if isinstance(overrides, dict) else {}
    # 覆盖选择器：实例 id（weixin_personal_demo）、能力表键（weixin_oc）与 `*` 都生效
    for selector in (key, matched, "*"):
        patch = table.get(selector) if selector else None
        if isinstance(patch, dict):
            for field_name, value in patch.items():
                if hasattr(caps, field_name) and field_name != "platform":
                    setattr(caps, field_name, value)
    # R7 硬规则：weixin_oc 的附件/图片/转发是**代码级禁用**，配置覆盖也不能打开。
    # 依据 findings-recon.md §1：该通道 70 轮挂 59 轮（prepare failed），且 Node/Nodes
    # 会被静默丢弃；一旦允许选附件，就会出现"文本与附件分离、失败不可知"的部分可达。
    if _is_weixin(key):
        caps.forward = False
        caps.file = False
        caps.image = False
    return caps


def _is_weixin(platform_key: str) -> bool:
    """是否为 weixin_oc 系通道（前缀 `weixin`/`wx`，实例 id 形如 weixin_personal_demo）。"""
    key = str(platform_key or "").strip().lower()
    return key.startswith("weixin") or key.startswith("wx") or "weixin" in key


def _clone(caps: ChannelCaps) -> ChannelCaps:
    return ChannelCaps(
        platform=caps.platform,
        plain=caps.plain,
        forward=caps.forward,
        file=caps.file,
        image=caps.image,
        max_chars=caps.max_chars,
    )


def render_alert_card(
    block,
    verdict: ThreatVerdict,
    *,
    now: float | None = None,
    max_hit_lines: int = 3,
) -> str:
    """把命中片段渲染成告警头（文本/转发节点都用它）。"""
    lines = block_lines(block)
    found = levels_in(lines) or ["未知等级"]
    first_hit = block.hit_indices[0] if block.hit_indices else -1
    last_hit = block.hit_indices[-1] if block.hit_indices else -1
    start = (
        parse_timestamp(block.lines[first_hit]) if 0 <= first_hit < len(block.lines) else None
    )
    end = parse_timestamp(block.lines[last_hit]) if 0 <= last_hit < len(block.lines) else None
    header = [
        f"【AstrBot 日志告警｜{verdict.severity.value}】",
        f"命中 {block.hit_count} 条 {'/'.join(found)}（共 {len(block.lines)} 行摘录）",
    ]
    if start:
        header.append(f"时间：{start}" if start == end or not end else f"时间：{start} ~ {end}")
    if block.source:
        header.append(f"来源：{block.source.rsplit('/', 1)[-1]}")
    if verdict.fingerprint:
        header.append(f"指纹：{verdict.fingerprint}")
    if verdict.tags:
        header.append("标签：" + "、".join(str(tag) for tag in verdict.tags))
    if verdict.reason:
        header.append(f"研判：{verdict.reason}")
    if verdict.confidence:
        header.append(f"置信度：{verdict.confidence:.2f}（{verdict.source}）")
    if getattr(block, "truncated_after", False):
        missing = int(getattr(block, "missing_after", 0) or 0)
        tail = f"（缺 {missing} 行）" if missing else ""
        header.append(f"注：末尾片段后文未凑齐{tail}，日志停更或本轮无新行")
    hits = [
        line_text.strip()
        for index, (line_text, level) in enumerate(lines)
        if level
    ][: max(1, int(max_hit_lines))]
    if hits:
        header.append("—— 命中行 ——")
        header.extend(hits)
    return "\n".join(header)


@dataclass
class ReportSpec:
    """本轮告警报告的元信息（文件由 main 写入，这里只描述它，便于渲染与测试）。

    ``mode`` 是**内容口径**，会写进首段与文件名说明里，取证时一眼能看出这份文件装的是
    「本轮命中段」还是「整份日志」（Q3 裁定=A：默认 excerpt，``report.raw_mode=file`` 才整份）。
    """

    path: str = ""
    name: str = ""
    mode: str = "excerpt"
    size: int = 0
    lines: int = 0
    truncated: bool = False
    keep_days: int = 7

    @property
    def mode_text(self) -> str:
        """人读的口径说明（进首段与文件首行）。"""
        return "整份日志（raw_mode=file）" if self.mode == "file" else "本轮命中段（含前后文，逐字）"

    def size_text(self) -> str:
        """把字节数渲染成人读体积。"""
        size = max(0, int(self.size or 0))
        if size >= 1024 * 1024:
            return f"{size / 1024 / 1024:.1f} MiB"
        if size >= 1024:
            return f"{size / 1024:.0f} KiB"
        return f"{size} 字节"


def diagnosis_kind(verdict: ThreatVerdict) -> str:
    """诊断来源分派：``llm`` | ``manual`` | ``degraded`` | ``local``。

    fail-closed：只有 ``judged=True`` **且** ``judge_source="llm"`` 才算「模型判定」；
    其余一律按未判定处理（宁可写「未取得模型诊断」，也不能把本地规则冒充模型结论）。
    人工覆写（manual 条目）单独一类：它不是模型说的，也不该被渲染成模型诊断。
    """
    source = str(getattr(verdict, "judge_source", "") or "")
    tags = [str(tag) for tag in (verdict.tags or [])]
    if source == "manual" or verdict.source == "manual" or "manual-override" in tags:
        return "manual"
    if bool(getattr(verdict, "judged", False)) and source == "llm":
        return "llm"
    if source == "degraded" or verdict.source == "degraded" or any(
        tag.startswith("degraded:") for tag in tags
    ):
        return "degraded"
    return "local"


def _degraded_reason(verdict: ThreatVerdict) -> str:
    """降级原因（用 T3 定的 ``degraded:*`` 枚举，不自己编新串）。"""
    for tag in verdict.tags or []:
        text = str(tag)
        if text.startswith("degraded:"):
            return text
    return "degraded:unknown"


def _one_line(text: object, max_chars: int = DIAGNOSIS_MAX_CHARS) -> str:
    """单行化 + 中性化 + 截断（模型/日志文本进聊天前的唯一处理，复用 classify 的实现）。"""
    return neutralize_untrusted(str(text or ""), max_chars=max(0, int(max_chars)), single_line=True)


def should_fix_text(severity: Severity) -> str:
    """「是否建议修复」的固定文案（只看等级，不听模型）。"""
    level = Severity.parse(severity)
    if level is Severity.CRITICAL:
        return "建议立即人工修复（先止损并保留现场）"
    if level is Severity.HIGH:
        return "建议尽快人工修复（先只读复现，再改配置）"
    if level is Severity.MEDIUM:
        return "建议先观察；确认可复现后再修"
    return "暂不建议修复（仅存档，供比对）"


def advice_text(severity: Severity) -> str:
    """「修复建议」的第一条（来自静态清单；没有对应等级就给通用建议）。"""
    items = HANDLING_CHECKLIST.get(Severity.parse(severity)) or ()
    return items[0] if items else "暂不需要处置；持续出现再按报告文件里的原始行定位"


def render_diagnosis(verdict: ThreatVerdict, *, max_chars: int = DIAGNOSIS_MAX_CHARS) -> str:
    """诊断段（固定三段）：可能原因 / 是否建议修复 / 修复建议。

    首行永远回答「这话是谁说的」：
    - 模型判定 ⇒ ``—— 诊断（模型判定｜置信度 0.82）——``；
    - 无模型诊断 ⇒ **首行逐字** ``本地规则判定，未取得模型诊断``（带 ``degraded:*`` 原因）；
    - 人工覆写 ⇒ 首行 ``人工覆写（非模型判定）``。

    Args:
        verdict: 分级结论（读 ``judged`` / ``judge_source`` / ``reason`` / ``tags``）。
        max_chars: 「可能原因」的单行上限（超长压进报告文件，绝不撑破首段）。

    Returns:
        诊断段文本（不含首段头部；由 :func:`build_send_plan` 拼装）。
    """
    level = Severity.parse(verdict.severity)
    kind = diagnosis_kind(verdict)
    reason = _one_line(verdict.reason, max_chars)
    lines: list[str] = []
    if kind == "llm":
        lines.append(f"—— 诊断（模型判定｜置信度 {float(verdict.confidence or 0.0):.2f}）——")
    elif kind == "manual":
        lines.append(NO_MODEL_MANUAL)
    elif kind == "degraded":
        lines.append(f"{NO_MODEL_LOCAL}（{_degraded_reason(verdict)}）")
    else:
        lines.append(NO_MODEL_LOCAL)
    lines.append(f"可能原因：{reason or '（未给出原因，见原始日志）'}")
    lines.append(f"是否建议修复：{should_fix_text(level)}")
    lines.append(f"修复建议：{advice_text(level)}")
    return "\n".join(lines)


def render_alert_head(block, verdict: ThreatVerdict, *, repeat_count: int = 0) -> str:
    """首段的「头」（短，只放可核对的事实；命中行与长理由都进报告文件）。"""
    if block is None:  # 兜底：没有片段时也要能发出「最小首段」，不许抛异常
        return "\n".join(
            [
                f"【AstrBot 日志告警｜{verdict.severity.value}】",
                f"指纹：{verdict.fingerprint or '（无）'}",
            ]
        )
    lines_src = block_lines(block)
    found = levels_in(lines_src) or ["未知等级"]
    first_hit = block.hit_indices[0] if block.hit_indices else -1
    last_hit = block.hit_indices[-1] if block.hit_indices else -1
    start = (
        parse_timestamp(block.lines[first_hit]) if 0 <= first_hit < len(block.lines) else None
    )
    end = parse_timestamp(block.lines[last_hit]) if 0 <= last_hit < len(block.lines) else None
    header = [
        f"【AstrBot 日志告警｜{verdict.severity.value}】",
        f"命中 {block.hit_count} 条 {'/'.join(found)}（本轮 {len(block.lines)} 行）",
    ]
    if start:
        header.append(f"时间：{start}" if start == end or not end else f"时间：{start} ~ {end}")
    if block.source:
        header.append(f"来源：{block.source.rsplit('/', 1)[-1]}")
    facts: list[str] = []
    if verdict.component:
        facts.append(f"组件：{verdict.component}")
    if verdict.fingerprint:
        times = max(1, int(repeat_count or 0) + 1)
        facts.append(f"指纹：{verdict.fingerprint[:12]}（第 {times} 次命中）")
    if facts:
        header.append(" ｜ ".join(facts))
    return "\n".join(header)


def render_checklist(verdict: ThreatVerdict) -> str:
    """HIGH/CRITICAL 的静态人工处置清单（空串 = 该等级不需要）。"""
    items = HANDLING_CHECKLIST.get(Severity.parse(verdict.severity)) or ()
    if not items:
        return ""
    lines = ["—— 人工处置清单（静态表，非模型生成）——"]
    lines.extend(f"{index}. {item}" for index, item in enumerate(items, start=1))
    return "\n".join(lines)


def render_report_section(spec: ReportSpec | None, *, attached: bool) -> str:
    """「原始日志」段：附件形态同时给出文件名与本机留存路径；文本兜底写清本机路径。"""
    if spec is None or not str(getattr(spec, "path", "") or ""):
        return ""
    tail = f"{spec.mode_text}｜保留 {int(spec.keep_days)} 天"
    if spec.truncated:
        tail += "｜超限已截断（保留头尾）"
    if attached:
        name = spec.name or str(spec.path).rsplit("/", 1)[-1]
        return (
            f"—— 原始日志 ——\n{name}（{spec.size_text()}｜{tail}）\n"
            f"（本机留存：{spec.path}）"
        )
    return (
        f"—— 原始日志 ——\n完整日志见 {spec.path}\n"
        f"（本机路径，该通道不支持文件附件；{tail}）"
    )


def _report_body(
    verdict: ThreatVerdict,
    block,
    spec: ReportSpec,
    *,
    attached: bool,
    extra_note: str,
    repeat_count: int,
    max_chars: int,
) -> str:
    """拼出一条完整首段（头 + 诊断 + 清单 + 原始日志段 + 附加提示）。"""
    parts = [render_alert_head(block, verdict, repeat_count=repeat_count)]
    parts.append(render_diagnosis(verdict, max_chars=max_chars))
    checklist = render_checklist(verdict)
    if checklist:
        parts.append(checklist)
    section = render_report_section(spec, attached=attached)
    if section:
        parts.append(section)
    if extra_note:
        parts.append(extra_note)
    return "\n".join(part for part in parts if part)


def _fit_head(build, limit: int, *, tail: str = "") -> str:
    """把首段压进 ``limit``：先缩诊断，再硬截；**绝不切段**；``tail``（报告段）必须保留。

    Args:
        build: ``chars -> 完整首段`` 的构造函数。
        limit: 首段硬上限（字符数）。
        tail: 尾部必须保留的段（v2.3.0 的「—— 原始日志 ——」+ 本机路径）。硬截时先把它
            从正文里摘掉，再按 ``limit - len(tail) - len(截断提示)`` 截正文，最后原样附回；
            这样即使 ``report.head_max_chars`` 取到 schema 下界，非文件出口也不会既无附件
            又无路径（R2）。

    Returns:
        不超过 ``limit`` 的首段（``tail`` 本身长于上限时只能超限，但路径不会被截断）。
    """
    cap = max(1, int(limit))
    for chars in (DIAGNOSIS_MAX_CHARS, 240, 120, 40, 0):
        text = build(chars)
        if len(text) <= cap:
            return text
    text = build(0)
    if len(text) <= cap:
        return text
    body = text
    if tail:
        index = text.rfind(tail)
        if index >= 0:
            body = (text[:index] + text[index + len(tail) :]).rstrip()
    # 两个 "\n" 分隔符（正文+提示、提示+tail）也要计入预算。
    keep = max(0, cap - len(_HEAD_CLIP_NOTE) - (len(tail) + 1 if tail else 0) - 1)
    pieces = [body[:keep].rstrip()] if body[:keep].strip() else []
    pieces.append(_HEAD_CLIP_NOTE)
    if tail:
        pieces.append(tail)
    return "\n".join(pieces)


def split_text(text: str, max_chars: int) -> list[str]:
    """按行边界把长文本切成分片；超长单行硬切；不丢字符（除分片标记）。"""
    limit = max(1, int(max_chars))
    body = text.strip("\n")
    if not body.strip():
        return []
    if len(body) <= limit:
        return [body]
    pieces: list[str] = []
    current = ""
    for line in body.split("\n"):
        candidate = f"{current}\n{line}" if current else line
        while len(candidate) > limit:
            if current:
                pieces.append(current)
                current = ""
                candidate = line
                continue
            pieces.append(line[:limit])
            line = line[limit:]
            candidate = line
        current = candidate
    if current:
        pieces.append(current)
    return pieces


def _with_markers(pieces: list[str], *, prefix: str = "") -> list[str]:
    if len(pieces) <= 1:
        return [prefix + piece for piece in pieces]
    total = len(pieces)
    return [
        f"{prefix}{piece}\n（{index}/{total}）"
        for index, piece in enumerate(pieces, start=1)
    ]


def split_with_markers(text: str, limit: int, *, prefix: str = "") -> list[str]:
    """切片并补分片标记，保证每片（含标记）都不超过 limit。"""
    cap = max(1, int(limit))
    pieces = split_text(text, cap)
    for _ in range(3):
        if len(pieces) <= 1:
            return [prefix + piece for piece in pieces]
        marker = f"\n（{len(pieces)}/{len(pieces)}）"
        shrunk = split_text(text, max(1, cap - len(marker) - len(prefix)))
        if len(shrunk) <= len(pieces):
            return _with_markers(shrunk, prefix=prefix)
        pieces = shrunk
    return _with_markers(pieces, prefix=prefix)


def build_send_plan(
    verdict: ThreatVerdict,
    cfg: DeliverConfig | None = None,
    session: str = "",
    *,
    block=None,
    excerpt: str = "",
    caps: ChannelCaps | None = None,
    extra_note: str = "",
    report: ReportSpec | None = None,
    allow_attachment: bool = True,
    repeat_count: int = 0,
) -> SendPlan:
    """按通道能力生成投递计划（v2.3.0：1 条诊断文本 + 1 个原始日志文件）。

    两种形态：
    1. **有报告文件**（``report`` 非空）：首段 = 头 + 诊断 + 处置清单 + 原始日志段；
       ``chunks`` **永远只有 1 段**（超长就压缩诊断/硬截，绝不切段）；``caps.file`` 且
       ``allow_attachment`` 时才带 1 个附件（Q4=A：只有主出口发文件）。
    2. **无报告文件**（报告关闭 / 低等级 / 旧调用方）：沿用 v2.2.x 的内联摘录路径，
       那时才允许 ``split_with_markers`` 分片（带「（i/n）」标记）—— 它是兜底，不是主路径。

    Args:
        verdict: 分级结论（决定等级、指纹与诊断文案）。
        cfg: 投递形态配置。
        session: 目标会话（unified_msg_origin）。
        block: 命中的日志片段（渲染首段头部）。
        excerpt: 内联摘录正文（只在无报告文件的旧路径里用）。
        caps: 显式覆盖的通道能力（默认按 session 的平台推断）。
        extra_note: 追加提示（未送达积压、自我回声屏蔽等）。
        report: 报告文件元信息；给定时走新形态。
        allow_attachment: 这个出口是否允许附件（Q4=A 只给主出口 True）。
        repeat_count: 同指纹历史命中次数（首段写「第 N 次」）。

    Returns:
        SendPlan；``kind`` 为 ``text`` / ``forward`` / ``skip``。
    """
    settings = cfg or DeliverConfig()
    target_caps = caps or caps_for(session_platform(session))
    notes: list[str] = []

    if Severity.parse(verdict.severity) is Severity.IGNORE:
        return SendPlan(session=session, kind="skip", reason="IGNORE 仅入库，不通知")
    if verdict.route is Route.STORE:
        return SendPlan(session=session, kind="skip", reason="路由 store：仅入库")
    if verdict.route is Route.DIGEST and not settings.allow_digest_direct:
        return SendPlan(session=session, kind="skip", reason="路由 digest：由摘要聚合发送")

    if not target_caps.plain:
        return SendPlan(
            session=session,
            kind="skip",
            degradation=notes,
            reason=f"通道 {target_caps.platform} 不支持纯文本",
        )

    limit = (
        int(settings.max_chars_per_message)
        if int(settings.max_chars_per_message) > 0
        else int(target_caps.max_chars)
    )
    has_report = bool(report is not None and str(getattr(report, "path", "") or ""))

    if has_report:
        if "forward" in str(settings.send_mode or "").strip().lower() or bool(
            settings.prefer_forward
        ):
            notes.append("报告形态恒为单条文本：send_mode/prefer_forward 只影响旧内联路径")
        attach_ok = bool(target_caps.file and allow_attachment)
        if not attach_ok:
            if not target_caps.file:
                notes.append(
                    f"通道 {target_caps.platform} 不支持文件段："
                    "完整日志改用本机路径提示（不发附件）"
                )
            else:
                notes.append("备用出口只发文本；群只有做主出口时才会尝试发文件")
        head_limit = limit
        if int(settings.head_max_chars) > 0:
            head_limit = min(limit, int(settings.head_max_chars))

        # R2：报告段（含「—— 原始日志 ——」与本机路径）是首段必须保留的尾巴；
        # _fit_head 只压诊断/正文，报告段预留预算后原样附回，不再被硬截掉。
        section = render_report_section(report, attached=attach_ok)

        def build(chars: int) -> str:
            return _report_body(
                verdict,
                block,
                report,
                attached=attach_ok,
                extra_note=extra_note,
                repeat_count=repeat_count,
                max_chars=chars,
            )

        body = _fit_head(build, head_limit, tail=section)
        attachments: list[Attachment] = []
        if attach_ok:
            name = str(report.name or str(report.path).rsplit("/", 1)[-1])
            attachments.append(
                Attachment(path=str(report.path), name=name, size=int(report.size or 0))
            )
        if not body and not attachments:
            return SendPlan(
                session=session, kind="skip", degradation=notes, reason="没有可发送的内容"
            )
        return SendPlan(
            session=session,
            kind="text",
            chunks=[body] if body else [],
            attachments=attachments,
            degradation=notes,
            reason=(
                f"{target_caps.platform}：诊断文本"
                + ("+文件" if attachments else "（无附件）")
            ),
        )

    # ---------------- 旧内联路径（报告关闭 / 低等级 / 旧调用方） ----------------
    card = ""
    if block is not None:
        card = render_alert_card(block, verdict)
    else:
        card = f"【AstrBot 日志告警｜{verdict.severity.value}】\n指纹：{verdict.fingerprint}"
    if extra_note:
        card = f"{card}\n{extra_note}"
    body = card
    if excerpt and settings.include_excerpt:
        trimmed = excerpt.strip("\n")
        if len(trimmed) > settings.max_excerpt_chars > 0:
            trimmed = trimmed[: settings.max_excerpt_chars] + "\n…（摘录过长已截断）"
        body = f"{card}\n\n—— 摘录 ——\n{trimmed}"

    kind = "text"
    mode = str(settings.send_mode or "auto").strip().lower()
    if mode in {"file", "txt", "attachment"}:
        notes.append("历史配置 file（txt 附件）已废弃：附件段在部分通道必然失败，改发文本")
    elif mode == "forward" or settings.prefer_forward:
        if target_caps.forward:
            kind = "forward"
        else:
            notes.append(
                f"通道 {target_caps.platform} 不支持合并转发（会静默丢失），已降级为文本"
            )

    node_limit = limit if kind == "text" else max(1, int(settings.node_chars))
    chunks = split_with_markers(body, node_limit)
    if not chunks:
        return SendPlan(
            session=session, kind="skip", degradation=notes, reason="没有可发送的内容"
        )
    return SendPlan(
        session=session,
        kind=kind,
        chunks=chunks,
        degradation=notes,
        reason=f"{target_caps.platform} 能力：{'转发' if kind == 'forward' else '文本'}",
    )


def degrade(plan: SendPlan) -> SendPlan:
    """降级：只发一条最小纯文本摘要（丢掉长摘录、转发形态与附件）。

    v2.3.0：降级文本**自身**不带附件（避免这一次再放大失败）；但调用方的待发队列
    （``PendingItem.attachments``）仍保留原附件，**整条重试时会再发一次附件**（见
    ``main._retry_pending``）。降级提示要同时写清「报告文件已留在本机」与重试口径。
    """
    notes = list(plan.degradation)
    if plan.attachments:
        name = plan.attachments[0].name or plan.attachments[0].path
        notes.append(
            f"降级发送：仅保留摘要；报告文件已保留（{name}），可在本机查看；"
            "重试会再发一次附件"
        )
    else:
        notes.append("降级发送：仅保留摘要，完整日志见 AstrBot 日志目录")
    if not plan.chunks:
        return SendPlan(
            session=plan.session,
            kind="skip",
            degradation=notes + ["无可降级内容"],
            reason=plan.reason,
        )
    head = plan.chunks[0][: _DEGRADED_CHARS].rstrip()
    return SendPlan(
        session=plan.session,
        kind="text",
        chunks=[head],
        degradation=notes,
        reason="降级文本",
    )


def should_retry(attempts: int, policy: RetryPolicy) -> bool:
    """已失败 attempts 次后是否还该重试。"""
    return int(attempts) < max(1, int(policy.max_attempts))


def next_delay(attempt: int, policy: RetryPolicy, *, rng: random.Random | None = None) -> float:
    """第 attempt 次失败后的退避秒数（带确定性抖动，便于测试与观测）。

    Args:
        attempt: 已失败的次数（从 1 开始）。
        policy: 退避策略。
        rng: 可注入的随机源；不传时按 attempt 派生固定种子（结果可复现）。

    Returns:
        非负的等待秒数，不超过 policy.max_delay。
    """
    index = max(1, int(attempt))
    raw = float(policy.base_delay) * (float(policy.factor) ** (index - 1))
    raw = min(raw, float(policy.max_delay))
    if policy.jitter <= 0:
        return max(0.0, raw)
    source = rng or random.Random(policy.seed + index)
    spread = raw * float(policy.jitter)
    return max(0.0, min(float(policy.max_delay), raw + source.uniform(-spread, spread)))


_PLAN_MARKER_RE = re.compile(r"（\d+/\d+）\s*$")


def render_digest(payload: dict, *, limit: int = 30) -> str:
    """把 LOW 摘要聚合桶渲染成一条消息。"""
    items = list(payload.get("items") or [])
    count = int(payload.get("count") or len(items))
    lines = [f"【AstrBot 日志低危摘要｜LOW】过去一段时间命中 {count} 条低危日志"]
    seen: dict[str, int] = {}
    for item in items:
        key = str(item.get("fingerprint") or item.get("summary") or "")[:160]
        if key:
            seen[key] = seen.get(key, 0) + 1
    for key, hits in list(seen.items())[: max(1, int(limit))]:
        lines.append(f"- ×{hits} {key}")
    if len(seen) > limit:
        lines.append(f"…另有 {len(seen) - limit} 类未展开")
    return "\n".join(lines)


def render_burst(payload: dict) -> str:
    """把突发合并桶渲染成一条消息。"""
    items = list(payload.get("items") or [])
    count = int(payload.get("count") or len(items))
    lines = [f"【AstrBot 日志风暴合并｜{count} 条】短时间命中过多，已合并为一条"]
    seen: dict[str, int] = {}
    for item in items:
        key = str(item.get("fingerprint") or item.get("summary") or "")[:160]
        if key:
            seen[key] = seen.get(key, 0) + 1
    for key, hits in list(seen.items())[:20]:
        lines.append(f"- ×{hits} {key}")
    return "\n".join(lines)


def outlet_order(sessions) -> list[str]:
    """出口顺序：**列表即优先级**（第 1 个是主出口），去空白、去重、保序。

    2026-10-18 运营方定案：告警改走 QQ（私聊为主、测试群为备），微信撤出。
    出口列表从「都发一遍」变成「按序 fallback」，所以顺序本身是语义。
    """
    chain: list[str] = []
    for raw in sessions or []:
        text = str(raw or "").strip()
        if text and text not in chain:
            chain.append(text)
    return chain


def attachment_allowed(
    session: str, outlets, caps: ChannelCaps | None = None
) -> bool:
    """Q4=A 的**唯一**门控实现：只有主出口（列表第 1 个）才允许尝试附件。

    这是「非主出口不发文件」的纯函数版本 —— main 只负责调用它，不再自己写比较式，
    这样门控可以被单测直接钉住（F1：旧写法在测试里零判别力）。

    Args:
        session: 当前出口（unified_msg_origin）。
        outlets: ``notify.target_sessions``（列表即优先级，第 1 个是主出口）。
        caps: 该出口的通道能力；给定时还要求 ``caps.file`` 为真（weixin 恒 False）。

    Returns:
        True = 这个出口可以尝试发附件；空列表/空 session/非主出口/通道不支持都返回 False。
    """
    chain = outlet_order(outlets)
    if not chain or not str(session or "").strip():
        return False
    if str(session).strip() != chain[0]:
        return False
    if caps is not None and not bool(getattr(caps, "file", False)):
        return False
    return True


async def deliver_over_outlets(
    sessions,
    build_plan,
    send,
    *,
    attempts: int = 1,
    delay=None,
    sleep=None,
    on_event=None,
) -> tuple[bool, list, list]:
    """按出口顺序投递：主出口成功即停；每个出口最多 ``attempts`` 次尝试，用尽才切下一个。

    为什么放在这里而不是 main：顺序、预算、何时切出口都是纯逻辑，用注入的 ``send``/``sleep``
    就能逐条钉住（``tests/test_deliver.py``）；``main`` 只把真实发送函数接进来
    （唯一发送者仍是 ``main._send_plan``）。

    Args:
        sessions: 出口列表（前为优先），见 :func:`outlet_order`。
        build_plan: ``(session) -> SendPlan``；返回 None 或 ``plan.empty`` 表示这个出口这轮不发。
        send: ``async (session, plan) -> DeliveryOutcome``。
        attempts: 每个出口的最多尝试次数（含首次；配置键 ``delivery_max_attempts``）。
        delay: ``(attempt) -> float`` 第 attempt 次失败后等多久；None 表示不等待。
        sleep: ``async (seconds) -> None``；生产传 ``asyncio.sleep``。
        on_event: ``(kind, payload) -> None`` 观测点：``retry`` / ``switch`` / ``backup_used``
            / ``skipped`` / ``plan_error`` / ``give_up``（main 用它写日志）。

    Returns:
        ``(是否有出口成功, 每次尝试的结果, 每轮的 (出口, 计划))``；第三个元素供调用方
        记账与入队（全失败时只入队一次，别再按出口堆 abandoned）。
    """
    chain = outlet_order(sessions)
    budget = max(1, int(attempts or 1))
    outcomes: list = []
    planned: list[tuple[str, object]] = []

    def _emit(kind: str, **payload) -> None:
        if on_event is not None:
            on_event(kind, payload)

    for index, session in enumerate(chain):
        try:
            plan = build_plan(session)
        except Exception as exc:  # 构造计划失败只跳过这个出口，别把整条链路带走
            _emit("plan_error", session=session, error=f"{type(exc).__name__}: {exc}")
            continue
        if plan is None or getattr(plan, "empty", False):
            _emit("skipped", session=session)
            continue
        planned.append((session, plan))
        for attempt in range(1, budget + 1):
            outcome = await send(session, plan)
            outcomes.append(outcome)
            if getattr(outcome, "ok", False):
                if index:
                    _emit("backup_used", session=session, index=index)
                return True, outcomes, planned
            if attempt < budget:
                wait = float(delay(attempt) or 0.0) if delay is not None else 0.0
                _emit(
                    "retry",
                    session=session,
                    attempt=attempt,
                    budget=budget,
                    wait=wait,
                    error=str(getattr(outcome, "error", "")),
                )
                if sleep is not None and wait > 0:
                    await sleep(wait)
        _emit("switch", session=session, index=index, budget=budget)
    if outcomes:
        _emit("give_up", tried=len(planned))
    return False, outcomes, planned


def mask_session(session: str) -> str:
    """把会话串里的标识掩掉：``平台:类型:<ID>`` → ``平台:类型:（ID 已隐）``。

    为什么要掩：插件启动横幅会把出口列表写进 ``astrbot.log``，而这份日志**正是插件自己要扫的**
    —— 运营方的会话标识不该被顺带抄进日志（2026-10-18 fix 用「合成日志探针」才发现横幅里有全串）。
    解析不出三段就原样返回（宁可留着，也别因为掩码把调试信息弄丢）。
    """
    text = str(session or "")
    parts = text.split(":")
    if len(parts) < 3 or not parts[-1]:
        return text
    return ":".join([*parts[:-1], "（ID 已隐）"])


def has_redundant_outlets(sessions, *, minimum: int = 2) -> bool:
    """出口是否够冗余（策略：至少「主 + 备」两条，2026-10-18 运营方定案 Q8=b）。

    为什么只校验**条数**、不校验可达性：可达性只能靠「真发一条探针」来验（会在群里打扰，
    各平台也没有等价的健康检查）。所以这是**名义**校验 —— 配置里写两条不通的出口同样算通过，
    这一点必须让人知情（已写进 runbook §4：单出口/名义出口的可用性靠摘要里的成功记录自证）。
    """
    return len(outlet_order(sessions)) >= max(1, int(minimum))


def strip_plan_markers(text: str) -> str:
    """去掉分片标记（测试用：验证分片不丢内容）。"""
    return _PLAN_MARKER_RE.sub("", text)
