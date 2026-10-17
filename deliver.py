"""log_watcher 的投递层（纯逻辑）：通道能力 → 段型选择 → 分片 → 退避重试 → 降级。

设计要点（对应缺陷证据）：
1. 通道能力表决定段型：weixin_oc 只支持纯文本（astrbot/.../weixin_oc_adapter.py 的
   send_by_session 遇到 File 段会 raise `failed to send N message segment(s)`，
   且会把同一条消息里排在 File 之前的 Plain 摘要一起丢掉；遇到 Node/Nodes 这类
   不支持的段只记 debug 并静默不发），所以这里根本不生成该通道发不出的段型；
2. 失败不静默：投递失败由调用方落 PendingQueue 重试（退避由本模块计算），重试耗尽
   后走 degrade() 降级成最小文本，再失败才标记放弃并计数；
3. 历史配置 send_mode=file 不再落到附件形态，映射为通道自适应的文本投递。
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

try:  # 包内导入（main.py 走这条）
    from .log_reader import block_lines, levels_in, parse_timestamp
    from .models import (
        ChannelCaps,
        Route,
        SendPlan,
        Severity,
        ThreatVerdict,
    )
except ImportError:  # 纯逻辑直连导入（pytest / python -c 走这条）
    from log_reader import block_lines, levels_in, parse_timestamp
    from models import (
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
) -> SendPlan:
    """按通道能力生成投递计划。

    Args:
        verdict: 分级结论（决定等级、指纹与文案）。
        cfg: 投递形态配置。
        session: 目标会话（unified_msg_origin）。
        block: 命中的日志片段（用于渲染告警头）。
        excerpt: 摘录正文（已渲染好的文本；空串表示不附正文）。
        caps: 显式覆盖的通道能力（默认按 session 的平台推断）。
        extra_note: 追加提示（如「本插件自身日志已屏蔽」或未送达积压说明）。

    Returns:
        SendPlan；kind 为 `text` / `forward` / `skip`，chunks 为空时调用方不得发送。
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

    card = ""
    if block is not None:
        card = render_alert_card(block, verdict)
    else:
        card = f"【AstrBot 日志告警｜{verdict.severity.value}】\n指纹：{verdict.fingerprint}"
    if extra_note:
        card = f"{card}\n{extra_note}"
    if verdict.route in (Route.REMEDIATE, Route.EMERGENCY):
        notes.append(
            "已进入修复候选，修复结论会作为回执单独发送"
            if verdict.route is Route.REMEDIATE
            else "已触发紧急修复流程，修复结论会作为回执单独发送"
        )

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
    """降级：只发一条最小纯文本摘要（丢掉长摘录与转发形态）。"""
    if not plan.chunks:
        return SendPlan(
            session=plan.session,
            kind="skip",
            degradation=list(plan.degradation) + ["无可降级内容"],
            reason=plan.reason,
        )
    head = plan.chunks[0][: _DEGRADED_CHARS].rstrip()
    notes = list(plan.degradation) + [
        "降级发送：仅保留摘要，完整摘录见 AstrBot 日志目录"
    ]
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


def delivered(outcomes) -> bool:
    """**至少一个出口**把消息交出去了 ⇒ 算送达。

    为什么不是「全部成功」：投递模型从"双发到每个目标"改成"按优先级 fallback"
    （2026-10-18 定案）—— 成功路径上 ``outcomes`` 里通常只有一条记录，用「全部成功」
    会把"主出口失败、备出口成功"误判成没送达（``remediation_runs.receipt_sent`` 会恒 0）。
    空列表 = 没有出口发出 ⇒ 没告诉人。
    """
    items = list(outcomes or [])
    return any(bool(getattr(item, "ok", False)) for item in items)


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
