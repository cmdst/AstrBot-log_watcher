"""默认值的漂移守卫：同一个默认值写在多处时，必须一致。

为什么单开一个文件：**同一事实写多份**是本仓库最容易出静默故障的地方 —— 2026-10-17 那两个等级
旋钮（`unmatched_severity` / `transient_severity`）就是 schema 有、消费方认、**唯独
`main._engine_config()` 的显式白名单那处没转发** ⇒ 运营方的设置与派单承诺的「一步回滚」同时失效
（复盘见父手册 §3 第 8 条）。默认值同理：只有**生产链路**那份真正生效，另外两份是给人读的，
一旦漂移，读代码的人会得到错误结论。

本文件只做一件事：把「多处各写一份」的默认值钉在一起。加新键时请顺手加一条。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).resolve().parents[1]
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import remediate  # noqa: E402


def _schema() -> dict:
    return json.loads((_PLUGIN_DIR / "_conf_schema.json").read_text(encoding="utf-8"))


def _main_src() -> str:
    return (_PLUGIN_DIR / "main.py").read_text(encoding="utf-8")


def test_max_output_bytes_default_matches_in_all_three_places() -> None:
    """轨迹上限默认值：schema / remediate / main 白名单三处。

    这个值决定轨迹会不会被截断 —— 2026-10-19 实测一次**成功** run 的轨迹恰好封顶 262144，
    结尾的 `{"type":"final"}` 被截掉，按「看轨迹里有没有 final」验收会把成功判成失败。
    """
    wanted = 1048576
    assert _schema()["remediation_max_output_bytes"]["default"] == wanted
    assert remediate.DEFAULT_MAX_OUTPUT_BYTES == wanted
    assert f'self.config.get("remediation_max_output_bytes", {wanted})' in _main_src(), (
        "main 的显式白名单才是生产生效的那份；它没跟着改 = 生产仍按旧默认跑"
    )


def test_timeout_default_matches_schema_and_code() -> None:
    """修复超时默认值（300 → 900 那次）也要两处一致。"""
    assert _schema()["remediation_timeout_seconds"]["default"] == remediate.DEFAULT_TIMEOUT_SECONDS
    assert remediate.DEFAULT_TIMEOUT_SECONDS == 900


def test_output_bytes_bounds_are_unchanged() -> None:
    """只抬默认值，不动上下界（下界 4096 允许运营方按需调小）。"""
    assert (remediate.MIN_OUTPUT_BYTES, remediate.MAX_OUTPUT_BYTES) == (4096, 16777216)
    hint = _schema()["remediation_max_output_bytes"]["hint"]
    assert "4096-16777216" in hint, "hint 里的区间要跟着上下界走"
