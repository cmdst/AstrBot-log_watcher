"""静态检查守卫：未定义名（F821）必须在门禁里红，而不是在生产启动时炸。

为什么单开一条：v2.3.0 上线时 `LogWatcherPlugin.initialize` 的启动横幅用了
`report_cfg` 却没有赋值 —— **309 条测试全绿**（`initialize()` 根本不在测试覆盖面里），
生产启动直接 `Failed to load plugin log_watcher`（2026-10-23 21:25，靠热修 `bc25a2f` 补回）。
这类错误的本质是「静态可判定、运行期才炸」，把它前移到门禁比再加一条覆盖率断言便宜得多。

ruff 是**开发期工具**，不属于运行时依赖；缺失时 skip 并写明原因 —— 这是本仓库唯一
允许的 skip 面（工具不存在，不是断言不成立）。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_PLUGIN_DIR = Path(__file__).resolve().parents[1]


def _targets() -> list[str]:
    """运行时模块 + 随插件分发的离线工具。"""

    files = [
        "main.py",
        "deliver.py",
        "engine.py",
        "classify.py",
        "models.py",
        "store.py",
        "detect.py",
        "log_reader.py",
        "config_map.py",
    ]
    tools = sorted(path.name for path in (_PLUGIN_DIR / "tools").glob("*.py"))
    return files + [f"tools/{name}" for name in tools]


def _ruff_missing() -> bool:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "--version"],
            capture_output=True,
            text=True,
            cwd=_PLUGIN_DIR,
        )
    except OSError:
        return True
    return proc.returncode != 0


def test_no_undefined_names_in_shipped_modules() -> None:
    if _ruff_missing():
        pytest.skip("未装 ruff（开发期工具，不进运行时依赖）：本机/CI 建议装上以守住 F821")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "F821",
            "--no-cache",
            "--output-format",
            "concise",
            *_targets(),
        ],
        capture_output=True,
        text=True,
        cwd=_PLUGIN_DIR,
    )
    assert proc.returncode == 0, (
        "运行时模块存在未定义名（F821）。这类错误测试期间静默、却在 initialize 时把插件加载打挂"
        "（2026-10-23 的 report_cfg 事故）：\n" + (proc.stdout or proc.stderr)
    )
