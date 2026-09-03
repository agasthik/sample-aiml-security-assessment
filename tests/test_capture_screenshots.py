import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "sample-reports"
    / "scripts"
    / "capture_screenshots.py"
)
SPEC = importlib.util.spec_from_file_location("capture_screenshots", SCRIPT_PATH)
capture_screenshots = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture_screenshots)


def test_capture_all_screenshots_raises_when_clip_guard_fails(monkeypatch):
    clip_error = RuntimeError("Sidebar navigation remains clipped: Agentic AI")
    monkeypatch.setattr(
        capture_screenshots,
        "capture_screenshot",
        Mock(side_effect=clip_error),
    )

    with pytest.raises(RuntimeError, match="Failed to capture 1 screenshot"):
        capture_screenshots.capture_all_screenshots(
            Mock(),
            [
                {
                    "name": "agentcore-navigation",
                    "file": "report.html",
                    "description": "AgentCore navigation",
                    "actions": [],
                }
            ],
        )


def test_capture_all_screenshots_returns_successful_paths(monkeypatch, tmp_path):
    screenshot_path = tmp_path / "report.png"
    monkeypatch.setattr(
        capture_screenshots,
        "capture_screenshot",
        Mock(return_value=screenshot_path),
    )

    captured = capture_screenshots.capture_all_screenshots(
        Mock(),
        [
            {
                "name": "report",
                "file": "report.html",
                "description": "Report",
                "actions": [],
            }
        ],
    )

    assert captured == [screenshot_path]
