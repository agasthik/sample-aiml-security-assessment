"""Read the data model embedded in a Cloudscape report page.

Reports are drawn by the prebuilt Cloudscape UI from a JSON model the Python
builders embed in the page (see report-ui/src/types.ts). Tests assert on that
model rather than on rendered markup, which only exists in a browser.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = (
    ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "generate_consolidated_report"
    / "report_template.py"
)

_spec = importlib.util.spec_from_file_location(
    "tests_report_data_template", TEMPLATE_PATH
)
_template = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_template)

extract_report_data = _template.extract_report_data
rich_text = _template.rich_text


def report_data(page: str) -> dict[str, Any]:
    """The embedded model of a report page."""
    return extract_report_data(page)


def area(data: dict[str, Any], slug: str) -> dict[str, Any] | None:
    """One assessment area of a main-report model, or None when not shown."""
    return next((a for a in data["areas"] if a["slug"] == slug), None)


def overview(data: dict[str, Any], label: str) -> dict[str, Any]:
    """An overview counter of a main-report model by its label."""
    return next(m for m in data["overview"] if m["label"] == label)


def nav_headings(data: dict[str, Any]) -> list[str]:
    return [group["heading"] for group in data["navGroups"]]


def scope_text(data: dict[str, Any]) -> str:
    """The Assessment Scope source sentence(s) as plain text."""
    return rich_text(data["methodology"]["source"])


def scope_chip_labels(data: dict[str, Any]) -> list[str]:
    return [
        chip["label"]
        for group in data["methodology"]["scopeGroups"]
        for chip in group["chips"]
    ]
