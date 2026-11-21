"""Parts borrowed from the main report, for the assessment history pages.

The main report's builder (``report_template.py``) is loaded by file path
under its own module name. The changes page reuses its Cloudscape page writer
(the same prebuilt UI bundle, favicon and footer), its area names and icons,
and its link check, so the changes page looks and behaves like the main
report, including the reader's light/dark choice. Guard tests fail if
something used here moves.
"""

from __future__ import annotations

import functools
import importlib.util
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import CORE_AREAS

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = (
    REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "generate_consolidated_report"
    / "report_template.py"
)
# A name of its own, so it never clashes with consolidate_html_reports.py's
# plain `import report_template`.
TEMPLATE_MODULE_NAME = "assessment_history_report_template"


class RenderError(ValueError):
    """The main report's template can't be used; the message says why."""


@dataclass(frozen=True)
class PageParts:
    """What the changes page borrows from the main report."""

    area_labels: dict[str, str]
    # Area icons as data URIs, ready for the UI.
    area_icons: dict[str, str]
    # (heading, areas), in the main report's navigation order
    nav_groups: tuple[tuple[str, tuple[str, ...]], ...]
    footer: list[Any]
    github_url: str
    safe_https_url: Callable[[object], str | None]
    render_page: Callable[[dict, str], str]
    severity_options: list[dict[str, str]]


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(TEMPLATE_MODULE_NAME, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as error:
        raise RenderError(f"can't load {path}: {error}") from None
    return module


def load_parts(path: Path = TEMPLATE_PATH) -> PageParts:
    """Read the parts the changes page reuses from the main report's template."""
    module = _load_module(path)
    try:
        standards = {
            standard["slug"]: standard for standard in module.COMPLIANCE_STANDARDS
        }
        owasp = standards["owasp"]
        aisf = standards["aisf"]
        area_labels = {
            # The main report's Assessment Area filter names.
            **{area: module.AREA_NAMES[area] for area in CORE_AREAS},
            "agentic": module.AREA_NAMES["agentic"],
            "responsible-ai-grc": module.RESPONSIBLE_AI_GRC_LABEL,
            "owasp": owasp["name"],
            "aisf": aisf["name"],
        }
        icons = {
            **{area: module.AREA_ICONS[area] for area in CORE_AREAS},
            "agentic": module.AGENTIC_ICON,
            "responsible-ai-grc": module.RESPONSIBLE_AI_GRC_ICON,
            "owasp": owasp["icon"],
            "aisf": aisf["icon"],
        }
        area_icons = {area: module.svg_data_uri(svg) for area, svg in icons.items()}
        nav_groups = (
            (module.SERVICES_NAV_HEADING, CORE_AREAS),
            (module.LENS_NAV_HEADING, ("agentic",)),
            (module.RESPONSIBLE_AI_GRC_NAV_HEADING, ("responsible-ai-grc",)),
            (module.COMPLIANCE_NAV_HEADING, ("owasp", "aisf")),
        )
        footer = module.rich(module.FOOTER_MARKUP)
        parts = PageParts(
            area_labels=area_labels,
            area_icons=area_icons,
            nav_groups=nav_groups,
            footer=footer,
            github_url=module.GITHUB_URL,
            safe_https_url=module._safe_https_url,
            render_page=module.render_page,
            severity_options=list(module.SEVERITY_OPTIONS),
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise RenderError(
            f"report_template.py no longer provides what the changes page uses: {error!r}"
        ) from None
    return parts


@functools.lru_cache(maxsize=1)
def page_parts() -> PageParts:
    """The borrowed parts, read once per process."""
    return load_parts()
