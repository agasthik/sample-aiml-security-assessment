"""Presentation gate for the Responsible AI GRC rebrand.

The rebrand's central constraint is that labels change while machine identities
do not. tests/test_legacy_contracts.py pins the machine side; this module pins
the label side and, critically, asserts that the five retired capability names
never come back.

Before the rebrand the same capability appeared under five competing visible
names across ten hardcoded sites: FinServ, Financial Services, Financial
Services Risk, Financial Services GenAI Risk, and Financial Services GenAI Risk
Findings. Exactly one canonical label is permitted now.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)

if REPORT_DIR not in sys.path:
    sys.path.insert(0, REPORT_DIR)

_spec = importlib.util.spec_from_file_location(
    "grc_presentation_report_template", os.path.join(REPORT_DIR, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["grc_presentation_report_template"] = report_template
_spec.loader.exec_module(report_template)

CANONICAL_LABEL = "Responsible AI GRC"

# Every visible capability name the rebrand retires. None may appear in output.
RETIRED_LABELS = [
    "Financial Services Risk",
    "Financial Services GenAI Risk",
    "Financial Services GenAI Risk Findings",
    "<h3>By Industry</h3>",
    ">FinServ<",
]


def _render(with_capability: bool = True) -> str:
    findings = [
        {
            "account_id": "123456789012",
            "check_id": "FS-01",
            "finding": "Example Finding",
            "details": "Example details.",
            "resolution": "Example resolution.",
            "reference": "https://example.com/doc",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": "finserv" if with_capability else "bedrock",
        }
    ]
    slug = "finserv" if with_capability else "bedrock"
    return report_template.generate_html_report(
        all_findings=findings,
        service_findings={slug: findings},
        service_stats={slug: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )


@pytest.fixture(scope="module")
def html() -> str:
    return _render(with_capability=True)


@pytest.fixture(scope="module")
def html_without() -> str:
    return _render(with_capability=False)


# ---------------------------------------------------------------------------
# Centralized labels
# ---------------------------------------------------------------------------


def test_label_constants_are_centralized():
    """Ten label sites now resolve through these constants, not hardcoded text."""
    assert report_template.RESPONSIBLE_AI_GRC_LABEL == CANONICAL_LABEL
    assert report_template.RESPONSIBLE_AI_GRC_NAV_HEADING == "By Governance Framework"
    assert report_template.RESPONSIBLE_AI_GRC_SCOPE_LABEL == "Governance Framework"


def test_display_map_renames_the_slug_without_changing_it():
    assert report_template.RESPONSIBLE_AI_GRC_LABEL == CANONICAL_LABEL
    source = open(os.path.join(REPORT_DIR, "report_template.py")).read()
    assert '"finserv": RESPONSIBLE_AI_GRC_LABEL' in source
    assert '"finserv": "FinServ"' not in source


# ---------------------------------------------------------------------------
# Canonical label appears; retired names do not.
# ---------------------------------------------------------------------------


def test_canonical_label_renders(html):
    assert CANONICAL_LABEL in html


@pytest.mark.parametrize("retired", RETIRED_LABELS)
def test_retired_labels_do_not_render(html, retired):
    assert retired not in html


def test_no_financial_services_capability_label_anywhere(html):
    """The capability is cross-industry; the FSI label contradicted the rename.

    Financial-services provenance is recorded as origin and traceability in the
    docs and provenance record, not as a capability label in the report chrome.
    """
    assert "Financial Services" not in html


def test_taxonomy_moved_out_of_by_industry(html):
    assert "<h3>By Governance Framework</h3>" in html
    assert "<h3>By Industry</h3>" not in html
    assert '<div class="scope-industry-label">Governance Framework</div>' in html
    assert '<div class="scope-industry-label">Industry</div>' not in html


def test_capability_absent_from_the_by_service_nav(html):
    """It is a governance grouping, not a service."""
    by_service = html.split("<h3>By Service</h3>", 1)[1].split("<h3>", 1)[0]
    assert CANONICAL_LABEL not in by_service


# ---------------------------------------------------------------------------
# Machine identities survive the rename. Duplicated deliberately from
# test_legacy_contracts.py: this is the pairing that makes the rebrand safe, so
# it is asserted in the same breath as the label change.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "selector",
    [
        'id="finserv"',
        'href="#finserv"',
        'data-service="finserv"',
        'data-filter-service="finserv"',
        'data-scope-service="finserv"',
        '<option value="finserv">',
    ],
)
def test_selectors_survive_the_rename(html, selector):
    assert selector in html


@pytest.mark.parametrize(
    "css_class",
    [
        "industry-item",
        "industry-nav",
        "industry-chip",
        "scope-industry",
        "scope-industry-label",
    ],
)
def test_industry_css_classes_survive_the_rename(html, css_class):
    """The visible heading moved off "Industry"; the class names did not."""
    assert css_class in html


# ---------------------------------------------------------------------------
# Required qualification travels with the name.
# ---------------------------------------------------------------------------


def test_scope_statement_accompanies_the_name(html):
    assert "64 automated checks" in html
    assert "do not establish regulatory compliance" in html
    assert "Regulatory framework mappings are preliminary" in html


def test_lens_disambiguation_is_present(html):
    """Mandatory: the rename moves closer to the Lens than "FinServ" did."""
    assert "Responsible AI GRC is not the" in html
    assert "Responsible AI Lens" in html
    assert "eight focus areas" in html
    assert "does not" in html


def test_lens_is_never_claimed_as_implemented(html):
    for forbidden in (
        "implements the AWS Well-Architected Responsible AI Lens",
        "Responsible AI Lens compliant",
        "Responsible AI Lens alignment",
        "Responsible AI Lens coverage",
    ):
        assert forbidden not in html


def test_no_certification_or_completeness_claim(html):
    for forbidden in (
        "Responsible AI GRC certification",
        "Responsible AI GRC compliance",
        "Complete Responsible AI",
        "fully compliant",
    ):
        assert forbidden not in html


def test_source_shorthand_never_names_the_capability(html):
    """ "the Responsible AI GRC guide" is reserved for the AWS source document."""
    assert "Responsible AI GRC guide" not in html


# ---------------------------------------------------------------------------
# Absence behavior is unchanged.
# ---------------------------------------------------------------------------


def test_capability_chrome_omitted_when_no_findings(html_without):
    assert CANONICAL_LABEL not in html_without
    assert 'id="finserv"' not in html_without
    assert "<h3>By Governance Framework</h3>" not in html_without
    assert 'id="bedrock"' in html_without
