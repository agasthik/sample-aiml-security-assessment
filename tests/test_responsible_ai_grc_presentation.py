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
import json
import os
import sys

import pytest

from tests.report_data import area, nav_headings, report_data

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
PROVENANCE_PATH = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "responsible_ai_grc_assessments",
    "provenance.json",
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
CANONICAL_SLUG = "responsible-ai-grc"

# Every visible capability name the rebrand retires. None may appear in output.
RETIRED_LABELS = [
    "Financial Services Risk",
    "Financial Services GenAI Risk",
    "Financial Services GenAI Risk Findings",
    "By Industry",
    '"FinServ"',
]

# '"FinServ"' above only catches "FinServ" as a whole JSON string value -- it
# cannot catch the word inside a longer string (a finding name or resolution
# sentence). test_bare_finserv_word_is_absent_from_rendered_text below closes
# that gap with a substring check against the whole model text.
# The one legitimate survivor is the source PDF's URL slug
# (".../global-FinServ-ComplianceGuide-GenAIRisks-public.pdf"), which names an
# external AWS document, not this project's retired capability name.
_ACCEPTABLE_FINSERV_SUBSTRINGS = [
    "global-FinServ-ComplianceGuide-GenAIRisks-public.pdf",
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
            "_service": CANONICAL_SLUG if with_capability else "bedrock",
        }
    ]
    slug = CANONICAL_SLUG if with_capability else "bedrock"
    return report_template.generate_html_report(
        all_findings=findings,
        service_findings={slug: findings},
        service_stats={slug: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )


# The report page is the Cloudscape UI bundle plus an embedded JSON model; the
# model holds every word the report shows, so the text checks below read the
# model (serialized) rather than the bundle's source code.
@pytest.fixture(scope="module")
def data() -> dict:
    return report_data(_render(with_capability=True))


@pytest.fixture(scope="module")
def data_without() -> dict:
    return report_data(_render(with_capability=False))


@pytest.fixture(scope="module")
def html(data) -> str:
    return json.dumps(data, ensure_ascii=False)


@pytest.fixture(scope="module")
def html_without(data_without) -> str:
    return json.dumps(data_without, ensure_ascii=False)


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
    assert "RESPONSIBLE_AI_GRC_SLUG: RESPONSIBLE_AI_GRC_LABEL" in source
    assert '"finserv": "FinServ"' not in source
    assert '"finserv": RESPONSIBLE_AI_GRC_LABEL' not in source


# ---------------------------------------------------------------------------
# Canonical label appears; retired names do not.
# ---------------------------------------------------------------------------


def test_canonical_label_renders(html):
    assert CANONICAL_LABEL in html


@pytest.mark.parametrize("retired", RETIRED_LABELS)
def test_retired_labels_do_not_render(html, retired):
    assert retired not in html


def test_bare_finserv_word_is_absent_from_rendered_text(html):
    """Case-insensitive substring check over the whole report model.

    '"FinServ"' in RETIRED_LABELS only matches "FinServ" as a whole string
    value. It cannot catch the word occurring inside a longer string (a
    finding name, a resolution sentence) -- exactly the shape of the 7 finding_details/resolution
    leaks this test was added to close. Strip every substring known to be an
    acceptable, non-capability-name occurrence first (currently only the
    source PDF's URL slug), then require the word to be gone from what
    remains.
    """
    remaining = html
    for acceptable in _ACCEPTABLE_FINSERV_SUBSTRINGS:
        remaining = remaining.replace(acceptable, "")
    assert "finserv" not in remaining.lower(), (
        "A literal 'FinServ' occurrence survived outside the known-acceptable "
        "source-URL substrings -- likely a leaked finding_details/resolution "
        "string or check_name. Reword it to remove the retired capability name."
    )


def test_no_financial_services_capability_label_anywhere(html):
    """The capability is cross-industry; the FSI label contradicted the rename.

    Financial-services provenance is recorded as origin and traceability in the
    docs and provenance record, not as a capability label in the report chrome.
    """
    assert "Financial Services" not in html


def test_taxonomy_moved_out_of_by_industry(data):
    assert "By Governance Framework" in nav_headings(data)
    assert "By Industry" not in nav_headings(data)
    labels = [g["label"] for g in data["methodology"]["scopeGroups"]]
    assert "Governance Framework" in labels
    assert "Industry" not in labels


def test_capability_absent_from_the_by_service_nav(data):
    """It is a governance grouping, not a service."""
    by_service = next(g for g in data["navGroups"] if g["heading"] == "By Service")
    assert CANONICAL_SLUG not in by_service["areas"]
    governance = next(
        g for g in data["navGroups"] if g["heading"] == "By Governance Framework"
    )
    assert governance["areas"] == [CANONICAL_SLUG]


# ---------------------------------------------------------------------------
# Machine identity. Duplicated deliberately from test_legacy_contracts.py:
# this is the pairing that makes the rebrand safe, so it is asserted in the
# same breath as the label change. Unlike an earlier, additive-only revision
# of this capability, the machine identity itself changed here -- there is no
# legacy "finserv" selector or industry-* class left to assert alongside the
# label.
# ---------------------------------------------------------------------------


def test_machine_identity_uses_the_new_slug(data):
    """The slug is the section anchor id, the area filter value, and the row service.

    The Cloudscape report has no data-* attributes or <option> markup; the
    persisted identity lives in the model fields the UI turns into them.
    """
    grc = area(data, CANONICAL_SLUG)
    assert grc is not None and grc["name"] == CANONICAL_LABEL
    assert {"value": CANONICAL_SLUG, "label": CANONICAL_LABEL} in data["filters"][
        "areas"
    ]
    assert [f["service"] for f in data["findings"]] == [CANONICAL_SLUG]


def test_legacy_finserv_identity_is_retired(data, html):
    assert area(data, "finserv") is None
    assert all(o["value"] != "finserv" for o in data["filters"]["areas"])
    assert '"finserv"' not in html


def test_governance_grouping_fields_are_frozen(data):
    """Replaces the frozen governance-* CSS class checks: the Cloudscape UI has
    no such classes, so the grouping is frozen as model fields instead."""
    assert {"heading": "By Governance Framework", "areas": [CANONICAL_SLUG]} in data[
        "navGroups"
    ]
    group = next(
        g
        for g in data["methodology"]["scopeGroups"]
        if g["label"] == report_template.RESPONSIBLE_AI_GRC_SCOPE_LABEL
    )
    assert [c["label"] for c in group["chips"]] == [CANONICAL_LABEL]


@pytest.mark.parametrize(
    "legacy",
    ["industry-item", "industry-nav", "industry-chip", "scope-industry", "Industry"],
)
def test_legacy_industry_grouping_is_retired(data, html, legacy):
    assert legacy not in nav_headings(data)
    assert f'"{legacy}"' not in html


# ---------------------------------------------------------------------------
# Required qualification travels with the name.
# ---------------------------------------------------------------------------


def test_scope_statement_accompanies_the_name(html):
    assert "64 automated checks" in html
    assert "do not establish regulatory compliance" in html
    assert "Regulatory framework mappings are preliminary" in html


def test_scope_statement_check_count_matches_provenance():
    """The "64 automated checks" figure in RESPONSIBLE_AI_GRC_SCOPE_STATEMENT is a
    bare string literal in report_template.py, unconnected to any other source
    of truth for the check count. provenance.json's control_count (also
    generated, and gated against staleness by test_provenance.py) is that
    source of truth. This test is the tripwire: if the check count ever
    changes, this fails loudly instead of the two silently drifting apart.
    """
    with open(PROVENANCE_PATH) as handle:
        provenance = json.load(handle)
    expected = provenance["control_count"]
    assert (
        f"{expected} automated checks"
        in report_template.RESPONSIBLE_AI_GRC_SCOPE_STATEMENT
    ), (
        f"RESPONSIBLE_AI_GRC_SCOPE_STATEMENT says a different count than "
        f"provenance.json's control_count ({expected}). Update the literal in "
        f"report_template.py to match."
    )


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


def test_capability_chrome_omitted_when_no_findings(data_without, html_without):
    assert CANONICAL_LABEL not in html_without
    assert area(data_without, CANONICAL_SLUG) is None
    assert "By Governance Framework" not in nav_headings(data_without)
    assert area(data_without, "bedrock") is not None
