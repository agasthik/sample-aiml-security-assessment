"""Validation for the checked-in Responsible AI GRC provenance record.

provenance.json is generated from three sources that already exist in the repo:
the per-check [Guide §N.N.N] tags in docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md, the
COMPLIANCE_PLACEHOLDER docstrings in app.py, and COMPLIANCE_MAP. It is generated
AND checked in, so the record cannot drift silently.

These tests assert three things:
  1. the checked-in file matches a fresh generation (staleness gate),
  2. every control carries the provenance that IS derivable, and
  3. fields that require human authorship are explicitly null and declared in
     review_required rather than filled with invented prose.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from .support import finserv_app as app

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
GENERATOR = os.path.join(REPO_ROOT, "generate_provenance.py")
PROVENANCE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "responsible_ai_grc_assessments",
    "provenance.json",
)


@pytest.fixture(scope="module")
def provenance() -> dict:
    with open(PROVENANCE_PATH) as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def controls(provenance) -> dict:
    return {c["check_id"]: c for c in provenance["controls"]}


def test_generator_exists():
    assert os.path.exists(GENERATOR), "generate_provenance.py is the source of truth"


def test_checked_in_record_is_not_stale():
    """Regenerate and diff. Run `python generate_provenance.py` if this fails."""
    result = subprocess.run(
        [sys.executable, GENERATOR, "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"provenance.json is stale.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Coverage: every control in the registry must appear, and vice versa.
# ---------------------------------------------------------------------------


def test_every_compliance_map_check_has_provenance(controls):
    for check_id in app.COMPLIANCE_MAP:
        assert check_id in controls, f"{check_id} missing from provenance.json"


def test_provenance_has_no_orphan_controls(controls):
    for check_id, entry in controls.items():
        if entry.get("not_a_control"):
            continue
        assert check_id in app.COMPLIANCE_MAP, (
            f"{check_id} in provenance.json but not in COMPLIANCE_MAP"
        )


def test_control_count_is_sixty_four(provenance):
    assert provenance["control_count"] == 64


def test_fs_00_is_recorded_and_marked_not_a_control(controls):
    """FS-00 is emitted and CSV-persisted but is not a control.

    It is absent from build_finserv_checks() and COMPLIANCE_MAP, which is exactly
    why it needs an explicit record here.
    """
    assert "FS-00" in controls
    entry = controls["FS-00"]
    assert entry["not_a_control"] is True
    assert entry["regulatory_mapping_status"] == "not-applicable"
    assert entry["regulatory_mapping_shipped"] == []
    assert entry["derivation_rationale"], "FS-00 needs a stated reason for existing"


# ---------------------------------------------------------------------------
# Derivable provenance must be present for every real control.
# ---------------------------------------------------------------------------


def _real_controls(controls):
    return {k: v for k, v in controls.items() if not v.get("not_a_control")}


def test_every_control_has_a_guide_section(controls):
    """Section granularity is the repository's provenance contract."""
    missing = [
        cid for cid, c in _real_controls(controls).items() if not c["source_section"]
    ]
    assert missing == [], f"controls with no [Guide §...] tag: {missing}"


def test_every_control_has_a_derivation_type(controls):
    for cid, entry in controls.items():
        assert entry["derivation_type"] in ("direct-derived", "project-extension"), (
            f"{cid} has derivation_type {entry['derivation_type']!r}"
        )


def test_extension_controls_are_not_presented_as_source_requirements(controls):
    """A project extension must never be labelled as guide-derived."""
    extensions = [
        cid
        for cid, c in controls.items()
        if c["derivation_type"] == "project-extension"
    ]
    # 10 documented extensions plus FS-00, which is a project artifact.
    assert len(extensions) == 11, f"expected 11, got {len(extensions)}: {extensions}"
    assert "FS-00" in extensions


def test_every_control_records_inspected_evidence(controls):
    missing = [
        cid
        for cid, c in _real_controls(controls).items()
        if not c["inspected_aws_evidence"]
    ]
    assert missing == [], f"controls with no inspected_aws_evidence: {missing}"


def test_every_control_has_a_mapping_status(controls):
    for cid, entry in controls.items():
        assert entry["regulatory_mapping_status"] in (
            "preliminary",
            "reviewed",
            "validated",
            "not-applicable",
        ), f"{cid} status {entry['regulatory_mapping_status']!r}"


def test_mappings_are_declared_preliminary(controls):
    """No mapping may claim reviewed or validated without a review record."""
    for cid, entry in _real_controls(controls).items():
        assert entry["regulatory_mapping_status"] == "preliminary", (
            f"{cid} claims {entry['regulatory_mapping_status']} without evidence"
        )


# ---------------------------------------------------------------------------
# The shipped mapping must equal COMPLIANCE_MAP exactly.
# ---------------------------------------------------------------------------


def test_shipped_mapping_matches_compliance_map(controls):
    for check_id, value in app.COMPLIANCE_MAP.items():
        expected = [t.strip() for t in value.split("|") if t.strip()]
        assert controls[check_id]["regulatory_mapping_shipped"] == expected, (
            f"{check_id} provenance disagrees with COMPLIANCE_MAP"
        )


def test_corrected_controls_carry_authored_unsupported_assertions(controls):
    """The six evidence-corrected controls state what they do not prove."""
    for check_id in ("FS-08", "FS-28", "FS-39", "FS-41", "FS-66", "FS-67"):
        assert controls[check_id]["unsupported_assertions"], (
            f"{check_id} was corrected but records no unsupported_assertions"
        )


# ---------------------------------------------------------------------------
# Honesty gate: null means "needs a human", never "invented".
# ---------------------------------------------------------------------------


def test_null_fields_are_declared_in_review_required(controls):
    for cid, entry in _real_controls(controls).items():
        if entry["derivation_rationale"] is None:
            assert "derivation_rationale" in entry["review_required"], (
                f"{cid} has a null derivation_rationale that is not declared"
            )
        if not entry["unsupported_assertions"]:
            assert "unsupported_assertions" in entry["review_required"], (
                f"{cid} has no unsupported_assertions and does not declare it"
            )


def test_declared_review_fields_are_actually_empty(controls):
    """The inverse: review_required must not list a field that is populated."""
    for cid, entry in controls.items():
        for field in entry["review_required"]:
            assert not entry.get(field), (
                f"{cid} lists {field} as needing review but it is populated"
            )


def test_record_disclaims_the_responsible_ai_lens(provenance):
    text = provenance["not_the_responsible_ai_lens"]
    assert "not the AWS Well-Architected Responsible AI Lens" in text
    assert "eight focus areas" in text


def test_capability_name_and_qualifier(provenance):
    assert provenance["capability"] == "Responsible AI GRC"
    assert "Cross-industry" in provenance["capability_scope_qualifier"]


def test_source_shorthand_does_not_collide_with_the_capability_name(provenance):
    """The source is "the AWS GRC User Guide", never "the Responsible AI GRC guide"."""
    primary = provenance["sources"][0]
    assert primary["source_shorthand"] == "the AWS GRC User Guide"
    blob = json.dumps(provenance)
    assert "Responsible AI GRC guide" not in blob
