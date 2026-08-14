"""Parity guard between in-code provenance and the shipped compliance mappings.

COMPLIANCE_MAP values populate the Compliance_Frameworks CSV column, so they are
machine-readable regulatory assertions delivered to customers. The
COMPLIANCE_PLACEHOLDER list in each check's docstring is the in-code provenance
for those assertions.

These two sources disagreed on 23 framework-level points across 18 checks: 14
checks claimed a framework in provenance that the CSV omitted, and 8 asserted a
framework in the CSV with no provenance basis. This module fails if they diverge
again in either direction.

Comparison is at framework-FAMILY granularity. Section-level precision
differences (ISO 27001 A.12.5 versus A.12) are immaterial and collapse to one
family. Slash-joined citations such as "ECOA/Fair Housing" expand to both
families, so dropping one half cannot silently discard the other.
"""

from __future__ import annotations

import ast
import inspect
import re

import pytest

from .support import finserv_app as app

# (family name, lowercase substrings that identify it)
FAMILY_KEYS = [
    ("FFIEC CAT", ["ffiec"]),
    ("SR 11-7", ["sr 11-7", "sr11-7"]),
    ("NYDFS 500", ["nydfs"]),
    ("MAS TRM", ["mas trm"]),
    ("DORA", ["dora"]),
    ("PCI-DSS", ["pci"]),
    ("GDPR", ["gdpr"]),
    ("ECOA", ["ecoa"]),
    ("Fair Housing", ["fair housing"]),
    ("OWASP LLM", ["owasp"]),
    ("ISO 27001", ["iso 27001", "iso27001"]),
    ("EU AI Act", ["ai act"]),
    ("NIST", ["nist"]),
    ("WA FSI Lens", ["fsisec"]),
]


def _families(token: str) -> set:
    """Map one citation token to its framework family or families."""
    out = set()
    for part in token.split("/"):
        low = re.sub(r"\s+", " ", part).strip().lower()
        if not low:
            continue
        for name, keys in FAMILY_KEYS:
            if any(k in low for k in keys):
                out.add(name)
                break
        else:
            out.add(part.strip())
    return out


def _family_set(tokens) -> set:
    result = set()
    for token in tokens:
        result |= _families(token)
    return result


def _provenance_by_check() -> dict:
    """Extract COMPLIANCE_PLACEHOLDER lists keyed by the docstring's leading ID.

    Only the leading "FS-NN —" position attributes frameworks. Cross-references
    elsewhere in a docstring (for example "as with FS-08") must not transfer
    frameworks to another check.
    """
    tree = ast.parse(inspect.getsource(app))
    provenance: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        doc = ast.get_docstring(node) or ""
        placeholder = re.search(r"COMPLIANCE_PLACEHOLDER:\s*\[([^\]]*)\]", doc)
        leading = re.search(r"^\s*(FS-\d{2})\s*[—\-]", doc, re.M)
        if not (placeholder and leading):
            continue
        tokens = [t.strip() for t in placeholder.group(1).split(",") if t.strip()]
        provenance.setdefault(leading.group(1), set()).update(tokens)
    return provenance


PROVENANCE = _provenance_by_check()


def test_every_registry_check_has_provenance():
    """A shipped regulatory assertion must have an in-code basis."""
    for check_id in app.COMPLIANCE_MAP:
        assert check_id in PROVENANCE, f"{check_id} has no COMPLIANCE_PLACEHOLDER"


def test_provenance_covers_only_mapped_checks():
    for check_id in PROVENANCE:
        assert check_id in app.COMPLIANCE_MAP, (
            f"{check_id} has provenance but no COMPLIANCE_MAP entry"
        )


@pytest.mark.parametrize("check_id", sorted(app.COMPLIANCE_MAP))
def test_no_unfounded_framework_assertion(check_id):
    """Over-claim guard: the CSV must not assert a framework provenance omits.

    These are the release blockers — machine-readable regulatory claims with no
    stated basis, for example the former Fair Housing assertion on FS-40 and
    PCI-DSS on FS-46 and FS-66.
    """
    mapped = _family_set(
        t for t in app.COMPLIANCE_MAP[check_id].split("|") if t.strip()
    )
    documented = _family_set(PROVENANCE.get(check_id, set()))
    unfounded = mapped - documented
    assert not unfounded, (
        f"{check_id} asserts {sorted(unfounded)} in Compliance_Frameworks with no "
        f"provenance basis. Provenance: {sorted(documented)}"
    )


@pytest.mark.parametrize("check_id", sorted(app.COMPLIANCE_MAP))
def test_no_dropped_framework_mapping(check_id):
    """Under-map guard: provenance families must reach the CSV.

    For example GDPR on the three PII checks FS-43, FS-44, and FS-45, which
    provenance claimed but the CSV omitted.
    """
    mapped = _family_set(
        t for t in app.COMPLIANCE_MAP[check_id].split("|") if t.strip()
    )
    documented = _family_set(PROVENANCE.get(check_id, set()))
    missing = documented - mapped
    assert not missing, (
        f"{check_id} provenance claims {sorted(missing)} but Compliance_Frameworks "
        f"omits it. Mapped: {sorted(mapped)}"
    )


def test_reconciliation_is_complete():
    """Whole-corpus assertion, so a new check cannot be added unreconciled."""
    defects = []
    for check_id, value in app.COMPLIANCE_MAP.items():
        mapped = _family_set(t for t in value.split("|") if t.strip())
        documented = _family_set(PROVENANCE.get(check_id, set()))
        defects.extend(f"{check_id}:+{f}" for f in sorted(documented - mapped))
        defects.extend(f"{check_id}:-{f}" for f in sorted(mapped - documented))
    assert defects == [], f"{len(defects)} framework-level mismatches: {defects}"


def test_specific_over_claims_stay_removed():
    """Named regressions from the reconciliation."""
    assert "Fair Housing" not in app.COMPLIANCE_MAP["FS-40"]
    assert "PCI" not in app.COMPLIANCE_MAP["FS-46"]
    assert "PCI" not in app.COMPLIANCE_MAP["FS-66"]
    assert "OWASP" not in app.COMPLIANCE_MAP["FS-52"]
    assert "OWASP" not in app.COMPLIANCE_MAP["FS-54"]
    assert "DORA" not in app.COMPLIANCE_MAP["FS-65"]
    assert "FFIEC" not in app.COMPLIANCE_MAP["FS-43"]
    assert "FFIEC" not in app.COMPLIANCE_MAP["FS-45"]


def test_specific_under_maps_stay_added():
    """GDPR on all three PII checks, and ECOA on the explainability control."""
    for pii_check in ("FS-43", "FS-44", "FS-45"):
        assert "GDPR" in app.COMPLIANCE_MAP[pii_check]
    assert "ECOA" in app.COMPLIANCE_MAP["FS-41"]
    assert "ECOA" in app.COMPLIANCE_MAP["FS-40"]
    for mas_check in ("FS-35", "FS-36", "FS-42", "FS-47", "FS-59"):
        assert "MAS TRM" in app.COMPLIANCE_MAP[mas_check]
    assert "SR 11-7" in app.COMPLIANCE_MAP["FS-65"]
    for nydfs_check in ("FS-55", "FS-58"):
        assert "NYDFS" in app.COMPLIANCE_MAP[nydfs_check]
    assert "FFIEC" in app.COMPLIANCE_MAP["FS-56"]
    assert "DORA" in app.COMPLIANCE_MAP["FS-54"]
    assert "PCI" in app.COMPLIANCE_MAP["FS-54"]


def test_ecoa_incoherence_is_resolved():
    """FS-41 is the explainability control; adverse-action notices are its concern.

    Previously FS-39 and FS-40 carried ECOA while FS-41 carried neither, despite
    adverse-action reason codes being squarely an explainability matter.
    """
    assert "ECOA" in app.COMPLIANCE_MAP["FS-41"]
