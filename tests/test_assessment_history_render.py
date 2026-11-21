"""The changes page (render_changes.py) and the parts it borrows (render_common.py).

The page is drawn in the browser by the main report's Cloudscape UI from a
JSON model embedded in the HTML. These tests check that model; open
sample-reports/security_assessment_changes.html in a browser to try the page.
"""

from datetime import UTC, datetime

import pytest

from assessment_history.compare import compare_runs
from assessment_history.models import AREAS
from assessment_history.render_changes import (
    DETAILS_CHANGED_NOTE,
    ROW_ORDER,
    TONES,
    change_slug,
    changes_page_data,
    days_apart_text,
    format_time,
    render_changes_page,
)
from assessment_history.render_common import (
    TEMPLATE_PATH,
    RenderError,
    load_parts,
    page_parts,
)
from tests.assessment_history_helpers import ACCOUNT, make_finding, make_run, utc
from tests.report_data import report_data, rich_text

CSV_NAME = "security_assessment_changes_20260927_061500.csv"
MAIN_REPORT = "security_assessment_single_account_20260927_061433.html"
GENERATED = datetime(2026, 9, 27, 6, 20, tzinfo=UTC)
TEMPLATE_TEXT = TEMPLATE_PATH.read_text(encoding="utf-8")


def _comparison(previous_rows, current_rows, *, previous=None, current=None):
    return compare_runs(
        make_run(
            previous_rows,
            execution_id="run-p",
            saved_at=utc(3, 23, 37),
            **(previous or {}),
        ),
        make_run(
            current_rows,
            execution_id="run-c",
            saved_at=utc(27, 6, 15),
            **(current or {}),
        ),
    )


def _page(comparison, **options):
    """The page's data model, as the Cloudscape UI receives it."""
    options.setdefault("csv_name", CSV_NAME)
    options.setdefault("generated_at", GENERATED)
    return changes_page_data(comparison, **options)


def _html(comparison, **options):
    options.setdefault("csv_name", CSV_NAME)
    options.setdefault("generated_at", GENERATED)
    return render_changes_page(comparison, **options)


def _every_state():
    previous = [
        make_finding("BR-01", "Passed", details="No roles found"),
        make_finding("BR-02", "Failed", severity="Medium"),
        make_finding("SM-26", "Failed", region="us-east-1"),
        make_finding("SM-02", "Failed", region="us-east-1", severity="Low"),
        make_finding("AC-09", "Failed", severity="Medium"),
        make_finding("AR-02", "N/A", severity="Informational"),
        make_finding("AC-17", "Passed"),
        make_finding("AG-01", "Passed", details="Source check BR-01"),
    ]
    current = [
        make_finding("BR-01", "Failed", details="Role 'admin' has the policy"),
        make_finding("BR-02", "Failed", severity="Medium"),
        make_finding("SM-26", "Passed", region="us-east-1"),
        make_finding("AC-09", "N/A", severity="Informational"),
        make_finding("AR-02", "Failed", severity="Medium"),
        make_finding("AC-17", "Passed"),
        make_finding("AG-01", "Failed", details="Source check BR-01"),
    ]
    return _comparison(previous, current)


# --- borrowed parts ----------------------------------------------------------------


def test_parts_are_borrowed_from_the_main_report():
    parts = page_parts()
    assert set(parts.area_labels) == set(AREAS) == set(parts.area_icons)
    for icon in parts.area_icons.values():
        assert icon.startswith("data:image/svg+xml;base64,")
    assert [heading for heading, _areas in parts.nav_groups] == [
        "By Service",
        "By Lens",
        "By Governance Framework",
        "By Compliance Standard",
    ]
    assert rich_text(parts.footer).startswith("Copyright Amazon.com, Inc.")
    assert parts.github_url.startswith("https://github.com/")
    assert [o["value"] for o in parts.severity_options] == [
        "high",
        "medium",
        "low",
        "informational",
    ]
    assert page_parts() is parts  # read once


def test_icons_and_names_match_the_main_report():
    parts = page_parts()
    template = load_parts.__globals__["_load_module"](TEMPLATE_PATH)
    for area in ("bedrock", "sagemaker", "agentcore", "agent-registry", "agentic"):
        assert parts.area_icons[area] == template.svg_data_uri(
            template.AREA_ICONS[area]
        )
        # The main report's Assessment Area filter uses the same names.
        assert parts.area_labels[area] == template.AREA_NAMES[area]


def test_the_page_uses_the_main_reports_cloudscape_shell():
    html = _html(_every_state())
    assert html.startswith("<!DOCTYPE html>")
    assert '<script type="application/json" id="report-data">' in html
    assert '<link rel="icon" type="image/svg+xml"' in html
    assert "<title>Changes Since Last Assessment - 123456789012</title>" in html
    template = load_parts.__globals__["_load_module"](TEMPLATE_PATH)
    assets = template.report_ui_assets()
    assert assets["js"] in html and assets["css"] in html
    assert report_data(html)["kind"] == "changes"


def test_a_missing_template_is_a_render_error(tmp_path):
    with pytest.raises(RenderError, match="can't load"):
        load_parts(tmp_path / "missing.py")


FAKE_TEMPLATE = """
COMPLIANCE_STANDARDS = [
    {"slug": "owasp", "name": "OWASP", "icon": "<svg></svg>"},
    {"slug": "aisf", "name": "AISF", "icon": "<svg></svg>"},
]
RESPONSIBLE_AI_GRC_LABEL = "GRC"
RESPONSIBLE_AI_GRC_NAV_HEADING = "By Governance Framework"
"""


@pytest.mark.parametrize(
    "source",
    [
        "def get_html_template():\n    return ''\n",
        FAKE_TEMPLATE.replace('"owasp"', '"nist"'),
        FAKE_TEMPLATE,
    ],
)
def test_a_changed_template_is_a_render_error(tmp_path, source):
    path = tmp_path / "report_template.py"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(RenderError, match="no longer provides"):
        load_parts(path)


def test_a_template_with_bad_footer_markup_is_a_render_error(tmp_path):
    # rich() raises ValueError for markup it doesn't accept.
    source = TEMPLATE_TEXT.replace(
        'f\'<a href="{AWS_CUSTOMER_AGREEMENT_URL}">AWS Customer Agreement</a>',
        "'<em>AWS Customer Agreement</em>",
        1,
    )
    assert source != TEMPLATE_TEXT
    path = tmp_path / "report_template.py"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(RenderError, match="no longer provides"):
        load_parts(path)


# --- small helpers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "days, text", [(0, "same day"), (1, "1 day apart"), (24, "24 days apart")]
)
def test_days_apart_text(days, text):
    assert days_apart_text(days) == text


def test_format_time_uses_utc():
    assert format_time(utc(3, 23, 37)) == "Sep 3, 2026 23:37 UTC"


def test_change_slugs():
    assert [change_slug(change) for change in ROW_ORDER] == [
        "regressed",
        "new",
        "still-open",
        "resolved",
        "no-longer-reported",
        "no-longer-assessed",
        "not-failing",
    ]


# --- the page ---------------------------------------------------------------------------


def test_header_shows_both_runs_and_the_account():
    page = _page(_every_state())
    assert page["kind"] == "changes"
    assert page["title"] == f"Changes Since Last Assessment - {ACCOUNT}"
    assert page["meta"] == [
        "Previous run saved Sep 3, 2026 23:37 UTC",
        "Current run saved Sep 27, 2026 06:15 UTC",
        "24 days apart",
        f"Account {ACCOUNT}",
    ]
    assert page["mainReport"] is None


def test_main_report_is_linked_when_known():
    page = _page(_every_state(), main_report_name=MAIN_REPORT)
    assert page["mainReport"] == MAIN_REPORT
    assert page["csvName"] == CSV_NAME
    assert page["sameFolderNote"].startswith(
        "Links work when these files are in the same folder"
    )


def test_without_a_main_report_only_the_csv_is_linked():
    page = _page(_every_state(), main_report_name="")
    assert page["mainReport"] is None
    assert page["csvName"] == CSV_NAME
    assert page["generated"] == "Sep 27, 2026 06:20 UTC"
    assert page["accountId"] == ACCOUNT


def test_tiles_count_the_four_services():
    page = _page(_every_state())
    tiles = {tile["label"]: int(tile["value"]) for tile in page["tiles"]}
    # AG-01 regressed too, but it's derived, so it isn't counted here.
    assert tiles == {
        "Regressed": 1,
        "New": 1,
        "Still open": 1,
        "Resolved": 1,
        "No longer reported": 1,
        "No longer assessed": 1,
    }
    assert page["tiles"][0]["tone"] == "error"
    assert page["tiles"][0]["description"] == "Passed before, failing now"
    assert page["tiles"][4]["tone"] == "neutral"


def _table_rows(page):
    return page["areaTable"]["rows"]


def test_area_table_groups_areas_under_the_main_reports_headings():
    page = _page(_every_state())
    assert page["areaTable"]["columns"] == [
        "Regressed",
        "New",
        "Still open",
        "Resolved",
        "No longer reported",
        "No longer assessed",
    ]
    rows = _table_rows(page)
    assert [(row["type"], row["label"]) for row in rows] == [
        ("group", "By Service"),
        ("area", "Bedrock"),
        ("area", "SageMaker"),
        ("area", "AgentCore"),
        ("area", "AWS Agent Registry"),
        ("total", "By Service total"),
        ("group", "By Lens"),
        ("area", "Agentic AI Security"),
    ]
    assert rows[1]["counts"] == [1, 0, 1, 0, 0, 0]
    assert rows[5]["counts"] == [1, 1, 1, 1, 1, 1]
    assert rows[7]["counts"] == [1, 0, 0, 0, 0, 0]


def _nav_counts(page):
    return {
        area["slug"]: area["count"]
        for group in page["navGroups"]
        for area in group["areas"]
    }


def test_navigation_lists_areas_with_the_rows_shown_by_default():
    page = _page(_every_state())
    assert _nav_counts(page) == {
        "bedrock": "2",
        "sagemaker": "2",
        "agentcore": "1",  # AC-17 is Not failing
        "agent-registry": "1",
        "agentic": "1",
    }
    assert page["changedCount"] == 7
    assert [group["heading"] for group in page["navGroups"]] == [
        "By Service",
        "By Lens",
    ]  # GRC wasn't compared
    bedrock = page["navGroups"][0]["areas"][0]
    assert bedrock["name"] == "Bedrock"
    assert bedrock["icon"] == page_parts().area_icons["bedrock"]


def test_changes_table_rows():
    page = _page(_every_state())
    rows = page["rows"]
    # Ordered by change, as the Change column sorts.
    assert [row["rank"] for row in rows] == sorted(row["rank"] for row in rows)
    regressed = rows[0]
    assert (regressed["changeSlug"], regressed["service"]) == ("regressed", "bedrock")
    assert (regressed["account"], regressed["region"], regressed["checkId"]) == (
        ACCOUNT,
        "Global",
        "BR-01",
    )
    assert regressed["severity"] == "High"
    assert regressed["change"] == "Regressed"
    assert regressed["statuses"] == "Passed → Failed"


def test_change_labels_use_status_tones():
    page = _page(_every_state())
    tones = {row["changeSlug"]: row["tone"] for row in page["rows"]}
    assert tones == {
        "regressed": "error",
        "new": "error",
        "still-open": "warning",
        "resolved": "success",
        "no-longer-reported": "neutral",
        "no-longer-assessed": "info",
        "not-failing": "neutral",
    }
    assert set(TONES) == set(ROW_ORDER)


def _row(page, check_id):
    return next(row for row in page["rows"] if row["checkId"] == check_id)


def _details(page, check_id):
    return [(d["label"], d["text"]) for d in _row(page, check_id)["details"]]


def test_details_show_both_runs_only_when_they_differ():
    page = _page(_every_state())
    assert _details(page, "BR-01") == [
        ("Details (previous run)", "No roles found"),
        ("Details (current run)", "Role 'admin' has the policy"),
    ]
    assert _details(page, "BR-02") == [("Details", "details")]  # same in both
    assert _details(page, "SM-02") == [("Details", "details")]  # previous only


def test_a_single_row_pair_with_changed_details_is_marked():
    # Review item F3: say when two Failed rows may be about different resources.
    comparison = _comparison(
        [
            make_finding("AC-17", details="No configurations found."),
            make_finding("BR-02", severity="Medium"),
        ],
        [
            make_finding("AC-17", details="Configuration 'eval-1' is incomplete."),
            make_finding("BR-02", severity="Medium"),
        ],
    )
    page = _page(comparison)
    assert {row["checkId"]: row["statuses"] for row in page["rows"]} == {
        "AC-17": "Failed → Failed · details changed",
        "BR-02": "Failed → Failed",
    }
    assert _details(page, "AC-17")[2] == ("Note", DETAILS_CHANGED_NOTE)
    assert [label for label, _ in _details(page, "BR-02")] == ["Details"]


def test_a_finding_only_in_the_current_run_shows_its_details():
    comparison = _comparison([], [make_finding("BR-05", details="only now")])
    assert _details(_page(comparison), "BR-05") == [("Details", "only now")]


def test_severity_shown_is_the_previous_runs_for_findings_that_went_away():
    page = _page(_every_state())
    assert _row(page, "AC-09")["severity"] == "Medium"  # No longer assessed
    assert _row(page, "SM-02")["severity"] == "Low"  # No longer reported
    assert _row(page, "AR-02")["severity"] == "Medium"  # New: current run's


def test_resource_text_is_escaped_and_unsafe_links_are_not_links():
    hostile = '<script>alert(1)</script> & "quoted"'
    comparison = _comparison(
        [],
        [
            make_finding(
                "BR-05",
                finding=hostile,
                details=hostile,
                resolution=hostile,
                reference="javascript:alert(1)",
            ),
            make_finding("BR-06", reference="https://docs.aws.amazon.com/x?a=1&b=2"),
        ],
    )
    html = _html(comparison)
    assert "<script>alert(1)</script>" not in html
    assert html.count("</script>") == 2  # the data element and the UI bundle
    page = report_data(html)
    assert _row(page, "BR-05")["finding"] == hostile  # kept as text, not markup
    assert _row(page, "BR-05")["resolution"] == hostile
    assert _row(page, "BR-05")["reference"] is None
    assert _row(page, "BR-06")["reference"] == "https://docs.aws.amazon.com/x?a=1&b=2"


def test_filters_offer_only_what_is_on_the_page():
    page = _page(_every_state())
    filters = page["filters"]
    assert [(o["value"], o["label"]) for o in filters["regions"]] == [
        ("global", "Global"),
        ("us-east-1", "us-east-1"),
    ]
    assert [(o["value"], o["label"]) for o in filters["areas"]] == [
        ("bedrock", "Bedrock"),
        ("sagemaker", "SageMaker"),
        ("agentcore", "AgentCore"),
        ("agent-registry", "AWS Agent Registry"),
        ("agentic", "Agentic AI Security"),
    ]
    changes = [(o["value"], o["label"]) for o in filters["changes"]]
    assert changes[0] == ("changes", "All Changes")
    assert filters["defaultChange"] == "changes"
    assert [value for value, _ in changes][1:] == [
        change_slug(change) for change in ROW_ORDER[:-1]
    ] + ["not-failing", "all"]
    assert [o["value"] for o in filters["severities"]] == [
        "high",
        "medium",
        "low",
        "informational",
    ]


def test_every_row_has_the_keys_the_ui_filters_on():
    page = _page(_every_state())
    area_values = {o["value"] for o in page["filters"]["areas"]}
    region_values = {o["value"] for o in page["filters"]["regions"]}
    change_values = {o["value"] for o in page["filters"]["changes"]}
    for row in page["rows"]:
        assert row["service"] in area_values
        assert row["region"].lower() in region_values
        assert row["changeSlug"] in change_values
    nav_areas = {a["slug"] for group in page["navGroups"] for a in group["areas"]}
    assert nav_areas == area_values


def _notes(page):
    return page["notes"]


def test_notes_list_what_was_not_compared():
    extra = [make_finding(f"BR-{number}") for number in range(40, 62)]
    comparison = _comparison(
        [make_finding("BR-01"), make_finding("SM-26", region="us-east-1")],
        [make_finding("BR-01"), *extra, make_finding("OW-03")],
        previous={"regions": {"us-east-1", "us-west-2"}},
        current={"regions": {"us-east-1"}},
    )
    notes = _notes(_page(comparison))
    assert notes[0] == (
        "Not compared (enabled in only one run): OWASP Top 10 LLM (current run only)"
    )
    assert (
        notes[1]
        == "Not compared (scanned in only one run): us-west-2 (previous run only)"
    )
    assert notes[2].startswith(
        "Check IDs found in only one run: BR-40 (current run only)"
    )
    assert notes[2].endswith(", and 3 more")


def test_no_changes_is_said_plainly_and_empty_areas_still_show():
    same = [make_finding("BR-01", "Failed")]
    page = _page(_comparison(same, same))
    assert _notes(page) == ["No changes since the last assessment."]
    assert [row["changeSlug"] for row in page["rows"]] == ["still-open"]
    assert len(_nav_counts(page)) == 4


def _nav_areas(page):
    return [area["slug"] for group in page["navGroups"] for area in group["areas"]]


def _area_options(page):
    return [option["value"] for option in page["filters"]["areas"]]


def test_every_navigation_area_can_be_selected_in_the_area_filter():
    # Review item L4: SageMaker, AgentCore and Agent Registry have no rows here.
    # Their navigation links used to set a value the filter didn't have, and
    # the browser then showed every area.
    same = [make_finding("BR-01", "Failed")]
    page = _page(_comparison(same, same))
    assert _nav_areas(page) == ["bedrock", "sagemaker", "agentcore", "agent-registry"]
    assert _area_options(page) == _nav_areas(page)
    assert [option["label"] for option in page["filters"]["areas"]] == [
        "Bedrock",
        "SageMaker",
        "AgentCore",
        "AWS Agent Registry",
    ]


@pytest.mark.parametrize("which", ["every state", "optional areas", "empty"])
def test_the_area_filter_and_the_navigation_list_the_same_areas(which):
    comparison = {
        "every state": _every_state,
        "optional areas": lambda: _comparison(
            [make_finding("FS-01"), make_finding("OW-03")],
            [make_finding("FS-01", "Passed"), make_finding("OW-03")],
        ),
        "empty": lambda: _comparison([], []),
    }[which]()
    page = _page(comparison)
    assert _area_options(page) == _nav_areas(page)


NOT_COUNTED = "—"
WITHOUT_SAGEMAKER = ("bedrock", "agentcore", "agent-registry")
OMITTED_SAGEMAKER_AISF = (
    "AWS AI Security Framework controls not compared "
    "(a source check's service was not selected in both runs): AISF-07, AISF-08"
)


def _deselected_page(current_modules):
    comparison = _comparison(
        [
            make_finding("BR-01", "Failed"),
            make_finding("SM-26", "Failed", region="us-east-1"),
        ],
        [make_finding("BR-01", "Passed")],
        current={"modules": current_modules},
    )
    return comparison, _page(comparison)


def _area_rows(page):
    return {
        row["label"]: row["counts"] if row["counts"] is not None else [row["note"]]
        for row in _table_rows(page)
        if row["type"] != "group"
    }


def test_a_service_not_selected_in_both_runs_is_not_shown_as_zero():
    comparison, page = _deselected_page(WITHOUT_SAGEMAKER)
    assert comparison.not_selected_services == {"sagemaker": "previous run only"}
    assert [row["service"] for row in page["rows"]] == ["bedrock"]
    rows = _area_rows(page)
    assert rows["SageMaker"] == ["Not selected in both runs"]
    assert rows["Bedrock"] == [0, 0, 0, 1, 0, 0]
    assert rows["By Service total"] == [0, 0, 0, 1, 0, 0]
    assert _nav_counts(page) == {
        "bedrock": "1",
        "sagemaker": NOT_COUNTED,
        "agentcore": "0",
        "agent-registry": "0",
    }
    assert _notes(page) == [
        "Not compared (not selected in both runs): SageMaker (previous run only)",
        OMITTED_SAGEMAKER_AISF,
    ]


def test_a_service_selected_again_is_not_shown_as_zero_either():
    # The other direction: SageMaker off in the previous run, on now.
    comparison = _comparison(
        [make_finding("BR-01", "Failed")],
        [
            make_finding("BR-01", "Passed"),
            make_finding("SM-26", "Failed", region="us-east-1"),
        ],
        previous={"modules": WITHOUT_SAGEMAKER},
    )
    page = _page(comparison)
    assert [row["service"] for row in page["rows"]] == ["bedrock"]
    assert _area_rows(page)["SageMaker"] == ["Not selected in both runs"]
    assert _nav_counts(page)["sagemaker"] == NOT_COUNTED
    assert _notes(page) == [
        "Not compared (not selected in both runs): SageMaker (current run only)",
        OMITTED_SAGEMAKER_AISF,
    ]
    assert page["tileNote"].startswith(
        "Counts are for Bedrock, AgentCore, and AWS Agent Registry. SageMaker "
        "was not selected in both runs, so it isn't counted."
    )


@pytest.mark.parametrize(
    "current_modules, note",
    [
        (
            WITHOUT_SAGEMAKER,
            "Counts are for Bedrock, AgentCore, and AWS Agent Registry. SageMaker "
            "was not selected in both runs, so it isn't counted.",
        ),
        (
            ("bedrock", "agent-registry"),
            "Counts are for Bedrock and AWS Agent Registry. SageMaker and AgentCore "
            "were not selected in both runs, so they aren't counted.",
        ),
        (
            ("bedrock",),
            "Counts are for Bedrock. SageMaker, AgentCore, and AWS Agent Registry "
            "were not selected in both runs, so they aren't counted.",
        ),
    ],
)
def test_the_tile_note_names_the_services_left_out(current_modules, note):
    _comparison_result, page = _deselected_page(current_modules)
    assert page["tileNote"].startswith(note + " Agentic AI Security")


def test_with_no_service_selected_in_both_runs_there_are_no_headline_counts():
    governance = {"modules": ("responsible-ai-grc", "owasp")}
    page = _page(
        _comparison(
            [make_finding("FS-01", "Failed")],
            [make_finding("FS-01", "Passed")],
            previous=governance,
            current=governance,
        )
    )
    assert [tile["value"] for tile in page["tiles"]] == [NOT_COUNTED] * 6
    assert page["tileNote"].startswith(
        "None of Bedrock, SageMaker, AgentCore, and AWS Agent Registry was selected "
        "in both runs, so there are no headline counts."
    )
    rows = _area_rows(page)
    for service in ("Bedrock", "SageMaker", "AgentCore", "AWS Agent Registry"):
        assert rows[service] == ["Not selected in both runs"], service
    assert rows["By Service total"] == [NOT_COUNTED]
    assert _notes(page)[0] == (
        "Not compared (not selected in both runs): Bedrock (neither run), "
        "SageMaker (neither run), AgentCore (neither run), "
        "AWS Agent Registry (neither run)"
    )


def test_no_notes_when_there_is_nothing_to_note():
    comparison = _comparison([make_finding("BR-01", "Passed")], [make_finding("BR-01")])
    assert _notes(_page(comparison)) == []


def test_an_empty_comparison_has_no_rows():
    page = _page(_comparison([], []))
    assert page["rows"] == []
    assert page["changedCount"] == 0


def test_optional_areas_appear_under_their_headings():
    comparison = _comparison(
        [make_finding("FS-01"), make_finding("OW-03")],
        [make_finding("FS-01", "Passed"), make_finding("OW-03")],
    )
    page = _page(comparison)
    groups = {group["heading"]: group["areas"] for group in page["navGroups"]}
    assert [a["slug"] for a in groups["By Governance Framework"]] == [
        "responsible-ai-grc"
    ]
    assert [a["slug"] for a in groups["By Compliance Standard"]] == ["owasp"]
    assert [row["label"] for row in _table_rows(page) if row["type"] == "group"] == [
        "By Service",
        "By Governance Framework",
        "By Compliance Standard",
    ]


def test_both_saved_times_are_required():
    comparison = compare_runs(
        make_run([], execution_id="run-p"), make_run([], execution_id="run-c")
    )
    with pytest.raises(ValueError, match="saved time"):
        render_changes_page(comparison, csv_name=CSV_NAME)


def test_generated_time_defaults_to_now():
    html = render_changes_page(_comparison([], []), csv_name=CSV_NAME)
    generated = report_data(html)["generated"]
    assert generated[:12] == format_time(datetime.now(UTC))[:12]


def test_methodology_explains_every_change_state():
    page = _page(_every_state())
    states = page["methodology"]["states"]
    assert [state["change"] for state in states] == [c.value for c in ROW_ORDER]
    assert [state["tone"] for state in states] == [TONES[c] for c in ROW_ORDER]
    # One item per matching step, in order (compare.py; review item F1).
    steps = page["methodology"]["matching"]
    assert len(steps) == 5
    assert "Region, and Check ID" in steps[0]
    assert "Finding title isn't part of the group" in steps[0]
    assert "under a different title" in steps[1]
    assert "its run's only row" in steps[2] and "details changed" in steps[2]
    assert "several Failed rows" in steps[3] and "Passed summary" in steps[3]
    assert "unpaired" in steps[4]
    assert "docs/ASSESSMENT_HISTORY.md" in page["methodology"]["previousRun"]


def test_the_footer_is_the_main_reports():
    assert _page(_every_state())["footer"] == page_parts().footer
