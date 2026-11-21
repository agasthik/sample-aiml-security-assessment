"""The "Changes since last assessment" HTML page for one account.

Built from a ``models.Comparison`` as a data model drawn by the main report's
Cloudscape UI (``render_common``). Layout and filters follow the main report:

- side navigation with the main report's area headings; following an area
  filters the changes table to it;
- header with both runs' saved times, days apart, the account, and a link to
  the current run's main report when it's known;
- six headline counts for the four services, and counts by area; a service
  not selected in both runs is shown as not selected, never as zero;
- the main report's findings table, with a Change column in place of Status.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from .models import CORE_AREAS, Change, ComparedRow, Comparison
from .render_common import PageParts, page_parts

TILE_ORDER = (
    Change.REGRESSED,
    Change.NEW,
    Change.STILL_OPEN,
    Change.RESOLVED,
    Change.NO_LONGER_REPORTED,
    Change.NO_LONGER_ASSESSED,
)
# Table order, and the order the Change column sorts in.
ROW_ORDER = TILE_ORDER + (Change.NOT_FAILING,)
# Cloudscape status tone for each change (D10.4). A status indicator always
# shows an icon and the word, so color is never the only clue.
TONES = {
    Change.REGRESSED: "error",
    Change.NEW: "error",
    Change.STILL_OPEN: "warning",
    Change.RESOLVED: "success",
    Change.NO_LONGER_REPORTED: "neutral",
    Change.NO_LONGER_ASSESSED: "info",
    Change.NOT_FAILING: "neutral",
}
TILE_DESCRIPTIONS = {
    Change.REGRESSED: "Passed before, failing now",
    Change.NEW: "Failing now, not before",
    Change.STILL_OPEN: "Failing in both runs",
    Change.RESOLVED: "Failing before, passing now",
    Change.NO_LONGER_REPORTED: "Failing before, not in this run",
    Change.NO_LONGER_ASSESSED: "Failing before, N/A now",
}
MAX_LISTED = 20
NOT_COUNTED = "\u2014"
NOT_SELECTED = "Not selected in both runs"
SAME_FOLDER_NOTE = (
    "Links work when these files are in the same folder, for example "
    "downloaded together or copied with aws s3 sync."
)


def change_slug(change: Change) -> str:
    """The value used for a change in data attributes and the Change filter."""
    return change.value.lower().replace(" ", "-")


def format_time(moment: datetime) -> str:
    """A saved time as shown on the page, e.g. "Sep 3, 2026 23:37 UTC"."""
    moment = moment.astimezone(UTC)
    return f"{moment:%b} {moment.day}, {moment:%Y %H:%M} UTC"


def days_apart_text(days: int) -> str:
    if days == 0:
        return "same day"
    if days == 1:
        return "1 day apart"
    return f"{days} days apart"


def _shown_by_default(counts: Counter) -> int:
    return sum(n for change, n in counts.items() if change is not Change.NOT_FAILING)


def _present(areas: tuple[str, ...], by_area: dict) -> list[str]:
    """Areas to show: the four services always, the others when compared."""
    return [area for area in areas if area in CORE_AREAS or area in by_area]


def _page_areas(parts: PageParts, by_area: dict) -> list[str]:
    """Every area the sidebar lists, in sidebar order. The area filter offers
    exactly these, so clicking any sidebar area selects it (review item L4)."""
    return [
        area
        for _heading, areas in parts.nav_groups
        for area in _present(areas, by_area)
    ]


def _join(names: list[str]) -> str:
    """ "A", "A and B", "A, B, and C"."""
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + ", and " + names[-1]


def _area_count(comparison, area: str, by_area: dict) -> str:
    """The sidebar count for an area: "—" for a service not compared."""
    if area in comparison.not_selected_services:
        return NOT_COUNTED
    return str(_shown_by_default(by_area.get(area, Counter())))


def _listing(items: dict[str, str], name) -> str:
    shown = [
        f"{name(item)} ({side})" for item, side in list(items.items())[:MAX_LISTED]
    ]
    if len(items) > MAX_LISTED:
        shown.append(f"and {len(items) - MAX_LISTED} more")
    return ", ".join(shown)


# --- the page's parts -------------------------------------------------------------


def _nav_groups(comparison, by_area, parts: PageParts) -> list[dict]:
    groups = []
    for heading, areas in parts.nav_groups:
        present = _present(areas, by_area)
        if present:
            groups.append(
                {
                    "heading": heading,
                    "areas": [
                        {
                            "slug": area,
                            "name": parts.area_labels[area],
                            "icon": parts.area_icons.get(area),
                            "count": _area_count(comparison, area, by_area),
                        }
                        for area in present
                    ],
                }
            )
    return groups


def _meta(comparison) -> list[str]:
    return [
        f"Previous run saved {format_time(comparison.previous_saved_at)}",
        f"Current run saved {format_time(comparison.current_saved_at)}",
        days_apart_text(comparison.days_apart),
        f"Account {comparison.account_id}",
    ]


def _tiles(comparison) -> list[dict]:
    services = comparison.compared_services
    counts = comparison.tile_counts()
    return [
        {
            "label": change.value,
            "value": str(counts[change]) if services else NOT_COUNTED,
            "description": TILE_DESCRIPTIONS[change],
            "tone": TONES[change],
        }
        for change in TILE_ORDER
    ]


def _tile_note(comparison, parts: PageParts) -> str:
    """What the headline counts cover, naming any service not compared."""
    names = [parts.area_labels[area] for area in comparison.compared_services]
    left_out = [parts.area_labels[area] for area in comparison.not_selected_services]
    if not names:
        return (
            f"None of {_join(left_out)} was selected in both runs, so there are no "
            "headline counts. The table below includes the assessment areas that "
            "were compared."
        )
    note = f"Counts are for {_join(names)}."
    if left_out:
        verb, pronoun = (
            ("was", "it isn't") if len(left_out) == 1 else ("were", "they aren't")
        )
        note += f" {_join(left_out)} {verb} not selected in both runs, so {pronoun} counted."
    return note + (
        " Agentic AI Security, OWASP and AWS AI Security Framework rows are mostly "
        "derived from those findings, "
        "so one change can appear in several areas. The table below includes all "
        "assessment areas."
    )


def _notes(comparison, parts: PageParts) -> list[str]:
    def name(area):
        return parts.area_labels.get(area, area)

    items = []
    if not comparison.has_changes:
        items.append("No changes since the last assessment.")
    if comparison.not_selected_services:
        items.append(
            "Not compared (not selected in both runs): "
            + _listing(comparison.not_selected_services, name)
        )
    if comparison.not_compared_options:
        items.append(
            "Not compared (enabled in only one run): "
            + _listing(comparison.not_compared_options, name)
        )
    if comparison.not_compared_regions:
        items.append(
            "Not compared (scanned in only one run): "
            + _listing(comparison.not_compared_regions, str)
        )
    if comparison.single_run_check_ids:
        items.append(
            "Check IDs found in only one run: "
            + _listing(comparison.single_run_check_ids, str)
        )
    return items + list(comparison.notes)


def _count_row(label: str, counts: Counter, row_type: str = "area") -> dict:
    return {
        "type": row_type,
        "label": label,
        "counts": [counts[change] for change in TILE_ORDER],
        "note": None,
    }


def _note_row(label: str, text: str, row_type: str = "area") -> dict:
    return {"type": row_type, "label": label, "counts": None, "note": text}


def _area_table(comparison, by_area, parts: PageParts) -> dict:
    rows = []
    for heading, areas in parts.nav_groups:
        present = _present(areas, by_area)
        if not present:
            continue
        rows.append({"type": "group", "label": heading, "counts": None, "note": None})
        rows += [
            _note_row(parts.area_labels[area], NOT_SELECTED)
            if area in comparison.not_selected_services
            else _count_row(parts.area_labels[area], by_area.get(area, Counter()))
            for area in present
        ]
        if areas == CORE_AREAS:
            rows.append(
                _count_row("By Service total", comparison.tile_counts(), "total")
                if comparison.compared_services
                else _note_row("By Service total", NOT_COUNTED, "total")
            )
    return {"columns": [change.value for change in TILE_ORDER], "rows": rows}


DETAILS_CHANGED = "details changed"
DETAILS_CHANGED_NOTE = (
    "Each run reported one Failed row for this check, so the two rows were paired, but their "
    "details differ. Check whether one resource was fixed and another started failing."
)


def _details(row: ComparedRow) -> list[dict]:
    previous = row.previous.details if row.previous else None
    current = row.current.details if row.current else None
    if previous is None or current is None or previous == current:
        text = previous if current is None else current
        return [{"label": "Details", "text": text or ""}]
    details = [
        {"label": "Details (previous run)", "text": previous},
        {"label": "Details (current run)", "text": current},
    ]
    if row.details_changed:
        details.append({"label": "Note", "text": DETAILS_CHANGED_NOTE})
    return details


def _statuses(row: ComparedRow) -> str:
    text = f"{row.previous_status} → {row.current_status}"
    if row.details_changed:
        text += f" · {DETAILS_CHANGED}"
    return text


def table_row(row: ComparedRow, parts: PageParts) -> dict:
    """One row of the changes table, in the UI's row shape."""
    return {
        "account": row.account_id,
        "region": row.region,
        "checkId": row.check_id,
        "finding": row.finding,
        "severity": row.severity,
        "service": row.area,
        "change": row.change.value,
        "changeSlug": change_slug(row.change),
        "rank": ROW_ORDER.index(row.change),
        "tone": TONES[row.change],
        "statuses": _statuses(row),
        "details": _details(row),
        "resolution": row.resolution,
        "reference": parts.safe_https_url(row.reference),
    }


def _filters(comparison, by_area, parts: PageParts) -> dict:
    regions = sorted({row.region for row in comparison.rows})
    return {
        "regions": [{"value": region.lower(), "label": region} for region in regions],
        "areas": [
            {"value": area, "label": parts.area_labels[area]}
            for area in _page_areas(parts, by_area)
        ],
        "severities": parts.severity_options,
        "changes": [{"value": "changes", "label": "All Changes"}]
        + [
            {"value": change_slug(change), "label": change.value}
            for change in TILE_ORDER
        ]
        + [
            {"value": "not-failing", "label": "Not failing"},
            {"value": "all", "label": "All Findings"},
        ],
        "defaultChange": "changes",
    }


CHANGE_STATE_MEANINGS = (
    (Change.REGRESSED, "Passed in the previous run, Failed now."),
    (Change.NEW, "Failed now; N/A or not present in the previous run."),
    (Change.STILL_OPEN, "Failed in both runs."),
    (Change.RESOLVED, "Failed in the previous run, Passed now."),
    (Change.NO_LONGER_REPORTED, "Failed in the previous run, not present now."),
    (
        Change.NO_LONGER_ASSESSED,
        "Failed in the previous run, N/A now. Not counted as resolved: "
        "N/A also covers access-denied and unavailable-region results.",
    ),
    (Change.NOT_FAILING, "No Failed result in either run. Hidden by default."),
)
MATCHING_STEPS = (
    "Rows are grouped by assessment area, Region, and Check ID. The Finding title isn't part of the group, because many checks use one title when they fail and another when they pass.",
    "Within a group, rows with the same title and identical details are paired, then rows whose details match once day counts and dates are blanked out, then rows with matching details under a different title.",
    'Two remaining rows are paired if each is its run\'s only row, in the group or with its title. If both are Failed and their details differ, the row is marked "details changed": one resource may have been fixed and another started failing.',
    "If one run has several Failed rows and the other a single row that isn't Failed, such as a Passed summary, each Failed row is paired with that row.",
    "Anything left is unpaired and shows as New or No longer reported.",
)
PREVIOUS_RUN_NOTE = (
    "The previous run is the most recent usable run saved before this one: its results "
    "are complete and, in single-account mode, its run record doesn't say it failed. "
    "Only services selected, optional modules enabled, and regions scanned in both runs "
    "are compared. The changes CSV records which rule paired each row. See "
    "docs/ASSESSMENT_HISTORY.md in the repository."
)


def changes_page_data(
    comparison: Comparison,
    *,
    csv_name: str,
    main_report_name: str | None = None,
    generated_at: datetime | None = None,
    parts: PageParts | None = None,
) -> dict:
    """The changes page's data model (see report-ui/src/types.ts, ChangesReport)."""
    if comparison.previous_saved_at is None or comparison.current_saved_at is None:
        raise ValueError("both runs need a saved time to render the changes page")
    parts = parts or page_parts()
    by_area = comparison.counts_by_area()
    rows = sorted(comparison.rows, key=lambda row: ROW_ORDER.index(row.change))
    return {
        "kind": "changes",
        "title": f"Changes Since Last Assessment - {comparison.account_id}",
        "heading": "Changes Since Last Assessment",
        "subtitle": "Changes Since Last Assessment",
        "accountId": comparison.account_id,
        "generated": format_time(generated_at or datetime.now(UTC)),
        "meta": _meta(comparison),
        "mainReport": main_report_name or None,
        "csvName": csv_name,
        "sameFolderNote": SAME_FOLDER_NOTE,
        "githubUrl": parts.github_url,
        "tiles": _tiles(comparison),
        "tileNote": _tile_note(comparison, parts),
        "notes": _notes(comparison, parts),
        "changedCount": sum(_shown_by_default(c) for c in by_area.values()),
        "navGroups": _nav_groups(comparison, by_area, parts),
        "areaTable": _area_table(comparison, by_area, parts),
        "rows": [table_row(row, parts) for row in rows],
        "filters": _filters(comparison, by_area, parts),
        "methodology": {
            "states": [
                {"change": change.value, "tone": TONES[change], "meaning": meaning}
                for change, meaning in CHANGE_STATE_MEANINGS
            ],
            "matching": list(MATCHING_STEPS),
            "previousRun": PREVIOUS_RUN_NOTE,
        },
        "footer": parts.footer,
    }


def render_changes_page(
    comparison: Comparison,
    *,
    csv_name: str,
    main_report_name: str | None = None,
    generated_at: datetime | None = None,
    parts: PageParts | None = None,
) -> str:
    """The changes page for one comparison, as HTML text.

    ``csv_name`` and ``main_report_name`` are file names in the same folder,
    linked relatively. Pass ``main_report_name`` only when the current run's
    main report is known for certain; otherwise the link is left out.
    """
    parts = parts or page_parts()
    data = changes_page_data(
        comparison,
        csv_name=csv_name,
        main_report_name=main_report_name,
        generated_at=generated_at,
        parts=parts,
    )
    return parts.render_page(data, data["title"])
