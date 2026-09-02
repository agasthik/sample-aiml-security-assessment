"""Professional PDF renderer for AI/ML security assessment reports."""

from io import BytesIO
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from report_model import build_report_model, service_display_name


NAVY = colors.HexColor("#172B4D")
BLUE = colors.HexColor("#2563EB")
LIGHT_BLUE = colors.HexColor("#EFF6FF")
GREEN = colors.HexColor("#15803D")
LIGHT_GREEN = colors.HexColor("#F0FDF4")
AMBER = colors.HexColor("#B45309")
LIGHT_AMBER = colors.HexColor("#FFFBEB")
RED = colors.HexColor("#B91C1C")
LIGHT_RED = colors.HexColor("#FEF2F2")
SLATE = colors.HexColor("#475569")
LIGHT_SLATE = colors.HexColor("#F8FAFC")
BORDER = colors.HexColor("#CBD5E1")
WHITE = colors.white

# Severity is an ordered scale, so the severity chart uses a single-hue
# sequential ramp (palest = low, darkest = high) rather than three unrelated
# status hues: the red/amber pair used for table tints is only 9 Delta E apart
# for normal vision and under 6 for deuteranopia, which is too close for two
# touching segments of one stacked bar. Every bar also carries a direct total
# label, and the same numbers appear in the theme and coverage tables, so the
# palest step never has to carry meaning through contrast alone.
SEVERITY_LOW = colors.HexColor("#FCA5A5")
SEVERITY_MEDIUM = colors.HexColor("#DC2626")
SEVERITY_HIGH = colors.HexColor("#7F1D1D")

CHART_WIDTH = 6.4 * inch
CHART_BAND = 26.0


def _pdf_text(value: Any) -> str:
    """Escape report text and normalize punctuation unsupported by base fonts."""
    text = "" if value is None else str(value)
    replacements = {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\u00b7": "-",
        "\u2022": "-",
        "\u2026": "...",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
    }
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    return escape(text)


def _safe_reference(value: str) -> str:
    raw = (value or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme == "https" and parsed.netloc:
        return raw
    return ""


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=30,
            textColor=NAVY,
            alignment=TA_LEFT,
            spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=SLATE,
            spaceAfter=10,
        ),
        "h1": ParagraphStyle(
            "ReportH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=NAVY,
            spaceBefore=8,
            spaceAfter=10,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "ReportH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "ReportH3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=NAVY,
            spaceBefore=6,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=12.5,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=SLATE,
            spaceAfter=3,
        ),
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=WHITE,
        ),
        "metric_value": ParagraphStyle(
            "MetricValue",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=20,
            textColor=NAVY,
            alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "MetricLabel",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=SLATE,
            alignment=TA_CENTER,
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=NAVY,
            spaceBefore=7,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "label": ParagraphStyle(
            "FindingLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=SLATE,
        ),
        "reference": ParagraphStyle(
            "Reference",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=BLUE,
            wordWrap="CJK",
            spaceAfter=4,
        ),
        "disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.2,
            leading=10,
            textColor=SLATE,
            borderColor=BORDER,
            borderWidth=0.5,
            borderPadding=7,
            backColor=LIGHT_SLATE,
            spaceBefore=8,
        ),
    }


def _page_chrome(canvas, doc) -> None:
    canvas.saveState()
    width, height = letter
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(
        doc.leftMargin,
        height - 0.48 * inch,
        width - doc.rightMargin,
        height - 0.48 * inch,
    )
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(NAVY)
    canvas.drawString(doc.leftMargin, height - 0.38 * inch, "AI/ML Security Assessment")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawRightString(
        width - doc.rightMargin,
        0.38 * inch,
        f"Page {doc.page}",
    )
    canvas.line(doc.leftMargin, 0.48 * inch, width - doc.rightMargin, 0.48 * inch)
    canvas.restoreState()


_TOC_LEVELS = {"ReportH1": 0, "ReportH2": 1}


def _toc_headings(flowable: Any) -> Iterable[Any]:
    """Yield heading paragraphs, including any nested inside a container."""
    content = getattr(flowable, "_content", None)
    if content:
        for item in content:
            yield from _toc_headings(item)
        return
    style = getattr(flowable, "style", None)
    if style is not None and getattr(style, "name", "") in _TOC_LEVELS:
        yield flowable


class _ReportDocTemplate(BaseDocTemplate):
    """Document template that records headings for the contents page and outline.

    Platypus only learns which page a heading landed on after layout, so the
    story is laid out twice through ``multiBuild``. ``afterFlowable`` runs on
    each pass and notifies the table of contents while registering a matching
    PDF outline entry, so the two always agree.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="body",
        )
        self.addPageTemplates(
            [PageTemplate(id="report", frames=[frame], onPage=_page_chrome)]
        )
        self._heading_index = 0

    def handle_documentBegin(self) -> None:
        # Keys must be identical on both layout passes for the contents links
        # to resolve, so the counter restarts with each pass.
        self._heading_index = 0
        super().handle_documentBegin()

    def afterFlowable(self, flowable: Any) -> None:
        for heading in _toc_headings(flowable):
            level = _TOC_LEVELS[heading.style.name]
            text = heading.getPlainText()
            key = f"heading-{self._heading_index}"
            self._heading_index += 1
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=False)
            self.notify("TOCEntry", (level, text, self.page, key))


def _table_of_contents(styles: Dict[str, ParagraphStyle]) -> TableOfContents:
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [
        ParagraphStyle(
            "TocLevel0",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=16,
            textColor=NAVY,
            spaceBefore=4,
        ),
        ParagraphStyle(
            "TocLevel1",
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=SLATE,
            leftIndent=14,
        ),
    ]
    return toc


def _metric_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    metrics = model["metrics"]
    items = [
        ("Checks represented", metrics["unique_checks"], LIGHT_BLUE),
        ("Direct pass rate", f"{metrics['pass_rate']}%", LIGHT_GREEN),
        ("High failed", metrics["failed_high"], LIGHT_RED),
        ("Medium failed", metrics["failed_medium"], LIGHT_AMBER),
        ("Low failed", metrics["failed_low"], LIGHT_BLUE),
        ("N/A direct rows", metrics["na_direct"], LIGHT_SLATE),
    ]
    cells = []
    for label, value, background in items:
        cells.append(
            Table(
                [
                    [Paragraph(_pdf_text(value), styles["metric_value"])],
                    [Paragraph(_pdf_text(label), styles["metric_label"])],
                ],
                colWidths=[1.02 * inch],
                rowHeights=[0.29 * inch, 0.28 * inch],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), background),
                        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                ),
            )
        )
    table = Table([cells], colWidths=[1.08 * inch] * len(cells), hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _scope_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    scope_regions = list(model["regions"])
    if model["has_global_scope"]:
        scope_regions.append("Global")
    rows = [
        [
            Paragraph("<b>Assessment mode</b>", styles["small"]),
            Paragraph(
                "Multi-account" if model["mode"] == "multi" else "Single-account",
                styles["small"],
            ),
        ],
        [
            Paragraph("<b>Account IDs</b>", styles["small"]),
            Paragraph(
                _pdf_text(", ".join(model["accounts"]) or "Unknown"), styles["small"]
            ),
        ],
        [
            Paragraph("<b>Regions / scope</b>", styles["small"]),
            Paragraph(
                _pdf_text(", ".join(scope_regions) or "Not reported"), styles["small"]
            ),
        ],
        [
            Paragraph("<b>Generated</b>", styles["small"]),
            Paragraph(_pdf_text(model["timestamp"]), styles["small"]),
        ],
    ]
    table = Table(rows, colWidths=[1.25 * inch, 5.15 * inch], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_SLATE),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _posture_callout(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    tone_colors = {
        "high": (LIGHT_RED, RED),
        "medium": (LIGHT_AMBER, AMBER),
        "low": (LIGHT_BLUE, BLUE),
        "clear": (LIGHT_GREEN, GREEN),
    }
    background, accent = tone_colors[model["posture"]["tone"]]
    content = Paragraph(
        f"<b>{_pdf_text(model['posture']['label'])}</b><br/>"
        f"{_pdf_text(model['posture']['summary'])}",
        styles["body"],
    )
    table = Table([[content]], colWidths=[6.4 * inch], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.8, accent),
                ("LINEBEFORE", (0, 0), (0, -1), 4, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _name_list(names: List[str], limit: int = 3) -> str:
    """Join names for a sentence, summarizing the tail past ``limit``."""
    if len(names) <= limit:
        return ", ".join(names)
    return f"{', '.join(names[:limit])}, and {len(names) - limit} more"


def _key_takeaways(
    model: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> List[Paragraph]:
    metrics = model["metrics"]
    takeaways = [
        (
            f"{metrics['direct_unique_checks']} direct checks are represented by "
            f"{metrics['direct_rows']} direct rows; {metrics['passed_scored']} passed "
            f"and {metrics['failed_scored']} failed among scored rows."
        ),
        (
            f"The reported scope covers {len(model['accounts'])} account(s) and "
            f"{len(model['regions'])} regional scope(s)"
            f"{' plus global controls' if model['has_global_scope'] else ''}."
        ),
    ]
    if model["concerns"]:
        leading = model["concerns"][0]
        takeaways.append(
            f"Risk is most concentrated in {leading['name'].lower()}: "
            f"{leading['failed']} failed direct row(s) covering "
            f"{leading['failed_high']} high, {leading['failed_medium']} medium, and "
            f"{leading['failed_low']} low severity."
        )
    else:
        takeaways.append(
            "No failed high, medium, or low severity direct findings were observed."
        )
    takeaways.append(
        f"Weighted failed severity is {metrics['weighted_severity_score']} "
        "(high x 9 + medium x 3 + low x 1). It orders findings within this report "
        "and is not comparable to any external risk score."
    )
    takeaways.append(
        f"{metrics['contextual_unique_checks']} contextual checks add Agentic AI or "
        f"compliance views across {metrics['contextual_rows']} rows; these are not "
        "double-counted in direct posture totals."
    )
    for summary in model["standard_summaries"]:
        unit = (
            summary["unit"] if summary["represented"] == 1 else summary["unit_plural"]
        )
        if summary["affected"]:
            takeaways.append(
                f"{summary['standard']}: {summary['affected']} of "
                f"{summary['represented']} represented {unit} carry at least one "
                f"failed finding ({_name_list(summary['names'])})."
            )
        else:
            takeaways.append(
                f"{summary['standard']}: no failed findings across "
                f"{summary['represented']} represented {unit}."
            )
    return [
        Paragraph(f"&#8226;&nbsp; {_pdf_text(takeaway)}", styles["body"])
        for takeaway in takeaways
    ]


def _example_text(examples: List[Dict[str, str]]) -> str:
    return "; ".join(
        f"{example['check_id']} {example['finding']}" for example in examples
    )


def _header_cell(label: str, styles: Dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(
        f'<font color="#FFFFFF"><b>{_pdf_text(label)}</b></font>',
        styles["table_header"],
    )


def _strengths_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Control theme", styles),
            _header_cell("Observed evidence", styles),
            _header_cell("Coverage", styles),
        ]
    ]
    for theme in model["strengths"][:6]:
        coverage = (
            f"{theme['passed']} passed row(s); {theme['unique_checks']} check(s); "
            f"{len(theme['accounts'])} account(s); {len(theme['regions'])} scope(s)"
        )
        rows.append(
            [
                Paragraph(_pdf_text(theme["name"]), styles["small"]),
                Paragraph(
                    _pdf_text(
                        _example_text(theme["passed_examples"])
                        or "Passed controls were observed."
                    ),
                    styles["small"],
                ),
                Paragraph(_pdf_text(coverage), styles["small"]),
            ]
        )
    return _styled_table(rows, [1.75 * inch, 3.15 * inch, 1.5 * inch])


def _concerns_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Priority theme", styles),
            _header_cell("Observed gaps", styles),
            _header_cell("Potential security impact", styles),
        ]
    ]
    for theme in model["concerns"][:6]:
        severity = (
            f"{theme['failed']} failed: {theme['failed_high']} high, "
            f"{theme['failed_medium']} medium, {theme['failed_low']} low. "
        )
        examples = _example_text(theme["failed_examples"])
        rows.append(
            [
                Paragraph(_pdf_text(theme["name"]), styles["small"]),
                Paragraph(_pdf_text(severity + examples), styles["small"]),
                Paragraph(_pdf_text(theme["impact"]), styles["small"]),
            ]
        )
    return _styled_table(rows, [1.65 * inch, 2.65 * inch, 2.1 * inch])


def _action_plan_table(
    model: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Target window", styles),
            _header_cell("Control focus", styles),
            _header_cell("Recommended response", styles),
            _header_cell("Suggested owner", styles),
        ]
    ]
    for item in model["action_plan"][:8]:
        rows.append(
            [
                Paragraph(_pdf_text(item["timeframe"]), styles["small"]),
                Paragraph(
                    f"<b>{_pdf_text(item['theme'])}</b><br/>"
                    f"{item['failed']} failed row(s)",
                    styles["small"],
                ),
                Paragraph(_pdf_text(item["focus"]), styles["small"]),
                Paragraph(_pdf_text(item["owner"]), styles["small"]),
            ]
        )
    return _styled_table(
        rows,
        [0.9 * inch, 1.8 * inch, 2.25 * inch, 1.45 * inch],
    )


def _concentration_table(
    model: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Dimension", styles),
            _header_cell("Scope with failed direct rows", styles),
            _header_cell("High", styles),
            _header_cell("Medium", styles),
            _header_cell("Low", styles),
            _header_cell("Total", styles),
        ]
    ]
    dimensions = (
        ("Service", model["concentration"]["services"]),
        ("Account", model["concentration"]["accounts"]),
        ("Region", model["concentration"]["regions"]),
    )
    for dimension, items in dimensions:
        for index, item in enumerate(items[:3]):
            rows.append(
                [
                    Paragraph(dimension if index == 0 else "", styles["small"]),
                    Paragraph(_pdf_text(item["label"]), styles["small"]),
                    Paragraph(str(item["high"]), styles["small"]),
                    Paragraph(str(item["medium"]), styles["small"]),
                    Paragraph(str(item["low"]), styles["small"]),
                    Paragraph(str(item["failed"]), styles["small"]),
                ]
            )
    return _styled_table(
        rows,
        [0.75 * inch, 3.25 * inch, 0.6 * inch, 0.65 * inch, 0.55 * inch, 0.6 * inch],
        numeric_start=2,
    )


def _styled_table(
    rows: List[List[Any]],
    col_widths: List[float],
    *,
    numeric_start: int = None,
) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if numeric_start is not None:
        commands.append(("ALIGN", (numeric_start, 1), (-1, -1), "CENTER"))
    for row_index in range(2, len(rows), 2):
        commands.append(("BACKGROUND", (0, row_index), (-1, row_index), LIGHT_SLATE))
    table.setStyle(TableStyle(commands))
    return table


def _theme_paragraphs(
    themes: Iterable[Dict[str, Any]],
    styles: Dict[str, ParagraphStyle],
    *,
    positive: bool,
    limit: int = 4,
) -> List[Paragraph]:
    paragraphs = []
    for theme in list(themes)[:limit]:
        if positive and theme["failed"] == 0:
            sentence = (
                f"<b>{_pdf_text(theme['name'])}</b>: "
                f"{theme['passed']} passed row(s) across "
                f"{theme['unique_checks']} represented check(s), with no failed rows "
                "observed in this theme."
            )
        elif positive:
            sentence = (
                f"<b>{_pdf_text(theme['name'])}</b>: "
                f"{theme['passed']} passed and {theme['failed']} failed row(s) "
                f"({theme['pass_rate']}% pass rate among evaluated rows)."
            )
        else:
            sentence = (
                f"<b>{_pdf_text(theme['name'])}</b>: "
                f"{theme['failed']} failed row(s), including "
                f"{theme['failed_high']} high, {theme['failed_medium']} medium, "
                f"and {theme['failed_low']} low severity."
            )
        paragraphs.append(Paragraph(sentence, styles["body"]))
    return paragraphs


def _axis_bounds(peak: int) -> tuple:
    """Round a value axis up to a clean maximum and tick step."""
    peak = max(int(peak), 1)
    for step in (1, 2, 3, 5, 10, 20, 25, 50, 100, 250, 500, 1000):
        if peak <= step * 4:
            return step * 4, step
    return peak, max(peak // 4, 1)


def _configure_bar_chart(chart: HorizontalBarChart, peak: int) -> int:
    """Apply the shared recessive axis and mark styling to a bar chart."""
    value_max, value_step = _axis_bounds(peak)
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = value_max
    chart.valueAxis.valueStep = value_step
    chart.valueAxis.strokeColor = BORDER
    chart.valueAxis.strokeWidth = 0.5
    chart.valueAxis.visibleGrid = 1
    chart.valueAxis.gridStrokeColor = BORDER
    chart.valueAxis.gridStrokeWidth = 0.4
    chart.valueAxis.gridStrokeDashArray = None
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.labels.fillColor = SLATE
    chart.categoryAxis.strokeColor = BORDER
    chart.categoryAxis.strokeWidth = 0.5
    chart.categoryAxis.visibleTicks = 0
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7.5
    chart.categoryAxis.labels.fillColor = NAVY
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.labels.dx = -4
    # White strokes render as the surface gap that separates touching marks.
    chart.bars.strokeColor = WHITE
    chart.bars.strokeWidth = 1.2
    chart.groupSpacing = 12
    chart.barSpacing = 0
    return value_max


def _tip_labels(
    drawing: Drawing,
    chart: HorizontalBarChart,
    totals: List[int],
    value_max: int,
) -> None:
    """Write each bar's total just past its tip, in text ink rather than the
    mark colour, so the value is never carried by the fill alone."""
    band = chart.height / max(len(totals), 1)
    for index, total in enumerate(totals):
        x = chart.x + (total / value_max) * chart.width + 4
        y = chart.y + (index + 0.5) * band - 3
        drawing.add(
            String(
                x,
                y,
                str(total),
                fontName="Helvetica-Bold",
                fontSize=7.5,
                fillColor=SLATE,
            )
        )


def _severity_chart(model: Dict[str, Any]) -> Any:
    """Stacked bars: failed direct rows per assessment area, split by severity."""
    areas = model["area_severity"][:6]
    if not areas:
        return None
    ordered = list(reversed(areas))  # the chart draws categories bottom-up
    label_width = 108.0
    plot_height = CHART_BAND * len(ordered)
    axis_height = 22.0
    legend_height = 18.0
    drawing = Drawing(CHART_WIDTH, plot_height + axis_height + legend_height)
    chart = HorizontalBarChart()
    chart.x = label_width
    chart.y = axis_height
    chart.width = CHART_WIDTH - label_width - 30.0
    chart.height = plot_height
    chart.categoryAxis.style = "stacked"
    chart.data = [
        [area["high"] for area in ordered],
        [area["medium"] for area in ordered],
        [area["low"] for area in ordered],
    ]
    chart.categoryAxis.categoryNames = [_shorten(area["name"], 26) for area in ordered]
    value_max = _configure_bar_chart(chart, max(area["total"] for area in ordered))
    chart.bars[0].fillColor = SEVERITY_HIGH
    chart.bars[1].fillColor = SEVERITY_MEDIUM
    chart.bars[2].fillColor = SEVERITY_LOW
    drawing.add(chart)
    _tip_labels(drawing, chart, [area["total"] for area in ordered], value_max)

    # The legend sits above the plot: below it, it would overprint the
    # value-axis tick labels.
    legend = Legend()
    legend.x = label_width
    legend.y = axis_height + plot_height + legend_height - 4.0
    legend.boxAnchor = "nw"
    legend.columnMaximum = 1
    legend.deltax = 62
    legend.dx = 6
    legend.dy = 6
    legend.dxTextSpace = 4
    legend.fontName = "Helvetica"
    legend.fontSize = 7.5
    legend.fillColor = NAVY
    legend.strokeWidth = 0
    legend.strokeColor = None
    legend.colorNamePairs = [
        (SEVERITY_HIGH, "High"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_LOW, "Low"),
    ]
    drawing.add(legend)
    return drawing


def _theme_chart(model: Dict[str, Any]) -> Any:
    """Single-series bars: failed direct rows per control theme."""
    rows = model["theme_matrix"]["rows"][:8]
    if not rows:
        return None
    ordered = list(reversed(rows))
    label_width = 152.0
    plot_height = CHART_BAND * len(ordered)
    axis_height = 22.0
    drawing = Drawing(CHART_WIDTH, plot_height + axis_height + 4.0)
    chart = HorizontalBarChart()
    chart.x = label_width
    chart.y = axis_height
    chart.width = CHART_WIDTH - label_width - 30.0
    chart.height = plot_height
    chart.data = [[row["total"] for row in ordered]]
    chart.categoryAxis.categoryNames = [_shorten(row["theme"], 36) for row in ordered]
    value_max = _configure_bar_chart(chart, max(row["total"] for row in ordered))
    # One series, so no legend: the section heading already names what is plotted.
    chart.bars[0].fillColor = BLUE
    drawing.add(chart)
    _tip_labels(drawing, chart, [row["total"] for row in ordered], value_max)
    return drawing


def _shorten(text: str, limit: int = 34) -> str:
    """Trim a long identifier so narrow table cells do not wrap mid-token."""
    text = text.strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _priority_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            Paragraph("Priority", styles["table_header"]),
            Paragraph("Finding", styles["table_header"]),
            Paragraph("Affected scope and prevalence", styles["table_header"]),
            Paragraph("Recommended response", styles["table_header"]),
        ]
    ]
    for priority in model["priorities"][:8]:
        scope_parts = []
        if priority["accounts"]:
            scope_parts.append(f"Accounts: {', '.join(priority['accounts'])}")
        if priority["regions"]:
            scope_parts.append(f"Regions: {', '.join(priority['regions'])}")
        if priority["count"] > 1:
            scope_parts.append(f"Rows: {priority['count']}")
        prevalence = priority["prevalence"]
        rows.append(
            [
                Paragraph(
                    f"<b>{_pdf_text(priority['severity'])}</b><br/>"
                    f"{_pdf_text(priority['check_id'])}",
                    styles["small"],
                ),
                Paragraph(
                    f"<b>{_pdf_text(priority['finding'])}</b><br/>"
                    f"{_pdf_text(priority['service'])}<br/>"
                    f"{_pdf_text(priority['theme'])}"
                    + (
                        "<br/>Resources: "
                        + _pdf_text(
                            ", ".join(
                                _shorten(label) for label in priority["resources"]
                            )
                        )
                        if priority["resources"]
                        else ""
                    ),
                    styles["small"],
                ),
                Paragraph(
                    f"<b>{_pdf_text(prevalence['label'])}</b><br/>"
                    f"{_pdf_text(' | '.join(scope_parts) or 'Current scope')}",
                    styles["small"],
                ),
                Paragraph(
                    _pdf_text(
                        priority["resolution"]
                        or "Review and remediate the reported control gap."
                    ),
                    styles["small"],
                ),
            ]
        )
    table = Table(
        rows,
        colWidths=[0.7 * inch, 1.95 * inch, 1.95 * inch, 1.8 * inch],
        repeatRows=1,
    )
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_index in range(1, len(rows)):
        if row_index % 2 == 0:
            style_commands.append(
                ("BACKGROUND", (0, row_index), (-1, row_index), LIGHT_SLATE)
            )
    table.setStyle(TableStyle(style_commands))
    return table


def _leverage_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Single remediation action", styles),
            _header_cell("Checks closed", styles),
            _header_cell("Failed rows addressed", styles),
        ]
    ]
    for item in model["remediation_leverage"][:6]:
        coverage = (
            f"{item['rows']} row(s): {item['high']} high, {item['medium']} medium, "
            f"{item['low']} low<br/>"
            f"{len(item['accounts'])} account(s); {len(item['regions'])} scope(s)"
        )
        rows.append(
            [
                Paragraph(_pdf_text(item["resolution"]), styles["small"]),
                Paragraph(
                    f"<b>{_pdf_text(', '.join(item['checks']))}</b><br/>"
                    f"{_pdf_text(', '.join(item['services']))}",
                    styles["small"],
                ),
                Paragraph(coverage, styles["small"]),
            ]
        )
    return _styled_table(rows, [3.05 * inch, 1.75 * inch, 1.6 * inch])


def _scorecard_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Account", styles),
            _header_cell("Weighted severity", styles),
            _header_cell("High", styles),
            _header_cell("Medium", styles),
            _header_cell("Low", styles),
            _header_cell("Failed checks", styles),
            _header_cell("Pass rate", styles),
            _header_cell("Leading theme", styles),
        ]
    ]
    for item in model["account_scorecard"]:
        rows.append(
            [
                Paragraph(_pdf_text(item["account"]), styles["small"]),
                Paragraph(str(item["weighted_score"]), styles["small"]),
                Paragraph(str(item["high"]), styles["small"]),
                Paragraph(str(item["medium"]), styles["small"]),
                Paragraph(str(item["low"]), styles["small"]),
                Paragraph(str(item["failed_checks"]), styles["small"]),
                Paragraph(f"{item['pass_rate']}%", styles["small"]),
                Paragraph(
                    _pdf_text(item["leading_theme"] or "No failed rows"),
                    styles["small"],
                ),
            ]
        )
    return _styled_table(
        rows,
        [
            0.95 * inch,
            0.75 * inch,
            0.42 * inch,
            0.55 * inch,
            0.42 * inch,
            0.62 * inch,
            0.6 * inch,
            2.09 * inch,
        ],
        numeric_start=1,
    )


def _service_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            Paragraph("Assessment area", styles["table_header"]),
            Paragraph("Passed", styles["table_header"]),
            Paragraph("Failed", styles["table_header"]),
            Paragraph("N/A", styles["table_header"]),
            Paragraph("Type", styles["table_header"]),
        ]
    ]
    for service in model["services"]:
        rows.append(
            [
                Paragraph(_pdf_text(service["name"]), styles["small"]),
                Paragraph(str(service["passed"]), styles["small"]),
                Paragraph(str(service["failed"]), styles["small"]),
                Paragraph(str(service["na"]), styles["small"]),
                Paragraph(
                    "Contextual mapping"
                    if service["contextual"]
                    else "Direct assessment",
                    styles["small"],
                ),
            ]
        )
    table = Table(
        rows,
        colWidths=[2.55 * inch, 0.65 * inch, 0.65 * inch, 0.65 * inch, 1.9 * inch],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 1), (3, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _coverage_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Assessment area", styles),
            _header_cell("Checks represented", styles),
            _header_cell("Published catalogue", styles),
            _header_cell("Not represented", styles),
            _header_cell("Represented", styles),
        ]
    ]
    for item in model["coverage"]:
        rows.append(
            [
                Paragraph(_pdf_text(item["name"]), styles["small"]),
                Paragraph(str(item["represented"]), styles["small"]),
                Paragraph(str(item["catalog_total"]), styles["small"]),
                Paragraph(str(item["not_represented"]), styles["small"]),
                Paragraph(f"{item['coverage_rate']}%", styles["small"]),
            ]
        )
    return _styled_table(
        rows,
        [2.6 * inch, 0.95 * inch, 1.0 * inch, 0.95 * inch, 0.9 * inch],
        numeric_start=1,
    )


def _na_reason_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Why the row is N/A", styles),
            _header_cell("Rows", styles),
            _header_cell("Checks affected", styles),
        ]
    ]
    for item in model["na_reasons"]:
        checks = ", ".join(item["checks"][:12])
        if len(item["checks"]) > 12:
            checks = f"{checks} (+{len(item['checks']) - 12} more)"
        rows.append(
            [
                Paragraph(_pdf_text(item["reason"]), styles["small"]),
                Paragraph(str(item["rows"]), styles["small"]),
                Paragraph(_pdf_text(checks), styles["small"]),
            ]
        )
    return _styled_table(rows, [2.15 * inch, 0.55 * inch, 3.7 * inch], numeric_start=1)


def _compliance_table(
    model: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("Framework reference", styles),
            _header_cell("Chks", styles),
            _header_cell("Pass", styles),
            _header_cell("Fail", styles),
            _header_cell("High", styles),
            _header_cell("Med", styles),
            _header_cell("Low", styles),
            _header_cell("N/A", styles),
            _header_cell("Pass %", styles),
        ]
    ]
    for item in model["compliance_frameworks"][:16]:
        rows.append(
            [
                Paragraph(_pdf_text(item["framework"]), styles["small"]),
                Paragraph(str(item["checks"]), styles["small"]),
                Paragraph(str(item["passed"]), styles["small"]),
                Paragraph(str(item["failed"]), styles["small"]),
                Paragraph(str(item["high"]), styles["small"]),
                Paragraph(str(item["medium"]), styles["small"]),
                Paragraph(str(item["low"]), styles["small"]),
                Paragraph(str(item["na"]), styles["small"]),
                Paragraph(f"{item['pass_rate']}%", styles["small"]),
            ]
        )
    return _styled_table(
        rows,
        [2.05 * inch] + [0.5 * inch] * 7 + [0.85 * inch],
        numeric_start=1,
    )


def _owasp_table(model: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    rows: List[List[Any]] = [
        [
            _header_cell("OWASP Top 10 for LLM category", styles),
            _header_cell("Chks", styles),
            _header_cell("Pass", styles),
            _header_cell("Fail", styles),
            _header_cell("High", styles),
            _header_cell("Med", styles),
            _header_cell("Low", styles),
            _header_cell("N/A", styles),
        ]
    ]
    for item in model["owasp_rollup"]:
        rows.append(
            [
                Paragraph(
                    f"{_pdf_text(item['category'])}<br/>"
                    f"{_pdf_text(', '.join(item['checks']))}",
                    styles["small"],
                ),
                Paragraph(str(len(item["checks"])), styles["small"]),
                Paragraph(str(item["passed"]), styles["small"]),
                Paragraph(str(item["failed"]), styles["small"]),
                Paragraph(str(item["high"]), styles["small"]),
                Paragraph(str(item["medium"]), styles["small"]),
                Paragraph(str(item["low"]), styles["small"]),
                Paragraph(str(item["na"]), styles["small"]),
            ]
        )
    return _styled_table(
        rows,
        [2.9 * inch] + [0.5 * inch] * 7,
        numeric_start=1,
    )


def _theme_matrix_table(
    model: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> Table:
    matrix = model["theme_matrix"]
    header = [_header_cell("Control theme", styles)]
    header.extend(_header_cell(name, styles) for name in matrix["services"])
    header.append(_header_cell("Total", styles))
    rows: List[List[Any]] = [header]
    for row in matrix["rows"]:
        cells = [Paragraph(_pdf_text(row["theme"]), styles["small"])]
        cells.extend(Paragraph(str(count), styles["small"]) for count in row["counts"])
        cells.append(Paragraph(f"<b>{row['total']}</b>", styles["small"]))
        rows.append(cells)
    total_cells = [Paragraph("<b>Total</b>", styles["small"])]
    total_cells.extend(
        Paragraph(f"<b>{total}</b>", styles["small"]) for total in matrix["totals"]
    )
    total_cells.append(Paragraph(f"<b>{sum(matrix['totals'])}</b>", styles["small"]))
    rows.append(total_cells)
    service_count = len(matrix["services"])
    theme_width = 1.7 * inch
    total_width = 0.55 * inch
    service_width = (6.4 * inch - theme_width - total_width) / max(service_count, 1)
    return _styled_table(
        rows,
        [theme_width] + [service_width] * service_count + [total_width],
        numeric_start=1,
    )


def _status_color(status: str) -> colors.Color:
    if status == "failed":
        return LIGHT_RED
    if status == "passed":
        return LIGHT_GREEN
    return LIGHT_AMBER


def _scope_phrase(values: List[str], limit: int = 6) -> str:
    if not values:
        return "Not reported"
    if len(values) <= limit:
        return ", ".join(values)
    return f"{', '.join(values[:limit])} (+{len(values) - limit} more)"


def _finding_flowables(
    group: Dict[str, Any], styles: Dict[str, ParagraphStyle]
) -> List[Any]:
    """Render one grouped check: shared text once, with the scopes it covers."""
    check_id = group["check_id"] or "Unidentified check"
    title = group["finding"] or "Unnamed finding"
    status = group["status"]
    severity = group["severity"]
    metadata = Table(
        [
            [
                Paragraph(
                    f"<b>Status</b><br/>{_pdf_text(status.title())}", styles["small"]
                ),
                Paragraph(
                    f"<b>Severity</b><br/>{_pdf_text(severity.title())}",
                    styles["small"],
                ),
                Paragraph(
                    f"<b>Accounts</b><br/>{_pdf_text(_scope_phrase(group['accounts']))}",
                    styles["small"],
                ),
                Paragraph(
                    f"<b>Regions</b><br/>{_pdf_text(_scope_phrase(group['regions']))}",
                    styles["small"],
                ),
                Paragraph(f"<b>Rows</b><br/>{group['rows']}", styles["small"]),
            ]
        ],
        colWidths=[0.8 * inch, 0.8 * inch, 2.0 * inch, 1.9 * inch, 0.9 * inch],
        hAlign="LEFT",
    )
    metadata.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), _status_color(status)),
                ("BACKGROUND", (1, 0), (1, 0), LIGHT_SLATE),
                ("BACKGROUND", (2, 0), (-1, 0), LIGHT_BLUE),
                ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    reference = _safe_reference(group["reference"])
    if reference:
        reference_markup = (
            f'<link href="{_pdf_text(reference)}" color="#2563EB">'
            f"{_pdf_text(reference)}</link>"
        )
    else:
        reference_markup = _pdf_text(group["reference"] or "No reference reported.")

    header = [
        Paragraph(
            f"{_pdf_text(check_id)} - {_pdf_text(title)}",
            styles["finding_title"],
        ),
        metadata,
        Spacer(1, 4),
    ]
    body: List[Any] = []
    variants = group["variants"]
    # A check assessed across many scopes repeats its remediation text on every
    # scope, so hoist it when it is identical everywhere.  Without this a
    # multi-account run prints the same resolution once per account and region.
    resolutions = {variant["resolution"] for variant in variants}
    shared_resolution = resolutions.pop() if len(resolutions) == 1 else None
    for variant in variants:
        details = variant["details"] or "No additional details were reported."
        resolution = variant["resolution"] or "No remediation guidance was reported."
        if len(variants) > 1:
            scope_label = " / ".join(
                part
                for part in (
                    _scope_phrase(variant["accounts"], limit=4)
                    if variant["accounts"]
                    else "",
                    _scope_phrase(variant["regions"], limit=4)
                    if variant["regions"]
                    else "",
                )
                if part
            )
            body.append(
                Paragraph(
                    f"<b>Reported for {_pdf_text(scope_label or 'the assessed scope')}"
                    "</b>",
                    styles["small"],
                )
            )
        body.append(
            Paragraph(f"<b>Finding details:</b> {_pdf_text(details)}", styles["body"])
        )
        if shared_resolution is None:
            body.append(
                Paragraph(f"<b>Resolution:</b> {_pdf_text(resolution)}", styles["body"])
            )
    if shared_resolution is not None:
        label = "Resolution" if len(variants) == 1 else "Resolution (all scopes)"
        body.append(
            Paragraph(
                f"<b>{label}:</b> "
                f"{_pdf_text(shared_resolution or 'No remediation guidance was reported.')}",
                styles["body"],
            )
        )
    body.append(Paragraph(f"<b>Reference:</b> {reference_markup}", styles["reference"]))
    return [
        # Only the heading, metadata band and first paragraph are glued
        # together.  Keeping the whole block intact pushed tall multi-scope
        # findings onto a fresh page and abandoned the rest of the previous one.
        KeepTogether(header + body[:1]),
        *body[1:],
        HRFlowable(
            width="100%", thickness=0.4, color=BORDER, spaceBefore=2, spaceAfter=2
        ),
    ]


def _compact_findings_table(
    groups: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]
) -> Table:
    """Render checks needing no remediation as one row each.

    Passed and N/A checks outnumber failed ones roughly two to one, and their
    reported prose adds no action for the reader.  One row per check keeps the
    outcome and scope on the record while the full text stays in the CSV and
    HTML report.
    """
    rows = [
        [
            _header_cell("Check", styles),
            _header_cell("Finding", styles),
            _header_cell("Status", styles),
            _header_cell("Severity", styles),
            _header_cell("Accounts and regions", styles),
        ]
    ]
    commands: List[Any] = []
    for group in groups:
        scope = " / ".join(
            part
            for part in (
                _scope_phrase(group["accounts"], limit=3) if group["accounts"] else "",
                _scope_phrase(group["regions"], limit=3) if group["regions"] else "",
            )
            if part
        )
        rows.append(
            [
                Paragraph(_pdf_text(group["check_id"] or "-"), styles["small"]),
                Paragraph(
                    _pdf_text(group["finding"] or "Unnamed finding"), styles["small"]
                ),
                Paragraph(_pdf_text(group["status"].title()), styles["small"]),
                Paragraph(_pdf_text(group["severity"].title()), styles["small"]),
                Paragraph(_pdf_text(scope or "Not reported"), styles["small"]),
            ]
        )
        commands.append(
            (
                "BACKGROUND",
                (2, len(rows) - 1),
                (2, len(rows) - 1),
                _status_color(group["status"]),
            )
        )
    table = _styled_table(
        rows, [0.7 * inch, 2.9 * inch, 0.7 * inch, 0.8 * inch, 2.3 * inch]
    )
    # Applied after the shared style so the status tint wins over row banding.
    for command in commands:
        table.setStyle(TableStyle([command]))
    return table


def generate_pdf_report(
    *,
    all_findings: List[Dict[str, Any]],
    service_stats: Dict[str, Dict[str, int]],
    mode: str = "single",
    account_id: str = None,
    account_ids: List[str] = None,
    timestamp: str,
    regions: List[str] = None,
    contextual_services: Iterable[str] = None,
) -> bytes:
    """Render a complete PDF report and return its bytes."""
    model = build_report_model(
        all_findings=all_findings,
        service_stats=service_stats,
        mode=mode,
        account_id=account_id,
        account_ids=account_ids,
        timestamp=timestamp,
        regions=regions,
        contextual_services=contextual_services,
    )
    styles = _styles()
    buffer = BytesIO()
    document = _ReportDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.62 * inch,
        title="AI/ML Security Assessment Report",
        author="AWS AI/ML Security Assessment",
        subject="Executive security posture and detailed assessment findings",
    )
    story: List[Any] = []

    story.extend(
        [
            Spacer(1, 0.2 * inch),
            Paragraph("AI/ML Security Assessment Report", styles["cover_title"]),
            Paragraph(
                "Executive security posture and complete findings",
                styles["cover_subtitle"],
            ),
            HRFlowable(width="100%", thickness=3, color=BLUE, spaceAfter=14),
            _scope_table(model, styles),
            PageBreak(),
            Paragraph(
                "Contents",
                ParagraphStyle("ContentsTitle", parent=styles["h1"]),
            ),
            _table_of_contents(styles),
            PageBreak(),
            Paragraph("Executive summary", styles["h1"]),
            Paragraph(
                "This report presents deterministic observations from the assessment "
                "results. Direct service checks drive the posture metrics. Agentic AI "
                "and compliance-standard mappings are shown as contextual views and "
                "are not counted again as separate direct risks.",
                styles["body"],
            ),
            _posture_callout(model, styles),
            Spacer(1, 8),
            _metric_table(model, styles),
            Spacer(1, 10),
            Paragraph("Key takeaways", styles["h2"]),
        ]
    )
    story.extend(_key_takeaways(model, styles))

    severity_chart = _severity_chart(model)
    theme_chart = _theme_chart(model)
    if severity_chart is not None:
        story.append(
            KeepTogether(
                [
                    Paragraph(
                        "Failed direct rows by assessment area and severity",
                        styles["h2"],
                    ),
                    severity_chart,
                ]
            )
        )
    if theme_chart is not None:
        story.append(
            KeepTogether(
                [
                    Paragraph("Failed direct rows by control theme", styles["h2"]),
                    theme_chart,
                ]
            )
        )

    story.append(Paragraph("What is working well", styles["h2"]))
    if model["strengths"]:
        story.append(_strengths_table(model, styles))
    else:
        story.append(
            Paragraph(
                "No passed direct-control rows were available to support a positive "
                "control-theme observation.",
                styles["body"],
            )
        )

    story.append(Paragraph("Areas requiring attention", styles["h2"]))
    if model["concerns"]:
        story.append(_concerns_table(model, styles))
    else:
        story.append(
            Paragraph(
                "No failed high, medium, or low severity direct findings were observed.",
                styles["body"],
            )
        )

    story.extend(
        [
            Paragraph("Executive response plan", styles["h1"]),
            Paragraph(
                "The sequence below is generated from finding severity and control "
                "theme. Suggested owners are starting points and should be aligned "
                "with the organization's operating model.",
                styles["body"],
            ),
        ]
    )
    if model["action_plan"]:
        story.append(_action_plan_table(model, styles))
    else:
        story.append(
            Paragraph(
                "No remediation plan was generated because no actionable failed "
                "direct findings were identified.",
                styles["body"],
            )
        )

    story.append(Paragraph("Priority findings", styles["h2"]))
    if model["priorities"]:
        story.append(
            Paragraph(
                "Prevalence describes how widely each gap was observed: "
                "<b>Systemic</b> means it appeared in every assessed account and "
                "scope and is usually best fixed with a central guardrail; "
                "<b>Widespread</b> means it spans multiple accounts or regions and "
                "needs a coordinated rollout; <b>Isolated</b> means it was confined "
                "to a single scope and can be remediated in place.",
                styles["body"],
            )
        )
        story.append(_priority_table(model, styles))
    else:
        story.append(
            Paragraph(
                "No actionable failed direct findings were identified.",
                styles["body"],
            )
        )

    if model["remediation_leverage"]:
        story.extend(
            [
                Paragraph("Where one action closes several findings", styles["h2"]),
                Paragraph(
                    "The failed findings below report identical remediation guidance "
                    "across more than one check, so a single change addresses all of "
                    "the listed rows.",
                    styles["body"],
                ),
                _leverage_table(model, styles),
            ]
        )

    if len(model["account_scorecard"]) > 1:
        story.extend(
            [
                Paragraph("Account scorecard", styles["h2"]),
                Paragraph(
                    "Accounts are ordered by weighted failed severity "
                    "(high x 9 + medium x 3 + low x 1), which is an ordering aid for "
                    "this report only and not an absolute risk score. Pass rate counts "
                    "only scored direct rows, so N/A rows do not distort it.",
                    styles["body"],
                ),
                _scorecard_table(model, styles),
            ]
        )

    story.append(Paragraph("Risk concentration", styles["h2"]))
    if any(model["concentration"].values()):
        story.append(_concentration_table(model, styles))
    else:
        story.append(
            Paragraph(
                "No failed direct findings were available for concentration analysis.",
                styles["body"],
            )
        )

    if model["theme_matrix"]["rows"]:
        story.extend(
            [
                Paragraph("Failed findings by theme and assessment area", styles["h2"]),
                Paragraph(
                    "Each cell counts failed direct rows, so a theme spread across "
                    "several areas indicates a cross-service control gap rather than "
                    "a single service problem.",
                    styles["body"],
                ),
                _theme_matrix_table(model, styles),
            ]
        )

    story.extend(
        [
            Paragraph("Coverage and assessment-area results", styles["h2"]),
            Paragraph(
                f"The report contains {model['metrics']['total_rows']} rows: "
                f"{model['metrics']['direct_rows']} direct assessment rows and "
                f"{model['metrics']['contextual_rows']} contextual mapping rows. "
                f"{model['metrics']['na_direct']} direct rows were N/A and are "
                "retained to make coverage limitations visible.",
                styles["body"],
            ),
            _service_table(model, styles),
        ]
    )

    if model["coverage"]:
        story.extend(
            [
                Paragraph("Checks represented against the catalogue", styles["h2"]),
                Paragraph(
                    "Represented means the check produced at least one row in this "
                    "report. A shortfall does not mean the control failed: an "
                    "assessment area can be partly represented when an optional "
                    "assessment is disabled, a region or account was not in scope, "
                    "or a scan could not complete.",
                    styles["body"],
                ),
                _coverage_table(model, styles),
            ]
        )

    if model["na_reasons"]:
        story.extend(
            [
                Paragraph("Why direct rows were not applicable", styles["h2"]),
                Paragraph(
                    "N/A rows are classified from the reported finding text. Access "
                    "problems and unavailable APIs are distinguished from genuinely "
                    "absent resources, because only the first two limit what the "
                    "assessment was able to observe.",
                    styles["body"],
                ),
                _na_reason_table(model, styles),
            ]
        )

    if model["owasp_rollup"]:
        story.extend(
            [
                Paragraph("OWASP Top 10 for LLM coverage", styles["h2"]),
                Paragraph(
                    "Rows are grouped by OWASP category as reported by the mapping "
                    "layer. These are contextual views of the direct findings and are "
                    "not additional risks.",
                    styles["body"],
                ),
                _owasp_table(model, styles),
            ]
        )

    if model["compliance_frameworks"]:
        story.extend(
            [
                Paragraph("Framework references attached to findings", styles["h2"]),
                Paragraph(
                    "Framework identifiers are reproduced from the Responsible AI GRC "
                    "findings. They are illustrative mappings supplied by the "
                    "assessment, not audit evidence or a statement of compliance.",
                    styles["body"],
                ),
                _compliance_table(model, styles),
            ]
        )

    story.extend(
        [
            PageBreak(),
            Paragraph("Detailed findings", styles["h1"]),
            Paragraph(
                f"This section covers all {model['metrics']['total_rows']} report rows, "
                "including passed, failed, and N/A findings. Rows that repeat the same "
                "check and outcome across accounts or regions are shown once with the "
                f"scopes they cover ({len(model['finding_groups'])} grouped entries). "
                "Failed findings are reported in full, with the reported detail for "
                "each scope, remediation, and references. Passed and not-applicable "
                "checks are summarized one row per check, because they carry no "
                "remediation action; their full reported text remains in the CSV "
                "findings and the HTML report.",
                styles["body"],
            ),
        ]
    )

    # Groups arrive sorted failed, then passed, then N/A within each service, so
    # the compact tier is flushed when the service changes or the section ends.
    current_service = None
    compact: List[Dict[str, Any]] = []

    def _flush_compact() -> None:
        if not compact:
            return
        story.append(
            Paragraph("Passed and not-applicable checks", styles["h3"]),
        )
        story.append(_compact_findings_table(compact, styles))
        compact.clear()

    for group in model["finding_groups"]:
        service = group["service"]
        if service != current_service:
            _flush_compact()
            if current_service is not None:
                story.append(Spacer(1, 6))
            story.append(
                Paragraph(
                    _pdf_text(service_display_name(service)),
                    styles["h2"],
                )
            )
            current_service = service
        if group["status"] == "failed":
            story.extend(_finding_flowables(group, styles))
        else:
            compact.append(group)
    _flush_compact()

    story.extend(
        [
            PageBreak(),
            Paragraph("Methodology and limitations", styles["h1"]),
            Paragraph(
                "The assessment is point-in-time and evaluates only the controls "
                "implemented by this project. Security posture can change after the "
                "assessment as resources and policies are modified.",
                styles["body"],
            ),
            Paragraph(
                "Passed means the tested control was observed as compliant. Failed "
                "means the tested control was observed as non-compliant. N/A means "
                "there was nothing applicable to test or the API or feature was not "
                "available. A passed row is not a certification of the workload or "
                "account.",
                styles["body"],
            ),
            Paragraph(
                "The report does not establish regulatory compliance, certify a "
                "system as secure or responsible AI, or replace architecture, legal, "
                "model-risk, privacy, fairness, or use-case review.",
                styles["body"],
            ),
            Paragraph(
                "Mapped Agentic AI and compliance-standard rows can derive from the "
                "same underlying direct findings. They provide alternate context and "
                "must not be added to direct finding totals as independent risks.",
                styles["body"],
            ),
            Paragraph(
                "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. "
                "Licensed under MIT-0. This report is provided as-is for informational "
                "purposes and does not constitute professional security advice, "
                "compliance certification, or audit evidence.",
                styles["disclaimer"],
            ),
        ]
    )

    document.multiBuild(story)
    return buffer.getvalue()
