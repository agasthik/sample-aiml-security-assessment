#!/usr/bin/env python3
"""
Screenshot Capture Script for AI/ML Security Assessment Reports

This script captures and optimizes screenshots from the sample HTML reports.
Screenshots are saved in the sample-reports/ folder.

Requirements:
    - playwright
    - pillow (PIL)

The script automatically:
    - Re-launches itself with the repository-root .venv Python.
    - Installs sample-reports/dev-requirements.txt when dependencies are missing.
    - Installs and verifies Chromium under .venv/playwright-browsers.

Usage:
    ./sample-reports/scripts/capture_screenshots.py
    ./sample-reports/scripts/capture_screenshots.py --check-dependencies
    ./sample-reports/scripts/capture_screenshots.py --anonymize-only
"""

import bisect
import collections
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Configuration
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLE_REPORTS_DIR = REPO_ROOT / "sample-reports"
SCREENSHOT_REQUIREMENTS = SAMPLE_REPORTS_DIR / "dev-requirements.txt"
PLAYWRIGHT_BROWSERS_DIR = REPO_ROOT / ".venv" / "playwright-browsers"
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900
JPEG_QUALITY = 85  # Balance between quality and file size
PNG_OPTIMIZE = True

# Placeholder account IDs (not real accounts). Real account IDs discovered in
# the sample reports are consistently remapped to these before screenshots are
# captured. The first four are the AWS documentation example IDs, see
# https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
# The rest are repeated-digit patterns, so each one reads as synthetic. Keep
# the existing order: an ID's position decides which discovered ID maps to it.
ANONYMIZED_ACCOUNT_IDS = [
    "111122223333",
    "444455556666",
    "777788889999",
    "123456789012",
    "555555555555",
    "666677778888",
    "222233334444",
    "333344445555",
    "555566667777",
    "888899990000",
    "999900001111",
    "111111111111",
    "222222222222",
    "333333333333",
    "444444444444",
    "666666666666",
    "777777777777",
    "888888888888",
    "999999999999",
    "000011112222",
]

# Resource identifiers in the sample reports are replaced by
# anonymize_resource_ids(). Hex IDs become zero-padded counters, such as
# vpc-000000000000000a1 or 00000000-0000-4000-8000-0000000000a1; the marker
# records that a report has been anonymized, so it isn't done twice.
ANONYMIZED_MARKER = "<!-- sample-report identifiers anonymized -->"
ANONYMIZED_NAMES_MARKER = "<!-- sample-report resource names anonymized -->"
ZERO_PADDED_KINDS = (
    "UUID",
    "AWS resource ID",
    "32-digit hex ID",
    "16-digit hex ID",
    "image digest",
)
UUID_PLACEHOLDER_HEAD = "00000000-0000-4000-8000-"
# The repository's patterned example organization IDs (without "o-").
ANONYMIZED_ORGANIZATION_IDS = ["f6g7h8i9j0", "a1b2c3d4e5"]

CHANGES_PAGE = "security_assessment_changes.html"

# Elements of the Cloudscape report UI the captures wait for or use. The UI
# draws the page from its embedded data after load, so captures wait for it.
OVERVIEW_READY = '[data-testid="overview-metrics"]'
FINDINGS_READY = '[data-testid="findings-table"] tbody tr'
CHANGES_READY = '[data-testid="change-tiles"]'
# The light/dark toggle at the top right of the top navigation.
# The top navigation also renders hidden copies for measuring, so pick the
# visible element.
THEME_TOGGLE = '#report-top-nav [aria-label^="Switch to"] >> visible=true'
NAVIGATION = 'nav[aria-label="Report sections"] >> visible=true'
# The first finding's radio button, which opens its details in the split panel.
FIRST_FINDING_RADIO = (
    '[data-testid="findings-table"] tbody tr:first-child input[type="radio"]'
)
DETAILS_PANEL = '[data-testid="finding-details"]'

# Screenshots to capture
SCREENSHOTS = [
    {
        "name": "dashboard-overview-light",
        "file": "security_assessment_single_account.html",
        "description": "Executive Dashboard (Light Mode)",
        "actions": [
            {"type": "wait", "selector": OVERVIEW_READY, "timeout": 10000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
    {
        "name": "dashboard-overview-dark",
        "file": "security_assessment_single_account.html",
        "description": "Executive Dashboard (Dark Mode)",
        "actions": [
            {"type": "wait", "selector": OVERVIEW_READY, "timeout": 10000},
            {"type": "click", "selector": THEME_TOGGLE},
            {"type": "wait_time", "ms": 500},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
    {
        "name": "findings-table",
        "file": "security_assessment_single_account.html",
        "description": "Findings Table with Filters and the Details Panel",
        "actions": [
            {"type": "wait", "selector": FINDINGS_READY, "timeout": 10000},
            {"type": "scroll_to", "selector": "#findings"},
            {"type": "click", "selector": FIRST_FINDING_RADIO, "force": True},
            {"type": "wait", "selector": DETAILS_PANEL, "timeout": 5000},
            {"type": "wait_time", "ms": 500},
            {"type": "scroll_to", "selector": "#findings"},
            {"type": "wait_time", "ms": 300},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 900},
    },
    {
        "name": "multi-account-summary",
        "file": "security_assessment_multi_account.html",
        "description": "Multi-Account Consolidated View",
        "actions": [
            {"type": "wait", "selector": OVERVIEW_READY, "timeout": 10000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
]


def _repo_venv_python() -> Path:
    """Return the repository-root virtual environment's Python executable."""
    if os.name == "nt":
        return REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    return REPO_ROOT / ".venv" / "bin" / "python"


def ensure_repo_venv() -> None:
    """Re-launch this script with the repository-root virtual environment."""
    venv_python = _repo_venv_python()
    if not venv_python.is_file():
        print(f"ERROR: Repository virtual environment not found: {venv_python}")
        print("Create it with Python 3.12 before running this tool:")
        print("  python3.12 -m venv .venv")
        sys.exit(1)

    try:
        using_repo_venv = Path(sys.executable).resolve().samefile(venv_python.resolve())
    except OSError:
        using_repo_venv = Path(sys.executable).resolve() == venv_python.resolve()

    if not using_repo_venv:
        print(f"Re-launching with repository Python: {venv_python}", flush=True)
        os.execv(
            str(venv_python),
            [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
        )

    if sys.version_info[:2] != (3, 12):
        print(
            "ERROR: The repository .venv must use Python 3.12; found "
            f"{sys.version_info.major}.{sys.version_info.minor}."
        )
        print("Recreate it with: python3.12 -m venv .venv")
        sys.exit(1)

    print(f"Verified repository Python: {sys.version.split()[0]}")


def ensure_python_dependencies() -> None:
    """Install and verify screenshot Python dependencies in the root .venv."""
    required_modules = {"playwright": "playwright", "PIL": "pillow"}
    missing = [
        package
        for module, package in required_modules.items()
        if importlib.util.find_spec(module) is None
    ]

    if missing:
        print(
            "Installing missing screenshot dependencies in the repository "
            f".venv: {', '.join(missing)}",
            flush=True,
        )
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    str(SCREENSHOT_REQUIREMENTS),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
        except subprocess.CalledProcessError as error:
            print(
                f"ERROR: Dependency installation failed with exit code {error.returncode}"
            )
            sys.exit(error.returncode)

    still_missing = [
        package
        for module, package in required_modules.items()
        if importlib.util.find_spec(module) is None
    ]
    if still_missing:
        print(
            "ERROR: Required screenshot dependencies remain unavailable: "
            + ", ".join(still_missing)
        )
        sys.exit(1)

    print("Verified Python dependencies: playwright, pillow")


def ensure_chromium() -> None:
    """Ensure the matching Playwright Chromium binary exists under the root .venv."""
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(PLAYWRIGHT_BROWSERS_DIR)

    print(
        f"Ensuring Playwright Chromium under: {PLAYWRIGHT_BROWSERS_DIR}",
        flush=True,
    )
    try:
        # Idempotent: exits quickly when the browser revision matching the
        # installed Playwright package is already present.
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            cwd=REPO_ROOT,
            env=os.environ.copy(),
            check=True,
        )
    except subprocess.CalledProcessError as error:
        print(f"ERROR: Chromium installation failed with exit code {error.returncode}")
        sys.exit(error.returncode)


def bootstrap_screenshot_environment() -> None:
    """Prepare and verify the screenshot tooling environment."""
    ensure_repo_venv()
    ensure_python_dependencies()
    ensure_chromium()


def anonymize_account_ids(html_files: list) -> None:
    """
    Replace real 12-digit AWS account IDs in the given HTML files with
    well-known example account IDs, in place.

    Each distinct real account ID is mapped to a stable placeholder so that
    filtering and grouping in the reports keep working. The mapping is shared
    across all provided files, so an account that appears in multiple reports
    is anonymized to the same placeholder everywhere.

    IDs that are already placeholders are left as they are, and real IDs get
    only the placeholders no file uses yet. Running this again, or on a mix of
    anonymized and new reports, changes nothing in the anonymized ones.

    Args:
        html_files: List of Path objects pointing to HTML report files.
    """
    print("\n Anonymizing account IDs...")

    # Collect every distinct 12-digit account ID across all files first so the
    # placeholder assignment is deterministic regardless of processing order.
    account_id_pattern = re.compile(r"(?<!\d)\d{12}(?!\d)")
    discovered = []
    file_contents = {}
    for html_file in html_files:
        if not html_file.exists():
            print(f"  WARNING: {html_file} not found, skipping...")
            continue
        content = html_file.read_text(encoding="utf-8")
        file_contents[html_file] = content
        for text, _in_code in _page_texts(content):
            for account_id in account_id_pattern.findall(text):
                if account_id not in discovered:
                    discovered.append(account_id)

    placeholders = set(ANONYMIZED_ACCOUNT_IDS)
    real_ids = [
        account_id for account_id in discovered if account_id not in placeholders
    ]
    available = [
        placeholder
        for placeholder in ANONYMIZED_ACCOUNT_IDS
        if placeholder not in discovered
    ]

    if not real_ids:
        print("  No account IDs found to anonymize.")
        return

    if len(real_ids) > len(available):
        print(
            f"  ERROR: Found {len(real_ids)} distinct account IDs to anonymize but "
            f"only {len(available)} placeholders are unused. "
            "Add more entries to ANONYMIZED_ACCOUNT_IDS."
        )
        sys.exit(1)

    mapping = dict(zip(real_ids, available))
    for real_id, placeholder in mapping.items():
        print(f"  {real_id} -> {placeholder}")

    # Apply the mapping to each file, including IDs beside letters or "_".
    # Digit boundaries avoid touching a 12-digit part of a longer number.
    def _replace(match: "re.Match") -> str:
        return mapping.get(match.group(0), match.group(0))

    for html_file, content in file_contents.items():
        updated = _map_page_text(
            content, lambda text: account_id_pattern.sub(_replace, text)
        )
        if updated != content:
            html_file.write_text(updated, encoding="utf-8")
            print(f"  Updated: {html_file.name}")


def _load_generated_value_kinds():
    """Load anonymize_patterns.py by path for its GENERATED_VALUE_KINDS."""
    path = Path(__file__).resolve().parent / "anonymize_patterns.py"
    spec = importlib.util.spec_from_file_location("sample_anonymize_patterns", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


# A run's main report link, and its changes CSV link, as a changes page
# writes them under "Related files".
_RUN_REPORT_LINK = re.compile(
    r'<a href="(security_assessment_single_account)_\d{8}_\d{6}\.html">'
    r"[^<]*</a>"
)
_RUN_CSV_LINK = re.compile(
    r'\s*<p><a href="security_assessment_changes_\d{8}_\d{6}\.csv">[^<]*</a></p>'
)
_PAGE_CODE = re.compile(r"<(style|script)\b[^>]*>.*?(?:</\1\s*>|\Z)", re.S | re.I)
_HTML_TAG = re.compile(r"""<[A-Za-z][^>"']*(?:(?:"[^"]*"|'[^']*')[^>"']*)*>""", re.S)
_HTML_ATTRIBUTE = re.compile(
    r"""\s+([^\s=/>]+)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.S
)
_INLINE_HANDLER = re.compile(r"on[a-z][\w:-]*", re.I)
_PLAIN_WORD = re.compile(r"[a-z]+")


def _page_code_test(content: str):
    """Test whether a position is in page code, including inline attributes."""
    spans = [match.span() for match in _PAGE_CODE.finditer(content)]
    for tag in _HTML_TAG.finditer(content):
        for attribute in _HTML_ATTRIBUTE.finditer(tag.group()):
            name = attribute.group(1)
            if name.lower() == "style" or _INLINE_HANDLER.fullmatch(name):
                spans.append(
                    (tag.start() + attribute.start(), tag.start() + attribute.end())
                )
    starts, ends = [], []
    for start, end in sorted(spans):
        if starts and start <= ends[-1]:
            ends[-1] = max(ends[-1], end)
        else:
            starts.append(start)
            ends.append(end)

    def in_code(position: int) -> bool:
        index = bisect.bisect_right(starts, position) - 1
        return index >= 0 and position < ends[index]

    return in_code


def _never(_position: int) -> bool:
    return False


def _page_texts(content: str) -> list:
    """(text, in_code) pairs holding a page's report text.

    A report page (report_template.render_page) keeps its text in the page
    title and its data model; each string is one text and holds no page code,
    and the inlined Cloudscape script and styles are never read. Any other
    HTML is one text, with its styles, scripts and inline code marked.
    """
    units = _patterns().report_text_units(content)
    if units is None:
        return [(content, _page_code_test(content))]
    return [(unit, _never) for unit in units]


def _map_page_text(content: str, function) -> str:
    """content with function applied to each text of _page_texts()."""
    if _patterns().is_report_page(content):
        return _patterns().map_report_text(content, function)
    return function(content)


_PATTERNS = None


def _patterns():
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = _load_generated_value_kinds()
    return _PATTERNS


def point_changes_links_at_samples(changes_page: Path) -> None:
    """Link the changes page to the sample report instead of a run's files.

    A changes page links to its run's report and CSV by their saved names
    ("security_assessment_single_account_<timestamp>.html"). The sample report
    has no timestamp, and no changes CSV is published with the samples, so
    that link is removed.
    """
    if not changes_page.exists():
        print(f"  WARNING: {changes_page} not found, skipping...")
        return
    content = changes_page.read_text(encoding="utf-8")
    if _patterns().is_report_page(content):
        updated = _point_model_links_at_samples(content)
    else:
        updated = _RUN_CSV_LINK.sub("", content)
        updated = _RUN_REPORT_LINK.sub(r'<a href="\1.html">\1.html</a>', updated)
    if updated != content:
        changes_page.write_text(updated, encoding="utf-8")
        print(f"  Linked {changes_page.name} to the sample files")


_RUN_REPORT_NAME = re.compile(r"(security_assessment_single_account)_\d{8}_\d{6}\.html")
_RUN_CSV_NAME = re.compile(r"security_assessment_changes_\d{8}_\d{6}\.csv")


def _point_model_links_at_samples(content: str) -> str:
    """The changes page's data model, linked to the sample report, no CSV."""
    patterns = _patterns()
    data = patterns.report_data(content)
    main_report = data.get("mainReport")
    csv_name = data.get("csvName")
    if main_report:
        main_report = _RUN_REPORT_NAME.sub(r"\1.html", main_report)
    if csv_name and _RUN_CSV_NAME.fullmatch(csv_name):
        csv_name = None
    if main_report == data.get("mainReport") and csv_name == data.get("csvName"):
        return content
    data = {**data, "mainReport": main_report, "csvName": csv_name}
    match = patterns._REPORT_DATA.search(content)
    return (
        content[: match.start(2)]
        + patterns._template()._json_for_script(data)
        + content[match.end(2) :]
    )


def _synthetic_value(kinds, value: str, kind: str, index: int, taken: set) -> str:
    """The synthetic value for the index-th distinct value of a kind.

    Hex IDs (ZERO_PADDED_KINDS) become a zero-padded counter, so they read as
    placeholders (vpc-000000000000000a1). Other values become made-up
    characters of the same shape. Either way the result depends only on the
    kind, the index and the value's shape, never on the real value, so a
    placeholder cannot be traced back to the value it replaced.
    """
    if kind in ZERO_PADDED_KINDS:
        # "a" and a decimal counter, padded with zeros: vpc-000000000000000a1.
        # The "a" keeps it from reading as part of a longer run of digits.
        tail = value.rpartition("-")[2] if kind == "UUID" else value
        head = UUID_PLACEHOLDER_HEAD if kind == "UUID" else ""
        counter = f"a{index}".rjust(len(tail), "0")
        if len(counter) > len(tail):
            raise ValueError(f"too many distinct {kind} values to number")
        return head + counter
    if kind == "Organizations ID" and len(value) == 10:
        if index <= len(ANONYMIZED_ORGANIZATION_IDS):
            return ANONYMIZED_ORGANIZATION_IDS[index - 1]
    preserved = {
        position
        for match in re.finditer(r"(?<!\d)\d{12}(?!\d)", value)
        if match.group() in ANONYMIZED_ACCOUNT_IDS
        for position in range(*match.span())
    }
    hex_only = kinds._HEX.fullmatch(value.replace("-", "")) is not None
    attempt = 0
    while True:
        seed = f"sample-identifier:{kind}:{index}:{attempt}".encode()
        stream = hashlib.shake_256(seed).digest(len(value))
        made_up = "".join(
            character
            if position in preserved
            else kinds._made_up_character(character, byte, hex_only)
            for position, (character, byte) in enumerate(zip(value, stream))
        )
        if made_up != value and made_up not in taken:
            return made_up
        attempt += 1


def anonymize_resource_ids(html_files: list, *, names_only: bool = False) -> dict:
    """
    Replace resource IDs and other values AWS generated in the given HTML
    report files with synthetic placeholders, in place.

    The values are the ones anonymize_patterns.py's GENERATED_VALUE_KINDS
    find anywhere outside page code: resource IDs (vpc-, sg-, subnet-, i-, ...),
    GuardDuty detector and finding IDs, UUIDs, Organizations and Cognito IDs,
    and the random parts of resource names. Each distinct value gets one
    placeholder, shared across the files anonymized together, so filtering and
    grouping keep working. A file is marked once anonymized and skipped after
    that, so running this again changes nothing. A file anonymized later (a
    regenerated report) keeps the marked files' placeholders it already holds,
    and its other values get placeholders no marked file uses. A real value it
    shares with a marked file can't get that file's placeholder, as no mapping
    back to the real values is kept: regenerate and anonymize the reports
    together when they must share one. Every file is checked before
    any is written, so a failure leaves them all as they were.

    Returns the number of replacements made, by kind.
    """
    print(
        "\n Anonymizing resource names..."
        if names_only
        else "\n Anonymizing resource identifiers..."
    )
    kinds = _load_generated_value_kinds()
    marker = ANONYMIZED_NAMES_MARKER if names_only else ANONYMIZED_MARKER
    selected = (
        kinds.NAME_KINDS
        if names_only
        else {kind for kind, _ in kinds.GENERATED_VALUE_KINDS} - kinds.NAME_KINDS
        | {kinds.PERSONAL_NAME}
    )

    def values(text):
        return [
            (start, end, kind)
            for start, end, kind in kinds.generated_values(text)
            if kind in selected
        ]

    contents = {}
    # Placeholders the marked files already use, by kind: new ones are
    # numbered after them and never repeat them.
    used: dict = {}
    for html_file in html_files:
        if not html_file.exists():
            print(f"  WARNING: {html_file} not found, skipping...")
            continue
        content = html_file.read_text(encoding="utf-8")
        if marker in content:
            print(f"  Already anonymized: {html_file.name}")
            texts = _page_texts(content)
            if names_only and any(
                kinds.source_account_names(text) for text, _in_code in texts
            ):
                print(f"  ERROR: {html_file.name} still holds a source account name")
                print("  No file was changed.")
                sys.exit(1)
            for text, in_code in texts:
                for start, end, kind in values(text):
                    if not in_code(start):
                        used.setdefault(text[start:end], kind)
            continue
        contents[html_file] = content

    # Number the distinct values in the order they first appear, file by file.
    kind_of: dict = {}
    for content in contents.values():
        for text, in_code in _page_texts(content):
            for start, end, kind in values(text):
                if not in_code(start):
                    kind_of.setdefault(text[start:end], kind)
    mapping: dict = {}
    counters: collections.Counter = collections.Counter(used.values())
    taken = set(kind_of) | set(used)
    for value, kind in kind_of.items():
        if value in used:
            # Already a marked file's placeholder: a file anonymized after
            # the marked ones keeps the placeholders they gave it.
            continue
        placeholder = value
        while placeholder in taken:
            counters[kind] += 1
            placeholder = _synthetic_value(kinds, value, kind, counters[kind], taken)
        mapping[value] = placeholder
        taken.add(placeholder)

    if contents and not mapping:
        print("  No resource identifiers found to anonymize.")
    # A value found in one context (a resource ID in a finding's text) can also
    # appear where no kind's pattern finds it (in an ARN, or a role name):
    # those occurrences are matched as whole tokens. A value that is one
    # lowercase word, such as a policy named 'root', is also an ordinary word
    # of the page (":root" in its CSS, "the root" in a finding, a docs URL), so
    # it is replaced only where a kind's pattern finds it.
    token_values = [value for value in mapping if not _PLAIN_WORD.fullmatch(value)]
    plain_values = [value for value in mapping if _PLAIN_WORD.fullmatch(value)]
    tokens = (
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            + "|".join(
                re.escape(value) for value in sorted(token_values, key=len)[::-1]
            )
            + r")(?![A-Za-z0-9])"
        )
        if token_values
        else None
    )
    plain_tokens = (
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            + "|".join(
                re.escape(value) for value in sorted(plain_values, key=len)[::-1]
            )
            + r")(?![A-Za-z0-9])"
        )
        if plain_values
        else None
    )

    def replace(content, in_code):
        """(content with the mapped values replaced, kinds of values left)."""
        spans = [
            (*match.span("v"), match.group("v"))
            for kind, pattern in kinds._GENERATED
            if kind in selected
            for match in pattern.finditer(content)
            if match.group("v") in mapping
        ]
        if names_only:
            spans += [
                (start, end, content[start:end])
                for start, end, _kind in kinds.source_account_names(content)
                if content[start:end] in mapping
            ]
        if not names_only:
            spans += [
                (*match.span(), match.group())
                for match in kinds._WORD.finditer(content)
                if match.group() in mapping
                and kind_of[match.group()] == kinds.PERSONAL_NAME
            ]
        if tokens:
            spans += [
                (*match.span(), match.group()) for match in tokens.finditer(content)
            ]
        spans = [span for span in spans if not in_code(span[0])]
        parts, last = [], 0
        for start, end, value in sorted(spans, key=lambda s: (s[0], s[0] - s[1])):
            if start < last:
                continue
            parts += [content[last:start], mapping[value]]
            replaced[kind_of[value]] += 1
            last = end
        updated = "".join(parts) + content[last:]
        # Whole tokens, as they were replaced: a short value can also occur
        # inside longer, unrelated text.
        # Styles and scripts included: a value there stops the run rather
        # than being left in place.
        left = (
            {kind_of[match.group()] for match in tokens.finditer(updated)}
            if tokens
            else set()
        )
        if plain_tokens and in_code is not _never:
            updated_in_code = _page_code_test(updated)
            left |= {
                kind_of[match.group()]
                for match in plain_tokens.finditer(updated)
                if updated_in_code(match.start())
            }
        return updated, left

    replaced: collections.Counter = collections.Counter()
    updates = {}
    for html_file, content in contents.items():
        # The page's own styles and scripts hold no report data: nothing in
        # them is replaced. On a report page only its title and data model
        # are read and written (see _page_texts).
        left: set = set()
        if kinds.is_report_page(content):

            def replace_text(text):
                updated_text, text_left = replace(text, _never)
                left.update(text_left)
                return updated_text

            updated = kinds.map_report_text(content, replace_text)
        else:
            updated, left = replace(content, _page_code_test(content))
        left = sorted(left)
        if left:
            print(f"  ERROR: {html_file.name} still holds values of kind(s) {left}")
            print("  No file was changed.")
            sys.exit(1)
        doctype = "<!DOCTYPE html>\n"
        if updated.startswith(doctype):
            updated = doctype + marker + "\n" + updated[len(doctype) :]
        else:
            updated = marker + "\n" + updated
        updates[html_file] = updated
    for html_file, updated in updates.items():
        html_file.write_text(updated, encoding="utf-8")
        print(f"  Updated: {html_file.name}")

    # Kinds and counts only, so the output doesn't repeat the real values.
    for kind, count in sorted(replaced.items()):
        print(f"  {kind}: {count} replacement(s)")
    return dict(replaced)


def anonymize_resource_names(html_files: list) -> dict:
    """Clean resource names in both new and previously ID-anonymized reports."""
    return anonymize_resource_ids(html_files, names_only=True)


def optimize_png(image_path: Path, max_size_kb: int = 300) -> None:
    """
    Optimize PNG image to reduce file size while maintaining quality.

    Args:
        image_path: Path to the PNG file
        max_size_kb: Maximum target file size in KB
    """
    from PIL import Image

    img = Image.open(image_path)

    # Convert RGBA to RGB if needed (reduces size)
    if img.mode == "RGBA":
        background = Image.new("RGB", img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[3])  # Use alpha channel as mask
        img = background

    # Save with optimization
    img.save(image_path, "PNG", optimize=True)

    # Check file size
    file_size_kb = image_path.stat().st_size / 1024

    # If still too large, reduce quality by converting to JPEG
    if file_size_kb > max_size_kb:
        jpeg_path = image_path.with_suffix(".jpg")
        img.save(jpeg_path, "JPEG", quality=JPEG_QUALITY, optimize=True)
        image_path.unlink()  # Remove PNG
        print(
            f"  Converted to JPEG: {jpeg_path.name} ({jpeg_path.stat().st_size / 1024:.1f} KB)"
        )
        return jpeg_path

    print(f"  Optimized PNG: {image_path.name} ({file_size_kb:.1f} KB)")
    return image_path


def fit_viewport_to_sidebar(page, minimum_height: int) -> int:
    """
    Expand the viewport until the entire side navigation fits without scrolling.

    The report's Cloudscape side navigation is a fixed-height panel with its
    own vertical overflow. A fixed screenshot height can therefore hide lower
    navigation sections even when the main page has enough content. Measuring
    its ``scrollHeight`` makes the capture resilient to additional lenses,
    governance frameworks, and compliance standards.

    Args:
        page: Playwright page instance.
        minimum_height: Minimum capture height requested by the screenshot.

    Returns:
        The viewport height required to include the full navigation.
    """
    try:
        page.wait_for_selector(NAVIGATION, timeout=10000)
    except Exception:
        return minimum_height
    measure = """element => {
        let panel = element;
        for (let node = element; node && node !== document.body; node = node.parentElement) {
            if (node.scrollHeight > node.clientHeight + 1) { panel = node; break; }
        }
        return Math.ceil(panel.getBoundingClientRect().top + panel.scrollHeight);
    }"""

    target_height = minimum_height
    for _ in range(3):
        target_height = max(target_height, page.eval_on_selector(NAVIGATION, measure))
        viewport = page.viewport_size or {
            "width": VIEWPORT_WIDTH,
            "height": VIEWPORT_HEIGHT,
        }
        if viewport["height"] >= target_height:
            break
        page.set_viewport_size({"width": viewport["width"], "height": target_height})
        page.wait_for_timeout(200)

    navigation = page.eval_on_selector(
        NAVIGATION,
        """element => {
            const bottom = window.innerHeight;
            const links = [...element.querySelectorAll("a[href]")];
            const hiddenItems = links
                .filter(link => link.getBoundingClientRect().bottom > bottom)
                .map(link => link.textContent.trim().replace(/\\s+/g, " "));
            return { navItemCount: links.length, hiddenItems };
        }""",
    )
    if navigation["hiddenItems"]:
        hidden = ", ".join(navigation["hiddenItems"])
        raise RuntimeError(f"Sidebar navigation remains clipped: {hidden}")

    print(
        f"  Full sidebar capture height: {target_height}px "
        f"({navigation['navItemCount']} navigation items visible)"
    )
    return target_height


def launch_chromium(playwright):
    """Playwright's Chromium, or the installed Google Chrome when it's missing."""
    try:
        return playwright.chromium.launch(headless=True)
    except Exception as error:
        print(f"  Playwright Chromium unavailable ({error}); trying Google Chrome")
        return playwright.chromium.launch(headless=True, channel="chrome")


def capture_screenshot(browser, screenshot_config: dict) -> Path:
    """
    Capture a screenshot based on the configuration.

    Args:
        browser: Playwright browser instance
        screenshot_config: Screenshot configuration dictionary

    Returns:
        Path to the captured screenshot
    """
    html_file = SAMPLE_REPORTS_DIR / screenshot_config["file"]

    if not html_file.exists():
        print(f"  WARNING: {html_file} not found, skipping...")
        return None

    print(f"\n Capturing: {screenshot_config['description']}")
    print(f"  Source: {screenshot_config['file']}")

    # Create a new page
    page = browser.new_page(
        viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT}
    )

    # Navigate to the HTML file
    page.goto(f"file://{html_file.absolute()}")

    capture_clip = dict(screenshot_config.get("clip", {}))
    minimum_height = capture_clip.get("height", VIEWPORT_HEIGHT)
    capture_height = fit_viewport_to_sidebar(page, minimum_height)
    if capture_clip:
        capture_clip["height"] = capture_height

    # Execute actions
    for action in screenshot_config["actions"]:
        if action["type"] == "wait":
            page.wait_for_selector(
                action["selector"], timeout=action.get("timeout", 5000)
            )
        elif action["type"] == "click":
            # Cloudscape draws its own radio buttons over the real inputs, so
            # a row's input needs force=True.
            page.click(action["selector"], force=action.get("force", False))
        elif action["type"] == "scroll":
            page.evaluate(f"window.scrollTo(0, {action['position']})")
        elif action["type"] == "scroll_to":
            page.eval_on_selector(
                action["selector"], "element => element.scrollIntoView()"
            )
        elif action["type"] == "wait_time":
            time.sleep(action["ms"] / 1000)

    # Capture screenshot
    output_path = SAMPLE_REPORTS_DIR / f"{screenshot_config['name']}.png"

    if capture_clip:
        page.screenshot(path=output_path, clip=capture_clip)
    else:
        page.screenshot(path=output_path, full_page=False)

    page.close()

    print(f"  OK Captured: {output_path.name}")

    # Optimize the screenshot
    optimized_path = optimize_png(output_path)

    return optimized_path


def capture_all_screenshots(browser, screenshot_configs=None) -> list[Path]:
    """Capture every configured screenshot and fail if any capture fails."""
    configs = SCREENSHOTS if screenshot_configs is None else screenshot_configs
    captured_files = []
    failures = []

    for screenshot_config in configs:
        try:
            output_path = capture_screenshot(browser, screenshot_config)
            if output_path:
                captured_files.append(output_path)
        except Exception as error:
            screenshot_name = screenshot_config.get("name", "unnamed")
            print(f"  ERROR: Failed to capture screenshot '{screenshot_name}': {error}")
            failures.append((screenshot_name, error))

    if failures:
        failed_names = ", ".join(name for name, _ in failures)
        raise RuntimeError(
            f"Failed to capture {len(failures)} screenshot(s): {failed_names}"
        ) from failures[0][1]

    return captured_files


def main():
    """Main function to capture all screenshots."""
    supported_options = ("--check-dependencies", "--anonymize-only")
    unexpected_arguments = [
        argument for argument in sys.argv[1:] if argument not in supported_options
    ]
    if unexpected_arguments:
        print(f"ERROR: Unsupported argument(s): {' '.join(unexpected_arguments)}")
        print(f"Supported options: {', '.join(supported_options)}")
        sys.exit(2)

    # The changes page names the same accounts and resources as the
    # single-account report, so the three are anonymized together and share
    # one set of placeholders. It goes last: an account's placeholder depends
    # on where it is first found, and the main reports keep their assignment.
    report_files = sorted({SAMPLE_REPORTS_DIR / cfg["file"] for cfg in SCREENSHOTS}) + [
        SAMPLE_REPORTS_DIR / CHANGES_PAGE
    ]
    if "--anonymize-only" in sys.argv[1:]:
        # No browser needed: anonymize the sample reports and stop.
        ensure_repo_venv()
        anonymize_account_ids(report_files)
        anonymize_resource_ids(report_files)
        anonymize_resource_names(report_files)
        point_changes_links_at_samples(SAMPLE_REPORTS_DIR / CHANGES_PAGE)
        return

    check_dependencies_only = "--check-dependencies" in sys.argv[1:]
    bootstrap_screenshot_environment()

    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            print("Verifying Playwright Chromium launch...")
            browser = launch_chromium(p)
            print(f"Verified browser: {browser.browser_type.name} {browser.version}")

            if check_dependencies_only:
                browser.close()
                print("Screenshot environment is ready.")
                return

            print("=" * 70)
            print("AI/ML Security Assessment - Screenshot Capture Tool")
            print("=" * 70)

            # Check if sample reports exist
            if not SAMPLE_REPORTS_DIR.exists():
                print(
                    f"\nERROR: Sample reports directory not found: {SAMPLE_REPORTS_DIR}"
                )
                browser.close()
                sys.exit(1)

            print(f"\n Sample reports directory: {SAMPLE_REPORTS_DIR}")
            print(f" Viewport size: {VIEWPORT_WIDTH}x{VIEWPORT_HEIGHT}")
            print(f" Target: {len(SCREENSHOTS)} screenshots")

            # Anonymize account and resource IDs only after the browser
            # environment has been verified, so a bootstrap failure cannot
            # modify report files.
            anonymize_account_ids(report_files)
            anonymize_resource_ids(report_files)
            anonymize_resource_names(report_files)
            point_changes_links_at_samples(SAMPLE_REPORTS_DIR / CHANGES_PAGE)

            try:
                captured_files = capture_all_screenshots(browser)
            finally:
                browser.close()

            # Summary
            print("\n" + "=" * 70)
            print(f"SUCCESS: Successfully captured {len(captured_files)} screenshots")
            print("=" * 70)

            print("\n Generated screenshots:")
            total_size = 0
            for file_path in captured_files:
                size_kb = file_path.stat().st_size / 1024
                total_size += size_kb
                print(f"  - {file_path.name} ({size_kb:.1f} KB)")

            print(f"\n Total size: {total_size:.1f} KB ({total_size / 1024:.2f} MB)")

            print("\n Next steps:")
            print("  1. Review the screenshots in the sample-reports/ folder")
            print("  2. Update README.md to reference these screenshots")
            print("  3. Commit the screenshots to the repository")

    except Exception as e:
        print(f"\nERROR: Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
