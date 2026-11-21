"""The committed Cloudscape report UI bundle and the page that inlines it.

report-ui/ is built once with npm and its output committed under
generate_consolidated_report/report_ui/, so neither the Lambda nor CodeBuild
needs Node. These tests fail when the source changes without a rebuild, when
the bundle cannot be inlined safely, and (when a local Chrome or Chromium is
available) when a rendered report does not display.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.report_data import TEMPLATE_PATH, report_data

ROOT = Path(__file__).resolve().parent.parent
UI_SOURCE = ROOT / "report-ui"
BUNDLE_DIR = TEMPLATE_PATH.parent / "report_ui"
MANIFEST = json.loads((BUNDLE_DIR / "manifest.json").read_text(encoding="utf-8"))


def _template():
    import importlib.util

    spec = importlib.util.spec_from_file_location("bundle_test_template", TEMPLATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_hash() -> str:
    """Mirror of report-ui/scripts/write-manifest.mjs."""
    inputs = sorted(p for p in (UI_SOURCE / "src").rglob("*") if p.is_file())
    inputs += [
        UI_SOURCE / name
        for name in (
            "package.json",
            "package-lock.json",
            "vite.config.ts",
            "tsconfig.json",
            "scripts/write-manifest.mjs",
        )
    ]
    digest = hashlib.sha256()
    for path in inputs:
        digest.update(path.relative_to(UI_SOURCE).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
        digest.update(b"\0")
    return digest.hexdigest()


def test_committed_bundle_matches_its_source():
    assert MANIFEST["sourceSha256"] == _source_hash(), (
        "report-ui/ changed without a rebuild: run `npm ci && npm run build` in report-ui/ "
        "and commit generate_consolidated_report/report_ui/"
    )


def test_bundle_uses_real_cloudscape_packages():
    versions = MANIFEST["versions"]
    for package in (
        "@cloudscape-design/components",
        "@cloudscape-design/global-styles",
        "@cloudscape-design/collection-hooks",
    ):
        assert versions.get(package), package
    css = (BUNDLE_DIR / "report-ui.css").read_text(encoding="utf-8")
    js = (BUNDLE_DIR / "report-ui.js").read_text(encoding="utf-8")
    assert "awsui_" in css and "awsui_" in js
    assert "Open Sans" in css


@pytest.mark.parametrize("name", ["report-ui.js", "report-ui.css"])
def test_bundle_can_be_inlined(name):
    text = (BUNDLE_DIR / name).read_text(encoding="utf-8").lower()
    assert "</script" not in text and "</style" not in text


def test_bundle_needs_no_network():
    """Fonts and icons are inlined, so reports open offline."""
    css = (BUNDLE_DIR / "report-ui.css").read_text(encoding="utf-8")
    assert "url(http" not in css and "@import" not in css


def test_page_is_self_contained_with_favicon_and_data():
    template = _template()
    page = template.render_page({"kind": "assessment", "title": "t"}, "A <title>")
    assert page.startswith("<!DOCTYPE html>")
    assert '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,' in page
    assert "<title>A &lt;title&gt;</title>" in page
    assert '<link rel="stylesheet"' not in page and "<script src=" not in page
    assert report_data(page) == {"kind": "assessment", "title": "t"}


def test_embedded_json_cannot_close_its_script_element():
    template = _template()
    hostile = "</script><script>alert(1)</script>& "
    page = template.render_page({"text": hostile}, "t")
    data_start = page.index('id="report-data">')
    data_end = page.index("</script>", data_start)
    embedded = page[data_start:data_end]
    assert "<" not in embedded.split(">", 1)[1]
    assert report_data(page) == {"text": hostile}


def test_missing_bundle_is_a_clear_error(monkeypatch, tmp_path):
    template = _template()
    monkeypatch.setattr(template, "REPORT_UI_DIR", tmp_path)
    with pytest.raises(template.ReportUiMissingError, match="npm run build"):
        template.render_page({}, "t")


@pytest.mark.parametrize(
    "markup, expected",
    [
        ("plain", ["plain"]),
        ("a <strong>b</strong> c", ["a ", {"strong": ["b"]}, " c"]),
        (
            'see <a href="https://example.com/x" target="_blank">docs</a>.',
            ["see ", {"link": "docs", "href": "https://example.com/x"}, "."],
        ),
        ("L &times; I", ["L × I"]),
    ],
)
def test_rich_text_accepts_only_trusted_tags(markup, expected):
    assert _template().rich(markup) == expected


@pytest.mark.parametrize(
    "markup",
    [
        "<script>x</script>",
        '<a href="javascript:alert(1)">x</a>',
        "<strong>open",
        "x</strong>",
    ],
)
def test_rich_text_rejects_anything_else(markup):
    with pytest.raises(ValueError):
        _template().rich(markup)


# --- rendered in a real browser ------------------------------------------------------


def _browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    manager = sync_api.sync_playwright().start()
    for options in ({}, {"channel": "chrome"}):
        try:
            return manager, manager.chromium.launch(**options)
        except Exception:  # noqa: BLE001 - try the next browser
            continue
    manager.stop()
    pytest.skip("no Chromium or Chrome available for the browser smoke test")


def _sample_report(tmp_path) -> Path:
    template = _template()
    findings = [
        {
            "Check_ID": "BR-01",
            "Finding": "Synthetic <b>failed</b> check",
            "Finding_Details": (
                "Synthetic details for 2 function(s): function 'a' (role 'r; x'); "
                "function 'b'. Roles are read once. bedrock:InvokeModel is allowed "
                "on arn:aws:bedrock:us-east-1:123456789012:guardrail/g1."
            ),
            "Resolution": "Fix it",
            "Reference": "https://docs.aws.amazon.com/bedrock/",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "_service": "bedrock",
        },
        {
            "Check_ID": "BR-02",
            "Finding": "Synthetic passed check",
            "Finding_Details": "",
            "Resolution": "",
            "Reference": "",
            "Severity": "Low",
            "Status": "Passed",
            "Region": "us-east-1",
            "_service": "bedrock",
        },
    ]
    page = template.generate_html_report(
        findings,
        {},
        {"bedrock": {"passed": 1, "failed": 1, "na": 0}},
        account_id="123456789012",
        regions=["us-east-1"],
    )
    path = tmp_path / "report.html"
    path.write_text(page, encoding="utf-8")
    return path


def test_report_displays_in_a_browser(tmp_path):
    path = _sample_report(tmp_path)
    manager, browser = _browser()
    try:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(path.as_uri())
        table = page.get_by_test_id("findings-table")
        table.wait_for(timeout=15000)
        # Failed rows are shown by default; markup in finding text stays text.
        assert "Synthetic <b>failed</b> check" in table.inner_text()
        assert "Synthetic passed check" not in table.inner_text()
        assert page.locator("#bedrock").count() == 1
        # A finding's radio button opens its details in the split panel;
        # closing the panel clears the choice.
        table.locator("input[type=radio]").first.click(force=True)
        panel = page.get_by_test_id("finding-details")
        panel.wait_for(timeout=5000)
        assert "Synthetic details for 2 function(s):" in panel.inner_text()
        # "lead: a; b" sentences show as a list; separators inside quotes or
        # brackets stay put, and the following sentence stays as text.
        items = panel.locator("li")
        assert items.count() == 2
        # AWS identifiers (quoted names, ARNs, IAM actions) show as inline
        # code, without the quotes around a name.
        assert items.nth(0).locator(".report-identifier").all_inner_texts() == [
            "a",
            "r; x",
        ]
        assert items.nth(1).locator(".report-identifier").all_inner_texts() == ["b"]
        identifiers = panel.locator(".report-identifier").all_inner_texts()
        assert "arn:aws:bedrock:us-east-1:123456789012:guardrail/g1" in identifiers
        assert "bedrock:InvokeModel" in identifiers
        assert "Roles are read once." in panel.inner_text()
        assert "Fix it" in panel.inner_text()
        page.get_by_role("button", name="Close finding details").first.click()
        page.wait_for_timeout(300)
        assert table.locator("input[type=radio]:checked").count() == 0
        # The theme toggle sits in the top navigation and switches the mode.
        page.get_by_role("button", name="Switch to dark mode").click()
        assert "awsui-dark-mode" in page.evaluate("document.body.className")
        assert errors == []
    finally:
        browser.close()
        manager.stop()
