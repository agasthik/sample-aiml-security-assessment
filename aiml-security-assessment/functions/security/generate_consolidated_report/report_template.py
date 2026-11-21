"""
Shared report builder for the AI/ML Security Assessment HTML reports.

Used by both:
- Single-account Lambda (app.py)
- Multi-account CodeBuild consolidation (consolidate_html_reports.py)
and, by file path, by the assessment-history changes page
(assessment_history/render_common.py).

The report is drawn with the Cloudscape Design System. Python owns every
figure, label, and sentence: `build_report_data()` returns a JSON-ready model,
and `render_page()` writes one self-contained HTML file holding that model and
the prebuilt Cloudscape UI bundle (report_ui/, built from report-ui/ at the
repository root). The reports need no network access to display.
"""

from datetime import datetime, timezone
import base64
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

# ---------------------------------------------------------------------------
# Area icons. Each is a standalone SVG, embedded in the report as a data URI.
# Bedrock, SageMaker AI and AgentCore use the AWS Architecture Icons; the
# others have no official AWS icon and use simple project marks.
# ---------------------------------------------------------------------------
BEDROCK_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" transform="translate(12,12)" d="M52,26.999C50.897,26.999 50,26.103 50,25 50,23.897 50.897,23 52,23 53.103,23 54,23.897 54,25 54,26.103 53.103,26.999 52,26.999L52,26.999ZM20.113,53.908L16.865,52.014 23.53,47.848 22.47,46.152 14.913,50.875 9,47.426 9,38.535 14.555,34.832 13.445,33.168 7.959,36.825 2,33.42 2,28.58 8.496,24.868 7.504,23.132 2,26.277 2,22.58 8,19.152 14,22.58 14,26.434 9.485,29.143 10.515,30.857 15,28.166 19.485,30.857 20.515,29.143 16,26.434 16,22.535 21.555,18.832C21.833,18.646 22,18.334 22,18L22,11 20,11 20,17.465 14.959,20.825 9,17.42 9,8.574 14,5.658 14,14 16,14 16,4.491 20.113,2.092 28,4.721 28,33.434 13.485,42.143 14.515,43.857 28,35.766 28,51.279 20.113,53.908ZM50,38C50,39.103 49.103,40 48,40 46.897,40 46,39.103 46,38 46,36.897 46.897,36 48,36 49.103,36 50,36.897 50,38L50,38ZM40,48C40,49.103 39.103,50 38,50 36.897,50 36,49.103 36,48 36,46.897 36.897,46 38,46 39.103,46 40,46.897 40,48L40,48ZM39,8C39,6.897 39.897,6 41,6 42.103,6 43,6.897 43,8 43,9.103 42.103,10 41,10 39.897,10 39,9.103 39,8L39,8ZM52,21C50.141,21 48.589,22.28 48.142,24L30,24 30,19 41,19C41.553,19 42,18.552 42,18L42,11.858C43.72,11.411 45,9.858 45,8 45,5.794 43.206,4 41,4 38.794,4 37,5.794 37,8 37,9.858 38.28,11.411 40,11.858L40,17 30,17 30,4C30,3.569 29.725,3.188 29.316,3.051L20.316,0.051C20.042,-0.039 19.744,-0.009 19.496,0.136L7.496,7.136C7.188,7.315 7,7.645 7,8L7,17.42 0.504,21.132C0.192,21.31 0,21.641 0,22L0,34C0,34.359 0.192,34.69 0.504,34.868L7,38.58 7,48C7,48.355 7.188,48.685 7.496,48.864L19.496,55.864C19.65,55.954 19.825,56 20,56 20.106,56 20.213,55.983 20.316,55.949L29.316,52.949C29.725,52.812 30,52.431 30,52L30,40 37,40 37,44.142C35.28,44.589 34,46.142 34,48 34,50.206 35.794,52 38,52 40.206,52 42,50.206 42,48 42,46.142 40.72,44.589 39,44.142L39,39C39,38.448 38.553,38 38,38L30,38 30,33 42.5,33 44.638,35.85C44.239,36.472 44,37.207 44,38 44,40.206 45.794,42 48,42 50.206,42 52,40.206 52,38 52,35.794 50.206,34 48,34 47.316,34 46.682,34.188 46.119,34.492L43.8,31.4C43.611,31.148 43.314,31 43,31L30,31 30,26 48.142,26C48.589,27.72 50.141,29 52,29 54.206,29 56,27.206 56,25 56,22.794 54.206,21 52,21L52,21Z"/></svg>'
SAGEMAKER_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M54.034,26.034C54.034,26.594 53.578,27.05 53.017,27.05 52.458,27.05 52.002,26.594 52.002,26.034 52.002,25.474 52.458,25.018 53.017,25.018 53.578,25.018 54.034,25.474 54.034,26.034L54.034,26.034ZM48.002,36C48.002,35.449 48.45,35 49.002,35 49.554,35 50.002,35.449 50.002,36 50.002,36.551 49.554,37 49.002,37 48.45,37 48.002,36.551 48.002,36L48.002,36ZM48.002,55C48.002,54.449 48.45,54 49.002,54 49.554,54 50.002,54.449 50.002,55 50.002,55.551 49.554,56 49.002,56 48.45,56 48.002,55.551 48.002,55L48.002,55ZM58.002,42C58.002,42.551 57.554,43 57.002,43 56.45,43 56.002,42.551 56.002,42 56.002,41.449 56.45,41 57.002,41 57.554,41 58.002,41.449 58.002,42L58.002,42ZM65,45.272L59.963,42.382C59.979,42.256 60.002,42.131 60.002,42 60.002,40.346 58.656,39 57.002,39 55.347,39 54.002,40.346 54.002,42 54.002,43.654 55.347,45 57.002,45 57.801,45 58.523,44.681 59.061,44.171L63.886,46.939 59.555,49.105C59.216,49.275 59.002,49.621 59.002,50L59.002,58.441 46.983,65.837 41.003,62.42 41.003,56 46.186,56C46.6,57.161 47.7,58 49.002,58 50.656,58 52.002,56.654 52.002,55 52.002,53.345 50.656,52 49.002,52 47.7,52 46.6,52.838 46.186,54L41.003,54 41.003,40C41.003,39.649 40.818,39.323 40.517,39.142L35.516,36.142 34.487,37.857 39.003,40.566 39.003,43.507 33.002,48.123 33.002,44C33.002,43.696 32.864,43.408 32.627,43.219L28.002,39.519 28.002,34.535 33.556,30.832C33.835,30.646 34.002,30.334 34.002,30L34.002,24 32.002,24 32.002,29.465 27.013,32.79 22.002,29.464 22.002,21.575 27.002,18.659 27.002,27 29.002,27 29.002,17.492 33.005,15.157 39.001,18.616 39.002,31C39.002,31.359 39.194,31.69 39.506,31.868L46.042,35.603C46.024,35.734 46.002,35.864 46.002,36 46.002,37.654 47.347,39 49.002,39 50.656,39 52.002,37.654 52.002,36 52.002,34.346 50.656,33 49.002,33 48.208,33 47.49,33.315 46.953,33.82L41.002,30.419 41.001,18.618 46.964,15.177 58.002,22.536 58.002,25 55.851,25C55.429,23.845 54.318,23.018 53.017,23.018 51.354,23.018 50.002,24.371 50.002,26.034 50.002,27.697 51.354,29.05 53.017,29.05 54.343,29.05 55.471,28.191 55.875,27L58.002,27 58.002,30C58.002,30.36 58.194,30.691 58.506,30.869L65,34.58 65,45.272ZM33.02,65.837L29.867,63.897 35.583,59.814 34.421,58.186 28.018,62.759 21.002,58.441 21.002,50.566 25.516,47.857 24.487,46.142 19.958,48.86 15.002,46.383 15.001,40.617 20.449,37.894 19.555,36.105 15.001,38.381 15.002,34.58 20.963,31.175 26.002,34.519 26.002,39.48 20.449,43.167 21.555,44.833 26.958,41.245 31.002,44.48 31.002,49.662 26.392,53.207 27.611,54.792 39.003,46.03 39.003,62.419 33.02,65.837ZM66.496,33.132L60.002,29.42 60.002,22C60.002,21.666 59.835,21.354 59.556,21.169L47.556,13.169C47.24,12.959 46.832,12.945 46.502,13.135L40.004,16.885 33.502,13.135C33.19,12.955 32.807,12.955 32.498,13.137L20.498,20.137C20.19,20.316 20.002,20.645 20.002,21L20.002,29.42 13.506,33.132C13.194,33.31 13.002,33.641 13.002,34L13.002,34.417C13.001,34.438 13,34.458 13,34.479L13,45.363C13,45.383 13.001,45.403 13.002,45.422L13.002,47C13.002,47.379 13.216,47.725 13.555,47.894L19.002,50.618 19.002,59C19.002,59.347 19.181,59.669 19.477,59.851L32.477,67.851C32.638,67.95 32.82,68 33.002,68 33.173,68 33.344,67.956 33.498,67.868L40.003,64.152 46.506,67.868C46.821,68.049 47.213,68.042 47.526,67.851L60.526,59.851C60.822,59.669 61.002,59.347 61.002,59L61.002,50.618 66.447,47.894C66.786,47.725 67,47.379 67,47L67,34C67,33.641 66.807,33.31 66.496,33.132L66.496,33.132Z"/></svg>'
AGENTCORE_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M67.372,28.073L64.178,26.792 62.933,23.634C62.781,23.252 62.412,23.001 62.002,23.001 61.591,23.001 61.222,23.253 61.071,23.636L59.814,26.838 56.638,28.071C56.253,28.22 55.999,28.592 56,29.005 56.001,29.419 56.257,29.79 56.643,29.937L59.89,31.178 61.063,34.348C61.205,34.735 61.572,34.995 61.985,35.001L62,35.001C62.407,35.001 62.774,34.754 62.928,34.375L64.231,31.142 67.36,29.934C67.743,29.786 67.997,29.418 68,29.007 68.003,28.597 67.754,28.226 67.372,28.073ZM63.106,29.432C62.849,29.532 62.643,29.734 62.539,29.991L62.04,31.228 61.607,30.058C61.508,29.788 61.296,29.574 61.027,29.471L59.782,28.996 60.947,28.543C61.207,28.442 61.414,28.237 61.516,27.977L62.004,26.732 62.435,27.822C62.523,28.142 62.767,28.398 63.079,28.506L64.269,28.983 63.106,29.432ZM64.053,38.6L54.914,34.935 51.351,25.902C51.123,25.325 50.575,24.953 49.955,24.953 49.335,24.954 48.786,25.327 48.56,25.905L44.958,35.083 42,36.23 42,16C42,15.569 41.725,15.188 41.316,15.051L32.316,12.051C32.042,11.961 31.744,11.991 31.496,12.136L19.496,19.136C19.189,19.315 19,19.645 19,20L19,29.42 12.504,33.132C12.192,33.31 12,33.641 12,34L12,46C12,46.359 12.192,46.69 12.504,46.868L19,50.58 19,60C19,60.355 19.189,60.685 19.496,60.864L31.496,67.864C31.65,67.954 31.825,68 32,68 32.106,68 32.213,67.983 32.316,67.949L41.316,64.949C41.725,64.813 42,64.431 42,64L42,43.738 45.2,44.961 48.561,54.046C48.777,54.632 49.32,55.017 49.945,55.026L49.969,55.026C50.584,55.026 51.128,54.66 51.359,54.087L55.089,44.845 64.035,41.392C64.614,41.168 64.991,40.623 64.995,40.001 64.999,39.381 64.629,38.831 64.053,38.6ZM32.113,65.908L28.865,64.014 35.53,59.848 34.47,58.186 26.913,62.759 21,58.441 21,50.566 26.555,46.832 25.445,45.168 19.959,48.825 14,45.42 14,40.58 20.496,36.868 19.504,35.132 14,38.277 14,34.58 20,31.152 26,34.58 26,38.434 21.485,41.143 22.515,42.857 27,40.166 31.485,42.857 32.515,41.143 28,38.434 28,34.535 33.555,30.832C33.833,30.646 34,30.334 34,30L34,24 32,24 32,29.465 26.959,32.825 21,29.42 21,20.574 26,17.658 26,27 28,27 28,16.491 32.113,14.092 40,16.721 40,45.434 25.485,54.143 26.515,55.857 40,47.766 40,63.279 32.113,65.908ZM53.964,43.135C53.706,43.235 53.501,43.438 53.397,43.694L49.988,52.14 46.918,43.842C46.818,43.572 46.607,43.358 46.338,43.255L42,41.597 42,38.375 46.09,36.788C46.351,36.687 46.558,36.481 46.659,36.221L49.957,27.818 53.14,35.886C53.209,36.252 53.486,36.548 53.84,36.659L62.129,39.983 53.964,43.135Z"/></svg>'
AGENT_REGISTRY_ICON = AGENTCORE_ICON
# Responsible AI GRC service icon (no official AWS icon exists for
# "Financial Services", the origin of this capability's controls).
RESPONSIBLE_AI_GRC_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#7C3AED" width="80" height="80"/><path fill="#FFF" d="M40 14 L66 26 L66 31 L14 31 L14 26 Z M20 35 h6 v23 h-6 z M37 35 h6 v23 h-6 z M54 35 h6 v23 h-6 z M14 62 h52 v5 h-52 z"/></svg>'
AGENTIC_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#0F766E" width="80" height="80"/><path fill="#FFF" d="M40 10 64 20v16c0 15-9.8 27.8-24 34-14.2-6.2-24-19-24-34V20l24-10zm0 8-16 6.7V36c0 10.4 6.1 19.9 16 25 9.9-5.1 16-14.6 16-25V24.7L40 18zm-8 17a8 8 0 1 1 14.9 4.1L52 48h-8l-3.2-5.3h-1.6L36 48h-8l5.1-8.9A8 8 0 0 1 32 35z"/></svg>'
# OWASP Top 10 for LLM icon (no official AWS icon; shield outline).
OWASP_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#10B981" width="80" height="80"/><path fill="#FFF" d="M40 12 20 20v18c0 14 8 26 20 30 12-4 20-16 20-30V20L40 12zm0 8 12 4.8V38c0 10-5.2 18.6-12 22-6.8-3.4-12-12-12-22V24.8L40 20zm-3 12h6l-3 8-3-8z"/></svg>'
# AWS AI Security Framework icon (no official AWS icon; layered-framework mark).
AISF_ICON = '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#0972D3" width="80" height="80"/><path fill="#FFF" d="M40 14L64 26L40 38L16 26L40 14ZM40 44L22 35L16 38L40 50L64 38L58 35L40 44ZM40 56L22 47L16 50L40 62L64 50L58 47L40 56Z"/></svg>'

GENAI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/"
    "generative-ai-lens.html"
)
AGENTIC_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/"
    "agentic-ai-lens.html"
)
RESPONSIBLE_AI_GRC_GUIDE_URL = (
    "https://aws.amazon.com/blogs/security/"
    "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/"
)
RESPONSIBLE_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/responsible-ai-lens/"
    "responsible-ai-lens.html"
)

# ---------------------------------------------------------------------------
# Responsible AI GRC display labels.
#
# Single source of truth for every customer-visible label on this capability.
# Before the rebrand the same capability appeared under several competing
# names (FinServ, Financial Services, Financial Services Risk, Financial
# Services GenAI Risk, Financial Services GenAI Risk Findings) across ten
# hardcoded sites. Renaming through these constants keeps them from diverging
# again.
#
# The machine identity is deliberately NOT here: the "responsible-ai-grc"
# service slug is a persisted contract. It is the area slug in the report
# data model (the section id, so "#responsible-ai-grc" links keep working),
# the Assessment Area filter value, and each finding row's "service" value,
# and the consolidators and assessment history use it as the area key.
# ---------------------------------------------------------------------------
RESPONSIBLE_AI_GRC_LABEL = "Responsible AI GRC"

# The DOM/CSV service slug. This is the one name for the capability now:
# the legacy "finserv" slug and the additive "responsible-ai-grc" alias
# (Phase 2 Stage 2b) have both been retired in favor of this single value.
RESPONSIBLE_AI_GRC_SLUG = "responsible-ai-grc"

# The capability is cross-industry, so it is grouped by governance framework
# rather than by industry. The governance-* CSS class names reflect that.
RESPONSIBLE_AI_GRC_NAV_HEADING = "By Governance Framework"
RESPONSIBLE_AI_GRC_SCOPE_LABEL = "Governance Framework"

RESPONSIBLE_AI_GRC_SCOPE_STATEMENT = (
    "Responsible AI GRC comprises 64 automated checks that evaluate selected AWS "
    "configuration evidence against project-authored technical controls informed "
    "by the AWS User Guide to Governance, Risk, and Compliance for Responsible AI "
    "Adoption and by AWS financial-services generative-AI risk guidance. The "
    "controls originated as financial-services controls and were found applicable "
    "across multiple industries. They do not establish regulatory compliance, "
    "certify a system as responsible AI, or provide complete Responsible AI or GRC "
    "coverage. Regulatory framework mappings are preliminary. Manual legal, "
    "policy, model-risk, fairness, and use-case review remains required."
)

# Required disambiguation. This rename moves closer to the AWS Well-Architected
# Responsible AI Lens than "FinServ" ever did, so the distinction is stated
# wherever the name appears rather than left to be inferred.
RESPONSIBLE_AI_LENS_DISAMBIGUATION = (
    "<strong>Responsible AI GRC is not the "
    f'<a href="{RESPONSIBLE_AI_LENS_URL}" target="_blank">AWS Well-Architected '
    "Responsible AI Lens</a>.</strong> The Lens (November 2025) is a separate "
    "architectural review framework with eight focus areas. These checks do not "
    "implement, validate, or measure conformance to it, and passing them does not "
    "indicate Lens alignment."
)

OWASP_LLM_TOP10_URL = "https://genai.owasp.org/llm-top-10/"


def _join_words(words: List[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


# AISF catalog figures the scope text states. They come from the AISF control
# catalog, which is not on the Lambda's filesystem, so they are copied here.
# `tests/test_aisf_derived_standard.py` pins covered and partial to the
# producers' `aisf_compliance_*.py` tag maps, and pins the documents that repeat
# these figures to them.
AISF_COVERED_CONTROLS = 64
AISF_PARTIAL_CONTROLS = 39
AISF_UNIMPLEMENTABLE_CONTROLS = 2
AISF_IN_SCOPE_CONTROLS = (
    AISF_COVERED_CONTROLS + AISF_PARTIAL_CONTROLS + AISF_UNIMPLEMENTABLE_CONTROLS
)


def _aisf_scope_text(derived: int, omitted: Optional[List[Any]] = None) -> str:
    """The AISF section's scope text, naming any control a deselected service removed.

    `derived` is `len(aisf_mappings.AISF_DERIVED_MAP)` and `omitted` holds
    (check id, [service label]) pairs from `aisf_mappings.omitted_aisf_controls()`;
    both arrive through `aisf_mappings.aisf_scope()`. When `omitted` is non-empty
    the first sentence also counts the derived controls this report can show.
    """
    remaining = AISF_IN_SCOPE_CONTROLS - derived
    if omitted:
        groups: Dict[tuple, List[str]] = {}
        for check_id, labels in omitted:
            groups.setdefault(tuple(labels), []).append(check_id)
        reasons = "; ".join(
            f"{_join_words(ids)} {'is' if len(ids) == 1 else 'are'} omitted "
            f"because {_join_words(list(labels))} "
            f"{'was' if len(labels) == 1 else 'were'} not selected"
            for labels, ids in groups.items()
        )
        shown = derived - len(omitted)
        opening = (
            f"Scope: {derived} of the {AISF_IN_SCOPE_CONTROLS} in-scope AISF "
            "controls carry a derived AISF- "
            f"row, and {shown} of them {'is' if shown == 1 else 'are'} in scope "
            f"for this report: {reasons}, so this report draws no conclusion "
            f"about them. The remaining {remaining} are not yet rendered as rows, "
            "and their absence from this section is not evidence of compliance. "
        )
    else:
        opening = (
            f"Scope: {derived} of the {AISF_IN_SCOPE_CONTROLS} in-scope AISF "
            "controls carry a derived AISF- "
            f"row; the remaining {remaining} are not yet rendered as rows, and "
            "their absence from this section is not evidence of compliance. "
        )
    return opening + (
        "A row is a "
        f"narrower claim than coverage: {AISF_COVERED_CONTROLS} of the "
        f"{AISF_IN_SCOPE_CONTROLS} are covered by checks "
        f"that already ship and assert the whole control, {AISF_PARTIAL_CONTROLS} "
        "are asserted in "
        f"part, and {AISF_UNIMPLEMENTABLE_CONTROLS} are not implementable from "
        "configuration. The "
        "Compliance_Frameworks column on the producer rows names the rest: "
        f"the {AISF_COVERED_CONTROLS - derived} covered controls without a row, "
        f"and the {AISF_PARTIAL_CONTROLS} asserted in "
        "part under a (partial) tag. AISF-01, AISF-02, "
        "AISF-03, AISF-04 and AISF-06 are retired: each restated a check "
        "that asserts only part of its control, so no row is derived for "
        "them. These rows restate existing check verdicts under AISF "
        "control ids, so they are <strong>not</strong> counted in the "
        "framework's 277-check total. AISF-00 marks an account and region "
        "where AISF-relevant checks ran but a mapped source check from a "
        "selected service was absent. Preliminary and illustrative: validate the control "
        "mapping with your Security/Compliance team before using it as "
        "evidence."
    )


# COMPLIANCE_STANDARDS: registry of compliance-standard sections.
# Each entry produces a navigation link + area card + section + filter
# option + scope chip in the report. Callers (generate_consolidated_report
# and consolidate_html_reports) also iterate this list to initialise
# service_stats/service_findings and route Check_ID prefixes.
#
# Required keys: slug, name, prefix, icon (a standalone SVG), reference_url,
# section_title, scope_text.
#
# Optional key "scope_text_for": a callable taking the caller's figures for the
# slug as keyword arguments, with any "omitted" (check id, [service]) pairs
# turned into (check id, [service label]) pairs, and returning the scope text.
# Used in place of scope_text when the caller passes compliance_scope for the
# slug, so the text can count what the caller's data holds and name the
# controls a deselected service removed.
#
# Optional key "derived" (bool, default False). A derived standard runs no
# assessment Lambda and writes no CSV to S3; its rows are computed at
# consolidation time from verdicts that checks already shipping produced (see
# aisf_mappings.derive_aisf_findings). A producing standard has an assessment
# function whose CSV lands under "<slug>_security_report_" in the assessment
# bucket.
#
# Appending an entry here is NOT sufficient on its own, contrary to what this
# comment claimed before AISF was added. Two things sit outside the loops:
#
#  1. S3 prefix construction. generate_consolidated_report/app.py turns every
#     non-derived slug into a list_objects_v2 prefix, and that function's
#     s3:ListBucket grant in template.yaml restricts s3:prefix to a fixed
#     StringLike list. A slug that writes no artifact draws AccessDenied,
#     which the caller re-raises, so the whole report fails. That is what the
#     "derived" key prevents: it keeps such a slug out of the prefix list.
#     Registering a producing standard instead means extending the IAM
#     condition and the artifact-validation sites too.
#  2. Row production. Nothing in the report layer invents rows. A producing
#     standard needs its Step Functions branch and its CSV; a derived standard
#     needs an explicit derivation call in both consolidators. A registered
#     standard with zero rows renders nothing at all (the compliance loop
#     below skips a standard whose _stats(...)["total"] is 0), which is
#     indistinguishable from a wiring bug, so registration and the first rows
#     ship together.
COMPLIANCE_STANDARDS: List[Dict[str, Any]] = [
    {
        "slug": "owasp",
        "name": "OWASP Top 10 LLM",
        "prefix": "OW-",
        "icon": OWASP_ICON,
        "reference_url": OWASP_LLM_TOP10_URL,
        "section_title": "OWASP Top 10 for LLM Findings",
        "scope_text": (
            "Scope: mapping-based derivation from existing BR/SM/AC/FS checks "
            "plus two net-new checks for LLM07 (System Prompt Leakage). "
            "Each finding's OWASP category (LLM01–LLM10) is encoded in the "
            "Finding_Details text. Preliminary and illustrative — validate "
            "mappings with your Security/Compliance team before using as evidence."
        ),
    },
    {
        "slug": "aisf",
        "name": "AWS AI Security Framework",
        "prefix": "AISF-",
        "icon": AISF_ICON,
        # Empty: no public AISF catalogue URL is cited in this repository, and
        # an empty value renders no "references" sentence in Assessment Scope.
        "reference_url": "",
        "section_title": "AWS AI Security Framework Findings",
        # Fallback for a caller that passes no compliance_scope. Both
        # consolidators pass aisf_mappings.aisf_scope(), and
        # test_scope_text_states_the_denominator_and_it_reconciles pins this
        # figure to len(AISF_DERIVED_MAP).
        "scope_text": _aisf_scope_text(derived=3),
        # Called with aisf_mappings.aisf_scope() when the caller passes
        # compliance_scope for this slug.
        "scope_text_for": _aisf_scope_text,
        # No assessment Lambda and no S3 artifact. See the `derived` note above.
        "derived": True,
    },
    # Future: {"slug": "nist", "name": "NIST AI RMF", "prefix": "NR-", ...}
    # Future: {"slug": "euaiact", "name": "EU AI Act", "prefix": "EU-", ...}
]


# ---------------------------------------------------------------------------
# Page rendering: the self-contained Cloudscape HTML file.
# ---------------------------------------------------------------------------

REPORT_UI_DIR = Path(__file__).resolve().parent / "report_ui"
REPORT_DATA_ELEMENT_ID = "report-data"
GITHUB_URL = "https://github.com/aws-samples/sample-aiml-security-assessment"
AWS_CUSTOMER_AGREEMENT_URL = "https://aws.amazon.com/agreement/"
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#232f3e"/>'
    '<path d="M16 5l9 3.5v6.5c0 5.8-3.8 10.6-9 12-5.2-1.4-9-6.2-9-12V8.5z" fill="#ff9900"/>'
    '<path d="M12 16l3 3 5-6" fill="none" stroke="#232f3e" stroke-width="2.4" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
FOOTER_MARKUP = (
    "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. Licensed "
    "under MIT-0. This report is provided as-is for informational purposes only and "
    "does not constitute professional security advice, compliance certification, or "
    "audit evidence. You are responsible for validating findings and determining "
    "applicability to your environment. See the "
    f'<a href="{AWS_CUSTOMER_AGREEMENT_URL}">AWS Customer Agreement</a> for terms of use.'
)


class ReportUiMissingError(RuntimeError):
    """The prebuilt Cloudscape bundle is missing; rebuild report-ui/."""


def _read_bundle_file(name: str) -> str:
    path = REPORT_UI_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReportUiMissingError(
            f"Cloudscape report UI bundle not found at {path}: {error}. "
            "Run `npm ci && npm run build` in report-ui/."
        ) from None


def report_ui_assets() -> Dict[str, str]:
    """The inlined Cloudscape bundle: {"js": ..., "css": ...}."""
    return {
        "js": _read_bundle_file("report-ui.js"),
        "css": _read_bundle_file("report-ui.css"),
    }


def svg_data_uri(svg: Optional[str]) -> Optional[str]:
    """An SVG as a base64 data URI for an <img>, or None."""
    if not svg:
        return None
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode(
        "ascii"
    )


def _json_for_script(data: Dict[str, Any]) -> str:
    """JSON safe to place inside a <script type="application/json"> element.

    `<`, `>` and `&` are written as \\u escapes, so finding text can never
    close the element or start markup; the JSON value is unchanged.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_page(data: Dict[str, Any], title: str) -> str:
    """One self-contained HTML report: the data model plus the Cloudscape UI."""
    assets = report_ui_assets()
    favicon = "data:image/svg+xml," + quote(FAVICON_SVG, safe="")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>{_escape_text(title)}</title>\n"
        f'<link rel="icon" type="image/svg+xml" href="{favicon}">\n'
        f"<style>{assets['css']}</style>\n"
        "</head>\n<body>\n"
        '<div id="root"><noscript>This report uses JavaScript to display its '
        "findings. Enable JavaScript, or open the CSV files from the same run."
        "</noscript></div>\n"
        f'<script type="application/json" id="{REPORT_DATA_ELEMENT_ID}">'
        f"{_json_for_script(data)}</script>\n"
        f"<script>{assets['js']}</script>\n"
        "</body>\n</html>\n"
    )


_REPORT_DATA_PATTERN = re.compile(
    r'<script type="application/json" id="'
    + REPORT_DATA_ELEMENT_ID
    + r'">(.*?)</script>',
    re.S,
)


def extract_report_data(page: str) -> Dict[str, Any]:
    """The data model embedded in a report written by `render_page()`."""
    match = _REPORT_DATA_PATTERN.search(page)
    if match is None:
        raise ValueError("no embedded report data found")
    return json.loads(match.group(1))


# ---------------------------------------------------------------------------
# Escaping and trusted rich text.
# ---------------------------------------------------------------------------


def _escape_text(value) -> str:
    """Escape untrusted text before placing it in HTML body text."""
    return html.escape("" if value is None else str(value), quote=False)


def _escape_attr(value) -> str:
    """Escape untrusted text before placing it in an HTML attribute."""
    return html.escape("" if value is None else str(value), quote=True)


def _safe_https_url(value) -> Optional[str]:
    """Return the URL when it is an absolute HTTPS link, otherwise None.

    The URL is returned unescaped: it travels in the JSON model and the UI sets
    it as a link target, which React escapes.
    """
    raw = "" if value is None else str(value).strip()
    if not raw or raw == "-":
        return None
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc:
        return None
    return raw


class _RichParser(HTMLParser):
    """Turns the module's own trusted markup into rich-text segments.

    Only <strong> and <a href="https://..."> are accepted. Anything else is a
    programming error in a constant here, not untrusted input, so it raises.
    Finding text never passes through this parser.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: List[List[Any]] = [[]]
        self.link: Optional[Dict[str, str]] = None

    def handle_starttag(self, tag, attrs):
        if tag == "strong" and self.link is None:
            self.stack.append([])
        elif tag == "a" and self.link is None:
            href = _safe_https_url(dict(attrs).get("href"))
            if href is None:
                raise ValueError("rich text links must be absolute HTTPS URLs")
            self.link = {"link": "", "href": href}
        else:
            raise ValueError(f"unsupported rich text tag <{tag}>")

    def handle_endtag(self, tag):
        if tag == "a" and self.link is not None:
            self.stack[-1].append(self.link)
            self.link = None
        elif tag == "strong" and len(self.stack) > 1 and self.link is None:
            inner = self.stack.pop()
            self.stack[-1].append({"strong": inner})
        else:
            raise ValueError(f"unbalanced rich text tag </{tag}>")

    def handle_data(self, data):
        if self.link is not None:
            self.link["link"] += data
        elif self.stack[-1] and isinstance(self.stack[-1][-1], str):
            self.stack[-1][-1] += data
        else:
            self.stack[-1].append(data)


def rich(markup: str) -> List[Any]:
    """Trusted markup (text, <strong>, https <a>) as rich-text segments."""
    parser = _RichParser()
    parser.feed(markup)
    parser.close()
    if len(parser.stack) != 1 or parser.link is not None:
        raise ValueError("unclosed rich text tag")
    return parser.stack[0]


def rich_text(segments: List[Any]) -> str:
    """The plain text of rich-text segments (for tests and logs)."""
    parts = []
    for segment in segments:
        if isinstance(segment, str):
            parts.append(segment)
        elif "strong" in segment:
            parts.append(rich_text(segment["strong"]))
        else:
            parts.append(segment["link"])
    return "".join(parts)


# ---------------------------------------------------------------------------
# Findings.
# ---------------------------------------------------------------------------


def _field(finding: Dict, lower: str, upper: str, default: str = "") -> str:
    value = finding.get(lower, finding.get(upper, default))
    return "" if value is None else str(value)


def finding_rows(findings: List[Dict]) -> List[Dict[str, Any]]:
    """Findings in the report model's row shape.

    Accepts either key casing (`Check_ID` from CSVs, `check_id` from older
    callers). Text stays raw; the UI renders it as text, never as markup.
    """
    rows = []
    for finding in findings:
        rows.append(
            {
                "account": _field(finding, "account_id", "Account_ID"),
                "region": _field(finding, "region", "Region"),
                "checkId": _field(finding, "check_id", "Check_ID"),
                "finding": _field(finding, "finding", "Finding"),
                "details": _field(finding, "details", "Finding_Details"),
                "resolution": _field(finding, "resolution", "Resolution"),
                "reference": _safe_https_url(_field(finding, "reference", "Reference")),
                "severity": _field(finding, "severity", "Severity", "Informational"),
                "status": _field(finding, "status", "Status"),
                # A row with no "_service" key is a direct Bedrock finding (the
                # historical default); an empty value stays empty so an
                # unrouted row matches no area filter instead of joining Bedrock.
                "service": finding.get("_service", "bedrock"),
            }
        )
    return rows


CORE_SERVICE_LABELS = {
    "bedrock": "Amazon Bedrock",
    "sagemaker": "Amazon SageMaker AI",
    "agentcore": "Amazon Bedrock AgentCore",
    "agent-registry": "AWS Agent Registry",
}

# Short names used in the navigation, the Assessment Area filter, the area
# cards, and the changes page.
AREA_NAMES = {
    "bedrock": "Bedrock",
    "sagemaker": "SageMaker",
    "agentcore": "AgentCore",
    "agent-registry": "AWS Agent Registry",
    "agentic": "Agentic AI Security",
    RESPONSIBLE_AI_GRC_SLUG: RESPONSIBLE_AI_GRC_LABEL,
}

AREA_ICONS = {
    "bedrock": BEDROCK_ICON,
    "sagemaker": SAGEMAKER_ICON,
    "agentcore": AGENTCORE_ICON,
    "agent-registry": AGENT_REGISTRY_ICON,
    "agentic": AGENTIC_ICON,
    RESPONSIBLE_AI_GRC_SLUG: RESPONSIBLE_AI_GRC_ICON,
}

SECTION_TITLES = {
    "bedrock": "Amazon Bedrock Findings",
    "sagemaker": "Amazon SageMaker Findings",
    "agentcore": "Amazon Bedrock AgentCore Findings",
    "agent-registry": "AWS Agent Registry Findings",
}

SERVICES_NAV_HEADING = "By Service"
LENS_NAV_HEADING = "By Lens"
COMPLIANCE_NAV_HEADING = "By Compliance Standard"

SEVERITY_OPTIONS = [
    {"value": "high", "label": "High"},
    {"value": "medium", "label": "Medium"},
    {"value": "low", "label": "Low"},
    {"value": "informational", "label": "Informational"},
]
STATUS_OPTIONS = [
    {"value": "failed", "label": "Failed"},
    {"value": "passed", "label": "Passed"},
    {"value": "n/a", "label": "N/A"},
]

SEVERITY_LEGEND = [
    {
        "severity": "High",
        "meaning": "Direct security risk - IAM/access control gaps, missing audit "
        "trails, guardrail bypasses that could lead to unauthorized access or data "
        "exposure",
        "action": rich("Remediate within <strong>7 days</strong>"),
    },
    {
        "severity": "Medium",
        "meaning": "Defense-in-depth gaps - encryption, logging, or configuration "
        "issues that reduce security posture",
        "action": rich("Remediate within <strong>30 days</strong>"),
    },
    {
        "severity": "Low",
        "meaning": "Best practice deviations - optimization opportunities that "
        "improve security hygiene",
        "action": rich("Remediate within <strong>90 days</strong>"),
    },
    {
        "severity": "Informational",
        "meaning": "Not applicable, unavailable, no resources found, or advisory-only rows",
        "action": rich("No action required"),
    },
]

METHODOLOGY_NOTES = (
    "<strong>Point-in-time:</strong> Security posture changes as resources are "
    "modified. <strong>Scope limited:</strong> Passed checks verify tested controls "
    "only. <strong>Scoring:</strong> Direct service rows are aggregated by unique "
    "Check ID; any failed assessable row fails the control, a control passes only "
    "when all assessable rows pass, and N/A rows are excluded. <strong>Context "
    "matters:</strong> Adjust severity for compliance requirements and environment type."
)

AGENTIC_SCOPE_TEXT = (
    "Scope: API-provable Agentic AI security controls mapped to the AWS "
    "Well-Architected Agentic AI Lens security guidance. Human-in-the-loop "
    "governance is referenced in methodology but not scored automatically unless "
    "an AWS API can prove the control."
)
RESPONSIBLE_AI_GRC_SECTION_SCOPE = (
    f"Scope: {RESPONSIBLE_AI_GRC_SCOPE_STATEMENT} This assessment records findings "
    "against each resolved CloudFormation TargetRegions entry. These checks are based on "
    f'<a href="{RESPONSIBLE_AI_GRC_GUIDE_URL}">the AWS User Guide to Governance, Risk, '
    "and Compliance for Responsible AI Adoption</a>. Severities follow a documented "
    f"Likelihood &times; Impact methodology. {RESPONSIBLE_AI_LENS_DISAMBIGUATION}"
)

# Scope chip labels in Assessment Methodology. The SageMaker chip predates
# the service's rename and keeps its original label.
SCOPE_CHIP_LABELS = {
    "bedrock": "Amazon Bedrock",
    "sagemaker": "Amazon SageMaker",
    "agentcore": "Amazon Bedrock AgentCore",
    "agent-registry": "AWS Agent Registry",
}


def core_service_selection(selection=None):
    """Read deployed service switches; reports from older executions select all."""
    selection = selection or {}
    result = {}
    for service in CORE_SERVICE_LABELS:
        value = selection.get(service, "true")
        if value not in ("true", "false", True, False):
            raise ValueError(f"Invalid assessment selection for {service}: {value!r}")
        result[service] = value is True or value == "true"
    return result


_SCORED_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _aggregate_scored_controls(
    findings: List[Dict], contextual_services: set[str]
) -> List[Dict[str, str]]:
    """Aggregate direct finding rows into one scored result per Check_ID.

    A control fails when any assessable row fails and passes only when every
    assessable row passes. Informational and N/A rows do not enter the score.
    """
    grouped: Dict[str, Dict[str, Optional[str]]] = {}

    for finding in findings:
        service = finding.get("_service", "").lower()
        if service in contextual_services:
            continue

        check_id = finding.get("check_id", finding.get("Check_ID", "")).strip()
        status = finding.get("status", finding.get("Status", "")).lower()
        severity = finding.get("severity", finding.get("Severity", "")).lower()
        if (
            not check_id
            or status not in {"passed", "failed"}
            or severity not in _SCORED_SEVERITY_RANK
        ):
            continue

        result = grouped.setdefault(
            check_id.upper(),
            {"passed_severity": None, "failed_severity": None},
        )
        severity_key = f"{status}_severity"
        current_severity = result[severity_key]
        if (
            current_severity is None
            or _SCORED_SEVERITY_RANK[severity] > _SCORED_SEVERITY_RANK[current_severity]
        ):
            result[severity_key] = severity

    aggregated = []
    for check_id, result in sorted(grouped.items()):
        if result["failed_severity"] is not None:
            aggregated.append(
                {
                    "check_id": check_id,
                    "status": "failed",
                    "severity": result["failed_severity"],
                }
            )
        elif result["passed_severity"] is not None:
            aggregated.append(
                {
                    "check_id": check_id,
                    "status": "passed",
                    "severity": result["passed_severity"],
                }
            )

    return aggregated


def _pass_rate(passed: int, count: int):
    return round((passed / count * 100), 1) if count > 0 else 0


def _rate(key: str, label: str, passed: int, count: int) -> Dict[str, Any]:
    rate = _pass_rate(passed, count)
    return {
        "key": key,
        "label": label,
        "passRate": rate,
        "passRateText": f"{rate}%",
        "description": f"{passed} of {count} scored controls passed",
    }


def _stats(service_stats: Dict[str, Dict[str, int]], slug: str) -> Dict[str, int]:
    stats = service_stats.get(slug, {})
    failed = stats.get("failed", 0)
    passed = stats.get("passed", 0)
    na = stats.get("na", 0)
    return {"failed": failed, "passed": passed, "na": na, "total": failed + passed + na}


def _selection_notice(omitted: List[str], agentic_description: str) -> Dict[str, Any]:
    return {
        "notSelected": omitted,
        "text": (
            "These direct service assessments did not run. This is different from "
            "an assessed service with no findings or N/A results. "
            + agentic_description
            + "When enabled, OWASP maps selected Bedrock, SageMaker, and AgentCore "
            "evidence plus Responsible AI GRC evidence and runs its own checks. "
            "Agent Registry is not an OWASP source. Affected OWASP controls include "
            "N/A coverage notices for deselected sources. Responsible AI GRC still "
            "assesses deselected services and calls their APIs when enabled, "
            "including when it runs as an OWASP dependency. Disable both optional "
            "assessments if only selected direct-service assessments should run. "
            "Service selection does not remove deployed IAM permissions."
        ),
    }


def build_report_data(
    all_findings: List[Dict],
    service_findings: Dict[str, List[Dict]],
    service_stats: Dict[str, Dict[str, int]],
    mode: str = "single",
    account_id: Optional[str] = None,
    account_ids: Optional[List[str]] = None,
    timestamp: Optional[str] = None,
    regions: list = None,
    service_selection: Optional[Dict[str, bool]] = None,
    compliance_scope: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """The report model the Cloudscape UI renders (see report-ui/src/types.ts).

    Arguments are those of `generate_html_report()`. `service_findings` is
    accepted for interface compatibility; rows come from `all_findings`.
    """
    del service_findings  # rows are routed by their "_service" key
    selected_services = core_service_selection(service_selection)
    omitted = [
        label
        for service, label in CORE_SERVICE_LABELS.items()
        if not selected_services[service]
    ]
    agentic_sources = [
        CORE_SERVICE_LABELS[service]
        for service in ("bedrock", "agentcore", "agent-registry")
        if selected_services[service]
    ]
    if agentic_sources and any(service_stats.get("agentic", {}).values()):
        agentic_selection_description = (
            "Agentic AI Security contains only findings from the selected sources: "
            + ", ".join(agentic_sources)
            + ". "
        )
    else:
        agentic_selection_description = (
            "Agentic AI Security is not included because no Agentic AI findings "
            "were produced by the selected direct assessments. "
        )

    def finding_severity(finding: Dict) -> str:
        return finding.get("severity", finding.get("Severity", "")).lower()

    def finding_status(finding: Dict) -> str:
        return finding.get("status", finding.get("Status", "")).lower()

    def finding_service(finding: Dict) -> str:
        return finding.get("_service", "").lower()

    def finding_region(finding: Dict) -> str:
        return finding.get("region", finding.get("Region", ""))

    scored_severities = {"high", "medium", "low"}
    compliance_slugs = {std["slug"] for std in COMPLIANCE_STANDARDS}
    contextual_services = {"agentic", RESPONSIBLE_AI_GRC_SLUG, *compliance_slugs}

    def is_failed_scored_row(finding: Dict) -> bool:
        return (
            finding_severity(finding) in scored_severities
            and finding_status(finding) == "failed"
        )

    def is_contextual_row(finding: Dict) -> bool:
        return finding_service(finding) in contextual_services

    # "Report Rows" is the visible row count, including N/A rows; unique checks
    # exclude blank Check_ID values so malformed rows do not inflate coverage.
    total_findings = len(all_findings)
    direct_risk_findings = [f for f in all_findings if not is_contextual_row(f)]
    unique_check_ids = {
        check_id
        for check_id in (
            f.get("check_id", f.get("Check_ID", "")).strip() for f in all_findings
        )
        if check_id
    }
    contextual_rows = sum(1 for f in all_findings if is_contextual_row(f))
    contextual_failed = sum(
        1 for f in all_findings if is_contextual_row(f) and is_failed_scored_row(f)
    )
    actionable_findings = sum(
        1 for f in direct_risk_findings if is_failed_scored_row(f)
    )

    def failed_counts(findings: List[Dict]) -> Dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding_severity(finding)
            if severity in counts and finding_status(finding) == "failed":
                counts[severity] += 1
        return counts

    direct_failed = failed_counts(direct_risk_findings)

    scored_controls = _aggregate_scored_controls(all_findings, contextual_services)
    severity_rates = []
    passed_total = 0
    for severity in ("high", "medium", "low"):
        count = sum(1 for c in scored_controls if c["severity"] == severity)
        passed = sum(
            1
            for c in scored_controls
            if c["severity"] == severity and c["status"] == "passed"
        )
        passed_total += passed
        severity_rates.append(_rate(severity, severity.upper(), passed, count))
    overall_rate = _rate("overall", "Overall", passed_total, len(scored_controls))

    if not timestamp:
        timestamp = datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M:%S UTC")
    generated = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Priority recommendations: up to three distinct failed High findings
    # (from the first four), then the first failed Medium finding.
    compliance_names = {std["slug"]: std["name"] for std in COMPLIANCE_STANDARDS}

    def area_display_name(slug: str) -> str:
        fixed = {**AREA_NAMES, "agentic": "Agentic AI"}
        return fixed.get(slug, compliance_names.get(slug, slug or "Unknown"))

    high_priority = [
        f
        for f in all_findings
        if finding_severity(f) == "high" and finding_status(f) == "failed"
    ]
    medium_priority = [
        f
        for f in all_findings
        if finding_severity(f) == "medium" and finding_status(f) == "failed"
    ]
    alert_groups: Dict[str, Dict[str, Any]] = {}
    for f in high_priority[:4]:
        key = f.get("finding", f.get("Finding", ""))
        group = alert_groups.setdefault(key, {"count": 0, "finding": f})
        group["count"] += 1
    alerts = [
        {
            "count": group["count"],
            "finding": key,
            "area": area_display_name(group["finding"].get("_service", "")),
            "level": "high",
        }
        for key, group in list(alert_groups.items())[:3]
    ]
    for f in medium_priority[:1]:
        alerts.append(
            {
                "count": 1,
                "finding": f.get("finding", f.get("Finding", "")),
                "area": area_display_name(f.get("_service", "")),
                "level": "medium",
            }
        )

    # Region filter: shown when there is more than one value to choose from.
    # "Global" tags IAM-only findings; it is excluded from `regions` (it must
    # not inflate the scanned region count) but still offered when present.
    has_global = any(
        (f.get("region") or f.get("Region")) == "Global" for f in all_findings
    )
    num_real_regions = len(regions) if regions else 0
    region_filter = None
    if num_real_regions + (1 if has_global else 0) > 1:
        region_filter = sorted(regions or []) + (["Global"] if has_global else [])

    def risk_card(label: str, findings: List[Dict]) -> Dict[str, Any]:
        counts = failed_counts(findings)
        return {"label": label, "total": sum(counts.values()), **counts}

    num_accounts = len(account_ids) if account_ids else 1
    num_regions = len(regions) if regions else 1
    account_filter = None
    account_cards = None
    if mode == "multi":
        title = "Multi-Account AI/ML Security Assessment Report"
        subtitle = "Multi-Account Assessment"
        account_info = f"Accounts: {num_accounts}"
        header_account_info = f"{num_accounts} Accounts"
        findings_sub = f"Visible rows across {num_accounts} accounts" + (
            f" · {num_regions} regions" if num_regions > 1 else ""
        )
        account_filter = sorted(account_ids or [])
        account_cards = [
            risk_card(
                acc_id,
                [
                    f
                    for f in direct_risk_findings
                    if f.get("account_id", f.get("Account_ID", "")) == acc_id
                ],
            )
            for acc_id in account_filter
        ]
    else:
        title = "AI/ML Security Assessment Report"
        subtitle = "Assessment Report"
        account_info = f"Account: {account_id or 'Unknown'}"
        if num_regions > 1:
            header_account_info = f"{account_info} · {num_regions} Regions"
            findings_sub = f"Visible rows across {num_regions} regions"
        else:
            header_account_info = account_info
            findings_sub = "Visible rows for this account"

    region_cards = None
    if (regions and len(regions) > 1) or has_global:
        region_cards = [
            risk_card(
                reg, [f for f in direct_risk_findings if finding_region(f) == reg]
            )
            for reg in sorted(regions or [])
        ]
        if has_global:
            region_cards.append(
                risk_card(
                    "Global",
                    [f for f in direct_risk_findings if finding_region(f) == "Global"],
                )
            )

    # Assessment areas, in navigation order.
    areas: List[Dict[str, Any]] = []
    nav_groups: List[Dict[str, Any]] = []

    def add_area(slug, name, icon, section_title, scope, selected=True, core=False):
        stats = _stats(service_stats, slug)
        if core:
            card_status = (
                f"{stats['failed']} Failed · {stats['passed']} Passed"
                + (f" · {stats['na']} N/A" if slug == "agent-registry" else "")
                if selected
                else "Not selected"
            )
        else:
            card_status = f"{stats['failed']} Failed · {stats['passed']} Passed · {stats['na']} N/A"
        areas.append(
            {
                "slug": slug,
                "name": name,
                "icon": svg_data_uri(icon),
                "selected": selected,
                **stats,
                "countText": str(stats["total"]) if selected else "—",
                "cardStatus": card_status,
                "sectionTitle": section_title,
                "scope": rich(scope) if scope else None,
            }
        )
        return slug

    nav_groups.append(
        {
            "heading": SERVICES_NAV_HEADING,
            "areas": [
                add_area(
                    slug,
                    AREA_NAMES[slug],
                    AREA_ICONS[slug],
                    SECTION_TITLES[slug],
                    None,
                    selected=selected_services[slug],
                    core=True,
                )
                for slug in ("bedrock", "sagemaker", "agentcore", "agent-registry")
            ],
        }
    )

    scope_groups: List[Dict[str, Any]] = [
        {
            "label": None,
            "chips": [
                {
                    "label": SCOPE_CHIP_LABELS[slug]
                    + ("" if selected_services[slug] else " — Not selected"),
                    "icon": svg_data_uri(AREA_ICONS[slug]),
                    "selected": selected_services[slug],
                }
                for slug in ("bedrock", "sagemaker", "agentcore", "agent-registry")
            ],
        }
    ]
    selected_labels = [
        label
        for service, label in CORE_SERVICE_LABELS.items()
        if selected_services[service]
    ]
    scope_source = (
        ", ".join(selected_labels)
        + " checks are based on the "
        + f'<a href="{GENAI_LENS_URL}">AWS Well-Architected Framework Generative AI Lens</a>. '
        if selected_labels
        else "No direct service assessments were selected. "
    )

    # Agentic AI Security (AG-*): a lens mapping, shown when AG rows exist.
    if _stats(service_stats, "agentic")["total"] > 0:
        nav_groups.append(
            {
                "heading": LENS_NAV_HEADING,
                "areas": [
                    add_area(
                        "agentic",
                        AREA_NAMES["agentic"],
                        AGENTIC_ICON,
                        "Agentic AI Security Findings",
                        AGENTIC_SCOPE_TEXT,
                    )
                ],
            }
        )
        scope_groups.append(
            {
                "label": "Agentic AI Security",
                "chips": [
                    {
                        "label": "Agentic AI Security Lens Mapping",
                        "icon": svg_data_uri(AGENTIC_ICON),
                        "selected": True,
                    }
                ],
            }
        )
        scope_source += (
            f'Agentic AI Security references the <a href="{AGENTIC_AI_LENS_URL}">'
            "AWS Well-Architected Agentic AI Lens</a>."
            " Controls that cannot be proven using AWS APIs, including semantic"
            " human-in-the-loop workflow quality, are not automatically scored."
        )

    # Responsible AI GRC (FS-*): shown only when its rows exist, so accounts
    # without it and EnableResponsibleAIGRCAssessment=false deploys stay clean.
    if _stats(service_stats, RESPONSIBLE_AI_GRC_SLUG)["total"] > 0:
        nav_groups.append(
            {
                "heading": RESPONSIBLE_AI_GRC_NAV_HEADING,
                "areas": [
                    add_area(
                        RESPONSIBLE_AI_GRC_SLUG,
                        RESPONSIBLE_AI_GRC_LABEL,
                        RESPONSIBLE_AI_GRC_ICON,
                        f"{RESPONSIBLE_AI_GRC_LABEL} Findings",
                        RESPONSIBLE_AI_GRC_SECTION_SCOPE,
                    )
                ],
            }
        )
        scope_groups.append(
            {
                "label": RESPONSIBLE_AI_GRC_SCOPE_LABEL,
                "chips": [
                    {
                        "label": RESPONSIBLE_AI_GRC_LABEL,
                        "icon": svg_data_uri(RESPONSIBLE_AI_GRC_ICON),
                        "selected": True,
                    }
                ],
            }
        )
        scope_source += (
            f" {RESPONSIBLE_AI_GRC_LABEL} checks are based on "
            f'<a href="{RESPONSIBLE_AI_GRC_GUIDE_URL}">the AWS User Guide to Governance, '
            "Risk, and Compliance for Responsible AI Adoption</a>. "
            f"{RESPONSIBLE_AI_LENS_DISAMBIGUATION}"
        )

    # Compliance standards (OWASP, AISF, future NIST / EU AI Act), driven by
    # COMPLIANCE_STANDARDS. Callers must also initialise service_stats /
    # service_findings from that registry; see generate_consolidated_report/app.py
    # and consolidate_html_reports.py for the reference wiring.
    compliance_areas = []
    compliance_chips = []
    for std in COMPLIANCE_STANDARDS:
        slug = std["slug"]
        if _stats(service_stats, slug)["total"] <= 0:
            continue
        scope_text = std.get("scope_text", "")
        scope = (compliance_scope or {}).get(slug)
        if scope is not None and std.get("scope_text_for"):
            scope_text = std["scope_text_for"](
                **{
                    **scope,
                    "omitted": [
                        (check_id, [CORE_SERVICE_LABELS[s] for s in services])
                        for check_id, services in scope.get("omitted", [])
                    ],
                }
            )
        compliance_areas.append(
            add_area(
                slug,
                std["name"],
                std["icon"],
                std.get("section_title", std["name"] + " Findings"),
                scope_text,
            )
        )
        compliance_chips.append(
            {"label": std["name"], "icon": svg_data_uri(std["icon"]), "selected": True}
        )
        reference_url = _safe_https_url(std.get("reference_url", ""))
        if reference_url:
            name = _escape_text(std["name"])
            scope_source += f' {name} references <a href="{_escape_attr(reference_url)}">{name}</a>.'
    if compliance_areas:
        nav_groups.append(
            {"heading": COMPLIANCE_NAV_HEADING, "areas": compliance_areas}
        )
        # One "By Compliance Standard" group with a chip per standard.
        scope_groups.append(
            {"label": COMPLIANCE_NAV_HEADING, "chips": compliance_chips}
        )

    overview = [
        {
            "label": "Unique Check IDs",
            "value": str(len(unique_check_ids)),
            "description": "Distinct Check_ID values represented",
            "tone": "neutral",
        },
        {
            "label": "Report Rows",
            "value": str(total_findings),
            "description": findings_sub,
            "tone": "neutral",
        },
        {
            "label": "Open Action Items",
            "value": str(actionable_findings),
            "description": "Direct failed service rows",
            "tone": "error",
        },
        {
            "label": "Lens / Compliance Rows",
            "value": str(contextual_rows),
            "description": f"{contextual_failed} failed; may map to service rows",
            "tone": "neutral",
        },
        {
            "label": "Failed High",
            "value": str(direct_failed["high"]),
            "description": "Direct High failed service rows",
            "tone": "error",
        },
        {
            "label": "Failed Medium / Low",
            "value": f"{direct_failed['medium']}/{direct_failed['low']}",
            "description": "Direct Medium / Low failed rows",
            "tone": "warning",
        },
    ]

    return {
        "kind": "assessment",
        "mode": "multi" if mode == "multi" else "single",
        "title": title,
        "subtitle": subtitle,
        "heading": "Security Assessment Overview",
        "timestamp": timestamp,
        "generated": generated,
        "accountInfo": account_info,
        "headerAccountInfo": header_account_info,
        "githubUrl": GITHUB_URL,
        "selectionNotice": (
            _selection_notice(omitted, agentic_selection_description)
            if omitted
            else None
        ),
        "overview": overview,
        "alerts": alerts,
        "severityLegend": SEVERITY_LEGEND,
        "risk": {
            "severity": severity_rates,
            "overall": overall_rate,
            "accounts": account_cards,
            "regions": region_cards,
        },
        "areas": areas,
        "navGroups": nav_groups,
        "filters": {
            "accounts": account_filter,
            "regions": region_filter,
            "areas": [{"value": area["slug"], "label": area["name"]} for area in areas],
            "severities": SEVERITY_OPTIONS,
            "statuses": STATUS_OPTIONS,
            "defaultStatus": "failed",
        },
        "findings": finding_rows(all_findings),
        "methodology": {
            "notes": rich(METHODOLOGY_NOTES),
            "scopeGroups": scope_groups,
            "source": rich(scope_source),
        },
        "footer": rich(FOOTER_MARKUP),
    }


def generate_html_report(
    all_findings: List[Dict],
    service_findings: Dict[str, List[Dict]],
    service_stats: Dict[str, Dict[str, int]],
    mode: str = "single",
    account_id: Optional[str] = None,
    account_ids: Optional[List[str]] = None,
    timestamp: Optional[str] = None,
    regions: list = None,
    service_selection: Optional[Dict[str, bool]] = None,
    compliance_scope: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """
    Generate the HTML report from findings data.

    Args:
        all_findings: List of all finding dictionaries
        service_findings: Dict mapping service name to list of findings
        service_stats: Dict mapping service name to {'passed': int, 'failed': int}
        mode: 'single' for single-account, 'multi' for multi-account
        account_id: Account ID (for single-account mode)
        account_ids: List of account IDs (for multi-account mode)
        timestamp: Optional timestamp string
        regions: Optional list of region strings for multi-region filtering
        service_selection: Direct service assessments selected for this run.
        compliance_scope: Per compliance slug, the figures its scope text
            counts, such as the derived-control count and the (check id,
            [service]) pairs left out because no source service was selected.

    Returns:
        Complete, self-contained HTML report string (Cloudscape UI).
    """
    data = build_report_data(
        all_findings=all_findings,
        service_findings=service_findings,
        service_stats=service_stats,
        mode=mode,
        account_id=account_id,
        account_ids=account_ids,
        timestamp=timestamp,
        regions=regions,
        service_selection=service_selection,
        compliance_scope=compliance_scope,
    )
    return render_page(data, data["title"])
