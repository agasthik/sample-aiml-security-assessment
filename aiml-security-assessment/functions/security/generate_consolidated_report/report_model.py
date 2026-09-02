"""Shared report data model for HTML and PDF assessment reports.

The HTML report remains the interactive source for exploration.  This module
provides deterministic, presentation-neutral metrics and executive themes so
the PDF renderer can use the same finding semantics without inventing a
separate risk-scoring system.
"""

import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence


DIRECT_SERVICES = {
    "bedrock",
    "sagemaker",
    "agentcore",
    "responsible-ai-grc",
}
SCORED_SEVERITIES = {"high", "medium", "low"}

# Field weights used by ``classify_theme``.
HEADLINE_WEIGHT = 3
BODY_WEIGHT = 1

SERVICE_DISPLAY_NAMES = {
    "bedrock": "Amazon Bedrock",
    "sagemaker": "Amazon SageMaker AI",
    "agentcore": "Amazon Bedrock AgentCore / AWS Agent Registry",
    "agentic": "Agentic AI Security",
    "responsible-ai-grc": "Responsible AI GRC",
    "owasp": "OWASP Top 10 for LLM",
}
SERVICE_ORDER = {
    "bedrock": 0,
    "sagemaker": 1,
    "agentcore": 2,
    "responsible-ai-grc": 3,
    "agentic": 4,
    "owasp": 5,
}

# Published catalogue size per assessment area (see docs/SECURITY_CHECKS*.md and
# README).  Used only to report how much of each area produced a row; it must be
# updated in the same change that adds or removes checks.
CHECK_CATALOG_TOTALS = {
    "bedrock": 40,
    "sagemaker": 29,
    "agentcore": 23,
    "agentic": 38,
    "responsible-ai-grc": 64,
    "owasp": 12,
}

# OWASP category per emitted OW check.  OW-01..OW-10 map one-to-one onto the
# 2025 Top 10; OW-11 and OW-12 are native LLM07 checks.
OWASP_CATEGORY_BY_CHECK = {
    "OW-01": "LLM01:2025 Prompt Injection",
    "OW-02": "LLM02:2025 Sensitive Information Disclosure",
    "OW-03": "LLM03:2025 Supply Chain",
    "OW-04": "LLM04:2025 Data and Model Poisoning",
    "OW-05": "LLM05:2025 Improper Output Handling",
    "OW-06": "LLM06:2025 Excessive Agency",
    "OW-07": "LLM07:2025 System Prompt Leakage",
    "OW-08": "LLM08:2025 Vector and Embedding Weaknesses",
    "OW-09": "LLM09:2025 Misinformation",
    "OW-10": "LLM10:2025 Unbounded Consumption",
    "OW-11": "LLM07:2025 System Prompt Leakage",
    "OW-12": "LLM07:2025 System Prompt Leakage",
}

# OWASP mapping rows carry "OWASP category: LLM01:2025 Prompt Injection." in
# their details, which is preferred over the check-ID table when present.
OWASP_CATEGORY_PATTERN = re.compile(r"OWASP category:\s*(LLM\d{2}:\d{4}[^.]*)")

# Splits "LLM06:2025 Excessive Agency" into its code and name so the year can be
# dropped where space is tight.
OWASP_CATEGORY_LABEL_PATTERN = re.compile(r"^(LLM\d{2}):\d{4}\s*(.*)$")

ARN_PATTERN = re.compile(
    r"arn:[a-z0-9-]*:(?P<service>[a-z0-9-]+):[a-z0-9-]*:\d*:(?P<resource>[^\s,;]+)"
)

# Why an N/A row was emitted, checked in order: an access problem must not be
# read as "no resources", and a missing prerequisite is a tooling condition
# rather than a coverage statement about the account.
NA_REASON_RULES = (
    (
        "Access not permitted",
        (
            "accessdenied",
            "access denied",
            "not authorized",
            "unauthorized",
            "explicit deny",
            "forbidden",
        ),
    ),
    (
        "API or feature unavailable in scope",
        (
            "not available",
            "unavailable",
            "not supported",
            "unsupported",
            "not enabled in",
            "opt-in",
            "does not support",
        ),
    ),
    (
        "Assessment prerequisite missing",
        (
            "permission cache",
            "could not initialise",
            "could not initialize",
            "prerequisite",
            "error listing",
            "could not be retrieved",
        ),
    ),
    (
        "No applicable resources",
        (
            "nothing to inspect",
            "no applicable",
            "not applicable",
            "were found",
            "were discovered",
            "none found",
            "no resources",
            "not found",
            "no matching",
        ),
    ),
)

# Theme keywords are matched against finding text with field weighting (see
# ``classify_theme``): a hit in the check ID or finding name counts for more
# than a hit in the longer detail/resolution prose, because remediation text
# routinely mentions adjacent controls ("restrict key usage permissions" on an
# encryption finding).  The list order only breaks score ties, so keywords must
# stay specific enough not to fire on incidental wording.
THEME_RULES = (
    (
        "Identity and access management",
        (
            "iam",
            "identity",
            "permission",
            "privilege",
            "role",
            "policy",
            "authorization",
            "authorizer",
            "access control",
            "cross-account",
        ),
    ),
    (
        "Data protection and privacy",
        (
            "encrypt",
            "kms",
            "key management",
            "data retention",
            "zero data",
            "privacy",
            "pii",
            "sensitive data",
            "token vault",
            "memory",
        ),
    ),
    (
        "Network and workload isolation",
        (
            "vpc",
            "network",
            "private",
            "vpc endpoint",
            "interface endpoint",
            "internet access",
            "public access",
            "security group",
            "subnet",
            "isolation",
        ),
    ),
    (
        "Logging, monitoring, and assurance",
        (
            "logging",
            "logged",
            "logs",
            "cloudtrail",
            "trail",
            "monitor",
            "metric",
            "alarm",
            "audit",
            "trace",
            "telemetry",
            "observability",
            "evaluation",
        ),
    ),
    (
        "AI safety and abuse prevention",
        (
            "guardrail",
            "prompt injection",
            "content filter",
            "content safety",
            "abuse",
            "toxicity",
            "harmful",
            "jailbreak",
            "denied topic",
            "grounding",
        ),
    ),
    (
        "Governance and software supply chain",
        (
            "registry",
            "approval",
            "provenance",
            "govern",
            "compliance",
            "model card",
            "marketplace",
            "supply chain",
            "version",
            "transparency",
            "document",
            "ownership",
            "lifecycle",
            "inventory",
        ),
    ),
    (
        "Resilience and cost controls",
        (
            "availability",
            "resilien",
            "timeout",
            "throttl",
            "quota",
            "budget",
            "cost",
            "capacity",
        ),
    ),
)

THEME_GUIDANCE = {
    "Identity and access management": {
        "impact": (
            "Overly broad or weakly constrained access can enable unauthorized model, "
            "agent, data, or administrative actions."
        ),
        "owner": "Security / IAM",
    },
    "Data protection and privacy": {
        "impact": (
            "Encryption, retention, or privacy gaps can increase the likelihood or "
            "impact of sensitive-data exposure."
        ),
        "owner": "Data security / Platform",
    },
    "Network and workload isolation": {
        "impact": (
            "Insufficient isolation can expose AI/ML workloads to unintended network "
            "paths and increase lateral-movement opportunities."
        ),
        "owner": "Cloud platform / Networking",
    },
    "Logging, monitoring, and assurance": {
        "impact": (
            "Incomplete telemetry can delay detection, investigation, and validation "
            "of security-relevant AI/ML activity."
        ),
        "owner": "Security operations / Platform",
    },
    "AI safety and abuse prevention": {
        "impact": (
            "Missing safeguards can increase exposure to harmful output, prompt abuse, "
            "or unintended model behavior."
        ),
        "owner": "AI engineering / AI safety",
    },
    "Governance and software supply chain": {
        "impact": (
            "Weak approval, provenance, or lifecycle controls can allow unreviewed or "
            "untrusted AI artifacts into production workflows."
        ),
        "owner": "AI governance / Engineering",
    },
    "Resilience and cost controls": {
        "impact": (
            "Capacity, throttling, or cost-control gaps can contribute to disruption, "
            "resource exhaustion, or unexpected spend."
        ),
        "owner": "Service owners / FinOps",
    },
    "General security posture": {
        "impact": (
            "The observed control gap can weaken the assessed workload's overall "
            "security posture."
        ),
        "owner": "Service owner / Security",
    },
}


def _value(finding: Dict[str, Any], lower: str, upper: str, default: str = "") -> str:
    """Read either normalized or CSV-style finding keys."""
    value = finding.get(lower, finding.get(upper, default))
    return "" if value is None else str(value)


def finding_service(finding: Dict[str, Any]) -> str:
    return _value(finding, "_service", "_service").strip().lower()


def finding_status(finding: Dict[str, Any]) -> str:
    return _value(finding, "status", "Status").strip().lower()


def finding_severity(finding: Dict[str, Any]) -> str:
    return _value(finding, "severity", "Severity", "Informational").strip().lower()


def finding_check_id(finding: Dict[str, Any]) -> str:
    return _value(finding, "check_id", "Check_ID").strip()


def finding_name(finding: Dict[str, Any]) -> str:
    return _value(finding, "finding", "Finding").strip()


def finding_details(finding: Dict[str, Any]) -> str:
    return _value(finding, "details", "Finding_Details").strip()


def finding_resolution(finding: Dict[str, Any]) -> str:
    return _value(finding, "resolution", "Resolution").strip()


def finding_reference(finding: Dict[str, Any]) -> str:
    return _value(finding, "reference", "Reference").strip()


def finding_account(finding: Dict[str, Any]) -> str:
    return _value(finding, "account_id", "Account_ID").strip()


def finding_region(finding: Dict[str, Any]) -> str:
    return _value(finding, "region", "Region").strip()


def finding_compliance_frameworks(finding: Dict[str, Any]) -> List[str]:
    """Split the Responsible AI GRC ``Compliance_Frameworks`` column.

    The scanner emits a pipe-separated list (``"FFIEC CAT | SR 11-7"``); other
    assessment areas do not populate the column at all.
    """
    raw = _value(finding, "compliance_frameworks", "Compliance_Frameworks")
    return [part.strip() for part in raw.split("|") if part.strip()]


def extract_resource_labels(text: str, limit: int = 3) -> List[str]:
    """Pull short resource labels out of ARNs already present in finding text.

    Only ARNs are extracted, because they are unambiguous.  The label keeps the
    service and resource portion (``bedrock guardrail/gr-a1b2c3``) so a reader
    can locate the resource without a full-width ARN in a narrow table cell.
    """
    labels: List[str] = []
    for match in ARN_PATTERN.finditer(text or ""):
        service = match.group("service")
        resource = match.group("resource").rstrip(".,;:)\"'")
        label = f"{service} {resource}" if resource else service
        if label not in labels:
            labels.append(label)
        if len(labels) >= limit:
            break
    return labels


def service_display_name(service: str) -> str:
    return SERVICE_DISPLAY_NAMES.get(service, service.replace("-", " ").title())


def theme_scores(finding: Dict[str, Any]) -> Dict[str, int]:
    """Score every theme against a finding using field-weighted keyword hits.

    A keyword in the check ID or finding name is worth ``HEADLINE_WEIGHT``; the
    same keyword in the detail or resolution prose is worth ``BODY_WEIGHT``.  A
    keyword is counted once, at the strongest field where it appears.
    """
    headline = f"{finding_check_id(finding)} {finding_name(finding)}".lower()
    body = f"{finding_details(finding)} {finding_resolution(finding)}".lower()
    scores = {}
    for theme, keywords in THEME_RULES:
        score = 0
        for keyword in keywords:
            if keyword in headline:
                score += HEADLINE_WEIGHT
            elif keyword in body:
                score += BODY_WEIGHT
        scores[theme] = score
    return scores


def classify_theme(finding: Dict[str, Any]) -> str:
    """Classify a finding into a broad executive control theme.

    The highest-scoring theme wins; ties fall back to ``THEME_RULES`` order,
    and a finding with no keyword hits at all is left unthemed.
    """
    scores = theme_scores(finding)
    best_theme = "General security posture"
    best_score = 0
    for theme, _keywords in THEME_RULES:
        if scores[theme] > best_score:
            best_theme = theme
            best_score = scores[theme]
    return best_theme


def _failed_severity_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding_severity(finding)
        if finding_status(finding) == "failed" and severity in counts:
            counts[severity] += 1
    return counts


def _build_theme_summaries(
    direct_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    themes: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "passed": 0,
            "failed": 0,
            "na": 0,
            "failed_high": 0,
            "failed_medium": 0,
            "failed_low": 0,
            "checks": set(),
            "accounts": set(),
            "regions": set(),
            "passed_examples": set(),
            "failed_examples": set(),
        }
    )
    for finding in direct_findings:
        theme_name = classify_theme(finding)
        summary = themes[theme_name]
        status = finding_status(finding)
        severity = finding_severity(finding)
        if status == "passed":
            summary["passed"] += 1
            summary["passed_examples"].add(
                (finding_check_id(finding), finding_name(finding))
            )
        elif status == "failed":
            summary["failed"] += 1
            summary["failed_examples"].add(
                (finding_check_id(finding), finding_name(finding))
            )
            if severity in SCORED_SEVERITIES:
                summary[f"failed_{severity}"] += 1
        elif status == "n/a":
            summary["na"] += 1
        check_id = finding_check_id(finding)
        if check_id:
            summary["checks"].add(check_id)
        if finding_account(finding):
            summary["accounts"].add(finding_account(finding))
        if finding_region(finding):
            summary["regions"].add(finding_region(finding))

    result = []
    for theme_name, summary in themes.items():
        evaluated = summary["passed"] + summary["failed"]
        result.append(
            {
                "name": theme_name,
                "passed": summary["passed"],
                "failed": summary["failed"],
                "na": summary["na"],
                "failed_high": summary["failed_high"],
                "failed_medium": summary["failed_medium"],
                "failed_low": summary["failed_low"],
                "unique_checks": len(summary["checks"]),
                "accounts": sorted(summary["accounts"]),
                "regions": sorted(summary["regions"]),
                "passed_examples": [
                    {"check_id": check_id, "finding": finding}
                    for check_id, finding in sorted(summary["passed_examples"])[:3]
                ],
                "failed_examples": [
                    {"check_id": check_id, "finding": finding}
                    for check_id, finding in sorted(summary["failed_examples"])[:3]
                ],
                "impact": THEME_GUIDANCE[theme_name]["impact"],
                "suggested_owner": THEME_GUIDANCE[theme_name]["owner"],
                "pass_rate": (
                    round(summary["passed"] / evaluated * 100, 1) if evaluated else 0.0
                ),
            }
        )
    return result


def _build_posture(severity_counts: Dict[str, int]) -> Dict[str, str]:
    if severity_counts["high"]:
        return {
            "label": "High-priority attention required",
            "summary": (
                "At least one high-severity direct control gap was observed. Leadership "
                "attention and prompt remediation planning are warranted."
            ),
            "tone": "high",
        }
    if severity_counts["medium"]:
        return {
            "label": "Improvement required",
            "summary": (
                "No high-severity direct gaps were observed, but medium-severity "
                "weaknesses require a defined remediation plan."
            ),
            "tone": "medium",
        }
    if severity_counts["low"]:
        return {
            "label": "Generally aligned with residual gaps",
            "summary": (
                "Only low-severity direct gaps were observed. They should be tracked "
                "through normal security improvement work."
            ),
            "tone": "low",
        }
    return {
        "label": "No actionable direct gaps observed",
        "summary": (
            "The assessment did not identify failed high, medium, or low severity "
            "direct controls in the reported scope."
        ),
        "tone": "clear",
    }


def _build_concentration(
    direct_findings: Sequence[Dict[str, Any]], dimension: str
) -> List[Dict[str, Any]]:
    accessors = {
        "service": lambda finding: service_display_name(finding_service(finding)),
        "account": finding_account,
        "region": finding_region,
    }
    groups: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"failed": 0, "high": 0, "medium": 0, "low": 0}
    )
    for finding in direct_findings:
        severity = finding_severity(finding)
        if finding_status(finding) != "failed" or severity not in SCORED_SEVERITIES:
            continue
        label = accessors[dimension](finding) or "Not reported"
        groups[label]["failed"] += 1
        groups[label][severity] += 1
    return sorted(
        ({"label": label, **counts} for label, counts in groups.items()),
        key=lambda item: (
            -(item["high"] * 9 + item["medium"] * 3 + item["low"]),
            -item["failed"],
            item["label"],
        ),
    )


def _build_action_plan(concerns: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    plan = []
    for theme in concerns:
        if theme["failed_high"]:
            timeframe = "0-30 days"
            focus = "Contain and remediate high-severity exposure"
        elif theme["failed_medium"]:
            timeframe = "30-90 days"
            focus = "Implement and validate control improvements"
        else:
            timeframe = "Planned improvement"
            focus = "Track residual hardening work"
        plan.append(
            {
                "timeframe": timeframe,
                "theme": theme["name"],
                "focus": focus,
                "failed": theme["failed"],
                "owner": theme["suggested_owner"],
            }
        )
    timeframe_rank = {"0-30 days": 0, "30-90 days": 1, "Planned improvement": 2}
    return sorted(
        plan,
        key=lambda item: (
            timeframe_rank[item["timeframe"]],
            -item["failed"],
            item["theme"],
        ),
    )


def _weighted_severity_score(high: int, medium: int, low: int) -> int:
    """Order failed rows by severity without inventing a new risk score."""
    return high * 9 + medium * 3 + low


def _normalize_resolution(text: str) -> str:
    """Collapse resolution text so identical guidance groups together."""
    return " ".join(text.lower().split()).rstrip(".")


def _prevalence(
    accounts: Sequence[str],
    regions: Sequence[str],
    *,
    total_accounts: int,
    total_scopes: int,
) -> Dict[str, str]:
    """Describe how widely one failed check repeats across the assessed scope.

    Prevalence is derived only from the account and region values on the rows,
    so it says how broadly the gap was observed - not how severe it is.
    """
    account_span = len(accounts)
    scope_span = len(regions)
    covers_all_accounts = total_accounts > 1 and account_span >= total_accounts
    covers_all_scopes = total_scopes > 1 and scope_span >= total_scopes
    if covers_all_accounts or covers_all_scopes:
        return {
            "label": "Systemic",
            "detail": (
                "Observed in every assessed account or regional scope, which points to "
                "a baseline or provisioning default rather than a one-off resource."
            ),
            "approach": (
                "Fix centrally: change the shared template, pipeline guardrail, or "
                "organization-level policy that provisions these resources."
            ),
        }
    if account_span > 1 or scope_span > 1:
        return {
            "label": "Widespread",
            "detail": (
                "Observed in more than one account or regional scope, so remediating a "
                "single resource will not close the gap."
            ),
            "approach": (
                "Remediate as a batch and add a preventive control so new resources "
                "inherit the corrected configuration."
            ),
        }
    return {
        "label": "Isolated",
        "detail": "Observed in a single account and regional scope.",
        "approach": (
            "Remediate in place with the owning team and confirm no other scope "
            "shares the configuration."
        ),
    }


def _build_remediation_leverage(
    direct_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Group failed rows from different checks that share one remediation action.

    Findings whose ``Resolution`` text is identical can be closed by the same
    piece of work.  Only groups spanning more than one check are reported: a
    single check repeating across accounts or regions is already described by
    its prevalence, so listing it here would restate the same fact.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for finding in direct_findings:
        severity = finding_severity(finding)
        resolution = finding_resolution(finding)
        if (
            finding_status(finding) != "failed"
            or severity not in SCORED_SEVERITIES
            or not resolution
        ):
            continue
        key = _normalize_resolution(resolution)
        if not key:
            continue
        group = groups.setdefault(
            key,
            {
                "resolution": resolution,
                "rows": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "checks": set(),
                "services": set(),
                "accounts": set(),
                "regions": set(),
            },
        )
        group["rows"] += 1
        group[severity] += 1
        if finding_check_id(finding):
            group["checks"].add(finding_check_id(finding))
        group["services"].add(service_display_name(finding_service(finding)))
        if finding_account(finding):
            group["accounts"].add(finding_account(finding))
        if finding_region(finding):
            group["regions"].add(finding_region(finding))

    leverage = []
    for group in groups.values():
        if len(group["checks"]) < 2:
            continue
        leverage.append(
            {
                "resolution": group["resolution"],
                "rows": group["rows"],
                "high": group["high"],
                "medium": group["medium"],
                "low": group["low"],
                "checks": sorted(group["checks"]),
                "services": sorted(group["services"]),
                "accounts": sorted(group["accounts"]),
                "regions": sorted(group["regions"]),
            }
        )
    return sorted(
        leverage,
        key=lambda item: (
            -len(item["checks"]),
            -_weighted_severity_score(item["high"], item["medium"], item["low"]),
            -item["rows"],
            item["resolution"],
        ),
    )


def _build_account_scorecard(
    direct_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Summarize direct posture per account so accounts can be compared."""
    accounts: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "passed": 0,
            "failed": 0,
            "na": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "failed_checks": set(),
            "regions": set(),
            "theme_scores": defaultdict(int),
        }
    )
    for finding in direct_findings:
        account = finding_account(finding) or "Not reported"
        entry = accounts[account]
        status = finding_status(finding)
        severity = finding_severity(finding)
        if finding_region(finding):
            entry["regions"].add(finding_region(finding))
        if status == "n/a":
            entry["na"] += 1
            continue
        if severity not in SCORED_SEVERITIES:
            continue
        if status == "passed":
            entry["passed"] += 1
        elif status == "failed":
            entry["failed"] += 1
            entry[severity] += 1
            if finding_check_id(finding):
                entry["failed_checks"].add(finding_check_id(finding))
            entry["theme_scores"][classify_theme(finding)] += _weighted_severity_score(
                1 if severity == "high" else 0,
                1 if severity == "medium" else 0,
                1 if severity == "low" else 0,
            )

    scorecard = []
    for account, entry in accounts.items():
        evaluated = entry["passed"] + entry["failed"]
        leading_theme = ""
        if entry["theme_scores"]:
            leading_theme = sorted(
                entry["theme_scores"].items(), key=lambda item: (-item[1], item[0])
            )[0][0]
        scorecard.append(
            {
                "account": account,
                "passed": entry["passed"],
                "failed": entry["failed"],
                "na": entry["na"],
                "high": entry["high"],
                "medium": entry["medium"],
                "low": entry["low"],
                "weighted_score": _weighted_severity_score(
                    entry["high"], entry["medium"], entry["low"]
                ),
                "failed_checks": len(entry["failed_checks"]),
                "regions": sorted(entry["regions"]),
                "leading_theme": leading_theme,
                "pass_rate": (
                    round(entry["passed"] / evaluated * 100, 1) if evaluated else 0.0
                ),
            }
        )
    return sorted(
        scorecard,
        key=lambda item: (-item["weighted_score"], -item["failed"], item["account"]),
    )


def classify_na_reason(finding: Dict[str, Any]) -> str:
    """Explain why an N/A row carries no pass/fail result."""
    text = f"{finding_details(finding)} {finding_resolution(finding)}".lower()
    for reason, keywords in NA_REASON_RULES:
        if any(keyword in text for keyword in keywords):
            return reason
    return "Reason not stated in the finding text"


def _build_na_reasons(
    direct_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Bucket N/A rows by why they were emitted, so coverage gaps are readable."""
    reasons: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"rows": 0, "checks": set(), "services": set()}
    )
    for finding in direct_findings:
        if finding_status(finding) != "n/a":
            continue
        entry = reasons[classify_na_reason(finding)]
        entry["rows"] += 1
        if finding_check_id(finding):
            entry["checks"].add(finding_check_id(finding))
        entry["services"].add(service_display_name(finding_service(finding)))
    return sorted(
        (
            {
                "reason": reason,
                "rows": entry["rows"],
                "checks": sorted(entry["checks"]),
                "services": sorted(entry["services"]),
            }
            for reason, entry in reasons.items()
        ),
        key=lambda item: (-item["rows"], item["reason"]),
    )


def _build_coverage(
    all_findings: Sequence[Dict[str, Any]],
    service_stats: Dict[str, Dict[str, int]],
) -> List[Dict[str, Any]]:
    """Compare represented checks against the published catalogue per area.

    Only areas that produced rows are reported, because a disabled optional
    assessment is a deployment choice rather than a coverage gap.
    """
    observed: Dict[str, set] = defaultdict(set)
    for finding in all_findings:
        check_id = finding_check_id(finding)
        if check_id:
            observed[finding_service(finding)].add(check_id)

    coverage = []
    for service, stats in service_stats.items():
        total_rows = (
            stats.get("passed", 0) + stats.get("failed", 0) + stats.get("na", 0)
        )
        catalog_total = CHECK_CATALOG_TOTALS.get(service)
        if total_rows == 0 or not catalog_total:
            continue
        represented = len(observed.get(service, set()))
        coverage.append(
            {
                "slug": service,
                "name": service_display_name(service),
                "represented": represented,
                "catalog_total": catalog_total,
                "not_represented": max(catalog_total - represented, 0),
                "coverage_rate": round(min(represented / catalog_total, 1.0) * 100, 1),
            }
        )
    return sorted(coverage, key=lambda item: SERVICE_ORDER.get(item["slug"], 100))


def _build_compliance_frameworks(
    all_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Roll findings up by the framework identifiers the scanners attached."""
    frameworks: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "passed": 0,
            "failed": 0,
            "na": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "checks": set(),
        }
    )
    for finding in all_findings:
        status = finding_status(finding)
        severity = finding_severity(finding)
        for framework in finding_compliance_frameworks(finding):
            entry = frameworks[framework]
            if status == "passed":
                entry["passed"] += 1
            elif status == "failed":
                entry["failed"] += 1
                if severity in SCORED_SEVERITIES:
                    entry[severity] += 1
            elif status == "n/a":
                entry["na"] += 1
            if finding_check_id(finding):
                entry["checks"].add(finding_check_id(finding))

    result = []
    for framework, entry in frameworks.items():
        evaluated = entry["passed"] + entry["failed"]
        result.append(
            {
                "framework": framework,
                "passed": entry["passed"],
                "failed": entry["failed"],
                "na": entry["na"],
                "high": entry["high"],
                "medium": entry["medium"],
                "low": entry["low"],
                "checks": len(entry["checks"]),
                "pass_rate": (
                    round(entry["passed"] / evaluated * 100, 1) if evaluated else 0.0
                ),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            -_weighted_severity_score(item["high"], item["medium"], item["low"]),
            -item["failed"],
            item["framework"],
        ),
    )


def owasp_category(finding: Dict[str, Any]) -> str:
    """Resolve the OWASP category for an OW row."""
    match = OWASP_CATEGORY_PATTERN.search(finding_details(finding))
    if match:
        return match.group(1).strip()
    return OWASP_CATEGORY_BY_CHECK.get(finding_check_id(finding), "")


def _build_owasp_rollup(
    all_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Summarize OWASP rows by LLM category rather than by OW check number."""
    categories: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "passed": 0,
            "failed": 0,
            "na": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "checks": set(),
        }
    )
    for finding in all_findings:
        if finding_service(finding) != "owasp":
            continue
        category = owasp_category(finding)
        if not category:
            continue
        entry = categories[category]
        status = finding_status(finding)
        severity = finding_severity(finding)
        if status == "passed":
            entry["passed"] += 1
        elif status == "failed":
            entry["failed"] += 1
            if severity in SCORED_SEVERITIES:
                entry[severity] += 1
        elif status == "n/a":
            entry["na"] += 1
        if finding_check_id(finding):
            entry["checks"].add(finding_check_id(finding))

    return sorted(
        (
            {
                "category": category,
                "passed": entry["passed"],
                "failed": entry["failed"],
                "na": entry["na"],
                "high": entry["high"],
                "medium": entry["medium"],
                "low": entry["low"],
                "checks": sorted(entry["checks"]),
            }
            for category, entry in categories.items()
        ),
        key=lambda item: item["category"],
    )


def owasp_short_label(category: str) -> str:
    """Drop the revision year so a category fits an executive summary bullet."""
    match = OWASP_CATEGORY_LABEL_PATTERN.match(category)
    if not match:
        return category
    return f"{match.group(1)} {match.group(2)}".strip()


def _affected_names(
    entries: Sequence[Dict[str, Any]],
    name_key: str,
    formatter: Optional[Any] = None,
) -> List[str]:
    """Name the entries carrying failed rows, most affected first."""
    affected = [entry for entry in entries if entry["failed"]]
    affected.sort(
        key=lambda entry: (
            -_weighted_severity_score(entry["high"], entry["medium"], entry["low"]),
            entry[name_key],
        )
    )
    return [
        formatter(entry[name_key]) if formatter else entry[name_key]
        for entry in affected
    ]


def _build_standard_summaries(
    owasp_rollup: Sequence[Dict[str, Any]],
    compliance_frameworks: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Summarize each compliance standard the findings represent.

    Compliance rows are contextual re-mappings of direct findings, so they are
    deliberately excluded from posture totals to avoid counting one gap twice.
    That also leaves the executive summary silent on whether a standard was
    assessed at all, so these summaries restate the standard's own coverage
    without introducing a second score.
    """
    summaries = []
    if owasp_rollup:
        affected = _affected_names(owasp_rollup, "category", owasp_short_label)
        summaries.append(
            {
                "standard": "OWASP Top 10 for LLM",
                "unit": "category",
                "unit_plural": "categories",
                "represented": len(owasp_rollup),
                "affected": len(affected),
                "names": affected,
            }
        )
    if compliance_frameworks:
        affected = _affected_names(compliance_frameworks, "framework")
        summaries.append(
            {
                "standard": "Framework references",
                "unit": "reference",
                "unit_plural": "references",
                "represented": len(compliance_frameworks),
                "affected": len(affected),
                "names": affected,
            }
        )
    return summaries


def _build_area_severity(
    direct_findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Break failed direct rows down by assessment area and severity."""
    counts: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"high": 0, "medium": 0, "low": 0}
    )
    for finding in direct_findings:
        severity = finding_severity(finding)
        if finding_status(finding) != "failed" or severity not in SCORED_SEVERITIES:
            continue
        counts[finding_service(finding)][severity] += 1

    areas = []
    for slug, severities in counts.items():
        total = sum(severities.values())
        if not total:
            continue
        areas.append(
            {
                "slug": slug,
                "name": service_display_name(slug),
                "high": severities["high"],
                "medium": severities["medium"],
                "low": severities["low"],
                "total": total,
                "weighted": _weighted_severity_score(
                    severities["high"], severities["medium"], severities["low"]
                ),
            }
        )
    areas.sort(key=lambda item: (-item["weighted"], -item["total"], item["name"]))
    return areas


def _build_theme_service_matrix(
    direct_findings: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Cross-tabulate failed direct rows by control theme and assessment area."""
    services: List[str] = []
    counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for finding in direct_findings:
        severity = finding_severity(finding)
        if finding_status(finding) != "failed" or severity not in SCORED_SEVERITIES:
            continue
        service = service_display_name(finding_service(finding))
        if service not in services:
            services.append(service)
        counts[classify_theme(finding)][service] += 1

    services.sort()
    rows = []
    for theme, _guidance in THEME_GUIDANCE.items():
        if theme not in counts:
            continue
        theme_counts = counts[theme]
        rows.append(
            {
                "theme": theme,
                "counts": [theme_counts.get(service, 0) for service in services],
                "total": sum(theme_counts.values()),
            }
        )
    rows.sort(key=lambda row: (-row["total"], row["theme"]))
    return {
        "services": services,
        "rows": rows,
        "totals": [
            sum(counts[row["theme"]].get(service, 0) for row in rows)
            for service in services
        ],
    }


def _build_finding_groups(
    findings: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Collapse rows that repeat the same check across accounts and regions.

    Multi-account and multi-region runs emit one row per scope for every check,
    so the detailed section otherwise repeats near-identical text.  Rows are
    grouped by check identity and outcome; distinct detail or resolution text is
    preserved as separate variants so no reported evidence is dropped.
    """
    groups: Dict[tuple, Dict[str, Any]] = {}
    order: List[tuple] = []
    for finding in findings:
        key = (
            finding_service(finding),
            finding_check_id(finding),
            finding_name(finding),
            finding_status(finding),
            finding_severity(finding),
        )
        if key not in groups:
            order.append(key)
            groups[key] = {
                "service": key[0],
                "check_id": key[1],
                "finding": key[2],
                "status": key[3],
                "severity": key[4],
                "reference": finding_reference(finding),
                "rows": 0,
                "accounts": set(),
                "regions": set(),
                "variants": {},
                "variant_order": [],
            }
        group = groups[key]
        group["rows"] += 1
        account = finding_account(finding)
        region = finding_region(finding)
        if account:
            group["accounts"].add(account)
        if region:
            group["regions"].add(region)
        if not group["reference"]:
            group["reference"] = finding_reference(finding)
        variant_key = (finding_details(finding), finding_resolution(finding))
        variant = group["variants"].get(variant_key)
        if variant is None:
            variant = {
                "details": variant_key[0],
                "resolution": variant_key[1],
                "accounts": set(),
                "regions": set(),
            }
            group["variants"][variant_key] = variant
            group["variant_order"].append(variant_key)
        if account:
            variant["accounts"].add(account)
        if region:
            variant["regions"].add(region)

    result = []
    for key in order:
        group = groups[key]
        result.append(
            {
                "service": group["service"],
                "check_id": group["check_id"],
                "finding": group["finding"],
                "status": group["status"],
                "severity": group["severity"],
                "reference": group["reference"],
                "rows": group["rows"],
                "accounts": sorted(group["accounts"]),
                "regions": sorted(group["regions"]),
                "variants": [
                    {
                        "details": group["variants"][variant_key]["details"],
                        "resolution": group["variants"][variant_key]["resolution"],
                        "accounts": sorted(group["variants"][variant_key]["accounts"]),
                        "regions": sorted(group["variants"][variant_key]["regions"]),
                    }
                    for variant_key in group["variant_order"]
                ],
            }
        )
    return result


def _build_priorities(
    direct_findings: Sequence[Dict[str, Any]],
    *,
    total_accounts: int = 1,
    total_scopes: int = 1,
) -> List[Dict[str, Any]]:
    groups: Dict[tuple, Dict[str, Any]] = {}
    for finding in direct_findings:
        severity = finding_severity(finding)
        if finding_status(finding) != "failed" or severity not in SCORED_SEVERITIES:
            continue
        key = (finding_check_id(finding), finding_name(finding), severity)
        group = groups.setdefault(
            key,
            {
                "check_id": key[0],
                "finding": key[1],
                "severity": severity.title(),
                "count": 0,
                "accounts": set(),
                "regions": set(),
                "service": service_display_name(finding_service(finding)),
                "resolution": finding_resolution(finding),
                "_theme": classify_theme(finding),
                "_resources": [],
            },
        )
        for label in extract_resource_labels(finding_details(finding)):
            if label not in group["_resources"]:
                group["_resources"].append(label)
        group["count"] += 1
        if finding_account(finding):
            group["accounts"].add(finding_account(finding))
        if finding_region(finding):
            group["regions"].add(finding_region(finding))

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    priorities = sorted(
        groups.values(),
        key=lambda item: (
            severity_rank[item["severity"].lower()],
            -item["count"],
            item["check_id"],
            item["finding"],
        ),
    )
    for item in priorities:
        item["accounts"] = sorted(item["accounts"])
        item["regions"] = sorted(item["regions"])
        item["theme"] = item.pop("_theme")
        item["resources"] = item.pop("_resources")[:3]
        item["prevalence"] = _prevalence(
            item["accounts"],
            item["regions"],
            total_accounts=total_accounts,
            total_scopes=total_scopes,
        )
    return priorities


def _finding_sort_key(finding: Dict[str, Any]) -> tuple:
    status_rank = {"failed": 0, "passed": 1, "n/a": 2}
    severity_rank = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    service = finding_service(finding)
    return (
        SERVICE_ORDER.get(service, 100),
        service,
        status_rank.get(finding_status(finding), 3),
        severity_rank.get(finding_severity(finding), 4),
        finding_check_id(finding),
        finding_account(finding),
        finding_region(finding),
        finding_name(finding),
    )


def build_report_model(
    *,
    all_findings: Sequence[Dict[str, Any]],
    service_stats: Dict[str, Dict[str, int]],
    mode: str,
    timestamp: str,
    account_id: Optional[str] = None,
    account_ids: Optional[Sequence[str]] = None,
    regions: Optional[Sequence[str]] = None,
    contextual_services: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Build deterministic metrics and narrative inputs for report renderers."""
    contextual = set(contextual_services or ())
    if not contextual:
        contextual = {
            finding_service(finding)
            for finding in all_findings
            if finding_service(finding) not in DIRECT_SERVICES
        }

    direct_findings = [
        finding
        for finding in all_findings
        if finding_service(finding) not in contextual
    ]
    contextual_findings = [
        finding for finding in all_findings if finding_service(finding) in contextual
    ]
    scored_direct = [
        finding
        for finding in direct_findings
        if finding_severity(finding) in SCORED_SEVERITIES
    ]
    passed_scored = [
        finding for finding in scored_direct if finding_status(finding) == "passed"
    ]
    failed_scored = [
        finding for finding in scored_direct if finding_status(finding) == "failed"
    ]
    severity_counts = _failed_severity_counts(direct_findings)
    unique_checks = {
        finding_check_id(finding)
        for finding in all_findings
        if finding_check_id(finding)
    }

    theme_summaries = _build_theme_summaries(direct_findings)
    strengths = sorted(
        (
            theme
            for theme in theme_summaries
            if theme["passed"] > 0 and theme["failed"] == 0
        ),
        key=lambda theme: (
            -theme["pass_rate"],
            -theme["passed"],
            theme["name"],
        ),
    )
    concerns = sorted(
        (theme for theme in theme_summaries if theme["failed"] > 0),
        key=lambda theme: (
            -(
                theme["failed_high"] * 9
                + theme["failed_medium"] * 3
                + theme["failed_low"]
            ),
            -theme["failed"],
            theme["name"],
        ),
    )
    posture = _build_posture(severity_counts)

    discovered_accounts = {
        finding_account(finding) for finding in all_findings if finding_account(finding)
    }
    if account_id:
        discovered_accounts.add(account_id)
    discovered_accounts.update(account_ids or [])

    discovered_regions = set(regions or [])
    discovered_regions.update(
        finding_region(finding)
        for finding in all_findings
        if finding_region(finding) and finding_region(finding) != "Global"
    )
    has_global_scope = any(
        finding_region(finding) == "Global" for finding in all_findings
    )

    services = []
    for service, stats in service_stats.items():
        total = stats.get("passed", 0) + stats.get("failed", 0) + stats.get("na", 0)
        if total == 0:
            continue
        services.append(
            {
                "slug": service,
                "name": service_display_name(service),
                "passed": stats.get("passed", 0),
                "failed": stats.get("failed", 0),
                "na": stats.get("na", 0),
                "total": total,
                "contextual": service in contextual,
            }
        )
    services.sort(key=lambda service: (service["contextual"], service["name"]))

    total_scopes = len(discovered_regions) + (1 if has_global_scope else 0)
    sorted_findings = sorted(all_findings, key=_finding_sort_key)
    compliance_frameworks = _build_compliance_frameworks(all_findings)
    owasp_rollup = _build_owasp_rollup(all_findings)

    return {
        "mode": mode,
        "timestamp": timestamp,
        "accounts": sorted(discovered_accounts),
        "regions": sorted(discovered_regions),
        "has_global_scope": has_global_scope,
        "metrics": {
            "total_rows": len(all_findings),
            "unique_checks": len(unique_checks),
            "direct_unique_checks": len(
                {
                    finding_check_id(finding)
                    for finding in direct_findings
                    if finding_check_id(finding)
                }
            ),
            "contextual_unique_checks": len(
                {
                    finding_check_id(finding)
                    for finding in contextual_findings
                    if finding_check_id(finding)
                }
            ),
            "direct_rows": len(direct_findings),
            "contextual_rows": len(contextual_findings),
            "contextual_failed": sum(
                1
                for finding in contextual_findings
                if finding_status(finding) == "failed"
            ),
            "passed_scored": len(passed_scored),
            "failed_scored": len(failed_scored),
            "failed_high": severity_counts["high"],
            "failed_medium": severity_counts["medium"],
            "failed_low": severity_counts["low"],
            "weighted_severity_score": _weighted_severity_score(
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
            ),
            "na_direct": sum(
                1 for finding in direct_findings if finding_status(finding) == "n/a"
            ),
            "pass_rate": (
                round(len(passed_scored) / len(scored_direct) * 100, 1)
                if scored_direct
                else 0.0
            ),
        },
        "posture": posture,
        "strengths": strengths,
        "concerns": concerns,
        "action_plan": _build_action_plan(concerns),
        "concentration": {
            "services": _build_concentration(direct_findings, "service"),
            "accounts": _build_concentration(direct_findings, "account"),
            "regions": _build_concentration(direct_findings, "region"),
        },
        "priorities": _build_priorities(
            direct_findings,
            total_accounts=len(discovered_accounts),
            total_scopes=total_scopes,
        ),
        "remediation_leverage": _build_remediation_leverage(direct_findings),
        "account_scorecard": _build_account_scorecard(direct_findings),
        "na_reasons": _build_na_reasons(direct_findings),
        "coverage": _build_coverage(all_findings, service_stats),
        "compliance_frameworks": compliance_frameworks,
        "owasp_rollup": owasp_rollup,
        "standard_summaries": _build_standard_summaries(
            owasp_rollup, compliance_frameworks
        ),
        "area_severity": _build_area_severity(direct_findings),
        "theme_matrix": _build_theme_service_matrix(direct_findings),
        "services": services,
        "findings": sorted_findings,
        "finding_groups": _build_finding_groups(sorted_findings),
        "contextual_services": sorted(contextual),
    }
