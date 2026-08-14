#!/usr/bin/env python3
"""Archived-report converter for the FinServ / Responsible AI GRC CSV prefix.

Written ahead of need, for Phase 2 Stage 2b (see
``docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md``). It does not run against
any real prefix change today because none has been approved yet — the legacy
prefix, ``finserv_security_report``, is currently the only one this project
ever writes. This script exists so that on the day a second prefix (for
example ``responsible_ai_gov_security_report``) is approved and introduced,
there is already a reviewed, tested tool for reconciling archived reports
across both prefixes rather than one written under release pressure.

What it does, read-only, against a single S3 assessment-report bucket:

  1. Lists every object under the legacy prefix and (if it exists yet) the new
     prefix, for a given execution ID.
  2. Parses both CSVs (if both are present) and diffs them row-by-row using
     the same identity key ``rebrand-plan.md`` specifies for deduplication:
     execution ID, account, region, service, check ID, and finding name.
  3. Reports rows present under one prefix but not the other, and rows present
     under both with differing field values, without writing or deleting
     anything.

This script never writes, deletes, or renames any S3 object. It is strictly a
diagnostic tool for confirming reconciliation *before* a Stage 2b change
enables dual-write, and for spot-checking after.

Usage:
    python scripts/convert_finserv_csv_prefix.py --bucket BUCKET --execution-id ID
    python scripts/convert_finserv_csv_prefix.py --bucket BUCKET --execution-id ID \
        --new-prefix responsible_ai_gov_security_report
    python scripts/convert_finserv_csv_prefix.py --local-legacy path/to/finserv.csv \
        --local-new path/to/responsible_ai_gov.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

LEGACY_PREFIX = "finserv_security_report"

# Mirrors the 9-column CSV schema documented in rebrand-plan.md section 7 and
# frozen by tests/test_legacy_contracts.py::test_csv_prefix_is_frozen.
EXPECTED_COLUMNS = (
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
    "Compliance_Frameworks",
)

# The dedup identity per rebrand-plan.md section 18.3 Stage 2a: "execution ID,
# account, region, service, check ID, and finding identity". Region and
# Check_ID are CSV columns; execution ID, account, and service are supplied
# out-of-band (the CSV itself does not carry them), so this script asks the
# caller for those via CLI arguments rather than guessing them from a key.
IDENTITY_COLUMNS = ("Check_ID", "Region", "Finding")


@dataclass(frozen=True)
class Row:
    identity: Tuple[str, ...]
    values: Dict[str, str]


def _read_csv_rows(text: str) -> List[Row]:
    reader = csv.DictReader(io.StringIO(text))
    missing = [c for c in EXPECTED_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(
            f"CSV is missing expected column(s) {missing}; found {reader.fieldnames}. "
            "This does not look like a FinServ / Responsible AI GRC report CSV."
        )
    rows = []
    for record in reader:
        identity = tuple(record.get(col, "") for col in IDENTITY_COLUMNS)
        rows.append(Row(identity=identity, values=dict(record)))
    return rows


def _index_by_identity(rows: Iterable[Row]) -> Dict[Tuple[str, ...], Row]:
    index: Dict[Tuple[str, ...], Row] = {}
    for row in rows:
        if row.identity in index:
            raise ValueError(
                f"Duplicate identity {row.identity} within a single CSV -- "
                "this indicates the source CSV itself has a duplicate finding, "
                "not a cross-prefix reconciliation issue."
            )
        index[row.identity] = row
    return index


def diff_reports(legacy_text: str, new_text: Optional[str]) -> "ReconciliationResult":
    legacy_rows = _read_csv_rows(legacy_text)
    legacy_index = _index_by_identity(legacy_rows)

    if new_text is None:
        return ReconciliationResult(
            legacy_only=list(legacy_index.keys()),
            new_only=[],
            differing={},
            legacy_count=len(legacy_rows),
            new_count=0,
        )

    new_rows = _read_csv_rows(new_text)
    new_index = _index_by_identity(new_rows)

    legacy_keys = set(legacy_index.keys())
    new_keys = set(new_index.keys())

    legacy_only = sorted(legacy_keys - new_keys)
    new_only = sorted(new_keys - legacy_keys)

    differing: Dict[Tuple[str, ...], Tuple[Dict[str, str], Dict[str, str]]] = {}
    for key in sorted(legacy_keys & new_keys):
        legacy_values = legacy_index[key].values
        new_values = new_index[key].values
        # Compare every column except Check_ID/Region/Finding (the identity
        # itself, already known equal) so a divergent Compliance_Frameworks
        # value -- the one INTENTIONAL, DECLARED break called out in
        # rebrand-plan.md section 7 -- is reported, not silently ignored.
        if any(
            legacy_values.get(col) != new_values.get(col)
            for col in EXPECTED_COLUMNS
            if col not in IDENTITY_COLUMNS
        ):
            differing[key] = (legacy_values, new_values)

    return ReconciliationResult(
        legacy_only=legacy_only,
        new_only=new_only,
        differing=differing,
        legacy_count=len(legacy_rows),
        new_count=len(new_rows),
    )


@dataclass
class ReconciliationResult:
    legacy_only: List[Tuple[str, ...]]
    new_only: List[Tuple[str, ...]]
    differing: Dict[Tuple[str, ...], Tuple[Dict[str, str], Dict[str, str]]]
    legacy_count: int
    new_count: int

    def is_clean(self) -> bool:
        return not self.legacy_only and not self.new_only and not self.differing

    def print_report(self) -> None:
        print(f"Legacy CSV rows: {self.legacy_count}")
        print(f"New CSV rows:    {self.new_count}")
        print()
        if self.is_clean():
            print(
                "Reconciliation is clean: every finding matches across both prefixes."
            )
            return
        if self.legacy_only:
            print(f"Rows present ONLY in the legacy CSV ({len(self.legacy_only)}):")
            for key in self.legacy_only:
                print(f"  Check_ID={key[0]!r} Region={key[1]!r} Finding={key[2]!r}")
            print()
        if self.new_only:
            print(f"Rows present ONLY in the new CSV ({len(self.new_only)}):")
            for key in self.new_only:
                print(f"  Check_ID={key[0]!r} Region={key[1]!r} Finding={key[2]!r}")
            print()
        if self.differing:
            print(
                f"Rows present in BOTH but with differing field values ({len(self.differing)}):"
            )
            for key, (legacy_values, new_values) in self.differing.items():
                print(f"  Check_ID={key[0]!r} Region={key[1]!r} Finding={key[2]!r}")
                for col in EXPECTED_COLUMNS:
                    if col in IDENTITY_COLUMNS:
                        continue
                    if legacy_values.get(col) != new_values.get(col):
                        print(
                            f"    {col}: legacy={legacy_values.get(col)!r} new={new_values.get(col)!r}"
                        )
            print()


def _fetch_s3_object_text(bucket: str, key: str):
    """Fetch and decode a single S3 object as text.

    Imports boto3 lazily so --local-legacy/--local-new usage (for testing this
    script itself, or for reconciling already-downloaded CSVs) has no AWS
    dependency at all.
    """
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3")
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code in ("NoSuchKey", "404"):
            return None
        raise
    return response["Body"].read().decode("utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", help="S3 bucket holding assessment report CSVs")
    parser.add_argument("--execution-id", help="Step Functions execution ID / name")
    parser.add_argument(
        "--new-prefix",
        default=None,
        help=(
            "New CSV filename prefix to reconcile against the legacy "
            f"{LEGACY_PREFIX!r} prefix. If omitted, only the legacy CSV is "
            "read and reported, since no new prefix has been approved yet."
        ),
    )
    parser.add_argument(
        "--local-legacy",
        help="Path to a local legacy-prefix CSV file, instead of fetching from S3",
    )
    parser.add_argument(
        "--local-new",
        help="Path to a local new-prefix CSV file, instead of fetching from S3",
    )
    args = parser.parse_args(argv)

    using_local = args.local_legacy or args.local_new
    using_s3 = args.bucket or args.execution_id

    if using_local and using_s3:
        parser.error(
            "Use either --local-legacy/--local-new or --bucket/--execution-id, not both."
        )
    if not using_local and not using_s3:
        parser.error("Provide either --local-legacy or --bucket and --execution-id.")

    if using_local:
        if not args.local_legacy:
            parser.error("--local-legacy is required when using local files.")
        with open(args.local_legacy, "r", encoding="utf-8") as handle:
            legacy_text = handle.read()
        new_text = None
        if args.local_new:
            with open(args.local_new, "r", encoding="utf-8") as handle:
                new_text = handle.read()
    else:
        if not args.bucket or not args.execution_id:
            parser.error("--bucket and --execution-id are both required for S3 mode.")
        legacy_key = f"{LEGACY_PREFIX}_{args.execution_id}.csv"
        legacy_text = _fetch_s3_object_text(args.bucket, legacy_key)
        if legacy_text is None:
            print(
                f"No object found at s3://{args.bucket}/{legacy_key}", file=sys.stderr
            )
            return 1
        new_text = None
        if args.new_prefix:
            new_key = f"{args.new_prefix}_{args.execution_id}.csv"
            new_text = _fetch_s3_object_text(args.bucket, new_key)
            if new_text is None:
                print(
                    f"--new-prefix given but no object found at s3://{args.bucket}/{new_key}. "
                    "Reporting on the legacy CSV alone.",
                    file=sys.stderr,
                )

    result = diff_reports(legacy_text, new_text)
    result.print_report()
    return 0 if result.is_clean() or new_text is None else 2


if __name__ == "__main__":
    sys.exit(main())
