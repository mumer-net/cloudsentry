"""CloudSentry command line: scan and exposure."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import boto3
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cloudsentry import collect_aws, collect_plan, exposure, probe, rules
from cloudsentry.model import Inventory

console = Console()
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _inventories(args) -> list[Inventory]:
    if args.plan:
        return [collect_plan.load(args.plan)]
    session = boto3.Session(profile_name=args.profile)
    tag = tuple(args.tag.split("=", 1)) if args.tag else None
    if args.all_regions:
        return collect_aws.collect_all(session, tag)
    return [collect_aws.collect(session, args.region or session.region_name or "us-east-1", tag)]


def _say(text: str, markdown: bool, style: str | None = None) -> None:
    if markdown:
        print(text)
    else:
        console.print(text, style=style, markup=False, soft_wrap=True)


def _print_findings(findings: list[rules.Finding], markdown: bool) -> None:
    if not findings:
        return
    if markdown:
        print("| Control | Severity | Resource | Detail |\n| --- | --- | --- | --- |")
        for f in findings:
            print(f"| {f.control} | {f.severity} | `{f.resource}` | {f.detail} |")
        return
    table = Table()
    for column in ("Control", "Severity", "Resource", "Region", "Detail"):
        table.add_column(column)
    colors = {"high": "red", "medium": "yellow", "low": "cyan"}
    for f in findings:
        severity = f"[{colors[f.severity]}]{f.severity}[/]"
        table.add_row(f.control, severity, escape(f.resource), f.region, escape(f.detail))
    console.print(table)


def _compare_with_faults(inventories: list[Inventory], findings: list[rules.Finding], markdown: bool) -> bool:
    expected = set().union(*(rules.seeded_faults(inv) for inv in inventories))
    found = {(f.control, f.resource) for f in findings}
    missed, unexpected = expected - found, found - expected
    ok = not (missed or unexpected)
    summary = (
        f"Seeded faults detected: {len(expected & found)}/{len(expected)}, "
        f"missed {len(missed)}, unexpected findings {len(unexpected)}"
    )
    _say(f"\n{summary}" if markdown else summary, markdown, "green" if ok else "red")
    for control, resource in sorted(missed):
        _say(f"missed: {control} on {resource}", markdown)
    for control, resource in sorted(unexpected):
        _say(f"unexpected: {control} on {resource}", markdown)
    return ok


def run_scan(args) -> int:
    inventories = _inventories(args)
    by_source = {inv.source: rules.run(inv) for inv in inventories}
    findings = sorted(
        (f for found in by_source.values() for f in found),
        key=lambda f: (-SEVERITY_RANK[f.severity], f.control, f.resource),
    )
    _print_findings(findings, args.markdown)
    counts = ", ".join(f"{sum(f.severity == s for f in findings)} {s}" for s in ("high", "medium", "low"))
    sources = ", ".join(by_source) if len(by_source) < 4 else f"{len(by_source)} regions"
    _say(f"{len(findings)} findings ({counts}) in {sources}", args.markdown)

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        rows = [{**asdict(f), "severity": f.severity} for f in findings]
        Path(args.json).write_text(json.dumps({"sources": sources, "findings": rows}, indent=2) + "\n")

    ok = True
    if args.expect:
        ok = _compare_with_faults(inventories, findings, args.markdown)
    if args.fail_on and any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in findings):
        ok = False
    return 0 if ok else 1


def _add_scan(sub) -> None:
    p = sub.add_parser("scan", help="check VPCs against seven CIS AWS Foundations controls")
    p.add_argument("--plan", help="read a Terraform plan (terraform show -json) instead of AWS")
    p.add_argument("--region", help="AWS region (default: your profile's region)")
    p.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    p.add_argument("--tag", help="only VPCs with this tag, for example Project=cloudsentry")
    p.add_argument("--profile", help="AWS profile to use")
    p.add_argument("--json", metavar="FILE", help="also write the findings to a JSON file")
    p.add_argument("--markdown", action="store_true", help="print a Markdown table (for CI summaries)")
    p.add_argument("--expect", action="store_true", help="compare findings with the lab's Fault tags")
    p.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit 1 if any finding is this severe or worse")
    p.set_defaults(func=run_scan)


def _score(pairs: list[dict], key: str) -> dict[str, int]:
    flagged = [p for p in pairs if p[key]]
    return {
        "flagged": len(flagged),
        "true_positives": sum(p["probe"] for p in flagged),
        "false_positives": sum(not p["probe"] for p in flagged),
        "missed": sum(p["probe"] and not p[key] for p in pairs),
    }


def _probe_answers(inv: Inventory, results: list[exposure.Exposure]) -> dict[tuple[str, int], bool] | None:
    blocked = [port for port, ok in probe.preflight((22, 3389)).items() if not ok]
    if blocked:
        _say(
            f"This network blocks outbound TCP {', '.join(map(str, blocked))} (tested against portquiz.net). "
            "Probe from another network, such as a phone hotspot, or blocked ports will look closed.",
            markdown=False,
            style="red",
        )
        return None
    ips = {i.id: i.public_ip for i in inv.instances}
    targets = sorted({(ips[r.instance], r.port) for r in results if ips.get(r.instance)})
    found = probe.probe(targets)
    return {(r.instance, r.port): found.get((ips.get(r.instance), r.port), False) for r in results}


def _print_exposure(results: list[exposure.Exposure], answers: dict[tuple[str, int], bool]) -> None:
    columns = ["Instance", "Port", "Group open to world", "Reachable", "Blocked by"]
    if answers:
        columns.append("Probe")
    table = Table()
    for column in columns:
        table.add_column(column)
    yes_no = {True: "yes", False: "no"}
    for r in results:
        row = [escape(r.name), str(r.port), yes_no[r.naive], yes_no[r.reachable], r.blocked_by or ""]
        if answers:
            probed = answers[(r.instance, r.port)]
            row.append(yes_no[probed] if probed == r.reachable else f"[red]{yes_no[probed]}[/]")
        table.add_row(*row)
    console.print(table)


def run_exposure(args) -> int:
    session = boto3.Session(profile_name=args.profile)
    tag = tuple(args.tag.split("=", 1)) if args.tag else None
    inv = collect_aws.collect(session, args.region or session.region_name or "us-east-1", tag)
    results = exposure.analyze(inv, args.source or probe.my_public_ip())

    answers = {}
    if args.probe:
        answers = _probe_answers(inv, results)
        if answers is None:
            return 2
    _print_exposure(results, answers)
    if not answers:
        return 0

    pairs = [
        {
            "instance": r.name,
            "port": r.port,
            "naive": r.naive,
            "reachable": r.reachable,
            "blocked_by": r.blocked_by,
            "probe": answers[(r.instance, r.port)],
        }
        for r in results
    ]
    scores = {"security group only": _score(pairs, "naive"), "full path": _score(pairs, "reachable")}
    for name, s in scores.items():
        _say(
            f"{name}: flagged {s['flagged']}, confirmed by probe {s['true_positives']}, "
            f"false positives {s['false_positives']}, missed {s['missed']}",
            markdown=False,
        )
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        record = {
            "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%MZ"),
            "region": inv.region,
            "pairs": pairs,
            "scores": scores,
        }
        Path(args.out).write_text(json.dumps(record, indent=2) + "\n")
    return 0 if scores["full path"]["false_positives"] == scores["full path"]["missed"] == 0 else 1


def _add_exposure(sub) -> None:
    p = sub.add_parser("exposure", help="which instance ports are really reachable from the internet")
    p.add_argument("--region", help="AWS region (default: your profile's region)")
    p.add_argument("--tag", help="only VPCs with this tag, for example Project=cloudsentry")
    p.add_argument("--profile", help="AWS profile to use")
    p.add_argument("--source", help="source address to evaluate (default: this machine's public IP)")
    p.add_argument("--probe", action="store_true", help="also try real TCP connections and score both checks")
    p.add_argument("--out", metavar="FILE", help="with --probe, save the measurement as JSON")
    p.set_defaults(func=run_exposure)


COMMANDS = [_add_scan, _add_exposure]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloudsentry", description="Audit AWS VPC network security.")
    sub = parser.add_subparsers(dest="command", required=True)
    for add in COMMANDS:
        add(sub)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
