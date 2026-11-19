"""Offline, educational AWS IAM policy risk reviewer (not an AWS authorization engine)."""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
import io
import json
from pathlib import Path
import sys
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Info")
SCORES = {"Critical": 4, "High": 3, "Medium": 2, "Info": 1}
POLICY_MANAGEMENT = {
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:updateassumerolepolicy", "iam:createaccesskey", "iam:addusertogroup",
}
SENSITIVE_READ = {"kms:decrypt", "secretsmanager:getsecretvalue"}
CSV_FIELDS = ("policy", "statement", "rule", "severity", "title", "evidence", "explanation", "recommendation")


class PolicyError(ValueError):
    """Input is not a parseable, basic IAM policy document."""


@dataclass(frozen=True)
class Finding:
    policy: str
    statement: str
    rule: str
    severity: str
    title: str
    evidence: str
    explanation: str
    recommendation: str


def _strings(value: Any, field: str) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return value
    raise PolicyError(f"'{field}' must be a non-empty string or list of strings")


def _principal_is_star(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, dict):
        return any("*" in _strings(v, "Principal") for v in value.values())
    return False


def _validate_and_get_statements(policy: Any) -> list[dict[str, Any]]:
    if not isinstance(policy, dict):
        raise PolicyError("Policy root must be a JSON object")
    if "Statement" not in policy:
        raise PolicyError("Missing required 'Statement' field")
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyError("'Statement' must be a non-empty object or list of objects")
    for number, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise PolicyError(f"Statement {number} must be an object")
        if statement.get("Effect") not in ("Allow", "Deny"):
            raise PolicyError(f"Statement {number} must set Effect to Allow or Deny")
        if ("Action" in statement) == ("NotAction" in statement):
            raise PolicyError(f"Statement {number} must have exactly one of Action or NotAction")
        if "Resource" in statement and "NotResource" in statement:
            raise PolicyError(f"Statement {number} cannot have both Resource and NotResource")
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            if field in statement:
                _strings(statement[field], field)
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise PolicyError(f"Statement {number} Condition must be an object")
        if "Principal" in statement:
            p = statement["Principal"]
            if isinstance(p, dict):
                if not p:
                    raise PolicyError(f"Statement {number} Principal cannot be empty")
                for v in p.values():
                    _strings(v, "Principal")
            elif p != "*" and not (isinstance(p, str) and p):
                raise PolicyError(f"Statement {number} Principal has unsupported format")
    return statements


def scan_policy(policy: Any, policy_name: str = "uploaded-policy.json") -> list[Finding]:
    """Return review suggestions for Allow statements; findings are NOT proven access."""
    statements = _validate_and_get_statements(policy)
    findings: list[Finding] = []

    for index, statement in enumerate(statements, start=1):
        if statement["Effect"] == "Deny":
            continue  # Explicit denies are not permission grants; other statements are still reviewed.
        sid = str(statement.get("Sid", f"Statement{index}"))
        start_index = len(findings)
        condition = bool(statement.get("Condition"))
        actions = _strings(statement["Action"], "Action") if "Action" in statement else []
        lowered = [action.lower() for action in actions]
        resources = _strings(statement["Resource"], "Resource") if "Resource" in statement else []
        all_resources = "*" in resources

        def add(rule: str, severity: str, title: str, evidence: str,
                explanation: str, recommendation: str) -> None:
            findings.append(Finding(policy_name, sid, rule, severity, title,
                                    evidence, explanation, recommendation))

        if "NotAction" in statement:
            add("IAM-001", "High", "Broad NotAction allow",
                f"NotAction: {statement['NotAction']}",
                "Allow + NotAction can grant many actions other than the listed exceptions; actual scope depends on Resource and conditions.",
                "Prefer a short Action allowlist and verify intended access with IAM Access Analyzer.")

        if "NotResource" in statement:
            add("IAM-002", "High", "Broad NotResource allow",
                f"NotResource: {statement['NotResource']}",
                "Allow + NotResource can apply to many resources other than those excluded.",
                "Use specific Resource ARNs when possible and review with IAM Access Analyzer.")

        if "*" in lowered:
            sev = "High" if condition else "Critical"
            add("IAM-003", sev, "All-actions wildcard",
                'Action: "*"',
                "The statement names every action. A condition may limit when it applies; this is not proof of effective admin access.",
                "Replace Action '*' with only the actions required for the job.")

        service_wildcards = [a for a in actions if a.endswith(":*") and a != "*"]
        if service_wildcards:
            sev = "Medium" if condition else "High"
            add("IAM-004", sev, "All actions within a service",
                ", ".join(service_wildcards),
                "A service-wide action wildcard can include both read and write permissions.",
                "Specify individual actions, ideally narrowed to required Resource ARNs.")

        prefix_wildcards = [a for a in actions if "*" in a and a != "*" and not a.endswith(":*")]
        if prefix_wildcards:
            add("IAM-005", "Medium", "Action name contains wildcard",
                ", ".join(prefix_wildcards),
                "Action patterns can match additional permissions as the service changes.",
                "Prefer explicit, documented action names where practical.")

        if all_resources and "iam:passrole" in lowered:
            add("IAM-006", "High", "PassRole over all resources",
                'iam:PassRole with Resource: "*"',
                "Passing roles broadly can be risky in combination with service permissions; conditions and other policies affect actual access.",
                "Scope to specific role ARNs and consider the iam:PassedToService condition key.")

        powerful_actions = sorted(a for a in actions if a.lower() in POLICY_MANAGEMENT)
        if all_resources and powerful_actions:
            add("IAM-007", "High", "IAM administration on all resources",
                ", ".join(powerful_actions),
                "These policy or credential management actions deserve extra review when broadly scoped.",
                "Limit resources to intended principals/policies and require controlled administrative workflows.")

        secrets_actions = sorted(a for a in actions if a.lower() in SENSITIVE_READ)
        if all_resources and secrets_actions:
            add("IAM-008", "Medium", "Sensitive data access on all resources",
                ", ".join(secrets_actions),
                "These actions could reveal secrets or decrypt data if other policy requirements also permit the request.",
                "Scope to specific keys or secret ARNs and review resource policies and conditions.")

        if "Principal" in statement and _principal_is_star(statement["Principal"]):
            add("IAM-009", "Medium" if condition else "High", "Wildcard principal",
                'Principal includes "*"',
                "A wildcard principal in a trust/resource policy can allow a broad set of principals; conditions may restrict it.",
                "Restrict Principal to approved identities and review trust conditions with IAM Access Analyzer.")

        # Resource '*' is sometimes REQUIRED (e.g., Describe actions), so treat it only as informational.
        if all_resources and not any(
            f.severity in ("Critical", "High", "Medium")
            for f in findings[start_index:]
        ):
            add("IAM-010", "Info", "Wildcard resource — manual review",
                'Resource: "*"',
                "This may be required for some AWS actions and is not, on its own, a vulnerability.",
                "Check whether each action supports resource-level permissions in AWS Service Authorization Reference.")

    return sorted(findings, key=lambda finding: (-SCORES[finding.severity], finding.policy, finding.statement, finding.rule))


def read_policy(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Cannot read {path}: {exc}") from exc


def scan_path(path: Path) -> tuple[list[Finding], list[str], int]:
    """Read one .json file or a folder of policy .json files, collecting errors."""
    if path.is_file() and path.suffix.lower() == ".json":
        paths = [path]
    elif path.is_dir():
        paths = sorted(path.rglob("*.json"))
    else:
        raise PolicyError("Choose a .json policy file or a folder containing .json policies")
    if not paths:
        raise PolicyError("No .json policy files found")
    findings: list[Finding] = []
    errors: list[str] = []
    for candidate in paths:
        try:
            findings.extend(scan_policy(read_policy(candidate), candidate.name))
        except PolicyError as exc:
            errors.append(f"{candidate}: {exc}")
    findings.sort(key=lambda f: (-SCORES[f.severity], f.policy, f.statement, f.rule))
    return findings, errors, len(paths)


def summary(findings: list[Finding], total_policies: int) -> dict[str, Any]:
    return {"policies_checked": total_policies, "total_findings": len(findings),
            "by_severity": {severity: sum(f.severity == severity for f in findings)
                            for severity in SEVERITIES}}


def report_json(findings: list[Finding], errors: list[str], total_policies: int) -> str:
    return json.dumps({"summary": summary(findings, total_policies),
                       "findings": [asdict(f) for f in findings], "errors": errors}, indent=2)


def report_csv(findings: list[Finding]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(asdict(f) for f in findings)
    return stream.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline educational IAM policy scanner (does not contact AWS).")
    parser.add_argument("path", type=Path, help=".json file or folder with policies")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--output", type=Path, help="Save a report to this file")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "info"],
                        help="Optional CI gate: exit 2 when findings are at/above this severity")
    args = parser.parse_args(argv)
    try:
        findings, errors, policy_count = scan_path(args.path)
    except PolicyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        output = report_json(findings, errors, policy_count)
    elif args.format == "csv":
        output = report_csv(findings)
    else:
        totals = summary(findings, policy_count)
        lines = [f"Scanned {policy_count} policy file(s); {totals['total_findings']} finding(s)."]
        lines.append("Severity: " + ", ".join(
            f"{severity}={count}" for severity, count in totals["by_severity"].items()))
        lines.extend(f"[{f.severity:8}] {f.policy} / {f.statement} / {f.rule}: {f.title}"
                     for f in findings)
        lines.extend(f"ERROR: {error}" for error in errors)
        output = "\n".join(lines) + "\n"

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        except OSError as exc:
            print(f"Unable to save report: {exc}", file=sys.stderr)
            return 1
        print(f"Saved report: {args.output}")
    else:
        print(output, end="" if output.endswith("\n") else "\n")

    if errors:
        return 1
    if args.fail_on and any(SCORES[f.severity] >= SCORES[args.fail_on.title()] for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
