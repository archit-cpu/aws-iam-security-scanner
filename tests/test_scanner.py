"""Tests are intentionally small and readable for student review."""
import csv
import io
import json
from pathlib import Path

import pytest

from scanner import (PolicyError, main, read_policy, report_csv, report_json,
                     scan_path, scan_policy, summary)

ROOT = Path(__file__).resolve().parents[1]


def make_policy(action="s3:GetObject", resource="arn:aws:s3:::demo/*", **kwargs):
    statement = {"Effect": "Allow", "Action": action, "Resource": resource, **kwargs}
    return {"Version": "2012-10-17", "Statement": [statement]}


def rules(policy):
    return {finding.rule for finding in scan_policy(policy)}


def test_all_action_wildcard_critical():
    findings = scan_policy(make_policy("*", "*"))
    assert any(f.rule == "IAM-003" and f.severity == "Critical" for f in findings)


def test_conditions_lower_all_action_warning():
    policy = make_policy("*", "*", Condition={"Bool": {"aws:SecureTransport": "true"}})
    assert any(f.rule == "IAM-003" and f.severity == "High" for f in scan_policy(policy))


def test_service_wildcard():
    assert "IAM-004" in rules(make_policy("s3:*", "*"))


def test_prefix_wildcard():
    assert "IAM-005" in rules(make_policy("s3:Get*"))


def test_passrole_unscoped():
    assert "IAM-006" in rules(make_policy("iam:PassRole", "*"))


def test_policy_modification_unscoped():
    assert "IAM-007" in rules(make_policy("iam:AttachRolePolicy", "*"))


def test_secrets_unscoped():
    assert "IAM-008" in rules(make_policy("secretsmanager:GetSecretValue", "*"))


def test_wildcard_principal():
    policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                             "Action": "sts:AssumeRole"}]}
    assert "IAM-009" in rules(policy)


def test_public_principal_with_condition_is_medium():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
                             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]}
    findings = scan_policy(policy)
    assert any(f.rule == "IAM-009" and f.severity == "Medium" for f in findings)


def test_notaction_allow():
    policy = {"Statement": [{"Effect": "Allow", "NotAction": "iam:DeleteUser", "Resource": "*"}]}
    assert "IAM-001" in rules(policy)


def test_notresource_allow():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                             "NotResource": "arn:aws:s3:::demo/private/*"}]}
    assert "IAM-002" in rules(policy)


def test_resource_wildcard_informational_not_always_bad():
    findings = scan_policy(make_policy("ec2:DescribeInstances", "*"))
    assert len(findings) == 1
    assert findings[0].rule == "IAM-010" and findings[0].severity == "Info"


def test_least_privilege_has_no_matching_rules():
    assert scan_policy(make_policy()) == []


def test_deny_not_treated_as_grant():
    policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert scan_policy(policy) == []


def test_allow_deny_combination_does_not_claim_effective_access():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"},
                            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}
    assert "IAM-003" in rules(policy)


@pytest.mark.parametrize("invalid", [
    {}, [], {"Statement": []}, {"Statement": "oops"},
    {"Statement": [{"Effect": "Allow", "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "Action": [], "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "s3:GetObject"}]},
])
def test_invalid_structure_rejected(invalid):
    with pytest.raises(PolicyError):
        scan_policy(invalid)


def test_report_json_csv_and_summary():
    findings = scan_policy(make_policy("*", "*"), "example.json")
    obj = json.loads(report_json(findings, [], 1))
    assert obj["summary"]["policies_checked"] == 1
    assert obj["summary"]["by_severity"]["Critical"] == 1
    records = list(csv.DictReader(io.StringIO(report_csv(findings))))
    assert records[0]["policy"] == "example.json"
    assert summary(findings, 1)["total_findings"] == len(findings)


def test_scan_directory_includes_samples():
    findings, errors, count = scan_path(ROOT / "examples")
    assert count == 7
    assert not errors
    assert any(f.rule == "IAM-003" for f in findings)


def test_invalid_json_file_reported_without_crashing(tmp_path):
    (tmp_path / "invalid.json").write_text("{broken", encoding="utf-8")
    (tmp_path / "okay.json").write_text(json.dumps(make_policy()), encoding="utf-8")
    findings, errors, count = scan_path(tmp_path)
    assert count == 2 and len(errors) == 1 and findings == []


def test_cli_json_output(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(make_policy("*", "*")), encoding="utf-8")
    report = tmp_path / "reports" / "result.json"
    assert main([str(path), "--format", "json", "--output", str(report)]) == 0
    assert json.loads(report.read_text())["summary"]["total_findings"] == 1


def test_cli_fail_on_threshold(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(make_policy("*", "*")), encoding="utf-8")
    assert main([str(path), "--fail-on", "high"]) == 2
    assert main([str(path), "--fail-on", "info"]) == 2


def test_sample_policies_are_valid():
    for path in (ROOT / "examples").glob("*.json"):
        assert isinstance(scan_policy(read_policy(path), path.name), list)
