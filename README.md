# 🛡️ AWS IAM Security Scanner — IAM Policy Guard

**A beginner-friendly, offline security review tool for AWS IAM JSON policies.**

Built with Python and Streamlit, this project highlights **potentially risky permission patterns**, explains the reasoning, and suggests ways to review or narrow permissions. It uses deterministic, rule-based checks (not AI/ML).

> **Safety:** The app **does not connect to AWS**, does not need credentials, and does not modify cloud resources. Its findings are review prompts, not definitive vulnerabilities or effective-permission calculations.

## Features

- Analyze identity-based and selected trust/resource-style IAM policy JSON files.
- Find broad actions (`*`, `s3:*`), `NotAction`, `NotResource`, wildcard principals, broad `iam:PassRole`, and high-impact permissions.
- Display severity, affected statement, evidence, explanation and recommendation.
- Review bundled synthetic examples or upload your own local JSON.
- Export findings in **JSON or CSV** formats.
- Run as **Streamlit dashboard** or **command-line scanner**.
- Automated **pytest** tests and GitHub Actions for Python 3.12 and 3.13.

## Quick start (Windows PowerShell in VS Code)

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open **http://localhost:8501** in your browser.

If your terminal is already using a different environment, these commands still install and run packages from this project's own `.venv` folder.

## CLI examples

```powershell
# Scan all included demo policies
.\.venv\Scripts\python.exe scanner.py examples

# Scan just one JSON policy
.\.venv\Scripts\python.exe scanner.py examples\admin_access.json

# Save detailed reports
.\.venv\Scripts\python.exe scanner.py examples --format json --output reports\scan.json
.\.venv\Scripts\python.exe scanner.py examples --format csv --output reports\scan.csv

# Optional CI check: exit code 2 if any High or Critical findings
.\.venv\Scripts\python.exe scanner.py examples --fail-on high
```

The `--fail-on` example intentionally fails for the supplied risky demo policies. Exit codes: **0** scan completed; **1** input/file errors; **2** matched fail-on threshold.

## How it works

```text
IAM JSON policy file
       |
       v
Basic format checks
       |
       v
Review Allow statements
       |
       v
Apply understandable risk rules
       |
       v
Show findings + severity + why + suggested review
       |
       +--> Streamlit dashboard
       +--> CLI report (JSON / CSV)
```

## Example policies

| File | What you can learn |
|---|---|
| `admin_access.json` | Why `Action: "*"` deserves close review |
| `least_privilege.json` | A tightly scoped action and resource |
| `wildcard_service.json` | `s3:*`, policy changes, and `iam:PassRole` |
| `public_trust_policy.json` | Risk of wildcard principals in trust/resource policies |
| `conditioned_read_only.json` | Why some APIs need `Resource: "*"` |
| `deny_only.json` | Deny statements are not treated as grants |
| `notaction_allow.json` | Why `Allow` + `NotAction` needs extra care |

These are **fictional educational examples**. No live AWS policy or user data is included.

## Rules and severity

| Rule | What it checks | Typical severity |
|---|---|---|
| IAM-001 | Allow with `NotAction` | High |
| IAM-002 | Allow with `NotResource` | High |
| IAM-003 | All actions (`*`) | Critical / High with condition |
| IAM-004 | Whole-service actions (`s3:*`) | High / Medium with condition |
| IAM-005 | Action name wildcards (`s3:Get*`) | Medium |
| IAM-006 | Broad `iam:PassRole` | High |
| IAM-007 | Broad sensitive IAM administration | High |
| IAM-008 | Broad secret/decrypt actions | Medium |
| IAM-009 | Wildcard `Principal` | High / Medium with condition |
| IAM-010 | `Resource: "*"` without other flagged issues | Info only |

## Limits — read before using

- The scanner **does not evaluate AWS effective permissions** or validate every IAM JSON grammar detail.
- It does not consider policy attachments, explicit denies in other policies, permissions boundaries, SCPs, RCPs, sessions, trust relationships, or resource-based policy interactions.
- It does not fully evaluate conditions. A policy that looks broad may have meaningful safeguards.
- Some AWS API actions require `Resource: "*"`; that alone is **not a proven misconfiguration**.
- The scanner does not replace **AWS IAM Access Analyzer** or professional security review.
- Avoid uploading genuine or sensitive policy information to a publicly deployed demo.

Read [Learning Guide](docs/LEARNING_GUIDE.md) to understand what the code demonstrates and how to discuss it in interviews.

## References

- [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
- [AWS service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)

## Resume starter bullet (after verifying on your computer)

> Built an offline AWS IAM policy scanning tool in Python that identifies broad permissions and sensitive IAM actions, explains findings by severity, and generates CSV/JSON reports through a Streamlit dashboard; added automated tests and GitHub Actions CI.

**License:** MIT. See `LICENSE`.
