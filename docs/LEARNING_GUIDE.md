# Learning guide: why this project matters

## IAM in one minute

AWS IAM (Identity and Access Management) controls **who** can perform **which AWS actions** on **which resources**. A JSON statement usually contains:

- `Effect`: `Allow` or `Deny`
- `Action`: such as `s3:GetObject`
- `Resource`: such as a specific S3 object ARN
- Optional `Condition`: limits when the statement applies
- In many trust/resource policies: `Principal` identifies who is trusted

## What to try

1. Open `examples/least_privilege.json` in the dashboard. It should match no rules.
2. Select `admin_access.json`. You should see the **Critical** all-actions rule.
3. Select `wildcard_service.json`. Look for broad S3 access and risky IAM administration.
4. Select `public_trust_policy.json`. Explain why wildcard principals deserve review.
5. Select `conditioned_read_only.json`. Why is the `Resource: "*"` **informational**?
6. Download a JSON or CSV report and explain one finding to a friend.
7. Run `python -m pytest -q` and explain two tests.

## Important security reasoning

- **A finding is not confirmed exploitation**. This is an offline review of policy text, not an AWS access test.
- `Resource: "*"` is valid and sometimes required when an AWS action does not support resource-level restrictions.
- An **explicit Deny** overrides a corresponding Allow during real AWS evaluation. IAM also combines many other policy types.
- `Condition` can significantly narrow policy scope. This scanner does not evaluate condition keys.
- A trust policy can omit `Resource` and include `Principal`. A simple identity policy usually uses `Resource` instead.
- For production, use AWS IAM Access Analyzer validation and review actual service permissions.

## Possible future improvements

- Add a cross-platform pre-commit hook running tests automatically.
- Add a read-only integration using AWS SDK and explicit user permission.
- Integrate IAM Access Analyzer ValidatePolicy for deeper validation.
- Add more rules with documented examples, and test each new rule against false positives.
- Add a clean demo GIF and an architecture diagram.
