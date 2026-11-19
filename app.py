"""Streamlit dashboard for the offline IAM policy scanner."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from scanner import PolicyError, read_policy, report_csv, report_json, scan_policy, summary

BASE = Path(__file__).resolve().parent
EXAMPLES = BASE / "examples"

st.set_page_config(page_title="IAM Policy Guard", page_icon="🛡️", layout="wide")
st.title("🛡️ AWS IAM Security Scanner")
st.caption("Offline IAM policy risk review • rule-based checks • no AWS account or credentials required")

with st.sidebar:
    st.header("Controls")
    files = sorted(EXAMPLES.glob("*.json"))
    selection = st.selectbox("Choose a demo policy", files, format_func=lambda path: path.stem.replace("_", " ").title())
    uploaded = st.file_uploader("Or upload an IAM policy (.json)", type=["json"])
    st.info("Uploads are processed in this app session. Do not upload secrets or private production policies to a public deployment.")
    st.markdown("**Severity guide**")
    st.caption("Critical = potentially very broad permissions; High = important review; Medium = notable risk; Info = manual review.")

try:
    if uploaded is None:
        policy = read_policy(selection)
        name = selection.name
        st.write(f"**Scanning sample:** `{name}`")
    else:
        policy = json.loads(uploaded.getvalue().decode("utf-8"))
        name = uploaded.name
        st.write(f"**Scanning upload:** `{name}`")
    findings = scan_policy(policy, name)
except (PolicyError, ValueError, UnicodeError) as exc:
    st.error(f"Could not scan policy: {exc}")
    st.stop()

counts = summary(findings, 1)
cols = st.columns(5)
cols[0].metric("Findings", counts["total_findings"])
for col, level in zip(cols[1:], ["Critical", "High", "Medium", "Info"]):
    col.metric(level, counts["by_severity"][level])

st.subheader("Findings")
if not findings:
    st.success("No issues matched these educational rules. This does NOT prove the policy is secure.")
else:
    data = pd.DataFrame([asdict(f) for f in findings])
    st.dataframe(data[["severity", "rule", "statement", "title", "evidence"]],
                 use_container_width=True, hide_index=True)
    for number, finding in enumerate(findings, 1):
        with st.expander(f"{number}. {finding.severity} — {finding.title} ({finding.rule})"):
            st.write(f"**Statement:** `{finding.statement}`")
            st.write(f"**Evidence:** {finding.evidence}")
            st.write(f"**Why it matters:** {finding.explanation}")
            st.write(f"**Suggested review:** {finding.recommendation}")

left, right = st.columns(2)
with left:
    st.download_button("Download findings as JSON", data=report_json(findings, [], 1),
                       file_name="iam-findings.json", mime="application/json")
with right:
    st.download_button("Download findings as CSV", data=report_csv(findings),
                       file_name="iam-findings.csv", mime="text/csv")

with st.expander("View original policy JSON"):
    st.json(policy)

st.divider()
st.warning("Educational static checks only. AWS IAM evaluates identity/resource policies, explicit denies, conditions, SCPs and permissions boundaries together. Findings are not proof of effective access. Validate with AWS IAM Access Analyzer before deployment.")
st.markdown("AWS reference: [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html) · [Policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)")
