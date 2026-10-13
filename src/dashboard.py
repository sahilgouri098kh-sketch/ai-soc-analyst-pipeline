
import hashlib
import json
from pathlib import Path


import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
ALERTS_FILE = ROOT / "alerts" / "ai_triaged" / "triaged_alerts.jsonl"
REPORTS_DIR = ROOT / "reports"


def load_jsonl(file_path):
    if not file_path.exists():
        return []

    records = []
    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def display_value(value):
    return value if value not in (None, "") else "N/A"


st.set_page_config(
    page_title="SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SOC Analyst Dashboard")
st.caption(
    "SOC Pipeline | Threat Detection • Triage • Incident Reporting"
)

# Uploaded-log analysis runs in memory and does not overwrite normal pipeline files.
st.header("📤 Upload & Analyze a Log File")
st.caption(
    "Upload a supported text log. Results appear below automatically; "
    "the uploaded file is not saved to disk by this dashboard."
)
uploaded_file = st.file_uploader(
    "Choose a log file",
    type=["log", "txt", "json", "jsonl", "ndjson", "csv"],
    help="Maximum 10 MB. Supports JSON/JSONL, CSV, and common Linux SSH authentication log lines.",
)
use_gemini = st.checkbox(
    "Send alert evidence to Google Gemini for AI triage",
    value=False,
    help=(
        "Optional. If enabled, alert metadata and selected log evidence are sent to "
        "the Gemini API. Leave unchecked to keep uploaded evidence local."
    ),
)

if uploaded_file is not None:
    from upload_analyzer import MAX_FILE_BYTES, analyze_events, parse_uploaded_file
    from incident_report import create_report

    if uploaded_file.size > MAX_FILE_BYTES:
        st.error("This file exceeds the 10 MB limit. Please upload a smaller file.")
    else:
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        cache_key = f"{file_hash}:{int(use_gemini)}"

        try:
            if st.session_state.get("upload_analysis_key") != cache_key:
                with st.spinner("Parsing and analyzing uploaded logs..."):
                    normalized_events, parse_errors = parse_uploaded_file(
                        uploaded_file.name, file_bytes
                    )
                    upload_alerts = analyze_events(
                        normalized_events, use_gemini=use_gemini
                    )
                st.session_state["upload_analysis_key"] = cache_key
                st.session_state["upload_analysis"] = {
                    "events": normalized_events,
                    "errors": parse_errors,
                    "alerts": upload_alerts,
                    "filename": uploaded_file.name,
                }

            result = st.session_state["upload_analysis"]
            upload_alerts = result["alerts"]
            normalized_events = result["events"]
            st.success(f"Analyzed: {result['filename']}")
            metric1, metric2, metric3 = st.columns(3)
            metric1.metric("Events Parsed", len(normalized_events))
            metric2.metric("Alerts Detected", len(upload_alerts))
            metric3.metric("Unparsed Lines/Records", result["errors"])

            if result["errors"]:
                st.warning(
                    f"{result['errors']} line(s)/record(s) could not be parsed. "
                    "Unsupported formats may need a dedicated parser."
                )

            if upload_alerts:
                st.subheader("🚨 Uploaded File — Detection Results")
                upload_rows = [{
                    "Alert ID": a.get("alert_id"),
                    "Alert Type": a.get("attack_type", a.get("alert_type", "Unknown")),
                    "Severity": a.get("severity", "Unknown"),
                    "Source IP": a.get("source_ip") or "N/A",
                    "Destination IP": a.get("destination_ip") or "N/A",
                    "MITRE Technique": a.get("mitre_technique") or "N/A",
                    "Verdict": a.get("verdict", "Needs Investigation"),
                    "Triage": a.get("triage_provider", "rules_fallback"),
                } for a in upload_alerts]
                st.dataframe(upload_rows, use_container_width=True, hide_index=True)

                for alert in upload_alerts:
                    label = (
                        f"{alert.get('alert_id')} — "
                        f"{alert.get('attack_type', alert.get('alert_type', 'Unknown'))}"
                    )
                    with st.expander(label):
                        st.write("**Severity:**", alert.get("severity", "Unknown"))
                        st.write("**Verdict:**", alert.get("verdict", "Needs Investigation"))
                        st.write("**Confidence:**", alert.get("confidence", "N/A"))
                        st.write("**Source IP:**", alert.get("source_ip") or "N/A")
                        st.write("**Destination IP:**", alert.get("destination_ip") or "N/A")
                        st.write("**MITRE ATT&CK:**", alert.get("mitre_technique") or "N/A")
                        st.write("**Reasoning:**", alert.get("reasoning_summary", "No reasoning available."))
                        st.write("**Recommended actions:**")
                        for action in alert.get("recommended_actions", []):
                            st.markdown(f"- {action}")
                        if alert.get("triage_note"):
                            st.caption(alert["triage_note"])
                        report = create_report(alert)
                        st.download_button(
                            "⬇️ Download this incident report",
                            data=report,
                            file_name=f"{alert.get('alert_id', 'incident')}.md",
                            mime="text/markdown",
                            key=f"upload_report_{file_hash}_{alert.get('alert_id')}",
                        )
                st.download_button(
                    "⬇️ Download all normalized events (JSONL)",
                    data="".join(json.dumps(e, ensure_ascii=False) + "\\n" for e in normalized_events),
                    file_name="normalized_uploaded_events.jsonl",
                    mime="application/x-ndjson",
                    key=f"normalized_download_{file_hash}",
                )
            else:
                st.info(
                    "No alerts matched the currently implemented rules. "
                    "This does not prove the file is clean; only supported patterns are checked."
                )
            st.info(
                "Privacy note: VirusTotal and AbuseIPDB are not queried automatically for uploaded files. "
                "Gemini is called only if you opt in above. Validate all findings manually."
            )
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Could not analyze this file ({type(exc).__name__}). Check the file format and try again.")

st.divider()
st.header("📊 Existing Pipeline Results")
alerts = load_jsonl(ALERTS_FILE)

if not alerts:
    st.info("No saved pipeline alerts found yet. Upload a log above, or run the simulated-log pipeline.")


# Dashboard metrics
total_alerts = len(alerts)
high_alerts = sum(
    str(a.get("severity", "")).lower() == "high" for a in alerts
)
medium_alerts = sum(
    str(a.get("severity", "")).lower() == "medium" for a in alerts
)
low_alerts = sum(
    str(a.get("severity", "")).lower() == "low" for a in alerts
)

report_files = (
    sorted(REPORTS_DIR.glob("*.md"))
    if REPORTS_DIR.exists()
    else []
)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Alerts", total_alerts)
col2.metric("High Severity", high_alerts)
col3.metric("Medium Severity", medium_alerts)
col4.metric("Low Severity", low_alerts)
col5.metric("Incident Reports", len(report_files))

st.divider()

# Alert severity distribution
st.subheader("📊 Alert Severity Distribution")

severity_counts = {
    "High": high_alerts,
    "Medium": medium_alerts,
    "Low": low_alerts,
}

chart_col, summary_col = st.columns([3, 1])

with chart_col:
    st.bar_chart(severity_counts)

with summary_col:
    st.markdown("#### Severity Summary")
    st.write(f"🔴 High: **{high_alerts}**")
    st.write(f"🟠 Medium: **{medium_alerts}**")
    st.write(f"🟢 Low: **{low_alerts}**")


# Search and severity filters
st.subheader("🚨 Detected Alerts")

filter_col1, filter_col2 = st.columns([2, 1])

with filter_col1:
    search_query = st.text_input(
        "🔍 Search alerts",
        placeholder="Search alert ID, attack type, or IP...",
    )

with filter_col2:
    severity_filter = st.selectbox(
        "Filter by severity",
        ["All", "High", "Medium", "Low"],
    )

filtered_alerts = []

for alert in alerts:
    severity = str(alert.get("severity", "Unknown"))

    matches_severity = (
        severity_filter == "All"
        or severity.lower() == severity_filter.lower()
    )

    searchable_text = " ".join(
        str(alert.get(field, ""))
        for field in [
            "alert_id",
            "attack_type",
            "source_ip",
            "destination_ip",
            "mitre_technique",
            "verdict",
        ]
    ).lower()

    matches_search = search_query.strip().lower() in searchable_text

    if matches_severity and matches_search:
        filtered_alerts.append(alert)


table_rows = []

for alert in filtered_alerts:
    table_rows.append({
        "Alert ID": alert.get("alert_id", "N/A"),
        "Alert Type": alert.get("attack_type", "Unknown"),
        "Severity": alert.get("severity", "Unknown"),
        "Source IP": alert.get("source_ip", "N/A"),
        "Destination IP": alert.get("destination_ip", "N/A"),
        "MITRE Technique": alert.get("mitre_technique", "N/A"),
        "Verdict": alert.get("verdict", "Needs Investigation"),
    })

st.caption(f"Showing {len(filtered_alerts)} of {total_alerts} alerts")

if table_rows:
    st.dataframe(
        table_rows,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No alerts match the selected filters.")


# Alert investigation
st.divider()
st.subheader("🔎 Investigate an Alert")

if filtered_alerts:
    alert_options = {
        (
            f"{alert.get('alert_id', 'N/A')} — "
            f"{alert.get('attack_type', 'Unknown')} — "
            f"{alert.get('severity', 'Unknown')}"
        ): alert
        for alert in filtered_alerts
    }

    selected_label = st.selectbox(
        "Select an alert",
        options=list(alert_options.keys()),
    )

    selected_alert = alert_options[selected_label]

    left, right = st.columns(2)

    with left:
        st.markdown("#### Alert Details")

        st.write(
            "**Alert ID:**",
            display_value(selected_alert.get("alert_id")),
        )
        st.write(
            "**Attack Type:**",
            display_value(selected_alert.get("attack_type")),
        )
        st.write(
            "**Severity:**",
            display_value(selected_alert.get("severity")),
        )
        st.write(
            "**Related Events:**",
            selected_alert.get("event_count", 0),
        )
        st.write(
            "**Source IP:**",
            display_value(selected_alert.get("source_ip")),
        )
        st.write(
            "**Destination IP:**",
            display_value(selected_alert.get("destination_ip")),
        )
        st.write(
            "**MITRE Technique:**",
            display_value(selected_alert.get("mitre_technique")),
        )
        st.write(
            "**Verdict:**",
            display_value(selected_alert.get("verdict")),
        )
        st.write(
            "**Confidence:**",
            display_value(selected_alert.get("confidence")),
        )

    with right:
        st.markdown("#### Analyst Reasoning")
        st.write(
            selected_alert.get(
                "reasoning_summary",
                "No reasoning available.",
            )
        )

        st.markdown("#### Threat Intelligence")

        threat_intel = selected_alert.get("threat_intelligence", {})

        for provider in ["virustotal", "abuseipdb"]:
            result = threat_intel.get(provider, {})

            provider_name = result.get(
                "provider",
                "VirusTotal" if provider == "virustotal" else "AbuseIPDB",
            )

            status = result.get("status", "not_available")
            ip_address = result.get("ip", selected_alert.get("source_ip", "N/A"))

            with st.expander(f"{provider_name} — {status.upper()}"):
                st.write("**IP Address:**", ip_address)
                st.write("**Lookup Status:**", status.replace("_", " ").title())

                if result.get("reason"):
                    st.info(result["reason"])

                if result.get("reputation") is not None:
                    st.write("**Reputation:**", result["reputation"])

                if result.get("abuse_score") is not None:
                    st.write("**Abuse Confidence Score:**", result["abuse_score"])

                if result.get("malicious_count") is not None:
                    st.write("**Malicious Detections:**", result["malicious_count"])

                if status == "skipped":
                    st.caption(
                        "Lookup was skipped. This does not mean the IP is safe or malicious."
                    )
                elif status == "error":
                    st.warning("The provider lookup did not complete successfully.")
                elif status == "not_available":
                    st.caption("No threat intelligence result is available.")


else:
    st.info("No alerts available to investigate with these filters.")



# Matching Incident Report
st.divider()
st.subheader("📄 Incident Report")

if filtered_alerts:
    selected_alert_id = str(selected_alert.get("alert_id", ""))

    matching_report = next(
        (
            path for path in report_files
            if path.stem == selected_alert_id
        ),
        None,
    )

    if matching_report:
        report_content = matching_report.read_text(encoding="utf-8")

        st.caption(f"Report for {selected_alert_id}")
        st.download_button(
            label="⬇️ Download Incident Report",
            data=report_content,
            file_name=matching_report.name,
            mime="text/markdown",
        )

        with st.expander("View Full Incident Report", expanded=True):
            st.markdown(report_content)
    else:
        st.warning(
            f"No incident report found for {selected_alert_id}. "
            "Run the incident report generator first."
        )
else:
    st.info("Select an existing pipeline alert to view its saved incident report.")
