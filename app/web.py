
from pathlib import Path

import streamlit as st
import pandas as pd

from app.ingestion.pcap_reader import read_pcap
from app.ingestion.authlog_reader import read_authlog
from app.normalization.normalizer import normalize_events
from app.detection.engine import detect_threats
from app.detection.rules_loader import load_rules
from app.reporting.html_report import generate_html_report
from app.reporting.json_report import generate_json_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "rules" / "detection_rules.yaml"


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="PyHunter | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==================================================
# LIGHT PROFESSIONAL THEME
# ==================================================

st.markdown("""
<style>

/* GLOBAL */
.stApp {
    background-color: #f4f6f9;
    color: #1e293b;
}

.main .block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] span {
    color: #334155;
}

/* TITLES */
h1 {
    color: #111827 !important;
    font-weight: 800 !important;
}

h2, h3, h4 {
    color: #1e293b !important;
    font-weight: 700 !important;
}

/* GENERAL TEXT */
p, label {
    color: #334155;
}

/* METRIC CARDS */
.metric-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 20px;
    min-height: 135px;
    box-shadow: 0 3px 12px rgba(15, 23, 42, 0.05);
}

.metric-label {
    color: #64748b;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

.metric-value {
    font-size: 36px;
    font-weight: 800;
    color: #111827;
    margin-top: 8px;
}

.metric-icon {
    font-size: 25px;
    margin-bottom: 8px;
}

/* INDIVIDUAL CARD COLORS */
.card-events {
    border-left: 5px solid #0d9488;
}

.card-alerts {
    border-left: 5px solid #64748b;
}

.card-high {
    border-left: 5px solid #dc2626;
}

.card-medium {
    border-left: 5px solid #ea580c;
}

/* STATUS BOX */
.status-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 3px 10px rgba(15, 23, 42, 0.04);
}

/* BUTTONS */
div.stButton > button {
    background-color: #0d9488;
    color: #ffffff;
    border: none;
    border-radius: 9px;
    font-weight: 700;
    min-height: 42px;
}

div.stButton > button:hover {
    background-color: #0f766e;
    color: #ffffff;
}

/* DOWNLOAD BUTTONS */
div.stDownloadButton > button {
    background-color: #15803d;
    color: #ffffff;
    border: none;
    border-radius: 9px;
    font-weight: 700;
    min-height: 45px;
}

div.stDownloadButton > button:hover {
    background-color: #166534;
    color: #ffffff;
}

/* STREAMLIT METRICS */
[data-testid="stMetric"] {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 17px;
    box-shadow: 0 3px 10px rgba(15, 23, 42, 0.04);
}

[data-testid="stMetricValue"] {
    color: #111827;
    font-weight: 800;
}

[data-testid="stMetricLabel"] {
    color: #64748b;
    font-weight: 700;
}

/* TABLE */
[data-testid="stDataFrame"] {
    background-color: #ffffff;
    border-radius: 12px;
}

/* EXPANDERS */
[data-testid="stExpander"] {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
}

/* FILE UPLOADER */
[data-testid="stFileUploader"] {
    background-color: #ffffff;
    border: 1px dashed #94a3b8;
    border-radius: 12px;
    padding: 15px;
}

/* PROGRESS */
[data-testid="stProgressBar"] {
    background-color: #e2e8f0;
}

/* DIVIDERS */
hr {
    border-color: #e2e8f0;
}

/* CAPTIONS */
.stCaption {
    color: #64748b;
}

</style>
""", unsafe_allow_html=True)


# ==================================================
# FILE HANDLING
# ==================================================

def save_uploaded_file(uploaded_file, suffix):

    upload_dir = PROJECT_ROOT / "data" / "web_uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_path = upload_dir / f"uploaded{suffix}"
    file_path.write_bytes(uploaded_file.getvalue())

    return file_path


# ==================================================
# ANALYSIS ENGINE
# ==================================================

def run_analysis(pcap_file, auth_file):

    events = []

    if pcap_file is not None:

        pcap_path = save_uploaded_file(pcap_file, ".pcap")

        pcap_events = read_pcap(pcap_path)

        events.extend(
            normalize_events(pcap_events, "PCAP")
        )

    if auth_file is not None:

        auth_path = save_uploaded_file(auth_file, ".log")

        auth_events = read_authlog(auth_path)

        events.extend(
            normalize_events(auth_events, "AUTHLOG")
        )

    rules = load_rules(RULES_PATH)

    alerts = detect_threats(events, rules)

    return events, alerts


# ==================================================
# METRIC CARD
# ==================================================

def metric_card(label, value, icon, css_class):

    st.markdown(
        f"""
        <div class="metric-card {css_class}">
            <div class="metric-icon">{icon}</div>
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==================================================
# DASHBOARD
# ==================================================

def show_dashboard():

    events = st.session_state.events
    alerts = st.session_state.alerts

    total_events = len(events)
    total_alerts = len(alerts)

    high = sum(
        a.get("severity") == "HIGH" for a in alerts
    )

    medium = sum(
        a.get("severity") == "MEDIUM" for a in alerts
    )

    low = sum(
        a.get("severity") == "LOW" for a in alerts
    )

    # HEADER
    st.title("🛡️ PyHunter Security Center")

    st.caption(
        "Network monitoring | Threat detection | Incident analysis"
    )

    st.divider()

    # STATISTICS
    st.subheader("Security Overview")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card(
            "EVENTS ANALYZED",
            total_events,
            "📦",
            "card-events",
        )

    with c2:
        metric_card(
            "TOTAL ALERTS",
            total_alerts,
            "🚨",
            "card-alerts",
        )

    with c3:
        metric_card(
            "HIGH SEVERITY",
            high,
            "🔴",
            "card-high",
        )

    with c4:
        metric_card(
            "MEDIUM SEVERITY",
            medium,
            "🟠",
            "card-medium",
        )

    st.write("")

    # SECURITY STATUS
    st.subheader("System Security Status")

    if not events:

        st.info(
            "No analysis available. Upload your PCAP or auth.log files."
        )

    elif high > 0:

        st.error(
            f"WARNING: {high} high-severity threat(s) detected."
        )

    elif total_alerts > 0:

        st.warning(
            "Suspicious activity detected. Please review the alerts."
        )

    else:

        st.success(
            "No threats detected in the analyzed files."
        )

    st.divider()

    # THREAT DISTRIBUTION
    st.subheader("Threat Analysis")

    left, right = st.columns(2)

    with left:

        st.markdown("#### Alert Severity Distribution")

        if total_alerts > 0:

            severity_data = pd.DataFrame({
                "Severity": ["HIGH", "MEDIUM", "LOW"],
                "Alerts": [high, medium, low],
            })

            st.bar_chart(
                severity_data.set_index("Severity"),
                color="#0d9488",
            )

            st.write(f"🔴 HIGH: {high}")
            st.write(f"🟠 MEDIUM: {medium}")
            st.write(f"🟢 LOW: {low}")

        else:

            st.info("No alerts available.")

    with right:

        st.markdown("#### Analysis Summary")

        detection_types = len(
            set(a.get("alert_type") for a in alerts)
        )

        st.markdown(
            f"""
            <div class="status-box">
                <p>📦 Events analyzed: <b>{total_events}</b></p>
                <p>🚨 Total alerts: <b>{total_alerts}</b></p>
                <p>🔍 Detection types: <b>{detection_types}</b></p>
                <p>🛡️ Detection engine: <b>Active</b></p>
                <p>🎯 MITRE ATT&CK: <b>Integrated</b></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # INPUT SOURCES
    st.subheader("Input Sources")

    if events:

        source_counts = {}

        for event in events:

            source = event.get("source", "Unknown")

            source_counts[source] = (
                source_counts.get(source, 0) + 1
            )

        source_columns = st.columns(max(1, len(source_counts)))

        for column, (source, count) in zip(
            source_columns,
            source_counts.items(),
        ):

            with column:

                st.metric(
                    label=source,
                    value=count,
                )

    else:

        st.info("No input sources available.")

    st.divider()

    # DETECTED THREATS
    st.subheader("🚨 Detected Threats")

    if alerts:

        rows = []

        for alert in alerts:

            rows.append({
                "Threat": alert.get("alert_type", "Unknown"),
                "Source IP": alert.get("source_ip", "N/A"),
                "Severity": alert.get("severity", "N/A"),
                "MITRE ATT&CK": alert.get("mitre_attack", "N/A"),
            })

        st.dataframe(
            rows,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("#### Threat Details")

        for index, alert in enumerate(alerts, start=1):

            severity = alert.get("severity", "UNKNOWN")
            threat = alert.get("alert_type", "Unknown")
            source_ip = alert.get("source_ip", "N/A")

            icon = {
                "HIGH": "🔴",
                "MEDIUM": "🟠",
                "LOW": "🟢",
            }.get(severity, "⚪")

            with st.expander(
                f"{icon} {index}. {threat} | {source_ip} | {severity}"
            ):

                st.json(alert)

    else:

        st.info("No threats detected yet.")

    st.divider()

    st.caption(
        "PyHunter | Network Threat Detection Platform | MITRE ATT&CK"
    )


# ==================================================
# MAIN APPLICATION
# ==================================================

def main():

    if "events" not in st.session_state:
        st.session_state.events = []

    if "alerts" not in st.session_state:
        st.session_state.alerts = []

    # SIDEBAR
    with st.sidebar:

        st.title("🛡️ PyHunter")

        st.caption("Network Threat Detection Platform")

        st.divider()

        page = st.radio(
            "NAVIGATION",
            [
                "Dashboard",
                "File Analysis",
                "Reports",
            ],
        )

        st.divider()

        st.markdown("### Detection Engine")

        st.success("Engine ready")

        st.caption("MITRE ATT&CK integration")
        st.caption("PCAP | SSH | DNS")

        st.divider()

        st.caption("Version 1.0")

    # DASHBOARD
    if page == "Dashboard":

        show_dashboard()

    # FILE ANALYSIS
    elif page == "File Analysis":

        st.title("📂 File Analysis")

        st.caption(
            "Upload PCAP and authentication logs for threat detection."
        )

        st.divider()

        pcap_file = st.file_uploader(
            "Upload PCAP file",
            type=["pcap"],
            key="pcap_upload",
        )

        auth_file = st.file_uploader(
            "Upload Linux auth.log",
            type=["log", "txt"],
            key="auth_upload",
        )

        st.info(
            "You can upload one file or both files."
        )

        if st.button(
            "🚀 Run Analysis",
            use_container_width=True,
        ):

            if pcap_file is None and auth_file is None:

                st.warning(
                    "Please upload at least one input file."
                )

            else:

                try:

                    with st.spinner(
                        "Analyzing events and detecting threats..."
                    ):

                        events, alerts = run_analysis(
                            pcap_file,
                            auth_file,
                        )

                        st.session_state.events = events
                        st.session_state.alerts = alerts

                    st.success(
                        f"Analysis completed: {len(events)} events, "
                        f"{len(alerts)} alerts detected."
                    )

                    st.subheader("Detection Results")

                    if alerts:

                        for alert in alerts:

                            severity = alert.get(
                                "severity",
                                "UNKNOWN",
                            )

                            title = alert.get(
                                "alert_type",
                                "Threat",
                            )

                            with st.expander(
                                f"{severity} | {title} | "
                                f"{alert.get('source_ip', 'N/A')}"
                            ):

                                st.json(alert)

                    else:

                        st.info("No threats detected.")

                except Exception as error:

                    st.error(f"Analysis failed: {error}")

    # REPORTS
    elif page == "Reports":

        st.title("📊 Security Reports")

        st.caption(
            "Generate and download your security analysis reports."
        )

        st.divider()

        events = st.session_state.events
        alerts = st.session_state.alerts

        if not events and not alerts:

            st.info(
                "Run an analysis first to generate reports."
            )

        else:

            report_dir = PROJECT_ROOT / "reports"
            report_dir.mkdir(exist_ok=True)

            json_path = report_dir / "report.json"
            html_path = report_dir / "report.html"

            generate_json_report(
                alerts,
                str(json_path),
            )

            generate_html_report(
                alerts,
                str(html_path),
            )

            st.success("Reports generated successfully.")

            json_bytes = json_path.read_bytes()
            html_bytes = html_path.read_bytes()

            col1, col2 = st.columns(2)

            with col1:

                st.download_button(
                    "⬇️ Download JSON Report",
                    data=json_bytes,
                    file_name="pyhunter_report.json",
                    mime="application/json",
                    use_container_width=True,
                )

            with col2:

                st.download_button(
                    "⬇️ Download HTML Report",
                    data=html_bytes,
                    file_name="pyhunter_report.html",
                    mime="text/html",
                    use_container_width=True,
                )

            st.divider()

            st.subheader("Report Summary")

            r1, r2 = st.columns(2)

            with r1:
                st.metric("Events Analyzed", len(events))

            with r2:
                st.metric("Alerts Detected", len(alerts))


if __name__ == "__main__":
    main()

