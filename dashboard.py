"""STEP 6 - Dashboard.  Run:  streamlit run dashboard.py"""
import pandas as pd, plotly.express as px, streamlit as st
from common import load

st.set_page_config(page_title="Threat-Informed Defense Lab", layout="wide")
st.title("🛡️ Threat-Informed Defense Lab")
st.caption("Lab alerts refresh every 5 s · threat feeds refresh on a schedule · recorded datasets are replays")

@st.fragment(run_every=5)
def live_alerts():
    a = load("alerts")
    n = len(a)
    c = st.columns(4)
    c[0].metric("Alerts", n)
    c[1].metric("Critical / High", int(a.severity.isin(["critical", "high"]).sum()) if n else 0)
    c[2].metric("Unique source IPs", a.src_ip.nunique() if n else 0)
    c[3].metric("Rules fired", a.rule.nunique() if n else 0)
    if not n:
        st.info("No alerts yet. Run: python hunt.py ssh data/auth.log"); return
    a["ts"] = pd.to_datetime(a["ts"], errors="coerce")
    a = a.sort_values("ts", ascending=False)
    l, r = st.columns(2)
    l.plotly_chart(px.bar(a.groupby("rule").size().reset_index(name="count"), x="rule", y="count",
                          title="Alerts by rule"), use_container_width=True)
    r.plotly_chart(px.scatter(a, x="ts", y="rule", color="severity", title="Alert timeline"),
                   use_container_width=True)
    st.dataframe(a, use_container_width=True, hide_index=True)

live_alerts()
t1, t2, t3 = st.tabs(["🕵️ Threat intel", "🔧 Vulnerabilities", "🤖 Machine learning"])

with t1:
    kev, epss, ioc = load("kev"), load("epss"), load("iocs")
    c = st.columns(3)
    c[0].metric("KEV entries", len(kev)); c[1].metric("EPSS scores", len(epss)); c[2].metric("IOCs", len(ioc))
    if not kev.empty:
        top = kev.merge(epss, on="cve", how="left").sort_values("epss", ascending=False).head(15)
        st.subheader("Known-exploited CVEs most likely to be exploited (EPSS)")
        st.dataframe(top, use_container_width=True, hide_index=True)
    if not ioc.empty:
        st.subheader("Indicators of compromise (scored)")
        st.dataframe(ioc.sort_values("score", ascending=False).head(50), use_container_width=True, hide_index=True)
    if kev.empty and ioc.empty: st.info("Run: python cti.py (or python demo.py)")

with t2:
    v = load("vulns")
    if v.empty: st.info("Run: python vuln.py data/findings.csv")
    else:
        c = st.columns(2)
        for col, ph in zip(c, ["before", "after"]):
            s = v[v.phase == ph]
            col.metric(f"Critical/High ({ph} fix)", int(s.priority.isin(["Critical", "High"]).sum()))
        st.plotly_chart(px.bar(v, x="cve", y="risk", color="phase", barmode="group",
                               title="Risk score before vs after remediation"), use_container_width=True)
        st.dataframe(v, use_container_width=True, hide_index=True)

with t3:
    m, cm, imp = load("ml_metrics"), load("ml_confusion"), load("ml_importance")
    iso, an = load("ml_iso"), load("ml_anomalies")
    if m.empty and iso.empty: st.info("Run: python ml.py rf <csv>   or   python ml.py iso data/features.csv")
    if not m.empty:
        st.subheader("Random Forest (supervised, labelled data)")
        st.dataframe(m, use_container_width=True, hide_index=True)
        if not cm.empty:
            st.plotly_chart(px.imshow(cm.set_index("actual"), text_auto=True, title="Confusion matrix"),
                            use_container_width=True)
        if not imp.empty:
            st.plotly_chart(px.bar(imp, x="importance", y="feature", orientation="h",
                                   title="Top features"), use_container_width=True)
    if not iso.empty:
        st.subheader("Isolation Forest (unsupervised, trained on normal traffic)")
        st.dataframe(iso, use_container_width=True, hide_index=True)
        st.caption("Anomalies are leads to investigate, not proof of attack.")
        st.dataframe(an.head(30), use_container_width=True, hide_index=True)
