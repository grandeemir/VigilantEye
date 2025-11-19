"""Optional Streamlit dashboard for visualizing a single enriched query.

Run with: `streamlit run dashboard.py`
"""
import streamlit as st
import json

from core.utils import detect_input_type
from core.collector import enrich


st.title("ThreatIntelApp Dashboard")

resource = st.text_input("IP / domain / URL / hash")
if st.button("Query") and resource:
    rtype = detect_input_type(resource)
    if rtype == "unknown":
        st.error("Could not detect resource type")
    else:
        with st.spinner("Querying sources..."):
            enriched = enrich(resource, rtype)
        st.subheader("Overall Score")
        st.metric("Risk Score", f"{enriched.get('overall_score', 0):.1f}/100")
        st.subheader("Raw JSON")
        st.json(enriched)
