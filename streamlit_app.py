import pandas as pd
import streamlit as st
import plotly.express as px
import requests
import json
import time
import io
import os
from fpdf import FPDF
import plotly.io as pio

# === CONFIG ===
API_KEY = "7fd4c5eba9c28f0b846f1f8e3ae013380bf4af60ec50f865d0163d2431b9bd8474caef849e8393a4"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TOP_N = 30

st.set_page_config(page_title="Cybersecurity Dashboard", layout="wide")
st.title("🔐 Threat Intelligence Dashboard + API Enrichment")

uploaded_file = st.file_uploader("📤 Upload your CSV file", type="csv")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

    ip_query = st.text_input("🔎 Search IP/domain/subnet", "")
    filtered_df = df[df['Source IP'].astype(str).str.contains(ip_query, na=False)] if ip_query else df

    st.subheader("📊 Traffic by Protocol (Total vs Malicious)")
    grouped = filtered_df.groupby(['Protocol', 'Label']).size().reset_index(name='Count')
    grouped['Label'] = grouped['Label'].replace({0: 'Benign', 1: 'Malicious'})
    fig1 = px.bar(grouped, x='Protocol', y='Count', color='Label', barmode='group')
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("🚨 Top Malicious IPs")
    malicious_df = df[df['Label'] == 1]
    if ip_query:
        malicious_df = malicious_df[malicious_df['Source IP'].astype(str).str.contains(ip_query, na=False)]
    top_ips = malicious_df['Source IP'].value_counts().nlargest(10).reset_index()
    top_ips.columns = ['Source IP', 'Count']
    fig2 = px.bar(top_ips, x='Source IP', y='Count')
    st.plotly_chart(fig2, use_container_width=True)

    st.subheader("📈 Detection Rate (Benign vs Malicious)")
    rate = filtered_df['Label'].value_counts(normalize=True).reset_index()
    rate.columns = ['Label', 'Percentage']
    rate['Label'] = rate['Label'].replace({0: 'Benign', 1: 'Malicious'})
    fig3 = px.pie(rate, values='Percentage', names='Label')
    st.plotly_chart(fig3, use_container_width=True)

    st.subheader("📆 Intrusion Events Over Time")
    intrusions = df[df['Label'] == 1]
    if ip_query:
        intrusions = intrusions[intrusions['Source IP'].astype(str).str.contains(ip_query, na=False)]
    time_df = intrusions.dropna(subset=['Timestamp']).groupby(
        intrusions['Timestamp'].dt.floor('H')).size().reset_index(name='Count')
    fig4 = px.line(time_df, x='Timestamp', y='Count')
    st.plotly_chart(fig4, use_container_width=True)

    if ip_query:
        st.subheader(f"🔍 Search Results for '{ip_query}'")
        result_df = filtered_df[['Timestamp', 'Source IP', 'Protocol', 'Label']]
        st.dataframe(result_df.head(10))

    st.subheader("🌐 Enrich Top Malicious IPs with AbuseIPDB")
    if 'Source IP' in df.columns:
        if st.button("🔍 Run IP Reputation Check on Top Malicious IPs"):
            ip_list = malicious_df['Source IP'].value_counts().head(TOP_N).index.tolist()
            results = {}
            with st.spinner("⏳ Querying AbuseIPDB..."):
                for ip in ip_list:
                    try:
                        response = requests.get(
                            ABUSEIPDB_URL,
                            headers={"Key": API_KEY, "Accept": "application/json"},
                            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
                        )
                        if response.status_code == 200:
                            results[ip] = response.json()
                        else:
                            results[ip] = {"error": f"Status {response.status_code}", "reason": response.text}
                        time.sleep(1)
                    except Exception as e:
                        results[ip] = {"error": str(e)}

                for ip, data in results.items():
                    with st.expander(f"IP: {ip}"):
                        st.json(data)

                json_str = json.dumps(results, indent=4)
                st.download_button("📥 Download Enrichment Results (JSON)", data=json_str,
                                   file_name="malicious_ip_enrichment.json", mime="application/json")

    st.subheader("📝 Generate PDF Report")
    if st.button("📄 Generate PDF Summary"):
        class PDF(FPDF):
            def header(self):
                self.set_font("Arial", 'B', 14)
                self.cell(0, 10, "Cybersecurity Threat Report", ln=True, align="C")
                self.ln(5)

            def footer(self):
                self.set_y(-15)
                self.set_font("Arial", 'I', 8)
                self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

        def save_fig_to_img(fig, filename):
            fig.write_image(filename, format="png")

        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, f"Total Records: {len(df)}", ln=True)
        total_malicious = len(df[df['Label'] == 1])
        pdf.cell(0, 10, f"Total Malicious Entries: {total_malicious}", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Top 5 Malicious IPs:", ln=True)
        pdf.set_font("Arial", size=11)
        for idx, row in top_ips.head(5).iterrows():
            pdf.cell(0, 10, f"{row['Source IP']}: {row['Count']} detections", ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Detection Breakdown:", ln=True)
        pdf.set_font("Arial", size=11)
        for i, r in rate.iterrows():
            pdf.cell(0, 10, f"{r['Label']}: {round(r['Percentage']*100, 2)}%", ln=True)

        charts = [(fig1, "protocol.png", "Traffic by Protocol"),
                  (fig2, "top_ips.png", "Top Malicious IPs"),
                  (fig3, "rate.png", "Detection Rate"),
                  (fig4, "intrusions.png", "Intrusion Over Time")]

        for fig, file, caption in charts:
            path = os.path.join("/tmp", file)
            save_fig_to_img(fig, path)
            pdf.add_page()
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, caption, ln=True)
            pdf.image(path, x=10, w=180)

        pdf_output = pdf.output(dest='S').encode('latin1')
        st.download_button("📄 Download PDF Report", data=pdf_output,
                           file_name="threat_report.pdf", mime="application/pdf")

else:
    st.info("👆 Please upload a CSV file to begin.")
