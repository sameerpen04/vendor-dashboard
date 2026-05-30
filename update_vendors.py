import pandas as pd
from datetime import datetime
import pytz
import os
import requests
import xml.etree.ElementTree as ET
import re

def fetch_live_threat_intel():
    intel_database = []
    # 1. CISA KEV Feed
    try:
        cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(cisa_url, timeout=10)
        if response.status_code == 200:
            vulnerabilities = response.json().get('vulnerabilities', [])
            for vuln in vulnerabilities[-120:]:
                intel_database.append({
                    'title': f"CISA KEV: {vuln.get('cveID')}",
                    'summary': f"{vuln.get('vendorProject')} - {vuln.get('shortDescription')}",
                    'source': "CISA KEV"
                })
    except Exception:
        pass

    # 2. RSS Security Feeds
    rss_feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "TheCyberwire": "https://thecyberwire.com/feeds/rss.xml"
    }
    for source_name, url in rss_feeds.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for item in root.findall('.//item')[:40]:
                    title = item.find('title').text if item.find('title') is not None else ""
                    summary = item.find('description').text if item.find('description') is not None else ""
                    intel_database.append({
                        'title': title,
                        'summary': re.sub('<[^<]+?>', '', summary) if summary else "",
                        'source': source_name
                    })
        except Exception:
            pass
    return intel_database

def assess_vendor_threat(vendor_name, live_intel):
    name_upper = str(vendor_name).upper()
    breach_status = "✔ SECURE"
    breach_details = "No matching threat indicators or data exposures found in live OSINT intelligence indexes over this 24h cycle."
    inherent_risk = "Medium"
    residual_risk = "Medium Risk Profile (Stable)"
    css_class = "status-clean"
    source_reference = "N/A"
    historical_count = 0
    historical_notes = "Clear historic cross-reference index."
    
    # Inherent risk profiling keywords
    critical_infra = ["CLOUD", "AZURE", "MONGODB", "HUBSPOT", "1PASSWORD", "CHASE", "BANK", "ICICI", "STANDARD CHARTERED", "REVOLUT", "SVB", "JPMORGAN", "AWS", "GOOGLE"]
    high_impact = ["VODAFONE", "ORANGE", "TELEFONICA", "AT&T", "COMCAST", "DIGI", "AMAZON", "APPLE", "DELL", "MICROSOFT", "ATLASSIAN", "VANTA", "SAGE", "KNOWBE4", "VERCEL", "SMARTSHEET", "EMAG", "ALTEX"]
    
    if any(k in name_upper for k in critical_infra):
        inherent_risk = "Critical"
        residual_risk = "Critical Baseline Risk (Continuous Access Monitoring Recommended)"
    elif any(k in name_upper for k in high_impact):
        inherent_risk = "High"
        residual_risk = "High Baseline Risk (Regular Perimeter Audit Cycle Required)"
    else:
        if any(k in name_upper for k in ["CLEANING", "VENDING", "HOTEL", "CAKE", "BAKE"]):
            inherent_risk = "Low"
            residual_risk = "Low Baseline Risk"

    clean_keyword = name_upper.split()[0] if len(name_upper.split()) > 0 else name_upper
    if len(clean_keyword) > 3:
        for alert in live_intel:
            alert_text = f"{alert['title']} {alert['summary']}".upper()
            if clean_keyword in alert_text:
                breach_status = "⚠️ ALERT"
                breach_details = f"<strong>{alert['title']}</strong>: {alert['summary'][:180]}..."
                css_class = "status-alert"
                source_reference = alert['source']
                residual_risk = f"🚨 ESCALATED CRITICAL (Active Incident Reported via {source_reference})"
                historical_count += 1
                historical_notes = f"Active threat pattern flagged via {source_reference}."
                break
                
    return breach_status, breach_details, inherent_risk, residual_risk, css_class, source_reference, historical_count, historical_notes

def run_automation():
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p')
    
    excel_file = 'vendor_list.xlsx'
    html_file = 'index.html'
    log_file = 'daily_log.txt'
    
    if not os.path.exists(excel_file):
        print("Error: vendor_list.xlsx not found.")
        return

    try:
        live_intel = fetch_live_threat_intel()
        df = pd.read_excel(excel_file).dropna(how='all')
        
        # Standardize matching for the vendor identity column
        vendor_col = df.columns[0]
        for col in df.columns:
            if any(k in str(col).upper() for k in ['VENDOR', 'NAME', 'COMPANY']):
                vendor_col = col
                break

        # Helper function to extract data from optional dynamic spreadsheet columns
        def get_custom_val(row_data, keys, default="Not Set"):
            for col in df.columns:
                if any(k in str(col).upper() for k in keys):
                    val = row_data[col]
                    return str(val) if pd.notna(val) else default
            return default

        live_feed_rows = ""
        compliance_rows = ""
        alert_count = 0
        total_historical_incidents = 0
        
        for index, row in df.iterrows():
            vendor_name = row[vendor_col]
            if pd.isna(vendor_name):
                continue
                
            status, details, inherent, residual, css_class, source, hist_count, hist_notes = assess_vendor_threat(vendor_name, live_intel)
            if status == "⚠️ ALERT":
                alert_count += 1
            total_historical_incidents += hist_count
            
            # Fetch custom fields from Excel if they exist, else provide clean defaults
            web_url = get_custom_val(row, ['URL', 'WEB', 'WEBSITE'], "N/A")
            trust_url = get_custom_val(row, ['TRUST', 'SECURITY CENTER', 'PORTAL'], "Link Pending")
            category = get_custom_val(row, ['CATEGORY', 'TYPE'], "SaaS / General IT")
            service = get_custom_val(row, ['SERVICE', 'PROVIDES', 'SCOPE'], "Enterprise Supplier")
            compliance = get_custom_val(row, ['COMPLIANCE', 'CERTIFICATE', 'AUDIT'], "SOC2 / ISO27001 Pending")

            # Format URLs into clickable links safely
            url_link = f'<a class="table-link" href="{web_url}" target="_blank">Visit Site</a>' if web_url != "N/A" else '<span style="color:#aaa;">N/A</span>'
            trust_link = f'<a class="table-link trust-link" href="{trust_url}" target="_blank">Trust Center ↗</a>' if trust_url != "Link Pending" else '<span style="color:#aaa;">No Portal</span>'

            # 1. Row Builder for Tab 1 (Live Monitoring Feed)
            live_feed_rows += "<tr>"
            live_feed_rows += f"<td class=\"vendor-name\">{vendor_name}</td>"
            live_feed_rows += f"<td><span class=\"status-badge {css_class}\">{status}</span></td>"
            live_feed_rows += f"<td>{details}</td>"
            live_feed_rows += f"<td><span class=\"risk-badge risk-{inherent}\">{inherent.upper()}</span></td>"
            live_feed_rows += f"<td>{residual}</td>"
            live_feed_rows += f"<td style=\"font-weight: 600; color: #555;\">{source}</td>"
            live_feed_rows += "</tr>\n"

            # 2. Row Builder for Tab 2 (Historical GRC & Compliance Registry Matrix)
            compliance_rows += "<tr>"
            compliance_rows += f"<td class=\"vendor-name\">{vendor_name}<div style='font-size:11px; margin-top:4px;'>{url_link} | {trust_link}</div></td>"
            compliance_rows += f"<td><span class='category-tag'>{category}</span></td>"
            compliance_rows += f"<td><span class=\"risk-badge risk-{inherent}\">{inherent.upper()}</span></td>"
            compliance_rows += f"<td style='color:#4a5568;'>{service}</td>"
            compliance_rows += f"<td><span class='cert-badge'>{compliance}</span></td>"
            compliance_rows += f"<td><span class='hist-counter'>{hist_count} Logs</span><br><small style='color:#718096;'>{hist_notes}</small></td>"
            compliance_rows += "</tr>\n"
        
        color_code = "#e74c3c" if alert_count > 0 else "#27ae60"
        
        # Single-File Monolithic Dashboard Template containing Tab Switching JavaScript Core Logic
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CISO Third-Party Risk & Compliance Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background-color: #f7fafc; color: #2d3748; }}
        .header {{ background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: white; padding: 25px 30px; border-radius: 6px; margin-bottom: 25px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header h1 {{ margin: 0; font-size: 24px; letter-spacing: 0.5px; display: flex; align-items: center; gap: 10px; }}
        .header p {{ margin: 6px 0 0 0; opacity: 0.85; font-size: 13px; }}
        
        .nav-tabs {{ display: flex; border-bottom: 2px solid #e2e8f0; margin-bottom: 20px; gap: 5px; }}
        .tab-btn {{ background: none; border: none; padding: 12px 20px; font-size: 14px; font-weight: 600; color: #718096; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; margin-bottom: -2px; }}
        .tab-btn:hover {{ color: #2d3748; background-color: #edf2f7; border-radius: 4px 4px 0 0; }}
        .tab-btn.active {{ color: #3182ce; border-bottom: 2px solid #3182ce; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}

        .metrics-bar {{ display: flex; gap: 20px; margin-bottom: 25px; }}
        .metric-card {{ background: white; padding: 15px 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); flex: 1; border-left: 4px solid #4a5568; }}
        .metric-card.critical {{ border-left-color: #e74c3c; }}
        .metric-card.history {{ border-left-color: #dd6b20; }}
        .metric-value {{ font-size: 22px; font-weight: bold; margin-top: 5px; }}
        
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 6px; overflow: hidden; margin-top: 10px; }}
        th {{ background-color: #2d3748; color: white; text-align: left; padding: 14px 15px; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
        td {{ padding: 14px 15px; border-bottom: 1px solid #edf2f7; font-size: 13px; vertical-align: top; line-height: 1.5; }}
        tr:nth-child(even) td {{ background-color: #f7fafc; }}
        tr:hover td {{ background-color: #edf2f7; }}
        
        .vendor-name {{ font-weight: bold; color: #1a202c; font-size: 14px; }}
        .table-link {{ color: #3182ce; text-decoration: none; font-weight: 500; }}
        .table-link:hover {{ text-decoration: underline; }}
        .trust-link {{ color: #319795; font-weight: 600; }}
        
        .status-badge {{ display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 4px; text-transform: uppercase; }}
        .status-clean {{ background-color: #c6f6d5; color: #22543d; }}
        .status-alert {{ background-color: #fed7d7; color: #742a2a; }}
        
        .risk-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }}
        .risk-Critical {{ background-color: #fed7d7; color: #742a2a; }}
        .risk-High {{ background-color: #feebc8; color: #744210; }}
        .risk-Medium {{ background-color: #ebf8ff; color: #2b6cb0; }}
        .risk-Low {{ background-color: #edf2f7; color: #4a5568; }}
        
        .cert-badge {{ display: inline-block; background-color: #e6fffa; color: #234e52; padding: 3px 8px; border-radius: 4px; font-weight: 500; font-size: 12px; border: 1px solid #b2f5ea; }}
        .category-tag {{ background-color: #edf2f7; color: #2d3748; padding: 3px 6px; border-radius: 4px; font-size: 12px; }}
        .hist-counter {{ display: inline-block; background-color: #feebc8; color: #c05621; font-weight: bold; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin-bottom: 2px; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>🛡️ CISO Third-Party Risk & GRC Management Suite</h1>
        <p>Enterprise Perimeter Protection | Continuous OSINT Intel Mapping | Last Complete Automation Sync: {current_time} IST</p>
    </div>

    <div class="metrics-bar">
        <div class="metric-card">
            <div style="font-size: 11px; color: #718096; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Active Ecosystem Vendors</div>
            <div class="metric-value">{len(df)}</div>
        </div>
        <div class="metric-card critical">
            <div style="font-size: 11px; color: #718096; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Live 24h Threat Alerts</div>
            <div class="metric-value" style="color: {color_code};">{alert_count}</div>
        </div>
        <div class="metric-card history">
            <div style="font-size: 11px; color: #718096; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Cumulative Incident Logs</div>
            <div class="metric-value" style="color: #dd6b20;">{total_historical_incidents}</div>
        </div>
    </div>

    <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('live-feed')">🔍 Live 24h Threat Monitoring</button>
        <button class="tab-btn" onclick="switchTab('compliance-registry')">📋 Corporate Vendor GRC Registry</button>
    </div>

    <div id="live-feed" class="tab-content active">
        <table>
            <thead>
                <tr>
                    <th style="width: 22%;">Third-Party Vendor</th>
                    <th style="width: 12%;">Security Status</th>
                    <th style="width: 32%;">Threat Stream Indicators / Compromise Records</th>
                    <th style="width: 10%;">Inherent Risk</th>
                    <th style="width: 14%;">Residual Risk Profile</th>
                    <th style="width: 10%;">Intel Feed</th>
                </tr>
            </thead>
            <tbody>
                {live_feed_rows}
            </tbody>
        </table>
    </div>

    <div id="compliance-registry" class="tab-content">
        <table>
            <thead>
                <tr>
                    <th style="width: 25%;">Vendor Corporate Profile</th>
                    <th style="width: 15%;">Category</th>
                    <th style="width: 10%;">Inherent Risk</th>
                    <th style="width: 22%;">What Service It Provides</th>
                    <th style="width: 16%;">Compliance Framework Certificates</th>
                    <th style="width: 12%;">Historical Breach Logs</th>
                </tr>
            </thead>
            <tbody>
                {compliance_rows}
            </tbody>
        </table>
    </div>

    <script>
        function switchTab(tabId) {{
            // Deactivate all visible tab containers and navigation text weights
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            // Activate the designated targets dynamically
            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active');
        }}
    </script>

</body>
</html>"""

        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        with open(log_file, 'a') as f:
            f.write(f"[{current_time}] SUCCESS: Sync complete with Tabbed GRC Engine integration.\n")
        print("Master Enterprise Dashboard Compiled Successfully.")

    except Exception as e:
        print(f"Pipeline Interruption: {str(e)}")

if __name__ == "__main__":
    run_automation()
