import pandas as pd
from datetime import datetime
import pytz
import os
import requests
import xml.etree.ElementTree as ET
import re

def fetch_live_threat_intel():
    """
    Aggregates real-time threat data from open-source security intelligence feeds.
    """
    intel_database = []
    
    # 1. CISA KEV Feed (JSON Format)
    try:
        cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(cisa_url, timeout=10)
        if response.status_code == 200:
            vulnerabilities = response.json().get('vulnerabilities', [])
            for vuln in vulnerabilities[-100:]:
                intel_database.append({
                    'title': f"CISA KEV Alert: {vuln.get('cveID')}",
                    'summary': f"{vuln.get('vendorProject')} - {vuln.get('shortDescription')}",
                    'source': "CISA KEV Catalog"
                })
    except Exception as e:
        print(f"Warning: Failed to sync CISA KEV: {e}")

    # 2. BleepingComputer & Cyberwire RSS Feeds (XML Format)
    rss_feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "TheCyberwire": "https://thecyberwire.com/feeds/rss.xml"
    }
    
    for source_name, url in rss_feeds.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for item in root.findall('.//item')[:30]:
                    title = item.find('title').text if item.find('title') is not None else ""
                    summary = item.find('description').text if item.find('description') is not None else ""
                    intel_database.append({
                        'title': title,
                        'summary': re.sub('<[^<]+?>', '', summary) if summary else "",
                        'source': source_name
                    })
        except Exception as e:
            print(f"Warning: Failed to sync {source_name} RSS: {e}")
        
    return intel_database

def assess_vendor_threat(vendor_name, live_intel):
    """
    Evaluates individual vendor names against the aggregated threat database.
    """
    name_upper = str(vendor_name).upper()
    
    breach_status = "✔ SECURE"
    breach_details = "No matching threat indicators or data exposures found in live OSINT intelligence indexes over this 24h cycle."
    inherent_risk = "Medium"
    new_risk = "Medium Risk Profile (Stable)"
    css_class = "status-clean"
    source_reference = "N/A"
    
    critical_infra = ["CLOUD", "AZURE", "MONGODB", "HUBSPOT", "1PASSWORD", "CHASE", "BANK", "ICICI", "STANDARD CHARTERED", "REVOLUT", "SVB", "JPMORGAN"]
    high_impact = ["VODAFONE", "ORANGE", "TELEFONICA", "AT&T", "COMCAST", "DIGI", "AMAZON", "APPLE", "DELL", "MICROSOFT", "ATLASSIAN", "VANTA", "SAGE", "KNOWBE4", "VERCEL", "SMARTSHEET", "EMAG", "ALTEX"]
    
    if any(k in name_upper for k in critical_infra):
        inherent_risk = "Critical"
        new_risk = "Critical Baseline Risk (Continuous Access Monitoring Recommended)"
    elif any(k in name_upper for k in high_impact):
        inherent_risk = "High"
        new_risk = "High Baseline Risk (Regular Perimeter Audit Cycle Required)"
    else:
        if any(k in name_upper for k in ["CLEANING", "VENDING", "HOTEL", "CAKE", "BAKE"]):
            inherent_risk = "Low"
            new_risk = "Low Baseline Risk"

    clean_keyword = name_upper.split()[0] if len(name_upper.split()) > 0 else name_upper
    
    if len(clean_keyword) > 3:
        for alert in live_intel:
            alert_text = f"{alert['title']} {alert['summary']}".upper()
            
            if clean_keyword in alert_text:
                breach_status = "⚠️ ALERT"
                breach_details = f"<strong>{alert['title']}</strong>: {alert['summary'][:200]}..."
                css_class = "status-alert"
                source_reference = alert['source']
                
                if inherent_risk == "Low":
                    new_risk = "⚠️ ELEVATED MEDIUM (Active Public Security Incident Disclosed)"
                else:
                    new_risk = f"🚨 ESCALATED CRITICAL (Active Incident Reported via {source_reference})"
                break
                
    return breach_status, breach_details, inherent_risk, new_risk, css_class, source_reference

def run_automation():
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p')
    
    excel_file = 'vendor_list.xlsx'
    log_file = 'daily_log.txt'
    html_file = 'index.html'
    
    if not os.path.exists(excel_file):
        print("Excel file not found.")
        return

    try:
        live_intel = fetch_live_threat_intel()
        
        df = pd.read_excel(excel_file)
        df = df.dropna(how='all')
        
        vendor_col = None
        for col in df.columns:
            if any(k in str(col).upper() for k in ['VENDOR', 'NAME', 'COMPANY']):
                vendor_col = col
                break
        if not vendor_col:
            vendor_col = df.columns[0]

        table_rows = ""
        alert_count = 0
        
        for index, row in df.iterrows():
            vendor_name = row[vendor_col]
            if pd.isna(vendor_name):
                continue
                
            status, details, inherent, residual, css_class, source = assess_vendor_threat(vendor_name, live_intel)
            
            if status == "⚠️ ALERT":
                alert_count += 1
            
            # Formatted using standard concatenation to avoid string literal collisions
            table_rows += "<tr>"
            table_rows += f"<td class=\"vendor-name\">{vendor_name}</td>"
            table_rows += f"<td><span class=\"status-badge {css_class}\">{status}</span></td>"
            table_rows += f"<td>{details}</td>"
            table_rows += f"<td><span class=\"risk-badge risk-{inherent}\">{inherent.upper()}</span></td>"
            table_rows += f"<td>{new_risk}</td>"
            table_rows += f"<td style=\"font-weight: 600; color: #555;\">{source}</td>"
            table_rows += "</tr>\n"
        
        # Base HTML Structure with standard string markers replaced safely
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CISO Third-Party Risk Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background-color: #fcfdfd; color: #2c3e50; }
        .header { background: linear-gradient(135deg, #141e30 0%, #243b55 100%); color: white; padding: 25px 30px; border-radius: 6px; margin-bottom: 25px; }
        .header h1 { margin: 0; font-size: 24px; letter-spacing: 0.5px; }
        .header p { margin: 5px 0 0 0; opacity: 0.9; font-size: 13px; }
        .metrics-bar { display: flex; gap: 20px; margin-bottom: 25px; }
        .metric-card { background: white; padding: 15px 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); flex: 1; border-left: 4px solid #34495e; }
        .metric-card.critical { border-left-color: #e74c3c; }
        .metric-value { font-size: 20px; font-weight: bold; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 6px; overflow: hidden; }
        th { background-color: #2c3e50; color: white; text-align: left; padding: 12px 15px; font-size: 13px; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #eef2f5; font-size: 13px; vertical-align: top; }
        tr:nth-child(even) td { background-color: #f8fafc; }
        .vendor-name { font-weight: bold; color: #2c3e50; }
        .status-badge { display: inline-block; padding: 3px 6px; font-weight: bold; font-size: 11px; border-radius: 4px; }
        .status-clean { background-color: #d1e7dd; color: #0f5132; }
        .status-alert { background-color: #f8d7da; color: #842029; font-weight: bold; }
        .risk-badge { display: inline-block; padding: 3px 6px; border-radius: 3px; font-weight: 600; font-size: 11px; }
        .risk-Critical { background-color: #f8d7da; color: #842029; }
        .risk-High { background-color: #fff3cd; color: #664d03; }
        .risk-Medium { background-color: #cfe2ff; color: #084298; }
        .risk-Low { background-color: #e2e3e5; color: #41464b; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CISO Third-Party Risk & Threat Intelligence Center</h1>
        <p>Enterprise Perimeter Security Operations | Live OSINT Correlated Feed | Last Updated: __TIME__ IST</p>
    </div>
    
    <div class="metrics-bar">
        <div class="metric-card">
            <div style="font-size: 12px; color: #7f8c8d; text-transform: uppercase;">Total Active Monitored Suppliers</div>
            <div class="metric-value">__TOTAL__</div>
        </div>
        <div class="metric-card critical">
            <div style="font-size: 12px; color: #7f8c8d; text-transform: uppercase;">Live 24h Compromise Warnings</div>
            <div class="metric-value" style="color: __COLOR__;">__ALERTS__</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th style="width: 22%;">Third-Party Legal Identity</th>
                <th style="width: 12%;">24h Security Status</th>
                <th style="width: 31%;">Threat Analysis / Compromise Indicators</th>
                <th style="width: 10%;">Inherent Risk</th>
                <th style="width: 15%;">Residual Risk Profile</th>
                <th style="width: 10%;">Intel Source</th>
            </tr>
        </thead>
        <tbody>
            __ROWS__
        </tbody>
    </table>
</body>
</html>"""
        
        # Safe structural placement parsing
        html_content = html_template.replace("__TIME__", current_time)
        html_content = html_content.replace("__TOTAL__", str(len(df)))
        html_content = html_content.replace("__ALERTS__", str(alert_count))
        html_content = html_content.replace("__COLOR__", "#e74c3c" if alert_count > 0 else "#27ae60")
        html_content = html_content.replace("__ROWS__", table_rows)
        
        with open(html_file, 'w', encoding="utf-8") as f:
            f.write(html_content)
            
        with open(log_file, 'a') as f:
            f.write(f"[{current_time}] SUCCESS: Live OSINT scan executed. Found {alert_count} active perimeter threats.\n")
            
        print("CISO Dashboard successfully updated via live scraping.")

    except Exception as e:
        with open(log_file, 'a') as f:
            f.write(f"[{current_time}] FAILED: {str(e)}\n")
        print(f"
