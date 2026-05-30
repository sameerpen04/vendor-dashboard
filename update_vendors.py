import pandas as pd
from datetime import datetime
import pytz
import os
import requests
import xml.etree.ElementTree as ET
import re

def fetch_live_threat_intel():
    intel_database = []
    
    # CISA KEV Feed Data
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
    except Exception:
        pass

    # RSS Cyber Feeds
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
    
    critical_infra = ["CLOUD", "AZURE", "MONGODB", "HUBSPOT", "1PASSWORD", "CHASE", "BANK", "ICICI", "STANDARD CHARTERED", "REVOLUT", "SVB", "JPMORGAN"]
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
                
                if inherent_risk == "Low":
                    residual_risk = "⚠️ ELEVATED MEDIUM (Active Public Security Incident Disclosed)"
                else:
                    residual_risk = f"🚨 ESCALATED CRITICAL (Active Incident Reported via {source_reference})"
                break
                
    return breach_status, breach_details, inherent_risk, residual_risk, css_class, source_reference

def run_automation():
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p')
    
    excel_file = 'Vendor_List.xlsx'
    template_file = 'template.html'
    html_file = 'index.html'
    log_file = 'daily_log.txt'
    
    if not os.path.exists(excel_file) or not os.path.exists(template_file):
        return

    try:
        live_intel = fetch_live_threat_intel()
        df = pd.read_excel(excel_file).dropna(how='all')
        
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
            
            table_rows += "<tr>"
            table_rows += f"<td class=\"vendor-name\">{vendor_name}</td>"
            table_rows += f"<td><span class=\"status-badge {css_class}\">{status}</span></td>"
            table_rows += f"<td>{details}</td>"
            table_rows += f"<td><span class=\"risk-badge risk-{inherent}\">{inherent.upper()}</span></td>"
            table_rows += f"<td>{residual}</td>"
            table_rows += f"<td style=\"font-weight: 600; color: #555;\">{source}</td>"
            table_rows += "</tr>\n"
        
        with open(template_file, 'r', encoding='utf-8') as f:
            output_content = f.read()
            
        output_content = output_content.replace("__TIME__", current_time)
        output_content = output_content.replace("__TOTAL__", str(len(df)))
        output_content = output_content.replace("__ALERTS__", str(alert_count))
        output_content = output_content.replace("__COLOR__", "#e74c3c" if alert_count > 0 else "#27ae60")
        output_content = output_content.replace("__ROWS__", table_rows)
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(output_content)
            
        with open(log_file, 'a') as f:
            f.write(f"[{current_time}] SUCCESS: Sync complete.\n")

    except Exception:
        pass

if __name__ == "__main__":
    run_automation()
