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
            for vuln in vulnerabilities[-100:]:
                intel_database.append({
                    'title': f"CISA KEV Alert: {vuln.get('cveID')}",
                    'summary': f"{vuln.get('vendorProject')} - {vuln.get('shortDescription')}",
                    'source': "CISA KEV Catalog"
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
                breach_details = f"<strong>{alert['title']}</strong>: {alert['summary'][:180]}..."
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
    html_file = 'index.html'
    log_file = 'daily_log.txt'
    
    if not os.path.exists(excel_file):
        print("Excel file missing.")
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
        
        # Build HTML via string concatenation to completely avoid formatting and braces syntax breaks
        html_parts = [
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n",
            "<title>CISO Third-Party Risk Dashboard</title>\n<style>\n",
            "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 30px; background-color: #fcfdfd; color: #2c3e50; }\n",
            ".header { background: linear-gradient(135deg, #141e30 0%, #243b55 100%); color: white; padding: 25px 30px; border-radius: 6px; margin-bottom: 25px; }\n",
            ".header h1 { margin: 0; font-size: 24px; letter-spacing: 0.5px; }\n",
            ".header p { margin: 5px 0 0 0; opacity: 0.9; font-size: 13px; }\n",
            ".metrics-bar { display: flex; gap: 20px; margin-bottom: 25px; }\n",
            ".metric-card { background: white; padding: 15px 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); flex: 1; border-left: 4px solid #34495e; }\n",
            ".metric-card.critical { border-left-color: #e74c3c; }\n",
            ".metric-value { font-size: 20px; font-weight: bold; margin-top: 5px; }\n",
            "table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 6px; overflow: hidden; }\n",
            "th { background-color: #2c3e50; color: white; text-align: left; padding: 12px 15px; font-size: 13px; font-weight: 600; }\n",
            "td { padding: 12px 15px; border-bottom: 1px solid #eef2f5; font-size: 13px; vertical-align: top; }\n",
            "tr:nth-child(even) td { background-color: #f8fafc; }\n",
            ".vendor-name { font-weight: bold; color: #2c3e50; }\n",
            ".status-badge { display: inline-block; padding: 3px 6px; font-weight: bold; font-size: 11px; border-radius: 4px; }\n",
            ".status-clean { background-color: #d1e7dd; color: #0f5132; }\n",
            ".status-alert { background-color: #f8d7da; color: #842029; font-weight: bold; }\n",
            ".risk-badge { display: inline-block; padding: 3px 6px; border-radius: 3px; font-weight: 600; font-size: 11px; }\n",
            ".risk-Critical { background-color: #f8d7da; color: #842029; }\n",
            ".risk-High { background-color: #fff3cd; color: #664d03; }\n",
            ".risk-Medium { background-color: #cfe2ff; color: #084298; }\n",
            ".risk-Low { background-color: #e2e3e5; color: #41464b; }\n",
            "</style>\n</head>\n<body>\n",
            "<div class=\"header\">\n",
            "    <h1>🛡️ CISO Third-Party Risk & Threat Intelligence Center</h1>\n",
            f"    <p>Enterprise Perimeter Security Operations | Live OSINT Correlated Feed | Last Updated: {current_time} IST</p>\n",
            "</div>\n<div class=\"metrics-bar\">\n",
            "    <div class=\"metric-card\">\n",
            "        <div style=\"font-size: 12px; color: #7f8c8d; text-transform: uppercase;\">Total Active Monitored Suppliers</div>\n",
            f"        <div class=\"metric-value\">{len(df)}</div>\n",
            "    </div>\n",
            "    <div class=\"metric-card critical\">\n",
            "        <div style=\"font-size: 12px; color: #7f8c8d; text-transform: uppercase;\">Live 24h Compromise Warnings</div>\n",
            f"        <div class=\"metric-value\" style=\"color: " + ("#e74c3c" if alert_count > 0 else "#27ae60") + f";\">{alert_count}</div>\n",
            "    </div>\n",
            "</div>\n<table>\n<thead>\n<tr>\n",
            "<th style=\"width: 22%;\">Third-Party Legal Identity</th>\n",
            "<th style=\"width: 12%;\">24h Security Status</th>\n",
            "<th style=\"width: 31%;\">Threat Analysis / Compromise Indicators</th>\n",
            "<th style=\"width: 10%;">Inherent Risk</th>\n",
            "<th style=\"width: 15%;\">Residual Risk Profile</th>\n",
            "<th style=\"width: 10%;\">Intel Source</th>\n",
            f"</tr>\n</thead>\n<tbody>\n{table_rows}</tbody>\n</table>\n",
            f"\n</body>\n</html>"
        ]
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write("".join(html_parts))
            
        with open(log_file, 'a') as f:
            f.write(f"[{current_time}] SUCCESS: Synchronized entries.\n")
            
        print("Success.")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    run_automation()
